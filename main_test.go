package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"testing"
)

func TestLogScanErrorDeduplicatesFailures(t *testing.T) {
	var output bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&output, nil))
	var previous error
	message := "app/lan: name already owned\nother/lan: rename refused"
	for i := 0; i < 1000; i++ {
		previous = logScanError(log, errors.New(message), previous)
	}
	assertScanErrorLog(t, &output, message)
	if previous == nil || previous.Error() != message {
		t.Fatalf("failure state = %v, want %q", previous, message)
	}
	previous = logScanError(log, errors.New("different failure"), previous)
	assertScanErrorLog(t, &output, "different failure")
	previous = logScanError(log, nil, previous)
	if previous != nil || output.Len() != 0 {
		t.Fatal("successful scan did not quietly clear failure state")
	}
	previous = logScanError(log, errors.New(message), previous)
	assertScanErrorLog(t, &output, message)
	logScanError(log, errors.New(message), previous)
	if output.Len() != 0 {
		t.Fatalf("repeated failure logged: %s", output.String())
	}
	logScanError(log, errors.New(""), nil)
	assertScanErrorLog(t, &output, "")
}

func assertScanErrorLog(t *testing.T, output *bytes.Buffer, want string) {
	t.Helper()
	decoder := json.NewDecoder(output)
	var got map[string]string
	if err := decoder.Decode(&got); err != nil {
		t.Fatalf("missing error log: %v", err)
	}
	if got["level"] != "ERROR" || got["msg"] != "scan failed; daemon will retry" || got["error"] != want {
		t.Fatalf("incorrect error log: %+v", got)
	}
	var extra json.RawMessage
	if err := decoder.Decode(&extra); err != io.EOF {
		t.Fatalf("expected exactly one error log; extra=%s err=%v", extra, err)
	}
	output.Reset()
}

func TestRepeatedFailedScansKeepRetrying(t *testing.T) {
	_, links, r := fixture()
	links.applyErr = errors.New("Device or resource busy")
	var output bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&output, nil))
	var previous error
	for i := 0; i < 25; i++ {
		result, err := r.run(context.Background())
		if err == nil || len(result.Mappings) != 1 || result.Mappings[0].Status != "error" {
			t.Fatalf("failed endpoint missing from scan: %+v %v", result, err)
		}
		previous = logScanError(log, err, previous)
	}
	if len(links.calls) != 25 {
		t.Fatalf("got %d attempts, want 25", len(links.calls))
	}
	assertScanErrorLog(t, &output, previous.Error())
}

func TestLogEndpointsDeduplicatesSkipped(t *testing.T) {
	base := mapping{
		ContainerID: "c1", Container: "mirenai", NetworkID: "n1", Network: "container-vlan20",
		RequestedName: "veth_mirenai", Status: "skipped", Error: "unsupported network driver: dhcp",
	}
	tests := []struct {
		name   string
		change func(*mapping)
	}{
		{"reason", func(m *mapping) { m.Error = "unsupported network driver: macvlan" }},
		{"requested name", func(m *mapping) { m.RequestedName = "veth_other" }},
		{"container recreation", func(m *mapping) { m.ContainerID = "c2" }},
		{"network recreation", func(m *mapping) { m.NetworkID = "n2" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var output bytes.Buffer
			log := slog.New(slog.NewJSONHandler(&output, nil))
			previous := logEndpoints(log, []mapping{base}, nil)
			assertEndpointLogs(t, &output, []mapping{base})
			for i := 0; i < 10; i++ {
				previous = logEndpoints(log, []mapping{base}, previous)
			}
			assertEndpointLogs(t, &output, nil)
			changed := base
			tt.change(&changed)
			previous = logEndpoints(log, []mapping{changed}, previous)
			assertEndpointLogs(t, &output, []mapping{changed})
			logEndpoints(log, []mapping{changed}, previous)
			assertEndpointLogs(t, &output, nil)
		})
	}
}

func TestLogEndpointsSkippedLifecycle(t *testing.T) {
	base := mapping{ContainerID: "c1", NetworkID: "n1", Status: "skipped", Error: "unsupported"}
	for _, status := range []string{"removed", "error", "unchanged"} {
		t.Run(status, func(t *testing.T) {
			var output bytes.Buffer
			log := slog.New(slog.NewJSONHandler(&output, nil))
			previous := logEndpoints(log, []mapping{base}, nil)
			assertEndpointLogs(t, &output, []mapping{base})
			var mappings []mapping
			if status != "removed" {
				changed := base
				changed.Status = status
				mappings = []mapping{changed}
			}
			previous = logEndpoints(log, mappings, previous)
			assertEndpointLogs(t, &output, nil)
			if len(previous) != 0 {
				t.Fatal("stale skipped endpoint retained")
			}
			logEndpoints(log, []mapping{base}, previous)
			assertEndpointLogs(t, &output, []mapping{base})
		})
	}
}

func TestLogEndpointsPreservesOtherLogging(t *testing.T) {
	var output bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&output, nil))
	mappings := []mapping{
		{Status: "applied", Container: "app", Interface: "veth_app", RequestedName: "veth_app", Namespace: "host"},
		{Status: "would-change", Container: "dry", Interface: "eth0", RequestedName: "veth_dry", Namespace: "container"},
		{Status: "unchanged"},
		{Status: "error", Error: "reported elsewhere"},
	}
	previous := logEndpoints(log, mappings, nil)
	assertEndpointLogs(t, &output, mappings[:2])
	logEndpoints(log, mappings, previous)
	assertEndpointLogs(t, &output, mappings[:2])
}

func TestLogEndpointsDeduplicatesMonitored(t *testing.T) {
	var output bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&output, nil))
	record := mapping{Status: "monitored", Interface: "dh-live", RequestedName: "veth_app", NamingWarning: "name occupied", VNStatStatus: "unchanged"}
	previous := logEndpoints(log, []mapping{record}, nil)
	assertEndpointLogs(t, &output, []mapping{record})
	logEndpoints(log, []mapping{record}, previous)
	assertEndpointLogs(t, &output, nil)
	record.Interface = "dh-recreated"
	logEndpoints(log, []mapping{record}, previous)
	assertEndpointLogs(t, &output, []mapping{record})
}

func assertEndpointLogs(t *testing.T, output *bytes.Buffer, want []mapping) {
	t.Helper()
	decoder := json.NewDecoder(output)
	for _, m := range want {
		var got map[string]string
		if err := decoder.Decode(&got); err != nil {
			t.Fatalf("missing or invalid endpoint log: %v", err)
		}
		for key, value := range map[string]string{
			"level": "INFO", "msg": "endpoint", "container": m.Container, "network": m.Network,
			"interface": m.Interface, "requested_name": m.RequestedName, "status": m.Status, "detail": m.Error,
			"namespace": m.Namespace,
		} {
			if got[key] != value {
				t.Errorf("log field %s = %q, want %q", key, got[key], value)
			}
		}
	}
	var extra json.RawMessage
	if err := decoder.Decode(&extra); err == nil {
		t.Fatalf("unexpected extra log: %s", extra)
	} else if err != io.EOF {
		t.Fatalf("invalid log output: %v", err)
	}
	output.Reset()
}

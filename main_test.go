package main

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"testing"
)

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

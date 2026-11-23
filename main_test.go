package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
	"veth-rename/internal/firewall"
)

func TestSandoSyncCLIHelper(t *testing.T) {
	if os.Getenv("VETH_SANDO_CLI_TEST") != "1" {
		return
	}
	for i, arg := range os.Args {
		if arg == "--" {
			os.Args = append([]string{os.Args[0]}, os.Args[i+1:]...)
			break
		}
	}
	flag.CommandLine = flag.NewFlagSet("sando-cli", flag.ContinueOnError)
	if err := run(slog.New(slog.NewTextHandler(os.Stderr, nil))); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Exit(0)
}

func TestSandoSyncDirectionOverrideCLI(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "firewall.yaml")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[{"ignorelist_id":"x","src_ip":"10.0.0.18","dst_ip":"*","protocol":6,"dst_port":443}]`))
	}))
	defer server.Close()
	config := "enabled: false\nmanual_rules: manual.yaml\nsando_rules: sando.yaml\nsando_endpoint: " + server.URL + "\nsando_direction: egress\n"
	if err := os.WriteFile(configPath, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "manual.yaml"), []byte("rules: []\n"), 0600); err != nil {
		t.Fatal(err)
	}
	runCLI := func(args ...string) ([]byte, error) {
		t.Helper()
		cmd := exec.Command(os.Args[0], append([]string{"-test.run=^TestSandoSyncCLIHelper$", "--", "--firewall-config=" + configPath}, args...)...)
		cmd.Env = append(os.Environ(), "VETH_SANDO_CLI_TEST=1")
		return cmd.CombinedOutput()
	}
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"--sando-sync"}, "egress"},
		{[]string{"--sando-sync", "--sando-direction=ingress"}, "ingress"},
		{[]string{"--sando-sync", "--sando-direction=both"}, "both"},
	} {
		out, err := runCLI(tc.args...)
		if err != nil {
			t.Fatalf("sync: %s %v", out, err)
		}
		var file firewall.RuleFile
		if err := yaml.Unmarshal(out, &file); err != nil || len(file.Rules) != 1 || file.Rules[0].Direction != tc.want {
			t.Fatalf("override: %s %v", out, err)
		}
		saved, err := os.ReadFile(filepath.Join(dir, "sando.yaml"))
		if err != nil || string(saved) != string(out) {
			t.Fatalf("persisted override: %v", err)
		}
	}
	before, err := os.ReadFile(filepath.Join(dir, "sando.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"--sando-sync", "--sando-direction=outbound"},
		{"--sando-sync", "--sando-direction="},
		{"--sando-dump", "--sando-direction=ingress"},
		{"--sando-direction=ingress"},
	} {
		if out, err := runCLI(args...); err == nil || !strings.Contains(string(out), "direction") {
			t.Fatalf("invalid override: %s %v", out, err)
		}
	}
	after, err := os.ReadFile(filepath.Join(dir, "sando.yaml"))
	if err != nil || string(before) != string(after) {
		t.Fatal("failed override replaced policy")
	}
	savedConfig, err := os.ReadFile(configPath)
	if err != nil || string(savedConfig) != config {
		t.Fatal("override changed config defaults")
	}
}

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

func TestMonitoredInterfacesOnlyVerifiedManagedHostVeths(t *testing.T) {
	records := []mapping{
		{Namespace: "host", IfIndex: 7, Interface: "veth_app", ContainerID: "c1", NetworkID: "n1", Status: "applied", IPv4: "10.0.0.1", IPv6: "2001:db8::1"},
		{Namespace: "host", IfIndex: 8, Interface: "veth_other", Status: "monitored"},
		{Namespace: "host", IfIndex: 9, Status: "unchanged"},
		{Namespace: "container", IfIndex: 10, Status: "applied"},
		{Namespace: "host", IfIndex: 11, Status: "error"},
		{Namespace: "host", IfIndex: 12, Status: "skipped"},
		{Namespace: "host", IfIndex: 13, Status: "would-change"},
	}
	got := monitoredInterfaces(records)
	if len(got) != 3 || got[0].Index != 7 || got[0].Name != "veth_app" || got[0].Identity != "c1/n1" {
		t.Fatalf("monitoring selection = %+v", got)
	}
	if got[0].IPv4 != "10.0.0.1" || got[0].IPv6 != "2001:db8::1" {
		t.Fatalf("endpoint addresses missing: %+v", got[0])
	}
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

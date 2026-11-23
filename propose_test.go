package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestProposeRulesCLI(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "drops.log")
	config := filepath.Join(dir, "firewall.yaml")
	now := time.Now()
	record := func(when time.Time) string {
		return when.Format(time.Stamp) + ` host veth-renamer[1]: DROP IF="app" DIR=ingress SRC=10.0.0.1 DST=203.0.113.1 PROTO=6 SPT=123 DPT=443 LEN=40 RULE="default" REASON=default-deny TIME=` + when.Format(time.RFC3339Nano) + "\n"
	}
	if err := os.WriteFile(path, []byte(record(now.Add(-time.Hour))+record(now.Add(-48*time.Hour))), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config, []byte("drop_log: drops.log\n"), 0600); err != nil {
		t.Fatal(err)
	}
	runCLI := func(args ...string) (string, error) {
		t.Helper()
		cmd := exec.Command(os.Args[0], append([]string{"-test.run=^TestSandoSyncCLIHelper$", "--"}, args...)...)
		cmd.Env = append(os.Environ(), "VETH_SANDO_CLI_TEST=1")
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	for _, tc := range []struct {
		args    []string
		packets string
	}{
		{[]string{"--propose-rules", "--firewall-log=" + path}, "1"},
		{[]string{"--propose-rules", "--firewall-config=" + config, "--since=7d", "--sort=bytes"}, "2"},
		{[]string{"--propose-rules", "--firewall-config=" + config, "--firewall-log=" + path, "--since=168h"}, "2"},
	} {
		out, err := runCLI(tc.args...)
		lines := strings.Split(strings.TrimSpace(out), "\n")
		if err != nil || len(lines) != 2 || strings.Fields(lines[1])[0] != tc.packets {
			t.Fatalf("CLI %v: %q %v", tc.args, out, err)
		}
	}
	for _, args := range [][]string{
		{"--propose-rules"},
		{"--since=7d"},
		{"--propose-rules", "--firewall-log=" + path, "--since=0d"},
		{"--propose-rules", "--firewall-log=" + path, "--sort=invalid"},
		{"--propose-rules", "--firewall-log=" + path, "--sando-sync"},
		{"--propose-rules", "--firewall-log=" + path, "--once"},
		{"--propose-rules", "--firewall-log=" + path, "--dry-run"},
		{"--propose-rules", "--firewall-log=" + path, "--ipfix-config=missing.yaml"},
		{"--propose-rules", "--firewall-log=" + filepath.Join(dir, "missing.log")},
	} {
		if out, err := runCLI(args...); err == nil || strings.Contains(out, "PACKETS") {
			t.Fatalf("invalid CLI %v: %q %v", args, out, err)
		}
	}
}

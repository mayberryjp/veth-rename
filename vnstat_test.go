package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestVNStatSync(t *testing.T) {
	for _, scenario := range []struct {
		name     string
		database string
		dryRun   bool
		fail     string
		want     []string
		status   string
	}{
		{"add", `{"interfaces":[]}`, false, "", []string{"--json s", "--add -i dh-live", "-i dh-live --setalias veth_app", "--json s"}, "applied"},
		{"alias", `{"interfaces":[{"name":"dh-live","alias":"old"}]}`, false, "", []string{"--json s", "-i dh-live --setalias veth_app", "--json s"}, "applied"},
		{"unchanged", `{"interfaces":[{"name":"dh-live","alias":"veth_app"}]}`, false, "", []string{"--json s"}, "unchanged"},
		{"dry run", `{"interfaces":[]}`, true, "", []string{"--json s"}, "would-change"},
		{"add failure", `{"interfaces":[]}`, false, "--add -i dh-live", []string{"--json s", "--add -i dh-live"}, "error"},
		{"alias failure", `{"interfaces":[{"name":"dh-live"}]}`, false, "-i dh-live --setalias veth_app", []string{"--json s", "-i dh-live --setalias veth_app"}, "error"},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			var calls []string
			database := scenario.database
			client := vnstatClient{path: "vnstat", exec: func(_ context.Context, _ string, args ...string) ([]byte, error) {
				call := strings.Join(args, " ")
				calls = append(calls, call)
				if call == scenario.fail {
					return nil, errors.New("denied")
				}
				if args[0] == "--add" {
					database = `{"interfaces":[{"name":"dh-live"}]}`
				} else if args[0] == "-i" {
					database = `{"interfaces":[{"name":"dh-live","alias":"veth_app"}]}`
				}
				return []byte(database), nil
			}}
			records := []mapping{{Namespace: "host", Interface: "dh-live", RequestedName: "veth_app", Status: "monitored"},
				{Namespace: "container", Interface: "eth0", Status: "applied"},
				{Namespace: "host", Interface: "unverified", Status: "error"}}
			err := client.sync(context.Background(), records, scenario.dryRun)
			if (err != nil) != (scenario.fail != "") || !reflect.DeepEqual(calls, scenario.want) || records[0].VNStatStatus != scenario.status {
				t.Fatalf("sync: err=%v calls=%v records=%+v", err, calls, records)
			}
		})
	}
}

func TestAutoMonitoringRecreation(t *testing.T) {
	_, links, reconciler := dhcpBridgeFixture("bridge")
	reconciler.mode = "auto"
	links.hs[0].Name = "dh-live"
	orphan := veth(99, 98, "veth_pihole", "02:00:00:00:00:01", "br-vlan20")
	links.hs = append(links.hs, orphan)
	aliases := map[string]string{}
	var commands []string
	reconciler.vnstat = &vnstatClient{path: "vnstat", exec: func(_ context.Context, _ string, args ...string) ([]byte, error) {
		commands = append(commands, strings.Join(args, " "))
		if args[0] == "--json" {
			entries := []map[string]string{}
			for name, alias := range aliases {
				entries = append(entries, map[string]string{"name": name, "alias": alias})
			}
			return json.Marshal(map[string]any{"interfaces": entries})
		}
		if args[0] == "--add" {
			aliases[args[2]] = ""
		} else {
			aliases[args[1]] = args[3]
		}
		return nil, nil
	}}
	for _, name := range []string{"dh-live", "dh-recreated"} {
		links.hs[0].Name = name
		result, err := reconciler.run(context.Background())
		if err != nil || result.Mappings[0].Status != "monitored" || result.Mappings[0].VNStatStatus != "applied" || result.Mappings[0].NamingWarning == "" {
			t.Fatalf("repair: %+v %v", result, err)
		}
		result, err = reconciler.run(context.Background())
		if err != nil || result.Mappings[0].VNStatStatus != "unchanged" {
			t.Fatalf("repeat: %+v %v", result, err)
		}
	}
	if aliases["dh-live"] != "veth_pihole" || aliases["dh-recreated"] != "veth_pihole" || len(links.calls) != 0 || !reflect.DeepEqual(links.hs[1], orphan) {
		t.Fatalf("history or links changed: aliases=%v calls=%v", aliases, links.calls)
	}
	if len(commands) != 10 {
		t.Fatalf("unexpected commands: %v", commands)
	}
}

func TestAutoNamingAndFallback(t *testing.T) {
	for _, scenario := range []struct {
		name       string
		mode       string
		collision  bool
		namingErr  bool
		monitor    bool
		dryRun     bool
		wantError  bool
		wantStatus string
	}{
		{"alternative", "auto", false, false, true, false, false, "applied"},
		{"unsupported alternative", "auto", false, true, true, false, false, "monitored"},
		{"collision without vnstat", "auto", true, false, false, false, true, "error"},
		{"explicit primary", "primary", true, false, true, false, true, "error"},
		{"collision dry run", "auto", true, false, true, true, false, "monitored"},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			_, links, reconciler := dhcpBridgeFixture("bridge")
			reconciler.mode, reconciler.dryRun = scenario.mode, scenario.dryRun
			if scenario.collision {
				links.hs = append(links.hs, link{Index: 99, Name: "veth_pihole"})
			}
			if scenario.namingErr {
				links.applyErr = errors.New("not supported")
			}
			if scenario.monitor {
				alias := ""
				reconciler.vnstat = &vnstatClient{exec: func(_ context.Context, _ string, args ...string) ([]byte, error) {
					if scenario.dryRun && args[0] != "--json" {
						t.Fatal("dry run modified vnStat")
					}
					if args[0] == "-i" {
						alias = "veth_pihole"
					}
					return json.Marshal(map[string]any{"interfaces": []map[string]string{{"name": "veth_random", "alias": alias}}})
				}}
			}
			result, err := reconciler.run(context.Background())
			if (err != nil) != scenario.wantError || result.Mappings[0].Status != scenario.wantStatus {
				t.Fatalf("run: %+v %v", result, err)
			}
			for _, call := range links.calls {
				if scenario.mode == "auto" && !strings.HasPrefix(call, "alternative:") {
					t.Fatalf("auto performed primary rename: %s", call)
				}
			}
		})
	}
}

func TestVNStatFailuresAndRetry(t *testing.T) {
	for _, scenario := range []struct {
		name   string
		output string
		err    error
	}{
		{"database unavailable", "", errors.New("database locked")},
		{"invalid JSON", "not json", nil},
		{"wrong schema", `{}`, nil},
		{"write not persisted", `{"interfaces":[]}`, nil},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			client := vnstatClient{exec: func(context.Context, string, ...string) ([]byte, error) {
				return []byte(scenario.output), scenario.err
			}}
			records := []mapping{{Namespace: "host", Interface: "dh-live", RequestedName: "veth_app", Status: "monitored"}}
			if err := client.sync(context.Background(), records, false); err == nil || records[0].VNStatStatus != "error" || records[0].VNStatError == "" || records[0].Status != "error" {
				t.Fatalf("unverified success: records=%+v err=%v", records, err)
			}
			client.exec = func(context.Context, string, ...string) ([]byte, error) {
				return []byte(`{"interfaces":[{"name":"dh-live","alias":"veth_app"}]}`), nil
			}
			records[0] = mapping{Namespace: "host", Interface: "dh-live", RequestedName: "veth_app", Status: "monitored"}
			if err := client.sync(context.Background(), records, false); err != nil || records[0].VNStatStatus != "unchanged" {
				t.Fatalf("retry failed: records=%+v err=%v", records, err)
			}
		})
	}
}

func TestVNStatEmptyDatabase(t *testing.T) {
	alias := ""
	client := vnstatClient{exec: func(_ context.Context, _ string, args ...string) ([]byte, error) {
		if args[0] == "--json" {
			if alias == "" {
				return []byte("Error: Database is empty.\n"), errors.New("exit status 1")
			}
			return []byte(`{"interfaces":[{"name":"dh-live","alias":"veth_app"}]}`), nil
		}
		if args[0] == "-i" {
			alias = args[3]
		}
		return nil, nil
	}}
	records := []mapping{{Namespace: "host", Interface: "dh-live", RequestedName: "veth_app", Status: "monitored"}}
	if err := client.sync(context.Background(), records, false); err != nil || records[0].VNStatStatus != "applied" {
		t.Fatalf("bootstrap: records=%+v err=%v", records, err)
	}
}

func TestVNStatBatchFailureIsolation(t *testing.T) {
	reads := 0
	alias := ""
	client := vnstatClient{exec: func(_ context.Context, _ string, args ...string) ([]byte, error) {
		if args[0] == "--json" {
			reads++
			return json.Marshal(map[string]any{"interfaces": []map[string]string{{"name": "dh-good", "alias": alias}}})
		}
		if args[0] == "--add" {
			return nil, errors.New("interface disappeared")
		}
		alias = args[3]
		return nil, nil
	}}
	records := []mapping{
		{Namespace: "host", Interface: "dh-gone", RequestedName: "veth_gone", Status: "monitored"},
		{Namespace: "host", Interface: "dh-good", RequestedName: "veth_good", Status: "monitored"},
	}
	if err := client.sync(context.Background(), records, false); err == nil || reads != 2 || records[0].VNStatStatus != "error" || records[1].VNStatStatus != "applied" {
		t.Fatalf("batch: reads=%d records=%+v err=%v", reads, records, err)
	}
}

func TestVNStatCLIIntegration(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getenv("VNSTAT_INTEGRATION") != "1" {
		t.Skip("requires Linux, vnStat 2.x, and VNSTAT_INTEGRATION=1; uses only a temporary database")
	}
	program, err := exec.LookPath("vnstat")
	if err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(t.TempDir(), "vnstat.conf")
	database := t.TempDir()
	if err := os.WriteFile(config, []byte(fmt.Sprintf("DatabaseDir %q\nUseLogging 0\n", database)), 0600); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := command(ctx, "vnstatd", "--config", config, "--initdb", "--noadd"); err != nil {
		t.Fatal(err)
	}
	client := vnstatClient{path: program, exec: func(ctx context.Context, program string, args ...string) ([]byte, error) {
		return command(ctx, program, append([]string{"--config", config}, args...)...)
	}}
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, iface := range interfaces {
		if iface.Name == "lo" {
			continue
		}
		records := []mapping{{Namespace: "host", Interface: iface.Name, RequestedName: "veth_test", Status: "monitored"}}
		if err := client.sync(ctx, records, true); err != nil || records[0].VNStatStatus != "would-change" {
			t.Fatalf("dry run: %+v %v", records, err)
		}
		for _, wantStatus := range []string{"applied", "unchanged"} {
			if err := client.sync(ctx, records, false); err != nil || records[0].VNStatStatus != wantStatus {
				t.Fatalf("sync: %+v %v", records, err)
			}
		}
		entries, err := client.interfaces(ctx)
		if err != nil || len(entries) != 1 || entries[iface.Name] != "veth_test" {
			t.Fatalf("database contents: %v %v", entries, err)
		}
		return
	}
	t.Fatal("no non-loopback interface available")
}

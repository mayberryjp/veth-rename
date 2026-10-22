package main

import (
	"context"
	"reflect"
	"strings"
	"testing"
)

func dhcpBridgeFixture(pluginMode string) (*fakeDocker, *fakeLinks, reconciler) {
	d, l, r := fixture()
	n := d.ns["0123456789abcdef"]
	n.Driver = "ghcr.io/claymore666/docker-net-dhcp:v2.3.1"
	n.Options = map[string]string{"bridge": "br-vlan20"}
	if pluginMode != "" {
		n.Options["mode"] = pluginMode
	}
	d.ns[n.ID] = n
	l.hs[0].Master = "br-vlan20"
	return d, l, r
}

func TestDHCPBridgeNaming(t *testing.T) {
	for _, pluginMode := range []string{"bridge", ""} {
		for _, namingMode := range []string{"primary", "alternative"} {
			t.Run(pluginMode+"/"+namingMode, func(t *testing.T) {
				_, l, r := dhcpBridgeFixture(pluginMode)
				r.mode = namingMode
				result, err := r.run(context.Background())
				if err != nil || len(result.Mappings) != 1 || !reflect.DeepEqual(l.applyPIDs, []int{0}) {
					t.Fatalf("apply: %+v %v pids=%v", result, err, l.applyPIDs)
				}
				m := result.Mappings[0]
				if m.Status != "applied" || m.Namespace != "host" || m.Bridge != "br-vlan20" ||
					m.IfIndex != 42 || !ownsName(l.hs[0], "veth_pihole") ||
					l.inner[100][0].Name != "eth7" {
					t.Fatalf("wrong target: %+v host=%+v inner=%+v", m, l.hs, l.inner[100])
				}
				result, err = r.run(context.Background())
				if err != nil || result.Mappings[0].Status != "unchanged" || len(l.calls) != 1 {
					t.Fatalf("not idempotent: %+v %v calls=%v", result, err, l.calls)
				}
			})
		}
	}
}

func TestDHCPBridgeDryRun(t *testing.T) {
	_, l, r := dhcpBridgeFixture("bridge")
	r.dryRun = true
	result, err := r.run(context.Background())
	if err != nil || result.Mappings[0].Status != "would-change" || len(l.calls) != 0 {
		t.Fatalf("dry run: %+v %v calls=%v", result, err, l.calls)
	}
}

func TestDHCPBridgeValidation(t *testing.T) {
	tests := []struct {
		name   string
		setup  func(*fakeDocker, *fakeLinks)
		substr string
	}{
		{"missing bridge", func(d *fakeDocker, _ *fakeLinks) {
			delete(d.ns["0123456789abcdef"].Options, "bridge")
		}, "no bridge interface"},
		{"wrong bridge", func(_ *fakeDocker, l *fakeLinks) { l.hs[0].Master = "other" }, "reciprocal veth"},
		{"wrong peer", func(_ *fakeDocker, l *fakeLinks) { l.hs[0].Peer++ }, "reciprocal veth"},
		{"wrong kind", func(_ *fakeDocker, l *fakeLinks) { l.hs[0].Info.Kind = "macvlan" }, "reciprocal veth"},
		{"collision", func(_ *fakeDocker, l *fakeLinks) {
			l.hs = append(l.hs, link{Index: 99, Name: "veth_pihole"})
		}, "already owned"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, l, r := dhcpBridgeFixture("bridge")
			tt.setup(d, l)
			result, err := r.run(context.Background())
			if err == nil || !strings.Contains(err.Error(), tt.substr) ||
				result.Mappings[0].Status != "error" || len(l.calls) != 0 {
				t.Fatalf("expected %q: %+v %v calls=%v", tt.substr, result, err, l.calls)
			}
		})
	}
}

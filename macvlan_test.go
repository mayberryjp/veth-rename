package main

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func macvlanFixture(driver string) (*fakeDocker, *fakeLinks, reconciler) {
	d, l, r := fixture()
	n := d.ns["0123456789abcdef"]
	n.Driver = driver
	n.Options = map[string]string{"mode": "macvlan", "parent": "enp44s0.20"}
	d.ns[n.ID] = n
	l.hs[0].Name = "enp44s0.20"
	l.hs[0].Info.Kind = "vlan"
	l.hs[0].Master = ""
	l.inner[100][0].Info.Kind = "macvlan"
	return d, l, r
}

func TestMacvlanNaming(t *testing.T) {
	for _, driver := range []string{
		"macvlan",
		"ghcr.io/claymore666/docker-net-dhcp:v2.3.1",
		"ghcr.io/claymore666/docker-net-dhcp:v2.4.0",
	} {
		for _, mode := range []string{"primary", "alternative"} {
			t.Run(driver+"/"+mode, func(t *testing.T) {
				_, l, r := macvlanFixture(driver)
				r.mode = mode
				// Host names do not collide with names in the container namespace.
				l.hs = append(l.hs, link{Index: 99, Name: "veth_pihole"})
				before := append([]link(nil), l.hs...)
				result, err := r.run(context.Background())
				if err != nil || len(l.calls) != 1 || !reflect.DeepEqual(l.applyPIDs, []int{100}) {
					t.Fatalf("apply: %+v %v calls=%v pids=%v", result, err, l.calls, l.applyPIDs)
				}
				m := result.Mappings[0]
				wantName := "veth_pihole"
				if mode == "alternative" {
					wantName = "eth7"
				}
				if m.Status != "applied" || m.Namespace != "container" || m.Bridge != "" ||
					m.Interface != wantName || m.IfIndex != 2 {
					t.Fatalf("incorrect container mapping: %+v", m)
				}
				if !reflect.DeepEqual(before, l.hs) {
					t.Fatalf("modified host interfaces: %+v", l.hs)
				}
				result, err = r.run(context.Background())
				if err != nil || result.Mappings[0].Status != "unchanged" || len(l.calls) != 1 {
					t.Fatalf("not idempotent: %+v %v calls=%v", result, err, l.calls)
				}
			})
		}
	}
}

func TestMacvlanDryRun(t *testing.T) {
	_, l, r := macvlanFixture("ghcr.io/claymore666/docker-net-dhcp:v2.3.1")
	r.dryRun = true
	result, err := r.run(context.Background())
	if err != nil || result.Mappings[0].Status != "would-change" || len(l.calls) != 0 ||
		l.inner[100][0].Name != "eth7" || l.hs[0].Name != "enp44s0.20" {
		t.Fatalf("dry run: %+v %v calls=%v", result, err, l.calls)
	}
}

func TestMixedBridgeAndMacvlan(t *testing.T) {
	d, l, r := macvlanFixture("ghcr.io/claymore666/docker-net-dhcp:v2.3.1")
	r.mode = "alternative"
	c := d.cs["c1"]
	c.Config.Labels[labelKey+".lan"] = "mac_app"
	c.Config.Labels[labelKey+".bridge"] = "veth_app"
	c.NetworkSettings.Networks["bridge"] = endpoint{
		NetworkID: "abcdef0123456789", EndpointID: "ep2", MacAddress: "02:42:ac:13:00:02",
	}
	d.ns["abcdef0123456789"] = network{ID: "abcdef0123456789", Driver: "bridge"}
	l.hs = append(l.hs, veth(77, 8, "veth_random", "", "br-abcdef012345"))
	l.inner[100] = append(l.inner[100], veth(8, 77, "eth8", "02:42:ac:13:00:02", ""))
	result, err := r.run(context.Background())
	if err != nil || len(result.Mappings) != 2 || !reflect.DeepEqual(l.applyPIDs, []int{0, 100}) {
		t.Fatalf("mixed apply: %+v %v pids=%v", result, err, l.applyPIDs)
	}
	if result.Mappings[0].Namespace != "host" || result.Mappings[1].Namespace != "container" ||
		!ownsName(l.hs[1], "veth_app") || !ownsName(l.inner[100][0], "mac_app") ||
		l.hs[0].Name != "enp44s0.20" {
		t.Fatalf("incorrect targets: %+v host=%+v inner=%+v", result, l.hs, l.inner[100])
	}
	result, err = r.run(context.Background())
	if err != nil || len(l.calls) != 2 ||
		result.Mappings[0].Status != "unchanged" || result.Mappings[1].Status != "unchanged" {
		t.Fatalf("mixed idempotency: %+v %v calls=%v", result, err, l.calls)
	}
}

func TestMacvlanRefusesUnsafeChanges(t *testing.T) {
	tests := []struct {
		name   string
		setup  func(*fakeDocker, *fakeLinks)
		substr string
	}{
		{"missing parent", func(d *fakeDocker, _ *fakeLinks) {
			delete(d.ns["0123456789abcdef"].Options, "parent")
		}, "no parent"},
		{"missing host parent", func(_ *fakeDocker, l *fakeLinks) { l.hs = nil }, "host parent"},
		{"wrong parent index", func(_ *fakeDocker, l *fakeLinks) { l.inner[100][0].Peer++ }, "one macvlan"},
		{"wrong MAC", func(_ *fakeDocker, l *fakeLinks) { l.inner[100][0].Address = "other" }, "one macvlan"},
		{"wrong kind", func(_ *fakeDocker, l *fakeLinks) { l.inner[100][0].Info.Kind = "veth" }, "one macvlan"},
		{"missing MAC", func(d *fakeDocker, _ *fakeLinks) {
			c := d.cs["c1"]
			ep := c.NetworkSettings.Networks["lan"]
			ep.MacAddress = ""
			c.NetworkSettings.Networks["lan"] = ep
		}, "no MAC"},
		{"ambiguous", func(_ *fakeDocker, l *fakeLinks) {
			l.inner[100] = append(l.inner[100], l.inner[100][0])
		}, "found 2"},
		{"primary collision", func(_ *fakeDocker, l *fakeLinks) {
			l.inner[100] = append(l.inner[100], link{Index: 99, Name: "veth_pihole"})
		}, "already owned"},
		{"alternative collision", func(_ *fakeDocker, l *fakeLinks) {
			l.inner[100] = append(l.inner[100], link{Index: 99, Name: "other", AltNames: []string{"veth_pihole"}})
		}, "already owned"},
		{"own alternative name", func(_ *fakeDocker, l *fakeLinks) {
			l.inner[100][0].AltNames = []string{"veth_pihole"}
		}, "already an alternative"},
		{"namespace error", func(_ *fakeDocker, l *fakeLinks) {
			l.nsErr = errors.New("namespace access denied")
		}, "namespace access denied"},
		{"endpoint changed", func(d *fakeDocker, _ *fakeLinks) {
			count := 0
			d.inspectHook = func(_ string, c container) container {
				count++
				if count > 1 {
					c.State.Pid++
				}
				return c
			}
		}, "endpoint changed"},
		{"namespace ownership changed", func(d *fakeDocker, _ *fakeLinks) {
			count := 0
			d.inspectHook = func(_ string, c container) container {
				count++
				if count > 1 {
					c.HostConfig.NetworkMode = "host"
				}
				return c
			}
		}, "endpoint changed"},
		{"parent changed", func(_ *fakeDocker, l *fakeLinks) {
			count := 0
			l.hostHook = func(l *fakeLinks) {
				count++
				if count > 1 {
					l.hs[0].Index++
				}
			}
		}, "one macvlan"},
		{"external rename", func(_ *fakeDocker, l *fakeLinks) {
			count := 0
			l.nsHook = func(l *fakeLinks, pid int) {
				count++
				if count > 1 {
					l.inner[pid][0].Name = "external"
				}
			}
		}, "container interface changed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, l, r := macvlanFixture("ghcr.io/claymore666/docker-net-dhcp:v2.3.1")
			tt.setup(d, l)
			result, err := r.run(context.Background())
			if err == nil || !strings.Contains(err.Error(), tt.substr) || len(l.calls) != 0 ||
				result.Mappings[0].Status != "error" || l.hs != nil && l.hs[0].Name != "enp44s0.20" {
				t.Fatalf("expected %q: %+v %v calls=%v", tt.substr, result, err, l.calls)
			}
		})
	}
}

func TestMacvlanApplyFailures(t *testing.T) {
	for _, failure := range []string{"busy", "no mutation", "verification namespace error", "replaced link"} {
		t.Run(failure, func(t *testing.T) {
			_, l, r := macvlanFixture("macvlan")
			switch failure {
			case "busy":
				l.applyErr = errors.New("Device or resource busy")
			case "no mutation":
				l.noMutation = true
			default:
				count := 0
				l.nsHook = func(l *fakeLinks, pid int) {
					count++
					if count == 3 {
						if failure == "verification namespace error" {
							l.nsErr = errors.New("verification failure")
						} else {
							l.inner[pid][0].Address = "replaced"
						}
					}
				}
			}
			result, err := r.run(context.Background())
			if err == nil || result.Mappings[0].Status != "error" ||
				!reflect.DeepEqual(l.applyPIDs, []int{100}) || l.hs[0].Name != "enp44s0.20" {
				t.Fatalf("failure hidden: %+v %v pids=%v", result, err, l.applyPIDs)
			}
		})
	}
}

func TestDHCPUnsupportedModesRemainSkipped(t *testing.T) {
	for _, mode := range []string{"ipvlan", "overlay", "unknown"} {
		t.Run(mode, func(t *testing.T) {
			d, l, r := macvlanFixture("ghcr.io/claymore666/docker-net-dhcp:v2.3.1")
			d.ns["0123456789abcdef"].Options["mode"] = mode
			result, err := r.run(context.Background())
			if err != nil || result.Mappings[0].Status != "skipped" || len(l.calls) != 0 {
				t.Fatalf("unsupported mode managed: %+v %v", result, err)
			}
		})
	}
}

func TestNameCommandNamespace(t *testing.T) {
	l := commandLinks{ip: "/usr/sbin/ip", nsenter: "/usr/bin/nsenter"}
	for _, pid := range []int{0, 100} {
		for _, mode := range []string{"primary", "alternative"} {
			program, args := l.nameCommand(pid, "eth0", "veth_app", mode)
			wantProgram := l.ip
			wantArgs := []string{"link", "set", "dev", "eth0", "name", "veth_app"}
			if mode == "alternative" {
				wantArgs = []string{"link", "property", "add", "dev", "eth0", "altname", "veth_app"}
			}
			if pid > 0 {
				wantProgram = l.nsenter
				wantArgs = append([]string{"-t", "100", "-n", "--", l.ip}, wantArgs...)
			}
			if program != wantProgram || !reflect.DeepEqual(args, wantArgs) {
				t.Fatalf("pid=%d mode=%s: got %s %v, want %s %v", pid, mode, program, args, wantProgram, wantArgs)
			}
		}
	}
}

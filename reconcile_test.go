package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type fakeDocker struct {
	cs          map[string]container
	ns          map[string]network
	listErr     error
	inspectErr  error
	inspectHook func(string, container) container
}

func (d *fakeDocker) containers(context.Context) ([]string, error) {
	var ids []string
	for id := range d.cs {
		ids = append(ids, id)
	}
	return ids, d.listErr
}

func (d *fakeDocker) inspect(_ context.Context, id string) (container, error) {
	c, ok := d.cs[id]
	if !ok {
		return c, fmt.Errorf("container not found")
	}
	if d.inspectHook != nil {
		c = d.inspectHook(id, c)
	}
	return c, d.inspectErr
}

func (d *fakeDocker) network(_ context.Context, id string) (network, error) {
	n, ok := d.ns[id]
	if !ok {
		return n, fmt.Errorf("network not found")
	}
	return n, nil
}

type fakeLinks struct {
	hs         []link
	inner      map[int][]link
	calls      []string
	applyPIDs  []int
	hostErr    error
	nsErr      error
	applyErr   error
	noMutation bool
	hostHook   func(*fakeLinks)
	nsHook     func(*fakeLinks, int)
}

func (l *fakeLinks) host(context.Context) ([]link, error) {
	if l.hostHook != nil {
		l.hostHook(l)
	}
	return l.hs, l.hostErr
}

func (l *fakeLinks) namespace(_ context.Context, pid int) ([]link, error) {
	if l.nsHook != nil {
		l.nsHook(l, pid)
	}
	return l.inner[pid], l.nsErr
}

func (l *fakeLinks) apply(_ context.Context, pid int, current, desired, mode string) error {
	l.calls = append(l.calls, mode+":"+current+":"+desired)
	l.applyPIDs = append(l.applyPIDs, pid)
	if l.applyErr != nil {
		return l.applyErr
	}
	if l.noMutation {
		return nil
	}
	targets := l.hs
	if pid > 0 {
		targets = l.inner[pid]
	}
	for i := range targets {
		if targets[i].Name == current {
			if mode == "alternative" {
				targets[i].AltNames = append(targets[i].AltNames, desired)
			} else {
				targets[i].Name = desired
			}
			return nil
		}
	}
	return fmt.Errorf("link not found")
}

func veth(index, peer int, name, mac, master string) link {
	l := link{Index: index, Peer: peer, Name: name, Address: mac, Master: master}
	l.Info.Kind = "veth"
	return l
}

func fixture() (*fakeDocker, *fakeLinks, reconciler) {
	c := container{ID: "c1", Name: "/pihole"}
	c.State.Running, c.State.Pid = true, 100
	c.Config.Labels = map[string]string{labelKey: "veth_pihole"}
	c.NetworkSettings.Networks = map[string]endpoint{
		"lan": {NetworkID: "0123456789abcdef", EndpointID: "ep1", MacAddress: "02:42:ac:12:00:02", IPAddress: "172.18.0.2"},
	}
	d := &fakeDocker{
		cs: map[string]container{c.ID: c},
		ns: map[string]network{"0123456789abcdef": {ID: "0123456789abcdef", Driver: "bridge"}},
	}
	l := &fakeLinks{
		hs: []link{veth(42, 2, "veth_random", "02:42:aa:00:00:01", "br-0123456789ab")},
		inner: map[int][]link{
			100: {veth(2, 42, "eth7", "02:42:ac:12:00:02", "")},
		},
	}
	return d, l, reconciler{docker: d, links: l, mode: "primary"}
}

func TestValidName(t *testing.T) {
	for _, name := range []string{"a", "veth_pihole", "123456789012345", "a.b-c_0"} {
		if err := validName(name); err != nil {
			t.Errorf("%q: %v", name, err)
		}
	}
	for _, name := range []string{"", ".", "..", "1234567890123456", "a b", "a/b", "a:b", "a%b", "a\nb", "café", "-bad;cmd"} {
		if err := validName(name); err == nil {
			t.Errorf("accepted invalid name %q", name)
		}
	}
}

func TestDesiredName(t *testing.T) {
	d, _, _ := fixture()
	c := d.cs["c1"]
	got, managed, err := desiredName(c, "lan")
	if err != nil || !managed || got != "veth_pihole" {
		t.Fatalf("single: %q %v %v", got, managed, err)
	}
	c.NetworkSettings.Networks["monitor"] = endpoint{}
	lan, _, err := desiredName(c, "lan")
	if err != nil || len(lan) != 15 || !strings.HasPrefix(lan, "veth_pih-") {
		t.Fatalf("multi: %q %v", lan, err)
	}
	other, _, _ := desiredName(c, "monitor")
	if lan == other {
		t.Fatal("different networks have the same generated name")
	}
	c.NetworkSettings.Networks["lan"] = endpoint{NetworkID: "recreated"}
	again, _, _ := desiredName(c, "lan")
	if again != lan {
		t.Fatal("network recreation changed the name")
	}
	c.Config.Labels[labelKey+".lan"] = "veth_lan"
	if got, _, err := desiredName(c, "lan"); err != nil || got != "veth_lan" {
		t.Fatalf("override: %q %v", got, err)
	}
	c.Config.Labels[labelKey+".lan"] = ""
	if _, managed, err := desiredName(c, "lan"); !managed || err == nil {
		t.Fatal("empty explicit label must fail")
	}
	delete(c.Config.Labels, labelKey)
	if _, managed, err := desiredName(c, "monitor"); managed || err != nil {
		t.Fatal("network-specific-only label must not manage other networks")
	}
}

func TestBridgeName(t *testing.T) {
	tests := []struct {
		n    network
		want string
	}{
		{network{ID: "0123456789abcdef", Driver: "bridge"}, "br-0123456789ab"},
		{network{Driver: "bridge", Options: map[string]string{"com.docker.network.bridge.default_bridge": "true"}}, "docker0"},
		{network{Driver: "bridge", Options: map[string]string{"com.docker.network.bridge.name": "mybridge"}}, "mybridge"},
	}
	for _, tt := range tests {
		got, err := bridgeName(tt.n)
		if err != nil || got != tt.want {
			t.Fatalf("%+v: %q %v", tt.n, got, err)
		}
	}
	for _, n := range []network{{Driver: "overlay"}, {Driver: "bridge", ID: "short"}} {
		if _, err := bridgeName(n); err == nil {
			t.Fatal("expected invalid network error")
		}
	}
}

func TestFindPeer(t *testing.T) {
	_, l, _ := fixture()
	h, err := findPeer(l.inner[100], l.hs, "02:42:AC:12:00:02", "br-0123456789ab")
	if err != nil || h.Index != 42 {
		t.Fatalf("find: %+v %v", h, err)
	}
	tests := []struct {
		name   string
		change func([]link, []link) ([]link, []link)
	}{
		{"wrong peer", func(in, hs []link) ([]link, []link) { hs[0].Peer = 3; return in, hs }},
		{"wrong bridge", func(in, hs []link) ([]link, []link) { hs[0].Master = "other"; return in, hs }},
		{"non-veth", func(in, hs []link) ([]link, []link) { hs[0].Info.Kind = "dummy"; return in, hs }},
		{"wrong MAC", func(in, hs []link) ([]link, []link) { in[0].Address = "other"; return in, hs }},
		{"ambiguous", func(in, hs []link) ([]link, []link) { return append(in, in[0]), hs }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, l, _ := fixture()
			in, hs := tt.change(l.inner[100], l.hs)
			if _, err := findPeer(in, hs, "02:42:ac:12:00:02", "br-0123456789ab"); err == nil {
				t.Fatal("unsafe peer accepted")
			}
		})
	}
	if _, err := findPeer(l.inner[100], l.hs, "", "br-0123456789ab"); err == nil {
		t.Fatal("accepted missing MAC")
	}
}

func TestReconcileModesAndIdempotency(t *testing.T) {
	for _, mode := range []string{"primary", "alternative"} {
		t.Run(mode, func(t *testing.T) {
			_, l, r := fixture()
			r.mode = mode
			result, err := r.run(context.Background())
			if err != nil || len(l.calls) != 1 || result.Mappings[0].Status != "applied" {
				t.Fatalf("apply: %+v %v calls=%v", result, err, l.calls)
			}
			want := "veth_pihole"
			if mode == "alternative" {
				want = "veth_random"
			}
			m := result.Mappings[0]
			if m.Interface != want || m.IfIndex != 42 || m.IPv4 != "172.18.0.2" || m.Container != "pihole" ||
				m.Namespace != "host" || len(l.applyPIDs) != 1 || l.applyPIDs[0] != 0 {
				t.Fatalf("unexpected mapping: %+v", m)
			}
			result, err = r.run(context.Background())
			if err != nil || len(l.calls) != 1 || result.Mappings[0].Status != "unchanged" {
				t.Fatalf("idempotency: %+v %v calls=%v", result, err, l.calls)
			}
		})
	}
}

func TestDryRun(t *testing.T) {
	_, l, r := fixture()
	r.dryRun = true
	result, err := r.run(context.Background())
	if err != nil || len(l.calls) != 0 || result.Mappings[0].Status != "would-change" || !result.DryRun {
		t.Fatalf("dry run mutated or failed: %+v %v %v", result, err, l.calls)
	}
}

func TestReconcileRefusesUnsafeChanges(t *testing.T) {
	tests := []struct {
		name   string
		setup  func(*fakeDocker, *fakeLinks)
		substr string
	}{
		{"bad label", func(d *fakeDocker, _ *fakeLinks) { d.cs["c1"].Config.Labels[labelKey] = "too_long_for_linux" }, "1-15"},
		{"existing name", func(_ *fakeDocker, l *fakeLinks) {
			l.hs = append(l.hs, link{Index: 99, Name: "veth_pihole"})
		}, "already owned"},
		{"existing altname", func(_ *fakeDocker, l *fakeLinks) {
			l.hs = append(l.hs, link{Index: 99, Name: "other", AltNames: []string{"veth_pihole"}})
		}, "already owned"},
		{"own altname", func(_ *fakeDocker, l *fakeLinks) { l.hs[0].AltNames = []string{"veth_pihole"} }, "alternative name"},
		{"namespace denied", func(_ *fakeDocker, l *fakeLinks) { l.nsErr = errors.New("nsenter denied") }, "nsenter denied"},
		{"endpoint missing", func(d *fakeDocker, _ *fakeLinks) { delete(d.ns, "0123456789abcdef") }, "network not found"},
		{"changed PID", func(d *fakeDocker, _ *fakeLinks) {
			calls := 0
			d.inspectHook = func(_ string, c container) container {
				calls++
				if calls > 1 {
					c.State.Pid++
				}
				return c
			}
		}, "endpoint changed"},
		{"reused ifindex", func(_ *fakeDocker, l *fakeLinks) {
			calls := 0
			l.hostHook = func(l *fakeLinks) {
				calls++
				if calls > 1 {
					l.hs[0].Peer = 999
				}
			}
		}, "reciprocal veth"},
		{"external rename", func(_ *fakeDocker, l *fakeLinks) {
			calls := 0
			l.hostHook = func(l *fakeLinks) {
				calls++
				if calls > 1 {
					l.hs[0].Name = "external"
				}
			}
		}, "host interface changed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, l, r := fixture()
			tt.setup(d, l)
			result, err := r.run(context.Background())
			if err == nil || !strings.Contains(err.Error(), tt.substr) || len(l.calls) != 0 {
				t.Fatalf("expected refusal %q: %+v %v calls=%v", tt.substr, result, err, l.calls)
			}
			if len(result.Mappings) != 1 || result.Mappings[0].Status != "error" {
				t.Fatalf("missing error mapping: %+v", result)
			}
		})
	}
}

func TestDuplicateClaimsRefuseBoth(t *testing.T) {
	d, l, r := fixture()
	c := d.cs["c1"]
	c.ID, c.Name, c.State.Pid = "c2", "/another", 200
	c.NetworkSettings.Networks = map[string]endpoint{
		"lan": {NetworkID: "0123456789abcdef", EndpointID: "ep2", MacAddress: "02:42:ac:12:00:03"},
	}
	d.cs["c2"] = c
	l.inner[200] = []link{veth(2, 43, "eth0", "02:42:ac:12:00:03", "")}
	l.hs = append(l.hs, veth(43, 2, "veth_other", "02:42:aa:00:00:02", "br-0123456789ab"))
	result, err := r.run(context.Background())
	if err == nil || len(result.Mappings) != 2 || len(l.calls) != 0 {
		t.Fatalf("duplicate claims: %+v %v calls=%v", result, err, l.calls)
	}
	for _, m := range result.Mappings {
		if m.Status != "error" || !strings.Contains(m.Error, "multiple endpoints") {
			t.Fatalf("claimant not rejected: %+v", m)
		}
	}
}

func TestNameCollisionIdentifiesBothInterfaces(t *testing.T) {
	for _, mode := range []string{"primary", "alternative"} {
		t.Run(mode, func(t *testing.T) {
			_, l, r := fixture()
			r.mode = mode
			l.hs = append(l.hs, link{Index: 99, Name: "veth_pihole"})
			result, err := r.run(context.Background())
			want := `interface "veth_pihole" (ifindex 99); target is "veth_random" (ifindex 42)`
			if err == nil || !strings.Contains(err.Error(), want) ||
				result.Mappings[0].Status != "error" || len(l.calls) != 0 {
				t.Fatalf("collision not safely diagnosed: %+v %v calls=%v", result, err, l.calls)
			}
		})
	}
}

func TestMultiNetworkOverrides(t *testing.T) {
	d, l, r := fixture()
	c := d.cs["c1"]
	c.Config.Labels[labelKey+".lan"] = "veth_lan"
	c.Config.Labels[labelKey+".monitor"] = "veth_mon"
	c.NetworkSettings.Networks["monitor"] = endpoint{
		NetworkID: "abcdef0123456789", EndpointID: "ep2", MacAddress: "02:42:ac:13:00:02",
	}
	d.ns["abcdef0123456789"] = network{
		ID: "abcdef0123456789", Driver: "bridge", Options: map[string]string{"com.docker.network.bridge.name": "monitor0"},
	}
	l.inner[100] = append(l.inner[100], veth(9, 43, "eth99", "02:42:ac:13:00:02", ""))
	l.hs = append(l.hs, veth(43, 9, "veth_other", "", "monitor0"))
	result, err := r.run(context.Background())
	if err != nil || len(l.calls) != 2 || len(result.Mappings) != 2 {
		t.Fatalf("multi-network: %+v %v calls=%v", result, err, l.calls)
	}
	if result.Mappings[0].Interface != "veth_lan" || result.Mappings[1].Interface != "veth_mon" {
		t.Fatalf("wrong names: %+v", result)
	}
}

func TestLabelScopeAndUnsupportedNetworks(t *testing.T) {
	for _, mode := range []string{"unlabeled", "stopped", "host", "container:c2", "overlay"} {
		t.Run(mode, func(t *testing.T) {
			d, l, r := fixture()
			c := d.cs["c1"]
			switch mode {
			case "unlabeled":
				c.Config.Labels = nil
			case "stopped":
				c.State.Running = false
			case "overlay":
				n := d.ns["0123456789abcdef"]
				n.Driver = "overlay"
				d.ns["0123456789abcdef"] = n
			default:
				c.HostConfig.NetworkMode = mode
			}
			d.cs["c1"] = c
			result, err := r.run(context.Background())
			if err != nil || len(l.calls) != 0 {
				t.Fatalf("scope: %+v %v", result, err)
			}
			if mode == "overlay" {
				if len(result.Mappings) != 1 || result.Mappings[0].Status != "skipped" {
					t.Fatalf("missing unsupported driver report: %+v", result)
				}
			} else if len(result.Mappings) != 0 {
				t.Fatalf("managed excluded container: %+v", result)
			}
		})
	}
}

func TestRenameFailureDoesNotBounceOrClaimSuccess(t *testing.T) {
	_, l, r := fixture()
	l.applyErr = errors.New("RTNETLINK answers: Device or resource busy")
	result, err := r.run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "never taken down") || len(l.calls) != 1 ||
		result.Mappings[0].Status != "error" || l.hs[0].Name != "veth_random" {
		t.Fatalf("rename failure: %+v %v calls=%v", result, err, l.calls)
	}
}

func TestVerifyAppliedName(t *testing.T) {
	_, l, r := fixture()
	l.noMutation = true
	result, err := r.run(context.Background())
	if err == nil || result.Mappings[0].Status != "error" {
		t.Fatalf("unverified success: %+v %v", result, err)
	}
}

func TestRecoveryRecreationAndRemoval(t *testing.T) {
	d, l, r := fixture()
	l.applyErr = errors.New("temporary failure")
	if _, err := r.run(context.Background()); err == nil {
		t.Fatal("expected initial failure")
	}
	l.applyErr = nil
	result, err := r.run(context.Background())
	if err != nil || result.Mappings[0].Status != "applied" {
		t.Fatalf("did not recover: %+v %v", result, err)
	}
	old := d.cs["c1"]
	delete(d.cs, "c1")
	old.ID, old.State.Pid = "replacement", 200
	old.NetworkSettings.Networks["lan"] = endpoint{
		NetworkID: "0123456789abcdef", EndpointID: "replacement-endpoint", MacAddress: "02:42:ac:12:00:09",
	}
	d.cs[old.ID] = old
	l.hs = []link{veth(77, 8, "veth_recreated", "", "br-0123456789ab")}
	l.inner[200] = []link{veth(8, 77, "renamed_inner", "02:42:ac:12:00:09", "")}
	result, err = r.run(context.Background())
	if err != nil || result.Mappings[0].Status != "applied" || result.Mappings[0].IfIndex != 77 ||
		result.Mappings[0].Interface != "veth_pihole" || result.Mappings[0].ContainerID != "replacement" {
		t.Fatalf("recreation not reconciled: %+v %v", result, err)
	}
	delete(d.cs, old.ID)
	result, err = r.run(context.Background())
	if err != nil || result.Mappings == nil || len(result.Mappings) != 0 {
		t.Fatalf("stale mappings: %+v %v", result, err)
	}
}

func TestOneBadEndpointDoesNotBlockAnother(t *testing.T) {
	d, l, r := fixture()
	c := d.cs["c1"]
	c.NetworkSettings.Networks["other"] = endpoint{NetworkID: "missing"}
	c.Config.Labels[labelKey+".lan"] = "veth_pihole"
	result, err := r.run(context.Background())
	if err == nil || len(result.Mappings) != 2 || len(l.calls) != 1 ||
		result.Mappings[0].Status != "applied" || result.Mappings[1].Status != "error" {
		t.Fatalf("partial failure handling: %+v %v calls=%v", result, err, l.calls)
	}
}

func TestDiscoveryErrors(t *testing.T) {
	for _, part := range []string{"list", "host", "inspect"} {
		t.Run(part, func(t *testing.T) {
			d, l, r := fixture()
			switch part {
			case "list":
				d.listErr = errors.New("list failure")
			case "host":
				l.hostErr = errors.New("host failure")
			case "inspect":
				d.inspectErr = errors.New("inspect failure")
			}
			_, err := r.run(context.Background())
			if err == nil || len(l.calls) != 0 {
				t.Fatalf("discovery error hidden: %v", err)
			}
		})
	}
}

func TestSnapshotOutput(t *testing.T) {
	_, _, r := fixture()
	result, err := r.run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "mappings.json")
	if err := writeSnapshot(path, result); err != nil {
		t.Fatal(err)
	}
	result.Mappings = []mapping{}
	if err := writeSnapshot(path, result); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var decoded snapshot
	if err := json.Unmarshal(data, &decoded); err != nil || decoded.Mappings == nil || len(decoded.Mappings) != 0 {
		t.Fatalf("invalid empty mapping output: %s %v", data, err)
	}
	files, err := os.ReadDir(filepath.Dir(path))
	if err != nil || len(files) != 1 {
		t.Fatalf("temporary files leaked: %v %v", files, err)
	}
	if err := writeSnapshot(filepath.Join(t.TempDir(), "missing", "mappings.json"), result); err == nil {
		t.Fatal("missing parent directory error hidden")
	}
}

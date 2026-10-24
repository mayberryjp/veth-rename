package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"reflect"
	"runtime"
	"testing"
	"time"
)

type fakeRepair struct {
	*fakeLinks
	links    []link
	calls    []string
	fail     string
	after    func(string)
	noChange bool
}

func (backend *fakeRepair) host(context.Context) ([]link, error) {
	return backend.links, nil
}

func (backend *fakeRepair) change(ctx context.Context, target link, action, value string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	call := target.Name + ":" + action + ":" + value
	backend.calls = append(backend.calls, call)
	if call == backend.fail {
		backend.fail = ""
		return errors.New("injected failure")
	}
	if backend.noChange {
		return nil
	}
	for index := range backend.links {
		current := &backend.links[index]
		if current.Index != target.Index || current.Name != target.Name {
			continue
		}
		switch action {
		case "name":
			previous := current.Name
			current.Name = value
			for peerIndex := range backend.links {
				if backend.links[peerIndex].PeerName == previous {
					backend.links[peerIndex].PeerName = value
				}
			}
		case "state":
			flags := []string{}
			for _, flag := range current.Flags {
				if flag != "UP" {
					flags = append(flags, flag)
				}
			}
			current.Flags = flags
			if value == "up" {
				current.Flags = append(current.Flags, "UP")
			}
		case "del-altname":
			current.AltNames = nil
		case "add-altname":
			current.AltNames = append(current.AltNames, value)
		}
		if backend.after != nil {
			backend.after(call)
		}
		return nil
	}
	return errors.New("identity changed")
}

func TestRepairPrimaryRollback(t *testing.T) {
	for _, failure := range []string{"", "dh-live:state:down", "dh-live:name:veth_app", "veth_app:state:up"} {
		t.Run(failure, func(t *testing.T) {
			target := veth(42, 2, "dh-live", "02:00:00:00:00:01", "br-lan")
			target.Flags = []string{"BROADCAST", "UP"}
			backend := &fakeRepair{links: []link{target}, fail: failure}
			validate := func(_ context.Context, expected link) error {
				current := backend.links[0]
				if current.Name != expected.Name || current.Index != expected.Index || !hasFlag(current, "UP") {
					return errors.New("verification failed")
				}
				return nil
			}
			result, err := repairPrimary(context.Background(), backend, target, "veth_app", nil, "", "", validate)
			want := "veth_app"
			if failure != "" {
				want = "dh-live"
			}
			if (err != nil) != (failure != "") || backend.links[0].Name != want || !hasFlag(backend.links[0], "UP") || failure == "" && result.Name != want {
				t.Fatalf("result=%+v err=%v links=%+v calls=%v", result, err, backend.links, backend.calls)
			}
		})
	}
}

func TestStaleDHCPName(t *testing.T) {
	target := veth(42, 2, "dh-live", "02:00:00:00:00:01", "br-lan")
	stale := veth(50, 0, "veth_app", "02:00:00:00:00:02", "br-lan")
	stale.PeerName, stale.Flags = "0123456789ab-dh", []string{"UP", "NO-CARRIER"}
	peer := veth(49, 0, "0123456789ab-dh", "02:42:00:00:00:03", "")
	peer.PeerName, peer.Flags = stale.Name, []string{"BROADCAST"}
	for _, scenario := range []struct {
		name   string
		change func([]link)
		valid  bool
	}{
		{"returned pair", func([]link) {}, true},
		{"peer UP", func(links []link) { links[2].Flags = []string{"UP"} }, false},
		{"carrier", func(links []link) { links[1].Flags = []string{"UP"} }, false},
		{"different container", func(links []link) { links[2].Address = "other" }, false},
		{"shared bridge", func(links []link) { links[1].Info.Kind = "bridge" }, false},
		{"peer namespace", func(links []link) { namespace := 2; links[1].NetNSID = &namespace }, false},
		{"nonreciprocal", func(links []link) { links[2].PeerName = "other" }, false},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			links := []link{target, stale, peer}
			scenario.change(links)
			name, err := staleDHCPName(links, target, links[1], peer.Address)
			if (err == nil) != scenario.valid || scenario.valid && name != "dh-0123456789ab" {
				t.Fatalf("name=%q err=%v links=%+v", name, err, links)
			}
		})
	}
	if !reflect.DeepEqual(stale.Flags, []string{"UP", "NO-CARRIER"}) {
		t.Fatal("fixture mutated")
	}
}

func repairFixture() (*fakeDocker, *fakeRepair, reconciler) {
	docker, links, reconciler := dhcpBridgeFixture("bridge")
	links.hs[0].Name = "dh-live"
	links.hs[0].Flags = []string{"UP", "BROADCAST"}
	stale := veth(50, 0, "veth_pihole", "02:00:00:00:00:02", "br-vlan20")
	stale.PeerName, stale.Flags = "0123456789ab-dh", []string{"UP", "NO-CARRIER"}
	peer := veth(49, 0, "0123456789ab-dh", "02:42:ac:12:00:02", "")
	peer.PeerName, peer.Flags = stale.Name, []string{"BROADCAST"}
	backend := &fakeRepair{fakeLinks: links, links: append(links.hs, stale, peer)}
	reconciler.links, reconciler.mode = backend, "primary-repair"
	return docker, backend, reconciler
}

func TestPrimaryRepairReclaimsName(t *testing.T) {
	_, backend, reconciler := repairFixture()
	result, err := reconciler.run(context.Background())
	if err != nil || result.Mappings[0].Interface != "veth_pihole" || result.Mappings[0].Status != "applied" || backend.links[1].Name != "dh-0123456789ab" || !hasFlag(backend.links[0], "UP") {
		t.Fatalf("repair: %+v err=%v links=%+v calls=%v", result, err, backend.links, backend.calls)
	}
	backend.calls = nil
	result, err = reconciler.run(context.Background())
	if err != nil || result.Mappings[0].Status != "unchanged" || len(backend.calls) != 0 {
		t.Fatalf("idempotence: %+v err=%v calls=%v", result, err, backend.calls)
	}
}

func TestPrimaryRepairReclamationRollback(t *testing.T) {
	for _, failure := range []string{
		"veth_pihole:state:down", "veth_pihole:name:dh-0123456789ab", "dh-0123456789ab:state:up",
		"dh-live:state:down", "dh-live:name:veth_pihole", "veth_pihole:state:up",
	} {
		t.Run(failure, func(t *testing.T) {
			_, backend, reconciler := repairFixture()
			backend.fail = failure
			result, err := reconciler.run(context.Background())
			if err == nil || result.Mappings[0].Status != "error" || backend.links[0].Name != "dh-live" || !hasFlag(backend.links[0], "UP") || backend.links[1].Name != "veth_pihole" || !hasFlag(backend.links[1], "UP") {
				t.Fatalf("rollback: %+v err=%v links=%+v calls=%v", result, err, backend.links, backend.calls)
			}
		})
	}
}

func TestPrimaryRepairCancellationAndDryRun(t *testing.T) {
	_, backend, reconciler := repairFixture()
	reconciler.dryRun = true
	result, err := reconciler.run(context.Background())
	if err != nil || result.Mappings[0].Status != "would-change" || len(backend.calls) != 0 {
		t.Fatalf("dry run: %+v err=%v calls=%v", result, err, backend.calls)
	}
	reconciler.dryRun = false
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	backend.after = func(call string) {
		if call == "dh-live:state:down" {
			cancel()
		}
	}
	_, err = reconciler.run(ctx)
	if err == nil || backend.links[0].Name != "dh-live" || !hasFlag(backend.links[0], "UP") || backend.links[1].Name != "veth_pihole" {
		t.Fatalf("cancellation: err=%v links=%+v calls=%v", err, backend.links, backend.calls)
	}
}

func TestPrimaryRepairFailsClosed(t *testing.T) {
	for _, scenario := range []string{"peer UP", "wrong MAC", "active name owner", "endpoint changed", "readback"} {
		t.Run(scenario, func(t *testing.T) {
			docker, backend, reconciler := repairFixture()
			switch scenario {
			case "peer UP":
				backend.links[2].Flags = append(backend.links[2].Flags, "UP")
			case "wrong MAC":
				backend.links[2].Address = "other"
			case "active name owner":
				backend.links[1].Flags = []string{"UP", "LOWER_UP"}
			case "endpoint changed":
				calls := 0
				docker.inspectHook = func(_ string, current container) container {
					calls++
					if calls >= 3 {
						current.State.Pid++
					}
					return current
				}
			case "readback":
				backend.noChange = true
			}
			result, err := reconciler.run(context.Background())
			if err == nil || result.Mappings[0].Status != "error" || backend.links[0].Name != "dh-live" || !hasFlag(backend.links[0], "UP") {
				t.Fatalf("unsafe success: %+v err=%v links=%+v calls=%v", result, err, backend.links, backend.calls)
			}
			if scenario != "readback" && len(backend.calls) != 0 {
				t.Fatalf("unexpected mutation: %v", backend.calls)
			}
		})
	}
}

func TestPrimaryRepairKernelIntegration(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getenv("PRIMARY_REPAIR_INTEGRATION") != "1" {
		t.Skip("requires Linux root and PRIMARY_REPAIR_INTEGRATION=1; uses an isolated network namespace")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	if os.Getenv("PRIMARY_REPAIR_NETNS_CHILD") != "1" {
		binary, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		child := exec.CommandContext(ctx, "unshare", "--net", "--", binary, "-test.run=^TestPrimaryRepairKernelIntegration$", "-test.v")
		child.Env = append(os.Environ(), "PRIMARY_REPAIR_NETNS_CHILD=1")
		if output, err := child.CombinedOutput(); err != nil {
			t.Fatalf("isolated kernel test: %v\n%s", err, output)
		} else {
			t.Logf("%s", output)
		}
		return
	}
	program, err := exec.LookPath("ip")
	if err != nil {
		t.Fatal(err)
	}
	backend := commandLinks{ip: program}
	for _, args := range [][]string{{"link", "add", "br-test", "type", "bridge"}, {"link", "set", "br-test", "up"}} {
		if _, err := command(ctx, program, args...); err != nil {
			t.Fatal(err)
		}
	}
	for _, scenario := range []struct {
		name     string
		live     string
		inner    string
		desired  string
		identity string
		rollback bool
	}{
		{"rename and reclaim", "live0", "inner0", "veth_app", "0123456789ab", false},
		{"rollback after verification", "live1", "inner1", "veth_other", "abcdef012345", true},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			peerName := scenario.identity + "-dh"
			for _, args := range [][]string{
				{"link", "add", scenario.live, "type", "veth", "peer", "name", scenario.inner},
				{"link", "set", scenario.live, "master", "br-test"},
				{"link", "set", scenario.live, "up"}, {"link", "set", scenario.inner, "up"},
				{"link", "add", scenario.desired, "type", "veth", "peer", "name", peerName},
				{"link", "set", peerName, "address", "02:42:00:00:00:03"},
				{"link", "set", scenario.desired, "master", "br-test"}, {"link", "set", scenario.desired, "up"},
			} {
				if _, err := command(ctx, program, args...); err != nil {
					t.Fatal(err)
				}
			}
			links, err := backend.host(ctx)
			if err != nil {
				t.Fatal(err)
			}
			var target, stale link
			for _, candidate := range links {
				if candidate.Name == scenario.live {
					target = candidate
				}
				if candidate.Name == scenario.desired {
					stale = candidate
				}
			}
			original, err := staleDHCPName(links, target, stale, "02:42:00:00:00:03")
			if err != nil {
				t.Fatal(err)
			}
			validations := 0
			validate := func(ctx context.Context, expected link) error {
				validations++
				if scenario.rollback && validations == 3 {
					return errors.New("injected endpoint verification failure")
				}
				links, err := backend.host(ctx)
				if err != nil {
					return err
				}
				for _, actual := range links {
					if sameLink(actual, expected) && hasFlag(actual, "UP") {
						return nil
					}
				}
				return errors.New("live link identity or UP state changed")
			}
			_, err = repairPrimary(ctx, backend, target, scenario.desired, &stale, original, "02:42:00:00:00:03", validate)
			if (err != nil) != scenario.rollback {
				t.Fatalf("transaction: %v", err)
			}
			links, err = backend.host(ctx)
			if err != nil {
				t.Fatal(err)
			}
			for _, actual := range links {
				if actual.Index == target.Index {
					want := scenario.desired
					if scenario.rollback {
						want = scenario.live
					}
					if actual.Name != want || !hasFlag(actual, "UP") || actual.Master != "br-test" || actual.Address != target.Address {
						t.Fatalf("live interface not restored: %+v", actual)
					}
				}
				if actual.Index == stale.Index {
					want := original
					if scenario.rollback {
						want = scenario.desired
					}
					if actual.Name != want || !hasFlag(actual, "UP") {
						t.Fatalf("stale interface not restored: %+v", actual)
					}
				}
			}
		})
	}
}

func TestPrimaryRepairRecoversDownAndAlternativeNames(t *testing.T) {
	for _, scenario := range []string{"down before rename", "down after rename", "alternative promotion", "alternative rollback"} {
		t.Run(scenario, func(t *testing.T) {
			_, backend, reconciler := repairFixture()
			backend.links = backend.links[:1]
			switch scenario {
			case "down before rename":
				backend.links[0].Flags = []string{"BROADCAST"}
			case "down after rename":
				backend.links[0].Name, backend.links[0].Flags = "veth_pihole", []string{"BROADCAST"}
			case "alternative promotion", "alternative rollback":
				backend.links[0].AltNames = []string{"veth_pihole"}
				if scenario == "alternative rollback" {
					backend.fail = "dh-live:name:veth_pihole"
				}
			}
			result, err := reconciler.run(context.Background())
			if scenario == "alternative rollback" {
				if err == nil || backend.links[0].Name != "dh-live" || !ownsName(backend.links[0], "veth_pihole") || !hasFlag(backend.links[0], "UP") {
					t.Fatalf("rollback: %+v err=%v link=%+v calls=%v", result, err, backend.links[0], backend.calls)
				}
			} else if err != nil || result.Mappings[0].Interface != "veth_pihole" || !hasFlag(backend.links[0], "UP") {
				t.Fatalf("recovery: %+v err=%v link=%+v calls=%v", result, err, backend.links[0], backend.calls)
			}
		})
	}
}

func TestPrimaryRepairPeerChangesDuringReclamation(t *testing.T) {
	_, backend, reconciler := repairFixture()
	backend.after = func(call string) {
		if call == "veth_pihole:state:down" {
			backend.links[2].Address = "02:00:00:00:00:ff"
		}
	}
	_, err := reconciler.run(context.Background())
	if err == nil || backend.links[0].Name != "dh-live" || !hasFlag(backend.links[0], "UP") || backend.links[1].Name != "veth_pihole" {
		t.Fatalf("changed peer accepted: err=%v links=%+v calls=%v", err, backend.links, backend.calls)
	}
}

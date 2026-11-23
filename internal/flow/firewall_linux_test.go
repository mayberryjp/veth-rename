//go:build linux

package flow

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
	"veth-rename/internal/firewall"
)

func firewallTestMeter(t *testing.T, rules []firewall.Rule, icmp bool, rate, filter uint32) *kernelMeter {
	return configuredFirewallTestMeter(t, rules, firewall.Config{Enabled: true, PermitAllICMP: icmp}, rate, filter)
}

func configuredFirewallTestMeter(t *testing.T, rules []firewall.Rule, config firewall.Config, rate, filter uint32) *kernelMeter {
	t.Helper()
	requireKernel(t)
	compiled, err := firewall.Compile(rules)
	if err != nil {
		t.Fatal(err)
	}
	p := &firewall.Policy{Config: config, Rules: rules, Kernel: compiled}
	m, err := loadConfiguredMeter(meterOptions{samplingRate: rate, filter: filter, firewall: p})
	if err != nil {
		var verifier *ebpf.VerifierError
		if errors.As(err, &verifier) {
			t.Fatalf("%+v", verifier)
		}
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := m.Close(); err != nil {
			t.Error(err)
		}
	})
	return m
}

func TestKernelFirewallAuditVerdictsAndCapture(t *testing.T) {
	rules := []firewall.Rule{{ID: "deny", Direction: "ingress", Action: "deny", Source: "*", Destination: "*", Protocol: "udp"}}
	m := configuredFirewallTestMeter(t, rules, firewall.Config{Enabled: true, AuditMode: true}, 4, 0)
	for i := 0; i < 8; i++ {
		verdict(t, m, "meter", ipv4Packet(false, 1234), ^uint32(0))
	}
	verdict(t, m, "meter_egress", ipv4Packet(true, 1234), ^uint32(0))
	fragment := ipv4Packet(false, 1234)
	fragment[20] = 0x20
	verdict(t, m, "meter", fragment, ^uint32(0))
	bad := ipv4Packet(false, 1234)
	bad[14] = 0x40
	verdict(t, m, "meter", bad, ^uint32(0))
	unsupported := make([]byte, 14)
	verdict(t, m, "meter_egress", unsupported, ^uint32(0))
	packets, err := m.Read()
	if err != nil || len(packets) != 2 {
		t.Fatalf("audit IPFIX sampling: %d %v", len(packets), err)
	}
	drops, err := m.ReadDrops()
	if err != nil || len(drops) != 12 {
		t.Fatalf("audit events: %d %v", len(drops), err)
	}
	for i, drop := range drops {
		reason := uint8(1)
		switch i {
		case 8:
			reason = 0
		case 9, 11:
			reason = 3
		case 10:
			reason = 2
		}
		if drop.Reason != reason {
			t.Fatalf("event %d: %+v", i, drop)
		}
	}
	disabled := configuredFirewallTestMeter(t, rules, firewall.Config{AuditMode: true}, 1, 0)
	verdict(t, disabled, "meter", ipv4Packet(false, 1234), ^uint32(0))
	if drops, err := disabled.ReadDrops(); err != nil || len(drops) != 0 {
		t.Fatalf("disabled firewall audited traffic: %+v %v", drops, err)
	}
}

func TestKernelFirewallAuditStateTracksOnlyPolicyAllows(t *testing.T) {
	rules := []firewall.Rule{{ID: "udp", Direction: "ingress", Action: "allow", Source: "*", Destination: "*", Protocol: "udp", DestinationPort: "443"}}
	m := configuredFirewallTestMeter(t, rules, firewall.Config{Enabled: true, AuditMode: true, PermitAllICMP: true}, 1, 0)
	denied := ipv4Packet(false, 5678)
	binary.BigEndian.PutUint16(denied[36:38], 444)
	verdict(t, m, "meter", denied, ^uint32(0))
	reply := ipv4Packet(true, 5678)
	binary.BigEndian.PutUint16(reply[34:36], 444)
	verdict(t, m, "meter_egress", reply, ^uint32(0))
	verdict(t, m, "meter", ipv4Packet(false, 1234), ^uint32(0))
	verdict(t, m, "meter_egress", ipv4Packet(true, 1234), ^uint32(0))
	icmp := ipv4Packet(false, 1234)
	icmp[23] = 1
	verdict(t, m, "meter", icmp, ^uint32(0))
	drops, err := m.ReadDrops()
	if err != nil || len(drops) != 2 || drops[0].DestinationPort != 444 || drops[1].SourcePort != 444 {
		t.Fatalf("audit state: %+v %v", drops, err)
	}
}

func TestKernelFirewallAuditStateCapacityStillPermits(t *testing.T) {
	requireKernel(t)
	rules := []firewall.Rule{{ID: "udp", Direction: "ingress", Action: "allow", Source: "*", Destination: "*", Protocol: "udp"}}
	compiled, err := firewall.Compile(rules)
	if err != nil {
		t.Fatal(err)
	}
	m, err := loadConfiguredMeter(meterOptions{samplingRate: 1, stateEntries: 1,
		firewall: &firewall.Policy{Config: firewall.Config{Enabled: true, AuditMode: true}, Rules: rules, Kernel: compiled}})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	verdict(t, m, "meter", ipv4Packet(false, 1234), ^uint32(0))
	verdict(t, m, "meter", ipv4Packet(false, 5678), ^uint32(0))
	verdict(t, m, "meter_egress", ipv4Packet(true, 5678), ^uint32(0))
	drops, err := m.ReadDrops()
	if err != nil || len(drops) != 2 || drops[0].Reason != 4 || drops[1].Reason != 0 {
		t.Fatalf("audit full state table: %+v %v", drops, err)
	}
}

func verdict(t *testing.T, m *kernelMeter, program string, packet []byte, want uint32) {
	t.Helper()
	got, _, err := m.collection.Programs[program].Test(packet)
	if err != nil || got != want {
		t.Fatalf("%s verdict %d want %d: %v", program, got, want, err)
	}
}

func TestKernelFirewallEnforcementDirection(t *testing.T) {
	rules := []firewall.Rule{{ID: "deny", Direction: "both", Action: "deny", Source: "*", Destination: "*", Protocol: "udp"}}
	for _, tc := range []struct {
		scope           string
		audit           bool
		ingress, egress uint32
	}{
		{"ingress", false, 2, ^uint32(0)},
		{"egress", false, ^uint32(0), 2},
		{"both", false, 2, 2},
		{"ingress", true, ^uint32(0), ^uint32(0)},
	} {
		t.Run(fmt.Sprintf("%s-audit-%t", tc.scope, tc.audit), func(t *testing.T) {
			m := configuredFirewallTestMeter(t, rules, firewall.Config{Enabled: true, EnforcementDirection: tc.scope, AuditMode: tc.audit}, 4, 0)
			for _, hook := range []struct {
				program string
				want    uint32
			}{{"meter", tc.ingress}, {"meter_egress", tc.egress}} {
				for i := 0; i < 4; i++ {
					verdict(t, m, hook.program, ipv4Packet(false, 1234), hook.want)
				}
				fragment := ipv4Packet(false, 1234)
				fragment[20] = 0x20
				verdict(t, m, hook.program, fragment, hook.want)
				malformed := ipv4Packet(false, 1234)
				malformed[14] = 0x40
				verdict(t, m, hook.program, malformed, hook.want)
			}
			drops, err := m.ReadDrops()
			if err != nil || len(drops) != 12 {
				t.Fatalf("both hooks must log denies: %d %v", len(drops), err)
			}
			packets, err := m.Read()
			// Samples 4 and 8 are UDP; sample 12 is malformed.
			if err != nil || len(packets) != 2 {
				t.Fatalf("IPFIX changed: %d %v", len(packets), err)
			}
		})
	}
}

func TestKernelFirewallDirectionalShadowState(t *testing.T) {
	rules := []firewall.Rule{{ID: "egress-allow", Direction: "egress", Action: "allow", Source: "*", Destination: "*", Protocol: "udp", DestinationPort: "443"}}
	m := configuredFirewallTestMeter(t, rules, firewall.Config{Enabled: true, EnforcementDirection: "ingress"}, 1, 0)
	verdict(t, m, "meter_egress", ipv4Packet(false, 1234), ^uint32(0))
	verdict(t, m, "meter", ipv4Packet(true, 1234), ^uint32(0))
	bypassed := ipv4Packet(false, 5678)
	binary.BigEndian.PutUint16(bypassed[36:38], 444)
	verdict(t, m, "meter_egress", bypassed, ^uint32(0))
	reply := ipv4Packet(true, 5678)
	binary.BigEndian.PutUint16(reply[34:36], 444)
	verdict(t, m, "meter", reply, 2)
	drops, err := m.ReadDrops()
	if err != nil || len(drops) != 2 || drops[0].Direction != 2 || drops[1].Direction != 1 {
		t.Fatalf("bypassed deny must not seed reply state: %+v %v", drops, err)
	}
}

func TestKernelFirewallCaptureBeforeDropAndSampling(t *testing.T) {
	m := firewallTestMeter(t, nil, true, 4, 0)
	for i := 0; i < 8; i++ {
		verdict(t, m, "meter", ipv4Packet(false, 1234), 2)
	}
	packets, err := m.Read()
	if err != nil || len(packets) != 2 {
		t.Fatalf("pre-drop capture: %d %v", len(packets), err)
	}
	drops, err := m.ReadDrops()
	if err != nil || len(drops) != 8 {
		t.Fatalf("unsampled drops: %d %v", len(drops), err)
	}
	for _, d := range drops {
		if d.SourcePort != 1234 || d.DestinationPort != 443 || d.Direction != 1 || d.Reason != 0 {
			t.Fatalf("drop: %+v", d)
		}
	}
	filtered := firewallTestMeter(t, nil, true, 1, 3)
	verdict(t, filtered, "meter", ipv4Packet(false, 1234), 2)
	if packets, err := filtered.Read(); err != nil || len(packets) != 0 {
		t.Fatalf("capture filter: %+v %v", packets, err)
	}
}

func TestKernelFirewallRingLossNeverBypassesPolicy(t *testing.T) {
	requireKernel(t)
	m, err := loadConfiguredMeter(meterOptions{samplingRate: 1, ringBytes: 4096,
		firewall: &firewall.Policy{Config: firewall.Config{Enabled: true}}})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	for i := 0; i < 128; i++ {
		verdict(t, m, "meter", ipv4Packet(false, 1234), 2)
	}
	losses, err := m.Losses()
	if err != nil || losses[0] == 0 {
		t.Fatalf("expected ring losses: %v %v", losses, err)
	}
	drops, err := m.ReadDrops()
	if err != nil || len(drops) != 128 {
		t.Fatalf("drops during meter overflow: %d %v", len(drops), err)
	}
}

func TestKernelFirewallLastRuleAtCapacity(t *testing.T) {
	rules := make([]firewall.Rule, firewall.MaxRulesPerVeth)
	for i := range rules {
		rules[i] = firewall.Rule{ID: fmt.Sprintf("rule-%d", i), Direction: "egress", Action: "allow",
			Source: "*", Destination: "*", Protocol: "udp", DestinationPort: fmt.Sprint(i)}
	}
	m := firewallTestMeter(t, rules, true, 1, 0)
	packet := ipv4Packet(false, 1234)
	binary.BigEndian.PutUint16(packet[36:38], 255)
	verdict(t, m, "meter_egress", packet, ^uint32(0))
	binary.BigEndian.PutUint16(packet[36:38], 256)
	verdict(t, m, "meter_egress", packet, 2)
	extra := rules[0]
	extra.ID = "extra"
	rules = append(rules, extra)
	compiled, err := firewall.Compile(rules)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.UpdateFirewall(&firewall.Policy{Kernel: compiled}); err == nil {
		t.Fatal("installed policy beyond per-veth kernel capacity")
	}
}

func TestKernelFirewallRuleOrderDirectionAndSandoMatch(t *testing.T) {
	rules := []firewall.Rule{
		{ID: "manual", Direction: "ingress", Action: "deny", Source: "*", Destination: "*", Protocol: "udp", DestinationPort: "443"},
		{ID: "sando:x", Direction: "both", Action: "allow", Source: "10.0.0.1", Destination: "10.0.0.2",
			Protocol: "udp", DestinationPort: "443", SandoMatch: true},
	}
	m := firewallTestMeter(t, rules, true, 1, 0)
	verdict(t, m, "meter", ipv4Packet(false, 1234), 2)
	verdict(t, m, "meter_egress", ipv4Packet(true, 1234), ^uint32(0))
	// Established replies run before manual denies.
	verdict(t, m, "meter", ipv4Packet(false, 1234), ^uint32(0))
	drops, err := m.ReadDrops()
	if err != nil || len(drops) != 1 || drops[0].Rule != 1 {
		t.Fatalf("manual precedence: %+v %v", drops, err)
	}
}

func TestKernelFirewallPartitionAndUpdatePreserveState(t *testing.T) {
	rules := make([]firewall.Rule, 600)
	for i := range rules {
		rules[i] = firewall.Rule{ID: fmt.Sprint(i), Direction: "both", Action: "allow",
			Source: fmt.Sprintf("10.0.%d.%d", i/250, i%250+1), Destination: "10.9.0.1",
			Protocol: "udp", SandoMatch: true}
	}
	kernel, err := firewall.Compile(rules)
	if err != nil {
		t.Fatal(err)
	}
	p := &firewall.Policy{Config: firewall.Config{Enabled: true}, Rules: rules, Kernel: kernel}
	selected, err := p.ForEndpoint("10.0.0.1", "")
	if err != nil {
		t.Fatal(err)
	}
	requireKernel(t)
	m, err := loadConfiguredMeter(meterOptions{samplingRate: 1, stateEntries: 1, firewall: selected})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	packet := ipv4Packet(false, 1234)
	copy(packet[30:34], []byte{10, 9, 0, 1})
	verdict(t, m, "meter", packet, ^uint32(0))
	copy(packet[26:30], []byte{10, 0, 2, 100})
	verdict(t, m, "meter", packet, 2)
	drops, err := m.ReadDrops()
	if err != nil || len(drops) != 1 || drops[0].Rule != 0 {
		t.Fatalf("other endpoint rule leaked: %+v %v", drops, err)
	}
	selected, err = p.ForEndpoint("10.0.2.100", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := m.UpdateFirewall(selected); err != nil {
		t.Fatal(err)
	}
	verdict(t, m, "meter", packet, 2)
	drops, err = m.ReadDrops()
	if err != nil || len(drops) != 1 || drops[0].Rule != 600 || drops[0].Reason != 4 {
		t.Fatalf("stable global log ID and retained state: %+v %v", drops, err)
	}
	reply := ipv4Packet(true, 1234)
	copy(reply[26:30], []byte{10, 9, 0, 1})
	verdict(t, m, "meter_egress", reply, ^uint32(0))
	copy(packet[26:30], []byte{10, 0, 0, 1})
	binary.BigEndian.PutUint16(packet[34:36], 5678)
	verdict(t, m, "meter", packet, 2)
}

func TestKernelFirewallICMPAndFragments(t *testing.T) {
	m := firewallTestMeter(t, nil, true, 1, 0)
	icmp := ipv4Packet(false, 1234)
	icmp[23] = 1
	verdict(t, m, "meter", icmp, ^uint32(0))
	icmp6 := ipv6Packet(false)
	icmp6[54] = 58
	verdict(t, m, "meter_egress", icmp6, ^uint32(0))
	disabled := firewallTestMeter(t, nil, false, 1, 0)
	verdict(t, disabled, "meter", icmp, 2)
	fragment := ipv4Packet(false, 1234)
	fragment[20] = 0x20
	verdict(t, m, "meter", fragment, 2)
}

func TestKernelFirewallConcurrentRuleReplacement(t *testing.T) {
	rules := []firewall.Rule{
		{ID: "first", Direction: "both", Action: "deny", Source: "*", Destination: "*", Protocol: "udp"},
		{ID: "second", Direction: "both", Action: "allow", Source: "*", Destination: "*", Protocol: "udp"},
	}
	m := firewallTestMeter(t, rules, true, 1, 0)
	first, err := firewall.Compile(rules)
	if err != nil {
		t.Fatal(err)
	}
	rules[0].Source = "10.99.0.1"
	rules[1].Action = "deny"
	second, err := firewall.Compile(rules)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		for i := 0; i < 400; i++ {
			got, _, err := m.collection.Programs["meter"].Test(ipv4Packet(false, 1234))
			if err != nil || got != 2 {
				done <- fmt.Errorf("partial policy permitted packet: verdict=%d error=%v", got, err)
				return
			}
		}
		done <- nil
	}()
	for i := 0; i < 50; i++ {
		kernel := first
		if i%2 == 0 {
			kernel = second
		}
		if err = m.UpdateFirewall(&firewall.Policy{Kernel: kernel}); err != nil {
			break
		}
	}
	packetErr := <-done
	if err != nil || packetErr != nil {
		t.Fatalf("atomic replacement: update=%v packets=%v", err, packetErr)
	}
}

func TestKernelFirewallTCPHandshakeAndExpiry(t *testing.T) {
	r := firewall.Rule{ID: "tcp", Direction: "ingress", Action: "allow", Source: "10.0.0.0/24", Destination: "*", Protocol: "tcp", DestinationPort: "443"}
	m := firewallTestMeter(t, []firewall.Rule{r}, true, 1, 0)
	syn := transportPacket(false, 6)
	syn[47] = 2
	reply := transportPacket(true, 6)
	reply[47] = 0x10
	verdict(t, m, "meter_egress", reply, 2)
	verdict(t, m, "meter", syn, ^uint32(0))
	verdict(t, m, "meter_egress", reply, 2)
	reply[47] = 0x13
	verdict(t, m, "meter_egress", reply, 2)
	reply[47] = 0x12
	verdict(t, m, "meter_egress", reply, ^uint32(0))
	ack := transportPacket(false, 6)
	ack[47] = 0x10
	verdict(t, m, "meter", ack, ^uint32(0))
	reply[47] = 0x10
	verdict(t, m, "meter_egress", reply, ^uint32(0))
	key := Key{Family: 4, Protocol: 6, SourcePort: 1234, DestinationPort: 443, Padding: 1}
	copy(key.Source[:], []byte{10, 0, 0, 1})
	copy(key.Destination[:], []byte{10, 0, 0, 2})
	now, err := monotonic()
	if err != nil {
		t.Fatal(err)
	}
	old := struct {
		Lock, Stage uint32
		Last        uint64
	}{Stage: 3, Last: now - 301000000000}
	if err := m.collection.Maps["connections"].Update(key, old, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	verdict(t, m, "expire_states", make([]byte, 14), 0)
	verdict(t, m, "meter_egress", reply, 2)
	binary.BigEndian.PutUint16(syn[36:38], 0)
	verdict(t, m, "meter", syn, 2)
}

func TestKernelFirewallStateCapacityAndUDPExpiry(t *testing.T) {
	requireKernel(t)
	rules := []firewall.Rule{{ID: "udp", Direction: "ingress", Action: "allow", Source: "*", Destination: "*", Protocol: "udp"}}
	compiled, err := firewall.Compile(rules)
	if err != nil {
		t.Fatal(err)
	}
	m, err := loadConfiguredMeter(meterOptions{samplingRate: 1, stateEntries: 1,
		firewall: &firewall.Policy{Config: firewall.Config{Enabled: true}, Rules: rules, Kernel: compiled}})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	verdict(t, m, "meter", ipv4Packet(false, 1234), ^uint32(0))
	verdict(t, m, "meter", ipv4Packet(false, 5678), 2)
	verdict(t, m, "meter_egress", ipv4Packet(true, 1234), ^uint32(0))
	drops, err := m.ReadDrops()
	if err != nil || len(drops) != 1 || drops[0].Reason != 4 {
		t.Fatalf("state capacity: %+v %v", drops, err)
	}
	key := Key{Family: 4, Protocol: 17, SourcePort: 1234, DestinationPort: 443, Padding: 1}
	copy(key.Source[:], []byte{10, 0, 0, 1})
	copy(key.Destination[:], []byte{10, 0, 0, 2})
	now, err := monotonic()
	if err != nil {
		t.Fatal(err)
	}
	old := struct {
		Lock, Stage uint32
		Last        uint64
	}{Stage: 1, Last: now - 31000000000}
	if err := m.collection.Maps["connections"].Update(key, old, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	verdict(t, m, "meter_egress", ipv4Packet(true, 1234), 2)
	verdict(t, m, "expire_states", make([]byte, 14), 0)
	verdict(t, m, "meter", ipv4Packet(false, 5678), ^uint32(0))
	verdict(t, m, "meter_egress", ipv4Packet(true, 5678), ^uint32(0))
}

func TestKernelFirewallLiveTCXDrop(t *testing.T) {
	testKernelFirewallLiveTCX(t, false)
}

func TestKernelFirewallAuditLiveTCX(t *testing.T) {
	testKernelFirewallLiveTCX(t, true)
}

func testKernelFirewallLiveTCX(t *testing.T, audit bool) {
	requireKernel(t)
	ip := func(args ...string) {
		t.Helper()
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			t.Fatalf("ip %v: %s %v", args, out, err)
		}
	}
	ip("link", "add", "fwhost", "type", "veth", "peer", "name", "fwpeer")
	defer exec.Command("ip", "link", "del", "fwhost").Run()
	for _, name := range []string{"fwhost", "fwpeer"} {
		ip("link", "set", name, "addrgenmode", "none")
		ip("link", "set", name, "up")
	}
	host, err := net.InterfaceByName("fwhost")
	if err != nil {
		t.Fatal(err)
	}
	peer, err := net.InterfaceByName("fwpeer")
	if err != nil {
		t.Fatal(err)
	}
	rules := []firewall.Rule{{ID: "udp", Direction: "egress", Action: "allow", Source: "*", Destination: "*", Protocol: "udp", DestinationPort: "443"}}
	compiled, err := firewall.Compile(rules)
	if err != nil {
		t.Fatal(err)
	}
	attached, err := attachMeter(Interface{Index: host.Index, Name: host.Name}, meterOptions{samplingRate: 1,
		firewall: &firewall.Policy{Config: firewall.Config{Enabled: true, AuditMode: audit}, Rules: rules, Kernel: compiled}})
	if err != nil {
		t.Fatal(err)
	}
	defer attached.Close()
	m := attached.(*kernelMeter)
	tx, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(0x0800)))
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(tx)
	rx, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(0x0800)))
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(rx)
	if err := unix.Bind(rx, &unix.SockaddrLinklayer{Ifindex: peer.Index, Protocol: htons(0x0800)}); err != nil {
		t.Fatal(err)
	}
	if err := unix.SetsockoptTimeval(rx, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Usec: 100000}); err != nil {
		t.Fatal(err)
	}
	packet := ipv4Packet(false, 1234)
	copy(packet[:6], peer.HardwareAddr)
	copy(packet[6:12], host.HardwareAddr)
	send := func(port uint16) error {
		t.Helper()
		binary.BigEndian.PutUint16(packet[36:38], port)
		return unix.Sendto(tx, packet, 0, &unix.SockaddrLinklayer{Ifindex: host.Index, Protocol: htons(0x0800)})
	}
	if err := send(444); err != nil && (audit || !errors.Is(err, unix.ENOBUFS)) {
		t.Fatal(err)
	}
	buffer := make([]byte, 1500)
	n, _, recvErr := unix.Recvfrom(rx, buffer, 0)
	if audit {
		if recvErr != nil || n != len(packet) {
			t.Fatalf("audit packet not delivered: n=%d err=%v", n, recvErr)
		}
	} else if n > 0 || (!errors.Is(recvErr, unix.EAGAIN) && !errors.Is(recvErr, unix.EWOULDBLOCK)) {
		t.Fatalf("denied packet reached peer: n=%d err=%v", n, recvErr)
	}
	if err := send(443); err != nil {
		t.Fatal(err)
	}
	if n, _, err := unix.Recvfrom(rx, buffer, 0); err != nil || n != len(packet) {
		t.Fatalf("allowed packet not delivered: %d %v", n, err)
	}
	time.Sleep(10 * time.Millisecond)
	packets, err := m.Read()
	if err != nil || len(packets) != 2 {
		t.Fatalf("live pre-verdict capture: %d %v", len(packets), err)
	}
	drops, err := m.ReadDrops()
	if err != nil || len(drops) != 1 || drops[0].Direction != 2 || drops[0].DestinationPort != 444 {
		t.Fatalf("live egress drop: %+v %v", drops, err)
	}
}

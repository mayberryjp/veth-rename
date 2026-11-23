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
	t.Helper()
	requireKernel(t)
	compiled, err := firewall.Compile(rules)
	if err != nil {
		t.Fatal(err)
	}
	p := &firewall.Policy{Config: firewall.Config{Enabled: true, PermitAllICMP: icmp}, Rules: rules, Kernel: compiled}
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

func verdict(t *testing.T, m *kernelMeter, program string, packet []byte, want uint32) {
	t.Helper()
	got, _, err := m.collection.Programs[program].Test(packet)
	if err != nil || got != want {
		t.Fatalf("%s verdict %d want %d: %v", program, got, want, err)
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
	rules := make([]firewall.Rule, firewall.MaxRules)
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
	rules = append(rules, firewall.Rule{ID: "extra"})
	if _, err := firewall.Compile(rules); err == nil {
		t.Fatal("accepted policy beyond kernel capacity")
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
		firewall: &firewall.Policy{Config: firewall.Config{Enabled: true}, Rules: rules, Kernel: compiled}})
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
	if err := send(444); err != nil && !errors.Is(err, unix.ENOBUFS) {
		t.Fatal(err)
	}
	buffer := make([]byte, 1500)
	if n, _, err := unix.Recvfrom(rx, buffer, 0); n > 0 || (!errors.Is(err, unix.EAGAIN) && !errors.Is(err, unix.EWOULDBLOCK)) {
		t.Fatalf("denied packet reached peer: n=%d err=%v", n, err)
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

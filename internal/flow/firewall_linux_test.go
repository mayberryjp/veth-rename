//go:build linux

package flow

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
	"veth-manager/internal/firewall"
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
	fragment := firewallFragment(4, 17, 1, 0, 8, true)
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
		case 9:
			reason = 1
		case 11:
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
				fragment := firewallFragment(4, 17, 1, 0, 8, true)
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

func firewallFragment(family, protocol uint8, id uint32, start, length int, more bool) []byte {
	payload := make([]byte, max(64, start+length))
	binary.BigEndian.PutUint16(payload[:2], 1234)
	binary.BigEndian.PutUint16(payload[2:4], 443)
	switch protocol {
	case 17:
		binary.BigEndian.PutUint16(payload[4:6], 64)
	case 6:
		payload[12], payload[13] = 0x50, 2
	case 1:
		payload[0], payload[1] = 8, 0
	case 58:
		payload[0], payload[1] = 128, 0
	}
	bits := uint16(start / 8)
	if family == 4 {
		b := append(ipv4Packet(false, 1234)[:34], payload[start:start+length]...)
		binary.BigEndian.PutUint16(b[16:18], uint16(20+length))
		binary.BigEndian.PutUint16(b[18:20], uint16(id))
		if more {
			bits |= 0x2000
		}
		binary.BigEndian.PutUint16(b[20:22], bits)
		b[23] = protocol
		return b
	}
	b := append(ipv6Packet(false)[:54], make([]byte, 8)...)
	b[20], b[54] = 44, protocol
	binary.BigEndian.PutUint16(b[18:20], uint16(8+length))
	bits *= 8
	if more {
		bits |= 1
	}
	binary.BigEndian.PutUint16(b[56:58], bits)
	binary.BigEndian.PutUint32(b[58:62], id)
	return append(b, payload[start:start+length]...)
}

func fragmentDropReasons(t *testing.T, m *kernelMeter, reasons ...uint8) {
	t.Helper()
	drops, err := m.ReadDrops()
	if err != nil || len(drops) != len(reasons) {
		t.Fatalf("fragment drops: %+v %v; want reasons %v", drops, err, reasons)
	}
	for i, reason := range reasons {
		if drops[i].Reason != reason {
			t.Fatalf("fragment drop %d: %+v; want reason %d", i, drops[i], reason)
		}
	}
}

func TestKernelFirewallFragmentAuthorization(t *testing.T) {
	rules := []firewall.Rule{{ID: "udp", Direction: "both", Action: "allow", Source: "*", Destination: "*", Protocol: "udp", DestinationPort: "443"}}
	for _, family := range []uint8{4, 6} {
		t.Run(fmt.Sprint(family), func(t *testing.T) {
			m := firewallTestMeter(t, rules, false, 4, 4)
			first := firewallFragment(family, 17, 1, 0, 16, true)
			last := firewallFragment(family, 17, 1, 48, 16, false)
			verdict(t, m, "meter", last, 2)
			verdict(t, m, "meter", first, ^uint32(0))
			verdict(t, m, "meter_egress", last, 2)
			other := append([]byte(nil), last...)
			if family == 4 {
				other[29] = 3
			} else {
				other[37] = 3
			}
			verdict(t, m, "meter", other, 2)
			// Once the first fragment is authorized, remaining fragments may reorder.
			verdict(t, m, "meter", last, ^uint32(0))
			verdict(t, m, "meter", firewallFragment(family, 17, 1, 16, 32, true), ^uint32(0))
			verdict(t, m, "meter", last, 2)
			verdict(t, m, "meter", first, 2)
			fragmentDropReasons(t, m, 6, 6, 6, 6, 7)
			packets, err := m.Read()
			if err != nil || len(packets) != 0 {
				t.Fatalf("real fragments entered IPFIX: %+v %v", packets, err)
			}
			// Fragment IDs do not authorize a different VLAN.
			tag := func(packet []byte, vlan byte) []byte {
				return append(append(append([]byte{}, packet[:12]...), 0x81, 0, 0, vlan), packet[12:]...)
			}
			first = firewallFragment(family, 17, 2, 0, 16, true)
			last = firewallFragment(family, 17, 2, 16, 48, false)
			verdict(t, m, "meter", tag(first, 1), ^uint32(0))
			verdict(t, m, "meter", tag(last, 2), 2)
			verdict(t, m, "meter", tag(last, 1), ^uint32(0))
			fragmentDropReasons(t, m, 6)
		})
	}
}

func TestKernelFirewallFragmentDenialsAndValidation(t *testing.T) {
	allow := []firewall.Rule{{ID: "allow", Direction: "both", Action: "allow", Source: "*", Destination: "*", Protocol: "*"}}
	for _, family := range []uint8{4, 6} {
		t.Run(fmt.Sprint(family), func(t *testing.T) {
			m := firewallTestMeter(t, allow, false, 1, 0)
			for _, tc := range []struct {
				name     string
				id       uint32
				fragment []byte
			}{
				{"overlap", 1, firewallFragment(family, 17, 1, 8, 16, true)},
				{"udp-length", 2, firewallFragment(family, 17, 2, 16, 16, false)},
			} {
				t.Run(tc.name, func(t *testing.T) {
					verdict(t, m, "meter", firewallFragment(family, 17, tc.id, 0, 16, true), ^uint32(0))
					verdict(t, m, "meter", tc.fragment, 2)
					verdict(t, m, "meter", firewallFragment(family, 17, tc.id, 16, 48, false), 2)
					fragmentDropReasons(t, m, 7, 6)
				})
			}
			for _, packet := range [][]byte{
				firewallFragment(family, 6, 3, 0, 8, true),
				firewallFragment(family, 17, 4, 0, 15, true),
				firewallFragment(family, 17, 5, 65528, 8, false),
			} {
				verdict(t, m, "meter", packet, 2)
			}
			fragmentDropReasons(t, m, 2, 2, 2)
			// Audit and unselected hooks pass denied traffic without authorizing it.
			for _, config := range []firewall.Config{
				{Enabled: true, AuditMode: true},
				{Enabled: true, EnforcementDirection: "egress"},
			} {
				denied := configuredFirewallTestMeter(t, nil, config, 1, 0)
				verdict(t, denied, "meter", firewallFragment(family, 17, 6, 0, 16, true), ^uint32(0))
				verdict(t, denied, "meter", firewallFragment(family, 17, 6, 16, 48, false), ^uint32(0))
				fragmentDropReasons(t, denied, 0, 6)
			}
		})
	}
}

func TestKernelFirewallFragmentProtocolsAndAtomic(t *testing.T) {
	rules := []firewall.Rule{{ID: "tcp", Direction: "both", Action: "allow", Source: "*", Destination: "*", Protocol: "tcp", DestinationPort: "443"}}
	for _, family := range []uint8{4, 6} {
		t.Run(fmt.Sprint(family), func(t *testing.T) {
			m := firewallTestMeter(t, rules, true, 1, 0)
			for _, protocol := range []uint8{6, 1, 58} {
				if (family == 4 && protocol == 58) || (family == 6 && protocol == 1) {
					continue
				}
				verdict(t, m, "meter", firewallFragment(family, protocol, uint32(protocol), 0, 24, true), ^uint32(0))
				verdict(t, m, "meter", firewallFragment(family, protocol, uint32(protocol), 24, 40, false), ^uint32(0))
			}
			fragmentDropReasons(t, m)
		})
	}
	udp := []firewall.Rule{{ID: "udp", Direction: "both", Action: "allow", Source: "*", Destination: "*", Protocol: "udp", DestinationPort: "443"}}
	m := firewallTestMeter(t, udp, false, 1, 0)
	atomic := firewallFragment(6, 17, 10, 0, 64, false)
	verdict(t, m, "meter", atomic, ^uint32(0))
	packets, err := m.Read()
	if err != nil || len(packets) != 1 || packets[0].Key.Protocol != 17 || packets[0].Key.DestinationPort != 443 {
		t.Fatalf("atomic fragment must be parsed and metered: %+v %v", packets, err)
	}
	denied := firewallTestMeter(t, nil, false, 1, 0)
	verdict(t, denied, "meter", atomic, 2)
	fragmentDropReasons(t, denied, 0)
	// The IPv6 Fragment next-header key precedes optional destination options.
	first := firewallFragment(6, 17, 11, 0, 16, true)
	first = append(append(append([]byte{}, first[:62]...), 17, 0, 0, 0, 0, 0, 0, 0), first[62:]...)
	first[54] = 60
	binary.BigEndian.PutUint16(first[18:20], 32)
	last := firewallFragment(6, 17, 11, 24, 48, false)
	last[54] = 60
	verdict(t, m, "meter", first, ^uint32(0))
	verdict(t, m, "meter", last, ^uint32(0))
	first = firewallFragment(6, 17, 12, 0, 16, true)
	first[57] |= 2
	verdict(t, m, "meter", first, 2)
	fragmentDropReasons(t, m, 2)
}

func TestKernelFirewallFragmentCapacityExpiryAndReload(t *testing.T) {
	requireKernel(t)
	rules := []firewall.Rule{{ID: "udp", Direction: "both", Action: "allow", Source: "*", Destination: "*", Protocol: "udp"}}
	compiled, err := firewall.Compile(rules)
	if err != nil {
		t.Fatal(err)
	}
	p := &firewall.Policy{Config: firewall.Config{Enabled: true}, Rules: rules, Kernel: compiled, Generation: 1}
	m, err := loadConfiguredMeter(meterOptions{samplingRate: 1, fragmentEntries: 1, firewall: p})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	first := firewallFragment(4, 17, 1, 0, 16, true)
	last := firewallFragment(4, 17, 1, 16, 48, false)
	verdict(t, m, "meter", first, ^uint32(0))
	verdict(t, m, "meter", firewallFragment(4, 17, 2, 0, 16, true), 2)
	verdict(t, m, "meter", last, ^uint32(0))
	verdict(t, m, "meter", first, 2)
	fragmentDropReasons(t, m, 8, 7)
	entries := m.collection.Maps["fragments"]
	key, value := make([]byte, entries.KeySize()), make([]byte, entries.ValueSize())
	iter := entries.Iterate()
	if !iter.Next(&key, &value) {
		t.Fatalf("missing retained fragment entry: %v", iter.Err())
	}
	age := func(elapsed time.Duration) {
		t.Helper()
		value, err := entries.LookupBytes(key)
		if err != nil {
			t.Fatal(err)
		}
		now, err := monotonic()
		if err != nil {
			t.Fatal(err)
		}
		binary.LittleEndian.PutUint64(value[8:16], now-uint64(elapsed))
		if err := entries.Update(key, value, ebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
	}
	age(31 * time.Second)
	verdict(t, m, "meter", last, 2)
	fragmentDropReasons(t, m, 6) // Polling also reclaims expired entries.
	verdict(t, m, "meter", first, ^uint32(0))
	age(29 * time.Second)
	verdict(t, m, "meter", firewallFragment(4, 17, 1, 16, 16, true), ^uint32(0))
	age(31 * time.Second)
	verdict(t, m, "meter", firewallFragment(4, 17, 1, 32, 32, false), 2)
	fragmentDropReasons(t, m, 6)
	verdict(t, m, "meter", first, ^uint32(0))
	next := &firewall.Policy{Config: p.Config, Generation: 2}
	if err := m.UpdateFirewall(next); err != nil {
		t.Fatal(err)
	}
	verdict(t, m, "meter", last, 2)
	fragmentDropReasons(t, m, 6)
	verdict(t, m, "meter", first, 2)
	fragmentDropReasons(t, m, 0)
}

func TestKernelFirewallFragmentRangeLimit(t *testing.T) {
	rules := []firewall.Rule{{ID: "gre", Direction: "both", Action: "allow", Source: "*", Destination: "*", Protocol: "47"}}
	m := firewallTestMeter(t, rules, false, 1, 0)
	for _, id := range []uint32{1, 2} {
		for i := 0; i < 64; i++ {
			more := id == 1 || i < 63
			verdict(t, m, "meter", firewallFragment(4, 47, id, i*8, 8, more), ^uint32(0))
		}
	}
	verdict(t, m, "meter", firewallFragment(4, 47, 1, 512, 8, false), 2)
	verdict(t, m, "meter", firewallFragment(4, 47, 1, 512, 8, false), 2)
	verdict(t, m, "meter", firewallFragment(4, 47, 2, 504, 8, false), 2)
	verdict(t, m, "meter", firewallFragment(4, 47, 3, 0, 8, true), ^uint32(0))
	results := make(chan error, 63)
	for i := 1; i < 64; i++ {
		go func(i int) {
			got, _, err := m.collection.Programs["meter"].Test(firewallFragment(4, 47, 3, i*8, 8, i < 63))
			if err == nil && got != ^uint32(0) {
				err = fmt.Errorf("concurrent fragment %d verdict %d", i, got)
			}
			results <- err
		}(i)
	}
	for i := 1; i < 64; i++ {
		if err := <-results; err != nil {
			t.Error(err)
		}
	}
	verdict(t, m, "meter", firewallFragment(4, 47, 3, 504, 8, false), 2)
	fragmentDropReasons(t, m, 7, 6, 6, 6)
}

func fragmentChecksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i < len(data); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + sum>>16
	}
	return ^uint16(sum)
}

func TestKernelFirewallFragmentLiveTCX(t *testing.T) {
	requireKernel(t)
	for _, family := range []uint8{4, 6} {
		t.Run(fmt.Sprint(family), func(t *testing.T) {
			ip := func(args ...string) {
				t.Helper()
				if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
					t.Fatalf("ip %v: %s %v", args, out, err)
				}
			}
			ip("link", "add", "frhost", "type", "veth", "peer", "name", "frpeer")
			defer exec.Command("ip", "link", "del", "frhost").Run()
			for _, name := range []string{"frhost", "frpeer"} {
				ip("link", "set", name, "addrgenmode", "none")
				ip("link", "set", name, "up")
			}
			address, network, ether := "10.0.0.2", "udp4", uint16(0x0800)
			if family == 4 {
				ip("addr", "add", address+"/24", "dev", "frpeer")
			} else {
				address, network, ether = "2001:db8::2", "udp6", 0x86dd
				ip("-6", "addr", "add", address+"/64", "dev", "frpeer", "nodad")
			}
			host, err := net.InterfaceByName("frhost")
			if err != nil {
				t.Fatal(err)
			}
			peer, err := net.InterfaceByName("frpeer")
			if err != nil {
				t.Fatal(err)
			}
			rules := []firewall.Rule{{ID: "udp", Direction: "both", Action: "allow", Source: "*", Destination: "*", Protocol: "udp", DestinationPort: "443"}}
			compiled, err := firewall.Compile(rules)
			if err != nil {
				t.Fatal(err)
			}
			var meters []*kernelMeter
			for _, iface := range []*net.Interface{host, peer} {
				attached, err := attachMeter(Interface{Index: iface.Index, Name: iface.Name}, meterOptions{samplingRate: 1,
					firewall: &firewall.Policy{Config: firewall.Config{Enabled: true}, Rules: rules, Kernel: compiled}})
				if err != nil {
					t.Fatal(err)
				}
				defer attached.Close()
				meters = append(meters, attached.(*kernelMeter))
			}
			tx, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(ether)))
			if err != nil {
				t.Fatal(err)
			}
			defer unix.Close(tx)
			for _, port := range []int{443, 444} {
				receiver, err := net.ListenUDP(network, &net.UDPAddr{IP: net.ParseIP(address), Port: port})
				if err != nil {
					t.Fatal(err)
				}
				defer receiver.Close()
				first := firewallFragment(family, 17, uint32(port), 0, 16, true)
				last := firewallFragment(family, 17, uint32(port), 16, 48, false)
				transport := 34
				if family == 6 {
					transport = 62
				}
				binary.BigEndian.PutUint16(first[transport+2:transport+4], uint16(port))
				if family == 6 {
					pseudo := append([]byte{}, first[22:54]...)
					pseudo = append(pseudo, 0, 0, 0, 64, 0, 0, 0, 17)
					pseudo = append(pseudo, first[transport:]...)
					pseudo = append(pseudo, last[transport:]...)
					checksum := fragmentChecksum(pseudo)
					if checksum == 0 {
						checksum = 0xffff
					}
					binary.BigEndian.PutUint16(first[transport+6:transport+8], checksum)
				}
				for _, packet := range [][]byte{first, last} {
					copy(packet[:6], peer.HardwareAddr)
					copy(packet[6:12], host.HardwareAddr)
					if family == 4 {
						binary.BigEndian.PutUint16(packet[24:26], fragmentChecksum(packet[14:34]))
					}
					err := unix.Sendto(tx, packet, 0, &unix.SockaddrLinklayer{Ifindex: host.Index, Protocol: htons(ether)})
					if err != nil && (port == 443 || !errors.Is(err, unix.ENOBUFS)) {
						t.Fatal(err)
					}
				}
				if err := receiver.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
					t.Fatal(err)
				}
				buffer := make([]byte, 128)
				n, _, err := receiver.ReadFromUDP(buffer)
				if port == 443 {
					if err != nil || n != 56 || !bytes.Equal(buffer[:n], make([]byte, 56)) {
						t.Fatalf("fragmented UDP was not reassembled after TC filtering: n=%d err=%v", n, err)
					}
				} else {
					var timeout net.Error
					if n != 0 || !errors.As(err, &timeout) || !timeout.Timeout() {
						t.Fatalf("denied fragmented UDP reached receiver: n=%d err=%v", n, err)
					}
				}
			}
			fragmentDropReasons(t, meters[0], 0, 6)
			fragmentDropReasons(t, meters[1])
		})
	}
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

func TestKernelFirewallReloadRevokesOnlyChangedVethState(t *testing.T) {
	for _, protocol := range []string{"udp", "tcp"} {
		t.Run(protocol, func(t *testing.T) {
			rules := []firewall.Rule{{ID: "allow", Direction: "ingress", Action: "allow", Source: "*", Destination: "*", Protocol: protocol}}
			changed := firewallTestMeter(t, rules, true, 1, 0)
			unchanged := firewallTestMeter(t, rules, true, 1, 0)
			forward, reply := ipv4Packet(false, 1234), ipv4Packet(true, 1234)
			if protocol == "tcp" {
				forward, reply = transportPacket(false, 6), transportPacket(true, 6)
			}
			for _, m := range []*kernelMeter{changed, unchanged} {
				if protocol == "tcp" {
					forward[47], reply[47] = 2, 0x12
					verdict(t, m, "meter", forward, ^uint32(0))
					verdict(t, m, "meter_egress", reply, ^uint32(0))
					forward[47], reply[47] = 0x10, 0x10
				}
				verdict(t, m, "meter", forward, ^uint32(0))
				verdict(t, m, "meter_egress", reply, ^uint32(0))
			}
			if err := changed.UpdateFirewall(&firewall.Policy{Generation: 2}); err != nil {
				t.Fatal(err)
			}
			verdict(t, changed, "meter", forward, 2)
			verdict(t, changed, "meter_egress", reply, 2)
			verdict(t, unchanged, "meter_egress", reply, ^uint32(0))
			drops, err := changed.ReadDrops()
			if err != nil || len(drops) != 2 || drops[0].Generation != 2 {
				t.Fatalf("reload events: %+v %v", drops, err)
			}
			// Restoring the allow must create state in the new generation.
			kernel, err := firewall.Compile(rules)
			if err != nil {
				t.Fatal(err)
			}
			if err := changed.UpdateFirewall(&firewall.Policy{Generation: 3, Kernel: kernel}); err != nil {
				t.Fatal(err)
			}
			if protocol == "tcp" {
				forward[47], reply[47] = 2, 0x12
			}
			verdict(t, changed, "meter", forward, ^uint32(0))
			verdict(t, changed, "meter_egress", reply, ^uint32(0))
		})
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
		Lock, Stage         uint32
		Last                uint64
		Generation, Padding uint32
	}{Stage: 3, Last: now - 301000000000, Generation: 1}
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
		Lock, Stage         uint32
		Last                uint64
		Generation, Padding uint32
	}{Stage: 1, Last: now - 31000000000, Generation: 1}
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

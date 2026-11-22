//go:build linux

package flow

import (
	"encoding/binary"
	"testing"
)

func loadMeter(_ uint32, rate uint32) (*kernelMeter, error) {
	return loadConfiguredMeter(meterOptions{samplingRate: rate})
}

func readMeterValues(m meter) (map[Key]Value, error) {
	packets, err := m.Read()
	values := make(map[Key]Value)
	for _, p := range packets {
		v := values[p.Key]
		v.Counters.add(p)
		values[p.Key] = v
	}
	return values, err
}

func TestKernelFiltersAndCollectorExclusion(t *testing.T) {
	requireKernel(t)
	icmp4 := ipv4Packet(false, 1234)
	icmp4[23] = 1
	icmp6 := ipv6Packet(false)
	icmp6[54] = 58
	other := ipv4Packet(false, 1234)
	other[23] = 47
	packets := [][]byte{ipv4Packet(false, 1234), ipv6Packet(false), transportPacket(false, 6), icmp4, icmp6, other}
	for filter, want := range map[string]int{"": 6, "ip": 4, "ip6": 2, "tcp": 1, "udp": 2, "icmp": 1, "icmp6": 1} {
		t.Run(filter, func(t *testing.T) {
			m, err := loadConfiguredMeter(meterOptions{samplingRate: 1, filter: captureFilters[filter]})
			if err != nil {
				t.Fatal(err)
			}
			defer m.Close()
			for _, p := range packets {
				testPacket(t, m, p)
			}
			selected, err := m.Read()
			if err != nil || len(selected) != want {
				t.Fatalf("filter %q: selected=%d want=%d err=%v", filter, len(selected), want, err)
			}
		})
	}
	for _, family := range []uint8{4, 6} {
		collector := Key{Family: family, DestinationPort: 443}
		var outgoing, reply, otherPort []byte
		if family == 4 {
			outgoing = ipv4Packet(false, 1234)
			reply = ipv4Packet(true, 1234)
			copy(collector.Destination[:], outgoing[30:34])
			otherPort = ipv4Packet(false, 1234)
			binary.BigEndian.PutUint16(otherPort[36:38], 444)
		} else {
			outgoing = ipv6Packet(false)
			reply = ipv6Packet(true)
			copy(collector.Destination[:], outgoing[38:54])
			otherPort = ipv6Packet(false)
			binary.BigEndian.PutUint16(otherPort[64:66], 444)
		}
		m, err := loadConfiguredMeter(meterOptions{samplingRate: 1, collector: collector})
		if err != nil {
			t.Fatal(err)
		}
		testPacket(t, m, outgoing)
		testPacket(t, m, reply)
		testPacket(t, m, otherPort)
		selected, err := m.Read()
		if err != nil || len(selected) != 2 {
			t.Fatalf("collector IPv%d exclusion: %+v %v", family, selected, err)
		}
		for _, p := range selected {
			if p.DestinationPort == 443 {
				t.Fatal("collector-bound UDP was captured")
			}
		}
		if err := m.Close(); err != nil {
			t.Fatal(err)
		}
	}
}
func testPacket(t *testing.T, m *kernelMeter, b []byte) {
	t.Helper()
	result, _, err := m.collection.Programs["meter"].Test(b)
	if err != nil || result != ^uint32(0) {
		t.Fatalf("packet verdict %d: %v", result, err)
	}
}

func TestKernelSampling(t *testing.T) {
	requireKernel(t)
	for _, rate := range []uint32{1, 4} {
		m, err := loadMeter(16, rate)
		if err != nil {
			t.Fatal(err)
		}
		for i := uint32(1); i <= 128; i++ {
			b := ipv4Packet(false, 1234)
			if rate > 1 && i%rate != 0 {
				// Sampling must precede parsing; skipped malformed IP is not a parse loss.
				b[14] = 0x40
			}
			testPacket(t, m, b)
		}
		values, err := readMeterValues(m)
		if err != nil || len(values) != 1 {
			t.Fatalf("sampled flows: %+v %v", values, err)
		}
		for _, v := range values {
			if v.Packets != uint64(128/rate) || v.Octets != uint64(128/rate)*28 {
				t.Fatalf("rate %d must count samples without scaling: %+v", rate, v)
			}
		}
		losses, err := m.Losses()
		if err != nil || losses != [2]uint64{} {
			t.Fatalf("sampling losses: %v %v", losses, err)
		}
		if err := m.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestKernelSamplingSequenceIncludesNonIP(t *testing.T) {
	requireKernel(t)
	m, err := loadMeter(16, 4)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	nonIP := ipv4Packet(false, 1234)
	binary.BigEndian.PutUint16(nonIP[12:14], 0x0806)
	for i := 0; i < 3; i++ {
		testPacket(t, m, nonIP)
	}
	testPacket(t, m, ipv4Packet(false, 1234))
	values, err := readMeterValues(m)
	if err != nil || len(values) != 1 {
		t.Fatalf("non-IP packets must advance the sampling sequence: %+v %v", values, err)
	}
	for _, v := range values {
		if v.Packets != 1 {
			t.Fatal("wrong sample count")
		}
	}
}

func TestKernelICMPTOSFlagsAndFragments(t *testing.T) {
	requireKernel(t)
	m, err := loadMeter(32, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	for _, tos := range []byte{0, 0xb8} {
		b := ipv4Packet(false, 1234)
		b[15] = tos
		testPacket(t, m, b)
		b = ipv6Packet(false)
		b[14] |= tos >> 4
		b[15] = tos << 4
		testPacket(t, m, b)
	}
	for _, flags := range []byte{0x02, 0x10, 0x01, 0x04} {
		b := transportPacket(false, 6)
		b[47] = flags
		testPacket(t, m, b)
	}
	for _, icmp := range []struct {
		family     uint8
		kind, code byte
	}{
		{4, 8, 0}, {4, 0, 0}, {4, 3, 1}, {6, 128, 0}, {6, 129, 0}, {6, 1, 4},
	} {
		b := ipv4Packet(false, 1234)
		transport := 34
		if icmp.family == 4 {
			b[23] = 1
		} else {
			b = ipv6Packet(false)
			b[54] = 58
			transport = 62
		}
		clear(b[transport:])
		b[transport], b[transport+1] = icmp.kind, icmp.code
		testPacket(t, m, b)
	}
	other := ipv4Packet(false, 1234)
	other[23] = 47
	testPacket(t, m, other)
	// Both initial and later IPv4 fragments, and IPv6 atomic/real fragments.
	for _, bits := range []uint16{0x2000, 1} {
		b := ipv4Packet(false, 1234)
		binary.BigEndian.PutUint16(b[20:22], bits)
		testPacket(t, m, b)
	}
	for _, bits := range []uint16{0, 1, 8} {
		b := ipv6Packet(false)
		b[20] = 44
		b[54] = 17
		binary.BigEndian.PutUint16(b[56:58], bits)
		testPacket(t, m, b)
	}
	values, err := readMeterValues(m)
	if err != nil || len(values) != 12 {
		t.Fatalf("metadata flow keys: %d %v", len(values), err)
	}
	icmpFlows, tosFlows, tcpFlows, otherFlows := 0, 0, 0, 0
	for k, v := range values {
		switch k.Protocol {
		case 1, 58:
			icmpFlows++
			if k.SourcePort != 0 || v.Packets != 1 {
				t.Fatalf("ICMP counters %+v %+v", k, v)
			}
			if k.Protocol == 1 && k.DestinationPort != 0 && k.DestinationPort != 0x0800 && k.DestinationPort != 0x0301 {
				t.Fatalf("ICMPv4 type/code encoding %+v", k)
			}
			if k.Protocol == 58 && k.DestinationPort != 0x8000 && k.DestinationPort != 0x8100 && k.DestinationPort != 0x0104 {
				t.Fatalf("ICMPv6 type/code encoding %+v", k)
			}
		case 17:
			tosFlows++
			if (k.TOS != 0 && k.TOS != 0xb8) || v.Packets != 1 {
				t.Fatalf("TOS key %+v %+v", k, v)
			}
		case 6:
			tcpFlows++
			if v.Packets != 4 || v.TCPFlags() != 0x17 {
				t.Fatalf("TCP flag aggregation %+v", v)
			}
		case 47:
			otherFlows++
			if k.SourcePort != 0 || k.DestinationPort != 0 || v.Packets != 1 {
				t.Fatal("other protocols must retain zero ports")
			}
		}
	}
	if icmpFlows != 6 || tosFlows != 4 || tcpFlows != 1 || otherFlows != 1 {
		t.Fatal("metadata flows missing")
	}
	var excluded []uint64
	if err := m.collection.Maps["losses"].Lookup(uint32(2), &excluded); err != nil {
		t.Fatal(err)
	}
	var total uint64
	for _, v := range excluded {
		total += v
	}
	if total != 5 {
		t.Fatalf("excluded fragment packets=%d", total)
	}
	losses, err := m.Losses()
	if err != nil || losses != [2]uint64{} {
		t.Fatalf("intentional exclusions are not metering errors: %v %v", losses, err)
	}
}

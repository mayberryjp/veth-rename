//go:build linux

package flow

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func requireKernel(t *testing.T) {
	t.Helper()
	if os.Getenv("FLOW_INTEGRATION") != "1" {
		t.Skip("set FLOW_INTEGRATION=1 in an isolated privileged network namespace")
	}
	if err := platformReady(); err != nil {
		t.Fatal(err)
	}
}

func ipv4Packet(reverse bool, port uint16) []byte {
	b := make([]byte, 14+20+8)
	binary.BigEndian.PutUint16(b[12:14], 0x0800)
	b[14] = 0x45
	binary.BigEndian.PutUint16(b[16:18], 28)
	b[22] = 64
	b[23] = 17
	copy(b[26:30], []byte{10, 0, 0, 1})
	copy(b[30:34], []byte{10, 0, 0, 2})
	binary.BigEndian.PutUint16(b[34:36], port)
	binary.BigEndian.PutUint16(b[36:38], 443)
	binary.BigEndian.PutUint16(b[38:40], 8)
	if reverse {
		copy(b[26:30], []byte{10, 0, 0, 2})
		copy(b[30:34], []byte{10, 0, 0, 1})
		binary.BigEndian.PutUint16(b[34:36], 443)
		binary.BigEndian.PutUint16(b[36:38], port)
	}
	return b
}

func transportPacket(reverse bool, protocol uint8) []byte {
	b := ipv4Packet(reverse, 1234)
	length := 40
	if protocol == 132 {
		length = 32
	}
	b = append(b, make([]byte, length-28)...)
	binary.BigEndian.PutUint16(b[16:18], uint16(length))
	b[23] = protocol
	if protocol == 6 {
		b[46] = 0x50
	}
	return b
}

func ipv6Packet(reverse bool) []byte {
	b := make([]byte, 14+40+8+8)
	binary.BigEndian.PutUint16(b[12:14], 0x86dd)
	b[14] = 0x60
	binary.BigEndian.PutUint16(b[18:20], 16)
	b[20] = 0
	b[21] = 64
	copy(b[22:38], net.ParseIP("2001:db8::1").To16())
	copy(b[38:54], net.ParseIP("2001:db8::2").To16())
	b[54] = 17 // Hop-by-Hop extension followed by UDP
	binary.BigEndian.PutUint16(b[62:64], 1234)
	binary.BigEndian.PutUint16(b[64:66], 443)
	binary.BigEndian.PutUint16(b[66:68], 8)
	if reverse {
		copy(b[22:38], net.ParseIP("2001:db8::2").To16())
		copy(b[38:54], net.ParseIP("2001:db8::1").To16())
		binary.BigEndian.PutUint16(b[62:64], 443)
		binary.BigEndian.PutUint16(b[64:66], 1234)
	}
	return b
}

func TestKernelParserAndCounters(t *testing.T) {
	requireKernel(t)
	m, err := loadMeter(16, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	run := func(b []byte) {
		t.Helper()
		result, _, err := m.collection.Programs["meter"].Test(b)
		if err != nil || result != ^uint32(0) {
			t.Fatalf("non-observational verdict %d: %v", result, err)
		}
	}
	for i := 0; i < 100; i++ {
		run(ipv4Packet(false, 1234))
		run(ipv4Packet(true, 1234))
		run(ipv6Packet(false))
		run(ipv6Packet(true))
		run(transportPacket(false, 6))
		run(transportPacket(true, 6))
		run(transportPacket(false, 132))
		run(transportPacket(true, 132))
	}
	values, err := readMeterValues(m)
	if err != nil {
		t.Fatal(err)
	}
	if len(values) != 8 {
		t.Fatalf("expected eight directional flows, got %d", len(values))
	}
	for k, v := range values {
		size := uint64(28)
		if k.Family == 6 {
			size = 56
		} else if k.Protocol == 6 {
			size = 40
		} else if k.Protocol == 132 {
			size = 32
		}
		if !((k.SourcePort == 1234 && k.DestinationPort == 443) ||
			(k.SourcePort == 443 && k.DestinationPort == 1234)) ||
			v.Packets != 100 || v.Octets != 100*size || v.First == 0 {
			t.Fatalf("unsampled directional flow: %+v %+v", k, v)
		}
		peer := k
		peer.Source, peer.Destination = k.Destination, k.Source
		peer.SourcePort, peer.DestinationPort = k.DestinationPort, k.SourcePort
		if _, ok := values[peer]; !ok {
			t.Fatalf("missing separately keyed opposite direction: %+v", peer)
		}
	}
	vlan := ipv4Packet(false, 1234)
	vlan = append(append(append([]byte{}, vlan[:12]...), []byte{0x81, 0, 0, 1}...), vlan[12:]...)
	run(vlan)
	fragment := ipv4Packet(false, 1234)
	fragment[20] = 0x20
	run(fragment)
	fragment = ipv4Packet(true, 1234)
	fragment[21] = 1
	run(fragment)
	values, err = readMeterValues(m)
	if err != nil {
		t.Fatal(err)
	}
	foundFragments := 0
	for k := range values {
		if k.SourcePort == 0 && k.DestinationPort == 0 {
			foundFragments++
		}
	}
	if foundFragments != 0 || len(values) != 1 {
		t.Fatal("fragments must be excluded, not metered as portless flows")
	}
	bad := ipv4Packet(false, 1234)
	bad[14] = 0x40
	run(bad)
	bad = transportPacket(false, 6)
	bad[46] = 0
	run(bad)
	losses, err := m.Losses()
	if err != nil || losses[0] != 0 || losses[1] != 2 {
		t.Fatalf("parse losses %v %v", losses, err)
	}
}

func TestKernelRingBufferLossIsExplicit(t *testing.T) {
	requireKernel(t)
	m, err := loadConfiguredMeter(meterOptions{samplingRate: 1, ringBytes: 4096})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	for i := 0; i < 128; i++ {
		if _, _, err := m.collection.Programs["meter"].Test(ipv4Packet(false, 1234)); err != nil {
			t.Fatal(err)
		}
	}
	losses, err := m.Losses()
	packets, readErr := m.Read()
	if err != nil || readErr != nil || losses[0] == 0 || uint64(len(packets))+losses[0] != 128 {
		t.Fatalf("lost packet count %v %v", losses, err)
	}
}

func TestKernelLiveVeth(t *testing.T) {
	requireKernel(t)
	for _, rate := range []uint32{1, 4} {
		t.Run(fmt.Sprintf("sampling_%d", rate), func(t *testing.T) {
			testKernelLiveVeth(t, rate)
		})
	}
}

func testKernelLiveVeth(t *testing.T, samplingRate uint32) {
	ip := func(args ...string) {
		t.Helper()
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			t.Fatalf("ip %v: %s %v", args, out, err)
		}
	}
	// Run only in the isolated netns supplied by the integration runner.
	ip("link", "add", "flowhost", "type", "veth", "peer", "name", "flowpeer")
	defer exec.Command("ip", "link", "del", "flowhost").Run()
	// Suppress automatic link-local/MLD traffic so exact counts cover the fixture only.
	ip("link", "set", "flowhost", "addrgenmode", "none")
	ip("link", "set", "flowpeer", "addrgenmode", "none")
	ip("link", "set", "flowhost", "up")
	ip("link", "set", "flowpeer", "up")
	host, err := net.InterfaceByName("flowhost")
	if err != nil {
		t.Fatal(err)
	}
	peer, err := net.InterfaceByName("flowpeer")
	if err != nil {
		t.Fatal(err)
	}
	ip("link", "set", "lo", "up")
	collector, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer collector.Close()
	config, err := readConfig(strings.NewReader(fmt.Sprintf("collector: '%s'\nactive_timeout: 100ms\nidle_timeout: 10ms\npoll_interval: 1ms\nsampling_rate: %d\n", collector.LocalAddr(), samplingRate)))
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Sync([]Interface{{Index: host.Index, Name: host.Name, Identity: "test"}}); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(0x0003)))
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	for i := 0; i < 20; i++ {
		for _, direction := range []struct {
			iface   *net.Interface
			reverse bool
		}{{peer, false}, {host, true}} {
			for _, b := range [][]byte{ipv4Packet(direction.reverse, 1234), ipv6Packet(direction.reverse)} {
				copy(b[:6], host.HardwareAddr)
				copy(b[6:12], peer.HardwareAddr)
				for repeat := uint32(0); repeat < samplingRate; repeat++ {
					if err := unix.Sendto(fd, b, 0, &unix.SockaddrLinklayer{
						Ifindex: direction.iface.Index, Protocol: htons(binary.BigEndian.Uint16(b[12:14])),
					}); err != nil {
						t.Fatal(err)
					}
				}
			}
		}
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		if s.interfaces[host.Index].meter.(*kernelMeter).reader.AvailableBytes() > 0 {
			time.Sleep(15 * time.Millisecond)
			if err := s.Poll(); err != nil {
				t.Fatal(err)
			}
			readUDP := func() []byte {
				t.Helper()
				if err := collector.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
					t.Fatal(err)
				}
				b := make([]byte, 512)
				n, _, err := collector.ReadFrom(b)
				if err != nil {
					t.Fatal(err)
				}
				return b[:n]
			}
			template := readUDP()
			var decoder recordDecoder
			decoder.decode(t, template)
			received := make(map[Key]bool)
			for attempts := 0; attempts < 16; attempts++ {
				b := readUDP()
				records := decoder.decode(t, b)
				if len(records) == 0 {
					continue
				}
				for _, record := range records {
					source, destination := record[8], record[12]
					size := uint64(560)
					family := uint8(4)
					if source == nil {
						source, destination = record[27], record[28]
						family, size = 6, 1120
					}
					sourcePort := binary.BigEndian.Uint16(record[7])
					if sourcePort != 1234 && sourcePort != 443 {
						continue
					}
					if binary.BigEndian.Uint64(record[2]) != 20 ||
						binary.BigEndian.Uint64(record[1]) != size ||
						binary.BigEndian.Uint32(record[34]) != samplingRate || record[35][0] != 1 {
						t.Fatalf("end-to-end UDP directional flow export %x", b)
					}
					key := Key{Family: family, Protocol: 17, SourcePort: sourcePort,
						DestinationPort: binary.BigEndian.Uint16(record[11])}
					copy(key.Source[:], source)
					copy(key.Destination[:], destination)
					if received[key] {
						t.Fatalf("wrong or duplicate observed flow direction: %+v", key)
					}
					received[key] = true
					if len(received) == 4 {
						for key := range received {
							peer := key
							peer.Source, peer.Destination = key.Destination, key.Source
							peer.SourcePort, peer.DestinationPort = key.DestinationPort, key.SourcePort
							if !received[peer] {
								t.Fatalf("missing opposite direction: %+v", peer)
							}
						}
						if s.export.sequence != 4 {
							t.Fatalf("directional record sequence = %d", s.export.sequence)
						}
						return
					}
				}
			}
			t.Fatal("missing IPv4/IPv6 data at collector")
		}
		if time.Now().After(deadline) {
			t.Fatal("no live ingress/egress events")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestKernelIPv6Collector(t *testing.T) {
	requireKernel(t)
	if out, err := exec.Command("ip", "link", "set", "lo", "up").CombinedOutput(); err != nil {
		t.Fatalf("loopback: %s %v", out, err)
	}
	collector, err := net.ListenPacket("udp6", "[::1]:0")
	if err != nil {
		t.Fatal(err)
	}
	defer collector.Close()
	c, err := readConfig(strings.NewReader("collector: '" + collector.LocalAddr().String() + "'\n"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := collector.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 512)
	n, _, err := collector.ReadFrom(b)
	if err != nil {
		t.Fatal(err)
	}
	decodeTemplates(t, b[:n])
}

func htons(v uint16) uint16 { return v<<8 | v>>8 }

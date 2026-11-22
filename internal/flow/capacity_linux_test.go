//go:build linux

package flow

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestKernelConcurrentCapacityExport(t *testing.T) {
	requireKernel(t)
	if out, err := exec.Command("ip", "link", "set", "lo", "up").CombinedOutput(); err != nil {
		t.Fatalf("loopback: %s %v", out, err)
	}
	collector, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer collector.Close()
	c, err := readConfig(strings.NewReader(fmt.Sprintf(
		"collector: '%s'\nmax_flows_per_veth: 8\nidle_timeout: 50ms\npoll_interval: 1ms\n", collector.LocalAddr())))
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	// Test-run injects packets into the real eBPF program while Poll consumes events.
	s.attach = func(_ Interface, options meterOptions) (meter, error) { return loadConfiguredMeter(options) }
	if err := s.Sync([]Interface{{Index: 1, Name: "lo", Identity: "capacity-test"}}); err != nil {
		t.Fatal(err)
	}
	m := s.interfaces[1].meter.(*kernelMeter)
	done := make(chan error, 1)
	go func() {
		for i := 0; i < 128; i++ {
			for copy := 0; copy < 2; copy++ {
				result, _, err := m.collection.Programs["meter"].Test(ipv4Packet(false, uint16(1000+i)))
				if err != nil {
					done <- err
					return
				}
				if result != ^uint32(0) {
					done <- fmt.Errorf("non-observational verdict %d", result)
					return
				}
			}
		}
		done <- nil
	}()
	finished := false
	deadline := time.Now().Add(3 * time.Second)
	for !finished && time.Now().Before(deadline) {
		if err := s.Poll(); err != nil {
			t.Fatal(err)
		}
		if len(s.interfaces[1].table.flows) > 8 {
			t.Fatal("concurrent flow limit exceeded")
		}
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
			finished = true
		default:
			time.Sleep(time.Millisecond)
		}
	}
	if !finished {
		t.Fatal("packet injection did not complete")
	}
	time.Sleep(60 * time.Millisecond)
	if err := s.Poll(); err != nil {
		t.Fatal(err)
	}
	if len(s.interfaces[1].table.flows) != 0 || len(s.interfaces[1].pending) != 0 || m.Buffered() {
		t.Fatal("capacity fixture left retained state")
	}
	seen := make(map[uint16]bool)
	datagrams, records := 0, 0
	if err := collector.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	for records < 128 {
		b := make([]byte, 512)
		n, _, err := collector.ReadFrom(b)
		if err != nil {
			t.Fatal(err)
		}
		b = b[:n]
		datagrams++
		if len(b) > maxMessage || binary.BigEndian.Uint32(b[8:12]) != uint32(records) {
			t.Fatal("message size or record sequence incorrect")
		}
		for _, r := range decodeRecords(t, b) {
			port := binary.BigEndian.Uint16(r[7])
			if seen[port] || binary.BigEndian.Uint64(r[2]) != 2 || binary.BigEndian.Uint64(r[1]) != 56 {
				t.Fatal("concurrent reclamation lost or duplicated traffic")
			}
			seen[port] = true
			records++
		}
	}
	if len(seen) != 128 || datagrams >= 64 {
		t.Fatalf("flows=%d datagrams=%d", len(seen), datagrams)
	}
	losses, err := m.Losses()
	if err != nil || losses != [2]uint64{} {
		t.Fatalf("metering losses=%v %v", losses, err)
	}
}

//go:build linux

package flow

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestUDPPathMTUOptions(t *testing.T) {
	for _, network := range []string{"udp4", "udp6"} {
		t.Run(network, func(t *testing.T) {
			address := "127.0.0.1:0"
			if network == "udp6" {
				address = "[::1]:0"
			}
			server, err := net.ListenPacket(network, address)
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			conn, err := net.Dial(network, server.LocalAddr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if err := configureUDP(conn); err != nil {
				t.Fatal(err)
			}
			err = withUDPSocket(conn, func(fd, domain int) error {
				level, option := unix.IPPROTO_IP, unix.IP_MTU_DISCOVER
				if domain == unix.AF_INET6 {
					level, option = unix.IPPROTO_IPV6, unix.IPV6_MTU_DISCOVER
				}
				value, err := unix.GetsockoptInt(fd, level, option)
				if err == nil && value != unix.IP_PMTUDISC_DO {
					return fmt.Errorf("fragmentation prevention disabled: %d", value)
				}
				return err
			})
			if err != nil {
				t.Fatal(err)
			}
			budget, err := udpMessageBudget(conn)
			if err != nil || budget < defaultMaxMessageSize {
				t.Fatalf("invalid loopback PMTU budget: %d %v", budget, err)
			}
			if err := conn.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := udpMessageBudget(conn); err == nil {
				t.Fatal("closed socket query failed silently")
			}
		})
	}
}

func TestKernelPMTUReductionAndReconnect(t *testing.T) {
	requireKernel(t)
	for _, tc := range []struct {
		name, address, collector string
		configured, mtu, budget  int
	}{
		{"ipv4", "198.18.0.1/24", "198.18.0.2:4739", 1200, 900, 872},
		{"ipv6", "fd00:53::1/64", "[fd00:53::2]:4739", 1400, 1280, 1232},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ip := func(args ...string) {
				t.Helper()
				if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
					t.Fatalf("ip %v: %s %v", args, out, err)
				}
			}
			ip("link", "add", "pmtuhost", "type", "veth", "peer", "name", "pmtupeer")
			defer exec.Command("ip", "link", "del", "pmtuhost").Run()
			ip("link", "set", "pmtuhost", "addrgenmode", "none")
			ip("link", "set", "pmtupeer", "addrgenmode", "none")
			ip("link", "set", "pmtuhost", "mtu", "1500", "up")
			ip("link", "set", "pmtupeer", "mtu", "1500", "up")
			args := []string{"addr", "add", tc.address, "dev", "pmtuhost"}
			if tc.name == "ipv6" {
				args = append(args, "nodad")
			}
			ip(args...)
			c, err := readConfig(strings.NewReader(fmt.Sprintf("collector: '%s'\nmax_message_size: %d\n", tc.collector, tc.configured)))
			if err != nil {
				t.Fatal(err)
			}
			s, err := New(context.Background(), c)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			if s.export.limit() != tc.configured {
				t.Fatal("initial configured size not applied")
			}
			o := &observed{iface: Interface{Index: 7}, meter: &fakeMeter{}, table: newTable(c)}
			for i := 0; i < 40; i++ {
				o.pending = append(o.pending, Record{Key: Key{Family: 6, SourcePort: uint16(i + 1)},
					Counters: Counters{Packets: 1, Octets: 56}})
			}
			s.interfaces[7] = o
			ip("link", "set", "pmtuhost", "mtu", fmt.Sprint(tc.mtu))
			err = s.Poll()
			if !errors.Is(err, syscall.EMSGSIZE) || s.export.limit() != tc.budget ||
				len(o.pending) != 40 || s.writer.conn != nil || s.export.sequence != 0 {
				t.Fatalf("kernel MTU failure not retained: limit=%d pending=%d err=%v", s.export.limit(), len(o.pending), err)
			}
			now := time.Now().Add(2 * time.Second)
			s.now = func() time.Time { return now }
			if err := s.Poll(); err != nil {
				t.Fatal(err)
			}
			if s.export.limit() != tc.budget || len(o.pending) != 0 || s.export.sequence != 40 {
				t.Fatal("reconnection did not preserve reduced size and exact record counts")
			}
			if err := configureUDP(s.writer.conn); err != nil {
				t.Fatal("recreated socket lost PMTU support")
			}
		})
	}
}

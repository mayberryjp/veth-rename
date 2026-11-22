package flow

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"syscall"
	"testing"
	"time"
)

type collectingConn struct {
	deadlineConn
	out *datagrams
}

func (c *collectingConn) Write(b []byte) (int, error) { return c.out.Write(b) }

func TestServicePMTUPartialFailureAndNewSession(t *testing.T) {
	s, m, out, clock, key := testService(t)
	m.packets = nil
	for i := 0; i < 40; i++ {
		k := key
		k.SourcePort = uint16(i + 1)
		m.packets = append(m.packets, Packet{Key: k, Time: uint64(i + 1), Octets: 28})
	}
	old := &collectingConn{out: out}
	s.writer = &udpWriter{conn: old}
	s.export.out = s.writer
	s.export.maxMessageSize = 1200
	s.export.pathBudget = func() (int, error) { return 400, nil }
	s.connect = func(context.Context) (net.Conn, error) { return &collectingConn{out: out}, nil }
	out.failAt, out.writeErr = 3, syscall.EMSGSIZE
	if err := s.Poll(); !errors.Is(err, syscall.EMSGSIZE) {
		t.Fatalf("EMSGSIZE was not surfaced: %v", err)
	}
	if !old.closed || s.export.limit() != 400 || len(s.interfaces[7].pending) != 25 {
		t.Fatal("partial failure did not retain the unsent suffix and learned budget")
	}
	out.failAt = 0
	*clock += uint64(time.Second)
	if err := s.Poll(); err != nil {
		t.Fatal(err)
	}
	if s.export.sequence != 25 || len(s.interfaces[7].pending) != 0 ||
		binary.BigEndian.Uint16(out.packets[2][16:18]) != 2 ||
		binary.BigEndian.Uint32(out.packets[2][8:12]) != 0 {
		t.Fatal("new session did not restart with templates and a fresh sequence")
	}
	records := allRecords(t, out)
	if len(records) != 40 {
		t.Fatal("PMTU reconnect lost records")
	}
	for i, r := range records {
		if binary.BigEndian.Uint16(r[7]) != uint16(i+1) {
			t.Fatal("PMTU reconnect replayed or reordered accepted records")
		}
	}
}

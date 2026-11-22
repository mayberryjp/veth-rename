package flow

import (
	"context"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
	"time"
)

type slowSuccessConn struct{ deadlineConn }

func (c *slowSuccessConn) Write(b []byte) (int, error) {
	delay := min(50*time.Millisecond, time.Until(c.deadline))
	if delay > 0 {
		time.Sleep(delay)
	}
	if !time.Now().Before(c.deadline) {
		return 0, context.DeadlineExceeded
	}
	return len(b), nil
}

func TestShutdownUsesOneDeadlineAcrossAllBatches(t *testing.T) {
	s, _, _, _, key := testService(t)
	conn := &slowSuccessConn{}
	s.writer = &udpWriter{conn: conn}
	s.export.out = s.writer
	o := s.interfaces[7]
	for i := 0; i < 300; i++ {
		o.pending = append(o.pending, Record{Key: key, Counters: Counters{Packets: 1, Octets: 28}})
	}
	start := time.Now()
	err := s.Close()
	elapsed := time.Since(start)
	if err == nil || !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "shutdown flush incomplete") {
		t.Fatalf("shutdown must report deadline and leftovers: %v", err)
	}
	if elapsed < 1800*time.Millisecond || elapsed > shutdownBudget+250*time.Millisecond {
		t.Fatalf("shared shutdown budget elapsed=%s", elapsed)
	}
}

func TestRetirementDrainsRemainingBufferedEvents(t *testing.T) {
	s, m, out, _, key := testService(t)
	m.maxRead = 1
	m.packets = []Packet{{Key: key, Time: 1, Octets: 28}, {Key: key, Time: 2, Octets: 28}}
	if err := s.Sync(nil); err != nil {
		t.Fatal(err)
	}
	if m.closed || len(s.interfaces) != 1 {
		t.Fatal("closed capture with buffered events")
	}
	if err := s.Poll(); err != nil {
		t.Fatal(err)
	}
	if !m.closed || len(s.interfaces) != 0 {
		t.Fatal("retirement did not complete")
	}
	total := uint64(0)
	for _, r := range allRecords(t, out) {
		total += binary.BigEndian.Uint64(r[2])
	}
	if total != 2 {
		t.Fatal("buffered events discarded during retirement")
	}
}

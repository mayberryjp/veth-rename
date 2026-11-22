package flow

import (
	"encoding/binary"
	"errors"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestExactPaddingBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name   string
		limit  int
		family uint8
		count  int
	}{
		{"two_ipv4", 176, 4, 2},
		{"three_ipv6", 324, 6, 3},
		{"four_ipv6", 424, 6, 4},
		{"fifteen_ipv4", 1176, 4, 15},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := &datagrams{}
			e := exporter{out: out, refresh: time.Minute, maxMessageSize: tc.limit}
			records := make([]Record, tc.count)
			for i := range records {
				records[i].Family = tc.family
			}
			if err := e.send(records, time.Now()); err != nil {
				t.Fatal(err)
			}
			if len(out.packets) != 2 || len(out.packets[1]) != tc.limit || len(allRecords(t, out)) != tc.count {
				t.Fatalf("exact boundary not packed: packets=%d limit=%d", len(out.packets), tc.limit)
			}
		})
	}
}

func TestPeriodicTemplatesDuringContinuousTraffic(t *testing.T) {
	out := &datagrams{}
	e := exporter{out: out, refresh: 30 * time.Second}
	now := time.Unix(1700000000, 0)
	for _, seconds := range []int{0, 10, 20, 30} {
		if err := e.send([]Record{{Key: Key{Family: 4}}}, now.Add(time.Duration(seconds)*time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	if len(out.packets) != 6 || e.sequence != 4 || !e.lastTemplate.Equal(now.Add(30*time.Second)) {
		t.Fatal("data sends postponed the periodic template timer")
	}
	for i, b := range out.packets {
		isTemplate := binary.BigEndian.Uint16(b[16:18]) == 2
		if isTemplate != (i == 0 || i == 4) {
			t.Fatal("unexpected template transmission")
		}
	}
	if len(allRecords(t, out)) != 4 {
		t.Fatal("template refresh changed data counters")
	}
}

func TestPacketTemplateRefreshWithinLargeBatch(t *testing.T) {
	out := &datagrams{}
	e := exporter{out: out, refresh: time.Minute, refreshPackets: 2, maxMessageSize: minimumMessageSize()}
	records := make([]Record, 5)
	for i := range records {
		records[i].Family = 6
	}
	if err := e.send(records, time.Now()); err != nil {
		t.Fatal(err)
	}
	if len(out.packets) != 8 || e.sequence != 5 || e.dataMessages != 1 {
		t.Fatalf("packet refresh missed during batch: messages=%d", len(out.packets))
	}
	sequences := []uint32{0, 0, 1, 2, 2, 3, 4, 4}
	for i, b := range out.packets {
		isTemplate := binary.BigEndian.Uint16(b[16:18]) == 2
		if isTemplate != (i%3 == 0) || binary.BigEndian.Uint32(b[8:12]) != sequences[i] {
			t.Fatal("template refresh ordering or sequence incorrect")
		}
	}
	if len(allRecords(t, out)) != 5 {
		t.Fatal("data did not reference previously received templates")
	}
}

func TestTemplateRefreshFailurePreservesAcknowledgment(t *testing.T) {
	out := &datagrams{failAt: 4}
	e := exporter{out: out, refresh: time.Minute, refreshPackets: 2, maxMessageSize: minimumMessageSize()}
	records := make([]Record, 5)
	for i := range records {
		records[i].Family = 6
	}
	now := time.Now()
	n, err := e.sendAcknowledged(records, now)
	if err == nil || n != 2 || e.sequence != 2 || e.dataMessages != 2 {
		t.Fatal("failed refresh acknowledged unsent records")
	}
	out.failAt = 0
	if n2, err := e.sendAcknowledged(records[n:], now); err != nil || n2 != 3 || len(allRecords(t, out)) != 5 {
		t.Fatalf("refresh recovery replayed or lost records: %v", err)
	}
}

func TestMixedFamilyByteBatching(t *testing.T) {
	out := &datagrams{}
	e := exporter{out: out, refresh: time.Minute, refreshPackets: 20, maxMessageSize: 1200}
	records := make([]Record, 256)
	for i := range records {
		records[i].Family = 4
		if i%2 != 0 {
			records[i].Family = 6
		}
		records[i].SourcePort = uint16(i + 1)
	}
	if err := e.send(records, time.Now()); err != nil {
		t.Fatal(err)
	}
	for _, b := range out.packets {
		if len(b) > 1200 {
			t.Fatalf("oversized mixed message: %d", len(b))
		}
	}
	got := allRecords(t, out)
	if len(got) != len(records) || len(out.packets) > 24 {
		t.Fatalf("mixed batches not packed: records=%d datagrams=%d", len(got), len(out.packets))
	}
	for i, record := range got {
		if binary.BigEndian.Uint16(record[7]) != uint16(i+1) {
			t.Fatal("mixed family batching reordered the acknowledgment prefix")
		}
	}
}

func TestEMSGSIZEReducesBudgetWithoutReplayingPrefix(t *testing.T) {
	out := &datagrams{failAt: 3, writeErr: syscall.EMSGSIZE}
	e := exporter{out: out, refresh: time.Minute, maxMessageSize: 1200,
		pathBudget: func() (int, error) { return 400, nil }}
	records := make([]Record, 40)
	for i := range records {
		records[i].Family = 4
		records[i].SourcePort = uint16(i + 1)
	}
	now := time.Now()
	n, err := e.sendAcknowledged(records, now)
	if !errors.Is(err, syscall.EMSGSIZE) || n != 15 || e.limit() != 400 ||
		!strings.Contains(err.Error(), "reduced from 1200 to 400") {
		t.Fatalf("PMTU failure lost its prefix or size adjustment: n=%d limit=%d err=%v", n, e.limit(), err)
	}
	out.failAt = 0
	if err := e.refreshPathBudget(); err != nil || e.limit() != 400 {
		t.Fatal("socket recreation lost learned size")
	}
	if err := e.send(records[n:], now); err != nil {
		t.Fatal(err)
	}
	for _, b := range out.packets[2:] {
		if len(b) > 400 {
			t.Fatal("retry used an oversized batch")
		}
	}
	got := allRecords(t, out)
	if len(got) != 40 || e.sequence != 40 {
		t.Fatal("PMTU reduction lost records")
	}
	for i, record := range got {
		if binary.BigEndian.Uint16(record[7]) != uint16(i+1) {
			t.Fatal("PMTU recovery replayed accepted data")
		}
	}
}

func TestEMSGSIZEFallbackAndUnusableMinimum(t *testing.T) {
	queryErr := errors.New("PMTU query failed")
	out := &datagrams{fail: true, writeErr: syscall.EMSGSIZE}
	e := exporter{out: out, refresh: time.Minute, maxMessageSize: 1200,
		pathBudget: func() (int, error) { return 0, queryErr }}
	if err := e.send(nil, time.Now()); !errors.Is(err, syscall.EMSGSIZE) || !errors.Is(err, queryErr) || e.limit() != 600 {
		t.Fatalf("fallback or query failure hidden: %v", err)
	}
	e.pathBudget = nil
	e.maxMessageSize, e.messageLimit = minimumMessageSize(), 0
	if err := e.send(nil, time.Now()); !errors.Is(err, syscall.EMSGSIZE) {
		t.Fatal("minimum-sized template failure hidden")
	}
	attempts := out.attempts
	if err := e.send(nil, time.Now()); err == nil || out.attempts != attempts {
		t.Fatal("repeated an oversized template that cannot fit")
	}
}

func TestPathBudgetClampingAndRecovery(t *testing.T) {
	budget := 400
	e := exporter{maxMessageSize: 1200, pathBudget: func() (int, error) { return budget, nil }}
	if err := e.refreshPathBudget(); err != nil || e.limit() != 400 {
		t.Fatal("configured limit not clamped to path")
	}
	budget = 1472
	if err := e.refreshPathBudget(); err != nil || e.limit() != 400 {
		t.Fatal("fresh socket estimate discarded the learned smaller limit")
	}
	budget = 100
	if err := e.refreshPathBudget(); err == nil || e.limit() != 100 {
		t.Fatal("unusable template MTU not reported")
	}
	budget = 500
	if err := e.refreshPathBudget(); err != nil || e.limit() != 500 {
		t.Fatal("repaired path did not recover")
	}
}

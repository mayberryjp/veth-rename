package flow

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

type fakeMeter struct {
	packets          []Packet
	losses           [2]uint64
	readErr          error
	detached, closed bool
	maxRead          int
}

func (m *fakeMeter) Read() ([]Packet, error) {
	n := len(m.packets)
	if m.maxRead > 0 {
		n = min(n, m.maxRead)
	}
	p := m.packets[:n]
	m.packets = m.packets[n:]
	return p, m.readErr
}
func (m *fakeMeter) Losses() ([2]uint64, error) { return m.losses, nil }
func (m *fakeMeter) Buffered() bool             { return len(m.packets) > 0 }
func (m *fakeMeter) Detach() error              { m.detached = true; return nil }
func (m *fakeMeter) Close() error               { m.closed = true; return nil }

func testService(t *testing.T) (*Service, *fakeMeter, *datagrams, *uint64, Key) {
	t.Helper()
	c, err := readConfig(strings.NewReader("collector: localhost:4739\nactive_timeout: 10s\nidle_timeout: 3s\n"))
	if err != nil {
		t.Fatal(err)
	}
	mono := uint64(11 * time.Second)
	key := Key{Family: 4, Protocol: 17, SourcePort: 1234, DestinationPort: 443}
	m := &fakeMeter{}
	for i := 0; i < 10; i++ {
		ts := uint64(time.Duration(i+1) * time.Second)
		m.packets = append(m.packets, Packet{Key: key, Time: ts, Octets: 100})
	}
	out := &datagrams{}
	s := &Service{config: c, export: exporter{out: out, refresh: time.Minute, samplingRate: 1},
		interfaces: make(map[int]*observed), clock: func() (uint64, error) { return mono, nil },
		now:     func() time.Time { return time.Unix(1700000000, int64(mono)) },
		options: meterOptions{samplingRate: 1}, attach: func(_ Interface, options meterOptions) (meter, error) {
			if options.samplingRate != c.SamplingRate {
				t.Fatal("sampling configuration not passed")
			}
			return m, nil
		}}
	if err := s.Sync([]Interface{{Index: 7, Name: "veth_app", Identity: "c1/n1"}}); err != nil {
		t.Fatal(err)
	}
	return s, m, out, &mono, key
}

func allRecords(t *testing.T, out *datagrams) []map[uint16][]byte {
	t.Helper()
	var records []map[uint16][]byte
	for _, b := range out.packets {
		records = append(records, decodeRecords(t, b)...)
	}
	return records
}

func TestServiceExpirationAndReclamation(t *testing.T) {
	s, m, out, clock, key := testService(t)
	if err := s.Poll(); err != nil {
		t.Fatal(err)
	}
	if len(s.interfaces[7].table.flows) != 0 {
		t.Fatal("expired flow was not reclaimed")
	}
	if singleRecord(t, out.packets[1])[136][0] != 2 {
		t.Fatal("active reason")
	}
	if err := s.Poll(); err != nil || len(allRecords(t, out)) != 1 {
		t.Fatal("duplicate export")
	}
	for i := 0; i < 3; i++ {
		m.packets = append(m.packets, Packet{Key: key, Time: uint64(12 * time.Second), Octets: 100})
	}
	*clock = uint64(12 * time.Second)
	if err := s.Poll(); err != nil || len(allRecords(t, out)) != 1 {
		t.Fatal("premature export")
	}
	*clock = uint64(15 * time.Second)
	if err := s.Poll(); err != nil {
		t.Fatal(err)
	}
	records := allRecords(t, out)
	if len(records) != 2 || binary.BigEndian.Uint64(records[1][2]) != 3 ||
		binary.BigEndian.Uint64(records[1][1]) != 300 || records[1][136][0] != 1 {
		t.Fatal("idle counters")
	}
	if len(s.interfaces[7].table.flows) != 0 {
		t.Fatal("idle flow was not reclaimed")
	}
}

func TestDirectionalExpiryAndFlags(t *testing.T) {
	s, m, out, clock, key := testService(t)
	key.Protocol = 6
	reverse := key
	reverse.SourcePort, reverse.DestinationPort = key.DestinationPort, key.SourcePort
	m.packets = []Packet{
		{Key: key, Time: uint64(time.Second), Octets: 40, Flags: 2},
		{Key: reverse, Time: uint64(9 * time.Second), Octets: 40, Flags: 16},
	}
	if err := s.Poll(); err != nil {
		t.Fatal(err)
	}
	r := allRecords(t, out)
	if len(r) != 1 || r[0][6][0] != 2 || binary.BigEndian.Uint16(r[0][7]) != 1234 {
		t.Fatal("directional merge")
	}
	*clock = uint64(12 * time.Second)
	m.packets = []Packet{{Key: key, Time: *clock, Octets: 40, Flags: 17}}
	if err := s.Poll(); err != nil {
		t.Fatal(err)
	}
	r = allRecords(t, out)
	if len(r) != 2 || binary.BigEndian.Uint16(r[1][7]) != 443 {
		t.Fatal("reverse expiration")
	}
	*clock = uint64(15 * time.Second)
	if err := s.Poll(); err != nil {
		t.Fatal(err)
	}
	r = allRecords(t, out)
	if len(r) != 3 || r[2][6][0] != 17 {
		t.Fatal("old flags leaked into next segment")
	}
}

func TestCapacityBurstExportsEveryFlow(t *testing.T) {
	s, m, out, clock, key := testService(t)
	s.config.MaxFlowsPerVeth = 8
	m.packets = nil
	for i := 0; i < 128; i++ {
		k := key
		k.SourcePort = uint16(1000 + i)
		m.packets = append(m.packets, Packet{Key: k, Time: uint64(i + 1), Octets: 28})
	}
	*clock = uint64(20 * time.Second)
	if err := s.Poll(); err != nil {
		t.Fatal(err)
	}
	records := allRecords(t, out)
	if len(records) != 128 || len(out.packets) >= 64 || len(s.interfaces[7].table.flows) != 0 {
		t.Fatalf("records=%d datagrams=%d active=%d", len(records), len(out.packets), len(s.interfaces[7].table.flows))
	}
	seen := make(map[uint16]bool)
	early := 0
	for _, r := range records {
		port := binary.BigEndian.Uint16(r[7])
		if seen[port] || binary.BigEndian.Uint64(r[2]) != 1 || binary.BigEndian.Uint64(r[1]) != 28 {
			t.Fatal("capacity lost or duplicated counters")
		}
		seen[port] = true
		if r[136][0] == 5 {
			early++
		}
	}
	if early != 120 {
		t.Fatalf("capacity expirations=%d", early)
	}
}

func TestCapacityEvictsLeastRecentlyUpdated(t *testing.T) {
	s, m, out, clock, key := testService(t)
	s.config.MaxFlowsPerVeth = 2
	a, b, c := key, key, key
	a.SourcePort = 1000
	b.SourcePort = 1001
	c.SourcePort = 1002
	m.packets = []Packet{{Key: a, Time: 1, Octets: 28}, {Key: b, Time: 2, Octets: 28},
		{Key: a, Time: 3, Octets: 28}, {Key: c, Time: 4, Octets: 28}}
	*clock = 5
	if err := s.Poll(); err != nil {
		t.Fatal(err)
	}
	r := allRecords(t, out)
	if len(r) != 1 || binary.BigEndian.Uint16(r[0][7]) != 1001 || r[0][136][0] != 5 {
		t.Fatal("wrong LRU eviction")
	}
}

func TestExportBackoffRetainsData(t *testing.T) {
	s, m, out, clock, _ := testService(t)
	out.fail = true
	if err := s.Poll(); err == nil {
		t.Fatal("export failure hidden")
	}
	if len(s.interfaces[7].pending) != 1 || s.retryDelay != time.Second {
		t.Fatal("pending data or backoff lost")
	}
	out.fail = false
	if err := s.Poll(); err == nil {
		t.Fatal("backoff should retain visible error")
	}
	*clock += uint64(time.Second)
	if err := s.Poll(); err != nil {
		t.Fatal(err)
	}
	if len(allRecords(t, out)) != 1 || len(s.interfaces[7].pending) != 0 {
		t.Fatal("retry lost data")
	}
	m.readErr = errors.New("read failure")
	if err := s.Poll(); err == nil || !strings.Contains(err.Error(), "read failure") {
		t.Fatal("capture error hidden")
	}
}

func TestPartialBatchFailureDoesNotReplayAcknowledgedRecords(t *testing.T) {
	s, m, out, clock, key := testService(t)
	m.packets = nil
	for i := 0; i < 30; i++ {
		k := key
		k.SourcePort = uint16(i + 1)
		m.packets = append(m.packets, Packet{Key: k, Time: 1, Octets: 28})
	}
	out.failAt = 3 // startup templates, then the first successful data batch, then fail.
	if err := s.Poll(); err == nil {
		t.Fatal("partial batch failure hidden")
	}
	acknowledged := len(allRecords(t, out))
	if acknowledged == 0 || acknowledged >= 30 || len(s.interfaces[7].pending) != 30-acknowledged {
		t.Fatal("partial acknowledgment")
	}
	out.failAt = 0
	*clock += uint64(time.Second)
	if err := s.Poll(); err != nil {
		t.Fatal(err)
	}
	r := allRecords(t, out)
	seen := make(map[uint16]bool)
	for _, record := range r {
		port := binary.BigEndian.Uint16(record[7])
		if seen[port] {
			t.Fatal("replayed accepted record")
		}
		seen[port] = true
	}
	if len(seen) != 30 || s.export.sequence != 30 {
		t.Fatal("partial recovery lost records")
	}
}

func TestRetirementAndRename(t *testing.T) {
	s, m, out, clock, key := testService(t)
	if err := s.Sync([]Interface{{Index: 7, Name: "new_name", Identity: "c1/n1"}}); err != nil || m.detached {
		t.Fatal("rename detached capture")
	}
	out.fail = true
	if err := s.Sync(nil); err == nil || !m.detached || m.closed {
		t.Fatal("retirement discarded unsent flows")
	}
	out.fail = false
	*clock += uint64(time.Second)
	if err := s.Poll(); err != nil || !m.closed || len(s.interfaces) != 0 {
		t.Fatal("retirement retry")
	}
	if len(allRecords(t, out)) != 1 {
		t.Fatal("retirement counters")
	}
	_ = key
}

func TestMeterLossAndQueueBound(t *testing.T) {
	s, m, _, clock, key := testService(t)
	m.losses[0] = 7
	if err := s.Poll(); err == nil || !strings.Contains(err.Error(), "ring_buffer_packets=7") {
		t.Fatal("capture losses hidden")
	}
	s.config.MaxFlowsPerVeth = 1
	o := s.interfaces[7]
	o.pending = make([]Record, s.pendingLimit())
	o.table.add(Packet{Key: key, Time: *clock, Octets: 28})
	k := key
	k.SourcePort++
	m.packets = []Packet{{Key: k, Time: *clock, Octets: 28}}
	s.nextRetry = s.now().Add(time.Hour)
	s.exportError = errors.New("offline")
	if err := s.Poll(); err == nil || !strings.Contains(err.Error(), "pending export queue full") {
		t.Fatal("overflow hidden")
	}
	if len(o.table.flows) != 1 || o.dropped != 1 || len(o.pending) != s.pendingLimit() {
		t.Fatal("memory bound or retained data lost")
	}
}

type deadlineConn struct {
	deadline time.Time
	closed   bool
}

func (c *deadlineConn) Read([]byte) (int, error) { return 0, errors.New("not used") }
func (c *deadlineConn) Write([]byte) (int, error) {
	time.Sleep(time.Until(c.deadline))
	return 0, context.DeadlineExceeded
}
func (c *deadlineConn) Close() error                       { c.closed = true; return nil }
func (c *deadlineConn) LocalAddr() net.Addr                { return &net.UDPAddr{} }
func (c *deadlineConn) RemoteAddr() net.Addr               { return &net.UDPAddr{} }
func (c *deadlineConn) SetDeadline(t time.Time) error      { c.deadline = t; return nil }
func (c *deadlineConn) SetReadDeadline(time.Time) error    { return nil }
func (c *deadlineConn) SetWriteDeadline(t time.Time) error { c.deadline = t; return nil }

func TestShutdownDeadlineAndIncompleteError(t *testing.T) {
	s, m, _, _, _ := testService(t)
	conn := &deadlineConn{}
	s.writer = &udpWriter{conn: conn}
	s.export.out = s.writer
	s.connect = func(context.Context) (net.Conn, error) { return conn, nil }
	start := time.Now()
	err := s.Close()
	if err == nil || !strings.Contains(err.Error(), "shutdown flush incomplete") || !m.closed || !conn.closed {
		t.Fatalf("shutdown did not report leftovers: %v", err)
	}
	if time.Since(start) > shutdownBudget+200*time.Millisecond {
		t.Fatal("shutdown exceeded total budget")
	}
}

func TestSocketRecreationAndBoundedBackoff(t *testing.T) {
	s, _, _, clock, _ := testService(t)
	bad := &deadlineConn{}
	client, server := net.Pipe()
	defer server.Close()
	s.writer = &udpWriter{conn: bad}
	s.export.out = s.writer
	attempts := 0
	s.connect = func(context.Context) (net.Conn, error) { attempts++; return nil, errors.New("reconnect refused") }
	if err := s.Poll(); err == nil || !bad.closed {
		t.Fatal("failed socket not closed")
	}
	if err := s.Poll(); err == nil || attempts != 0 {
		t.Fatal("retry ignored backoff")
	}
	for i := 0; i < 8; i++ {
		*clock += uint64(31 * time.Second)
		_ = s.Poll()
	}
	if s.retryDelay != 30*time.Second {
		t.Fatal("backoff not capped")
	}
	s.connect = func(context.Context) (net.Conn, error) { return client, nil }
	go func() {
		buffer := make([]byte, 4096)
		for {
			if _, err := server.Read(buffer); err != nil {
				return
			}
		}
	}()
	*clock += uint64(31 * time.Second)
	if err := s.Poll(); err != nil || s.retryDelay != 0 {
		t.Fatalf("reconnection failed: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
}

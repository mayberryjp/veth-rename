package flow

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"time"
)

const shutdownBudget = 2 * time.Second

type meter interface {
	Read() ([]Packet, error)
	Buffered() bool
	Losses() ([2]uint64, error)
	Detach() error
	Close() error
}

type observed struct {
	iface    Interface
	meter    meter
	table    flowTable
	pending  []Record
	losses   [2]uint64
	dropped  uint64
	retiring bool
}

type Service struct {
	config      Config
	export      exporter
	interfaces  map[int]*observed
	attach      func(Interface, meterOptions) (meter, error)
	options     meterOptions
	clock       func() (uint64, error)
	now         func() time.Time
	connect     func(context.Context) (net.Conn, error)
	writer      *udpWriter
	retryDelay  time.Duration
	nextRetry   time.Time
	exportError error
}

type udpWriter struct {
	conn     net.Conn
	deadline time.Time
}

func (w *udpWriter) Write(b []byte) (int, error) {
	if w.conn == nil {
		return 0, fmt.Errorf("IPFIX socket is not connected")
	}
	deadline := time.Now().Add(100 * time.Millisecond)
	if !w.deadline.IsZero() && w.deadline.Before(deadline) {
		deadline = w.deadline
	}
	if !deadline.After(time.Now()) {
		return 0, context.DeadlineExceeded
	}
	if err := w.conn.SetWriteDeadline(deadline); err != nil {
		return 0, err
	}
	return w.conn.Write(b)
}

func New(ctx context.Context, c Config) (*Service, error) {
	if err := platformReady(); err != nil {
		return nil, err
	}
	dialer := net.Dialer{Timeout: 5 * time.Second}
	conn, err := dialer.DialContext(ctx, "udp", c.Collector)
	if err != nil {
		return nil, fmt.Errorf("connect IPFIX collector: %w", err)
	}
	remote, ok := conn.RemoteAddr().(*net.UDPAddr)
	if !ok {
		return nil, errors.Join(fmt.Errorf("collector has no UDP address"), conn.Close())
	}
	options := meterOptions{samplingRate: c.SamplingRate, filter: captureFilters[c.CaptureFilter]}
	options.collector.DestinationPort = uint16(remote.Port)
	if ip := remote.IP.To4(); ip != nil {
		options.collector.Family = 4
		copy(options.collector.Destination[:], ip)
	} else {
		options.collector.Family = 6
		copy(options.collector.Destination[:], remote.IP.To16())
	}
	mono, err := monotonic()
	if err != nil {
		return nil, errors.Join(err, conn.Close())
	}
	s := &Service{config: c, interfaces: make(map[int]*observed), attach: attachMeter,
		options: options, clock: monotonic, now: time.Now, writer: &udpWriter{conn: conn}}
	// Preserve the resolved destination across retries so capture exclusion stays exact.
	s.connect = func(ctx context.Context) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "udp", remote.String())
	}
	s.export = exporter{out: s.writer, domain: c.ObservationDomainID,
		bootUnixNS: time.Now().UnixNano() - int64(mono), refresh: c.refresh, samplingRate: c.SamplingRate}
	if err := s.export.send(nil, time.Now()); err != nil {
		return nil, errors.Join(err, conn.Close())
	}
	return s, nil
}

func (s *Service) PollInterval() time.Duration { return s.config.poll }

func (s *Service) indices() []int {
	indices := make([]int, 0, len(s.interfaces))
	for index := range s.interfaces {
		indices = append(indices, index)
	}
	sort.Ints(indices)
	return indices
}

func (s *Service) pendingLimit() int { return max(4096, int(s.config.MaxFlowsPerVeth)) }

func (s *Service) expire(o *observed, f *activeFlow, reason uint8) bool {
	if len(o.pending) >= s.pendingLimit() {
		return false
	}
	o.pending = append(o.pending, Record{Key: f.key, Counters: f.counters, Interface: o.iface, Reason: reason})
	o.table.remove(f)
	return true
}

func (s *Service) expireDue(o *observed, mono uint64, forced uint8, deadline time.Time) {
	for o.table.due.Len() > 0 && time.Now().Before(deadline) {
		f := o.table.due.entries[0]
		reason := forced
		if reason == 0 {
			if o.table.due.time(f) > mono {
				break
			}
			reason = 2
			if f.counters.Last+uint64(s.config.idle) <= mono {
				reason = 1
			}
		}
		if !s.expire(o, f, reason) {
			break
		}
	}
}

func (s *Service) ingest(o *observed, deadline time.Time) error {
	packets, readErr := o.meter.Read()
	droppedBefore := o.dropped
	for _, p := range packets {
		// Use packet timestamps for expiry before merging, not the later polling time.
		s.expireDue(o, p.Time, 0, deadline)
		if _, exists := o.table.flows[p.Key]; !exists && uint32(len(o.table.flows)) >= s.config.MaxFlowsPerVeth {
			if !s.expire(o, o.table.recent.entries[0], 5) {
				o.dropped++
				continue
			}
		}
		o.table.add(p)
	}
	mono, err := s.clock()
	if err == nil {
		force := uint8(0)
		if o.retiring {
			force = 4
		}
		s.expireDue(o, mono, force, deadline)
	}
	losses, lossErr := o.meter.Losses()
	if lossErr == nil && losses != o.losses {
		o.losses = losses
		lossErr = fmt.Errorf("eBPF metering loss on %s: ring_buffer_packets=%d unsupported_or_malformed_ip_packets=%d; exports are incomplete",
			o.iface.Name, losses[0], losses[1])
	}
	var capacityErr error
	if o.dropped != droppedBefore {
		capacityErr = fmt.Errorf("metering loss on %s: pending export queue full; rejected_packets=%d; exports are incomplete", o.iface.Name, o.dropped)
	}
	return errors.Join(readErr, err, lossErr, capacityErr)
}

func (s *Service) failExport(err error) error {
	s.retryDelay = min(max(time.Second, s.retryDelay*2), 30*time.Second)
	s.nextRetry = s.now().Add(s.retryDelay)
	if s.writer != nil && s.writer.conn != nil {
		err = errors.Join(err, s.writer.conn.Close())
		s.writer.conn = nil
	}
	s.exportError = err
	return err
}

func (s *Service) exportPending(deadline time.Time, force bool) error {
	if !force && s.now().Before(s.nextRetry) {
		return s.exportError
	}
	if s.writer != nil {
		s.writer.deadline = deadline
		if s.writer.conn == nil {
			ctx, cancel := context.WithDeadline(context.Background(), minTime(deadline, time.Now().Add(100*time.Millisecond)))
			conn, err := s.connect(ctx)
			cancel()
			if err != nil {
				return s.failExport(fmt.Errorf("reconnect IPFIX collector: %w", err))
			}
			s.writer.conn = conn
			s.export.lastTemplate = time.Time{}
			s.export.sequence = 0
		}
	}
	for _, index := range s.indices() {
		o := s.interfaces[index]
		n, err := s.export.sendAcknowledged(o.pending, s.now())
		for i := 0; i < n; i++ {
			o.pending[i] = Record{}
		}
		o.pending = o.pending[n:]
		if len(o.pending) == 0 {
			o.pending = nil
		}
		if err != nil {
			return s.failExport(err)
		}
	}
	if err := s.export.send(nil, s.now()); err != nil {
		return s.failExport(err)
	}
	s.nextRetry = time.Time{}
	s.retryDelay = 0
	s.exportError = nil
	return nil
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func (s *Service) cleanup() error {
	var errs []error
	for index, o := range s.interfaces {
		if o.retiring && len(o.table.flows) == 0 && len(o.pending) == 0 && !o.meter.Buffered() {
			errs = append(errs, o.meter.Close())
			delete(s.interfaces, index)
		}
	}
	return errors.Join(errs...)
}

func (s *Service) Sync(interfaces []Interface) error {
	wanted := make(map[int]Interface)
	for _, iface := range interfaces {
		wanted[iface.Index] = iface
	}
	var errs []error
	for index, o := range s.interfaces {
		if iface, ok := wanted[index]; !ok || iface.Identity != o.iface.Identity {
			if !o.retiring {
				errs = append(errs, o.meter.Detach())
				o.retiring = true
			}
		}
	}
	// Drain retired endpoints before allowing an ifindex to be reused.
	needsDrain := false
	for _, o := range s.interfaces {
		needsDrain = needsDrain || o.retiring
	}
	if needsDrain {
		errs = append(errs, s.Poll())
	}
	for _, iface := range interfaces {
		if o, ok := s.interfaces[iface.Index]; ok {
			if !o.retiring {
				o.iface = iface
			}
			continue
		}
		m, err := s.attach(iface, s.options)
		if err != nil {
			errs = append(errs, fmt.Errorf("monitor %s: %w", iface.Name, err))
			continue
		}
		s.interfaces[iface.Index] = &observed{iface: iface, meter: m, table: newTable(s.config)}
	}
	return errors.Join(errs...)
}

func (s *Service) Poll() error {
	deadline := time.Now().Add(shutdownBudget)
	var errs []error
	// Retry old data first to make room, but continue metering through export outages.
	errs = append(errs, s.exportPending(deadline, false))
	for _, index := range s.indices() {
		errs = append(errs, s.ingest(s.interfaces[index], deadline))
	}
	errs = append(errs, s.exportPending(deadline, false), s.cleanup())
	return errors.Join(errs...)
}

func (s *Service) Close() error {
	deadline := time.Now().Add(shutdownBudget)
	var errs []error
	for _, o := range s.interfaces {
		errs = append(errs, o.meter.Detach())
		o.retiring = true
	}
	for time.Now().Before(deadline) && len(s.interfaces) > 0 {
		for _, index := range s.indices() {
			if !time.Now().Before(deadline) {
				break
			}
			errs = append(errs, s.ingest(s.interfaces[index], deadline))
		}
		err := s.exportPending(deadline, true)
		errs = append(errs, err, s.cleanup())
		if err != nil {
			break
		}
	}
	for _, o := range s.interfaces {
		errs = append(errs, fmt.Errorf("shutdown flush incomplete on %s: pending_records=%d active_flows=%d buffered_events=%t",
			o.iface.Name, len(o.pending), len(o.table.flows), o.meter.Buffered()), o.meter.Close())
	}
	s.interfaces = make(map[int]*observed)
	if s.writer != nil && s.writer.conn != nil {
		errs = append(errs, s.writer.conn.Close())
		s.writer.conn = nil
	}
	return errors.Join(errs...)
}

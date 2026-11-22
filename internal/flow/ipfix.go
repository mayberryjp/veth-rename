package flow

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"syscall"
	"time"
)

// RFC 7011 section 10.3.3: conservative size when path MTU is unknown.
const defaultMaxMessageSize = 464

type field struct {
	id, length uint16
}

func fields(family uint8) []field {
	source, destination, length := uint16(8), uint16(12), uint16(4)
	if family == 6 {
		source, destination, length = 27, 28, 16
	}
	return []field{
		{source, length}, {destination, length},
		{7, 2}, {11, 2}, {4, 1},
		{5, 1}, {6, 1}, // ipClassOfService, tcpControlBits
		{2, 8}, {1, 8},
		{152, 8}, {153, 8},
		{34, 4}, {35, 1}, // samplingInterval, samplingAlgorithm
		{138, 8}, // observationPointId: host veth ifindex
		{82, 16}, // interfaceName, zero-padded UTF-8
		{136, 1}, // flowEndReason
	}
}

func put16(b []byte, v uint16) []byte {
	return binary.BigEndian.AppendUint16(b, v)
}

func put64(b []byte, v uint64) []byte {
	return binary.BigEndian.AppendUint64(b, v)
}

func templateID(family uint8) uint16 {
	if family == 6 {
		return 257
	}
	return 256
}

func templates() []byte {
	set := put16(nil, 2)
	set = put16(set, 0)
	for _, family := range []uint8{4, 6} {
		fs := fields(family)
		set = put16(set, templateID(family))
		set = put16(set, uint16(len(fs)))
		for _, f := range fs {
			set = put16(set, f.id)
			set = put16(set, f.length)
		}
	}
	binary.BigEndian.PutUint16(set[2:4], uint16(len(set)))
	return set
}

func encodeRecord(r Record, bootUnixNS int64, samplingRate uint32) ([]byte, error) {
	if r.Family != 4 && r.Family != 6 {
		return nil, fmt.Errorf("unsupported IPFIX address family %d", r.Family)
	}
	n := 4
	if r.Family == 6 {
		n = 16
	}
	b := append([]byte{}, r.Source[:n]...)
	b = append(b, r.Destination[:n]...)
	b = put16(b, r.SourcePort)
	b = put16(b, r.DestinationPort)
	b = append(b, r.Protocol)
	b = append(b, r.TOS, r.TCPFlags())
	b = put64(b, r.Packets)
	b = put64(b, r.Octets)
	for _, ns := range []uint64{r.First, r.Last} {
		ms := uint64(0)
		if ns != 0 {
			ms = uint64((bootUnixNS + int64(ns)) / int64(time.Millisecond))
		}
		b = put64(b, ms)
	}
	b = binary.BigEndian.AppendUint32(b, samplingRate)
	b = append(b, 1)
	b = put64(b, uint64(r.Interface.Index))
	var name [16]byte
	copy(name[:], r.Interface.Name)
	b = append(b, name[:]...)
	return append(b, r.Reason), nil
}

type exporter struct {
	out              io.Writer
	domain, sequence uint32
	bootUnixNS       int64
	refresh          time.Duration
	lastTemplate     time.Time
	samplingRate     uint32
	maxMessageSize   int
	messageLimit     int
	pathMTUBudget    int
	pathBudget       func() (int, error)
	refreshPackets   uint32
	dataMessages     uint32
	now              func() time.Time
}

func minimumMessageSize() int { return 16 + len(templates()) }

func paddedSize(n int) int { return (n + 3) &^ 3 }

func (e *exporter) limit() int {
	configured := e.maxMessageSize
	if configured == 0 {
		configured = defaultMaxMessageSize
	}
	if e.messageLimit != 0 {
		return min(configured, e.messageLimit)
	}
	return configured
}

func (e *exporter) refreshPathBudget() error {
	if e.pathBudget == nil {
		return nil
	}
	budget, err := e.pathBudget()
	if err != nil {
		return fmt.Errorf("query IPFIX path MTU: %w", err)
	}
	if budget <= 0 {
		return fmt.Errorf("invalid IPFIX path MTU budget %d", budget)
	}
	if e.limit() < minimumMessageSize() && e.pathMTUBudget != 0 && budget > e.pathMTUBudget {
		e.messageLimit = budget
	} else {
		e.messageLimit = min(e.limit(), budget)
	}
	e.pathMTUBudget = budget
	if e.limit() < minimumMessageSize() {
		return fmt.Errorf("IPFIX path budget %d cannot carry the %d-byte templates", e.limit(), minimumMessageSize())
	}
	return nil
}

func (e *exporter) reduceMessageSize(err error) error {
	if !errors.Is(err, syscall.EMSGSIZE) {
		return err
	}
	old := e.limit()
	reduced := old / 2
	var queryErr error
	if e.pathBudget != nil {
		var budget int
		budget, queryErr = e.pathBudget()
		if queryErr == nil && budget > 0 {
			e.pathMTUBudget = budget
			if budget < old {
				reduced = budget
			}
		} else if queryErr == nil {
			queryErr = fmt.Errorf("invalid IPFIX path MTU budget %d", budget)
		}
	}
	// Retain the smaller limit across socket recreation; never retry the same oversized batch.
	e.messageLimit = reduced
	return errors.Join(err, queryErr, fmt.Errorf("IPFIX message budget reduced from %d to %d bytes after EMSGSIZE", old, reduced))
}

func (e *exporter) message(set []byte, count uint32, now time.Time) error {
	if 16+len(set) > e.limit() {
		return fmt.Errorf("IPFIX message needs %d bytes but its budget is %d", 16+len(set), e.limit())
	}
	b := put16(nil, 10)
	b = put16(b, uint16(16+len(set)))
	b = binary.BigEndian.AppendUint32(b, uint32(now.Unix()))
	b = binary.BigEndian.AppendUint32(b, e.sequence)
	b = binary.BigEndian.AppendUint32(b, e.domain)
	b = append(b, set...)
	n, err := e.out.Write(b)
	if err != nil {
		return fmt.Errorf("send IPFIX UDP message: %w", e.reduceMessageSize(err))
	}
	if n != len(b) {
		return io.ErrShortWrite
	}
	e.sequence += count
	return nil
}

func (e *exporter) refreshTemplates(now time.Time) error {
	if !e.lastTemplate.IsZero() && now.Sub(e.lastTemplate) < e.refresh &&
		(e.refreshPackets == 0 || e.dataMessages < e.refreshPackets) {
		return nil
	}
	if err := e.message(templates(), 0, now); err != nil {
		return err
	}
	e.lastTemplate = now
	e.dataMessages = 0
	return nil
}

func (e *exporter) send(records []Record, now time.Time) error {
	_, err := e.sendAcknowledged(records, now)
	return err
}

func (e *exporter) sendAcknowledged(records []Record, now time.Time) (int, error) {
	for _, record := range records {
		if record.Family != 4 && record.Family != 6 {
			return 0, fmt.Errorf("unsupported IPFIX address family %d", record.Family)
		}
	}
	if err := e.refreshTemplates(now); err != nil {
		return 0, err
	}
	sent := 0
	for sent < len(records) {
		var body []byte
		var count uint32
		for sent+int(count) < len(records) {
			family := records[sent+int(count)].Family
			set := put16(nil, templateID(family))
			set = put16(set, 0)
			start := count
			for _, record := range records[sent+int(count):] {
				if record.Family != family {
					break
				}
				b, err := encodeRecord(record, e.bootUnixNS, e.samplingRate)
				if err != nil {
					return sent, err
				}
				if 16+len(body)+paddedSize(len(set)+len(b)) > e.limit() {
					break
				}
				set = append(set, b...)
				count++
			}
			if count == start {
				break
			}
			set = append(set, make([]byte, paddedSize(len(set))-len(set))...)
			binary.BigEndian.PutUint16(set[2:4], uint16(len(set)))
			body = append(body, set...)
		}
		if count == 0 {
			return sent, fmt.Errorf("IPFIX record exceeds message budget")
		}
		sentAt := now
		if e.now != nil {
			sentAt = e.now()
		}
		if err := e.refreshTemplates(sentAt); err != nil {
			return sent, err
		}
		if err := e.message(body, count, sentAt); err != nil {
			return sent, err
		}
		e.dataMessages++
		sent += int(count)
	}
	return sent, nil
}

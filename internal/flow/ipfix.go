package flow

import (
	"encoding/binary"
	"fmt"
	"io"
	"time"
)

// RFC 7011 section 10.3.3: conservative size when path MTU is unknown.
const maxMessage = 464

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
}

func (e *exporter) message(set []byte, count uint32, now time.Time) error {
	body := templates()
	body = append(body, set...)
	b := put16(nil, 10)
	b = put16(b, uint16(16+len(body)))
	b = binary.BigEndian.AppendUint32(b, uint32(now.Unix()))
	b = binary.BigEndian.AppendUint32(b, e.sequence)
	b = binary.BigEndian.AppendUint32(b, e.domain)
	b = append(b, body...)
	if len(b) > maxMessage {
		return fmt.Errorf("IPFIX message exceeds maximum size")
	}
	n, err := e.out.Write(b)
	if err != nil {
		return fmt.Errorf("send IPFIX UDP message: %w", err)
	}
	if n != len(b) {
		return io.ErrShortWrite
	}
	e.sequence += count
	e.lastTemplate = now
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
	if len(records) == 0 {
		if e.lastTemplate.IsZero() || now.Sub(e.lastTemplate) >= e.refresh {
			return 0, e.message(nil, 0, now)
		}
		return 0, nil
	}
	sent := 0
	for sent < len(records) {
		family := records[sent].Family
		set := put16(nil, templateID(family))
		set = put16(set, 0)
		var count uint32
		for _, record := range records[sent:] {
			if record.Family != family {
				break
			}
			b, err := encodeRecord(record, e.bootUnixNS, e.samplingRate)
			if err != nil {
				return sent, err
			}
			if 16+len(templates())+len(set)+len(b)+3 > maxMessage {
				break
			}
			set = append(set, b...)
			count++
		}
		if count == 0 {
			return sent, fmt.Errorf("IPFIX record exceeds message budget")
		}
		for len(set)%4 != 0 {
			set = append(set, 0)
		}
		binary.BigEndian.PutUint16(set[2:4], uint16(len(set)))
		if err := e.message(set, count, now); err != nil {
			return sent, err
		}
		sent += int(count)
	}
	return sent, nil
}

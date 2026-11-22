package flow

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
	"time"
)

type datagrams struct {
	packets          [][]byte
	fail             bool
	failAt, attempts int
}

func (d *datagrams) Write(b []byte) (int, error) {
	d.attempts++
	if d.fail || d.failAt == d.attempts {
		return 0, errors.New("collector unavailable")
	}
	d.packets = append(d.packets, append([]byte(nil), b...))
	return len(b), nil
}

func decodeTemplates(t *testing.T, b []byte) map[uint16][]field {
	t.Helper()
	if len(b) < 20 || binary.BigEndian.Uint16(b[16:18]) != 2 {
		t.Fatal("every message must begin with Template Set 2")
	}
	end := 16 + int(binary.BigEndian.Uint16(b[18:20]))
	if end > len(b) || end < 20 {
		t.Fatal("invalid Template Set length")
	}
	result := make(map[uint16][]field)
	for offset := 20; offset < end; {
		if offset+4 > end {
			t.Fatal("truncated template")
		}
		id := binary.BigEndian.Uint16(b[offset : offset+2])
		count := int(binary.BigEndian.Uint16(b[offset+2 : offset+4]))
		offset += 4
		for i := 0; i < count; i++ {
			if offset+4 > end {
				t.Fatal("truncated field")
			}
			f := field{id: binary.BigEndian.Uint16(b[offset : offset+2]),
				length: binary.BigEndian.Uint16(b[offset+2 : offset+4])}
			offset += 4
			if f.id&0x8000 != 0 || f.id == 239 {
				t.Fatal("unexpected biflow IE")
			}
			result[id] = append(result[id], f)
		}
	}
	if len(result) != 2 || len(result[256]) != 16 || len(result[257]) != 16 {
		t.Fatalf("both directional templates must be included: %+v", result)
	}
	return result
}

func decodeRecords(t *testing.T, b []byte) []map[uint16][]byte {
	t.Helper()
	ts := decodeTemplates(t, b)
	var records []map[uint16][]byte
	for offset := 16 + int(binary.BigEndian.Uint16(b[18:20])); offset < len(b); {
		if offset+4 > len(b) {
			t.Fatal("truncated Set header")
		}
		id := binary.BigEndian.Uint16(b[offset : offset+2])
		end := offset + int(binary.BigEndian.Uint16(b[offset+2:offset+4]))
		fs, ok := ts[id]
		if !ok || end > len(b) || end < offset+4 {
			t.Fatal("invalid Data Set")
		}
		width := 0
		for _, f := range fs {
			width += int(f.length)
		}
		offset += 4
		for end-offset >= width {
			record := make(map[uint16][]byte)
			for _, f := range fs {
				record[f.id] = b[offset : offset+int(f.length)]
				offset += int(f.length)
			}
			records = append(records, record)
		}
		if end-offset > 3 || !bytes.Equal(b[offset:end], make([]byte, end-offset)) {
			t.Fatal("invalid zero Set padding")
		}
		offset = end
	}
	return records
}

func singleRecord(t *testing.T, b []byte) map[uint16][]byte {
	t.Helper()
	records := decodeRecords(t, b)
	if len(records) != 1 {
		t.Fatalf("expected one record, got %d", len(records))
	}
	return records[0]
}

func TestIPFIXWire(t *testing.T) {
	now := time.Unix(1700000000, 0)
	out := &datagrams{}
	e := exporter{out: out, domain: 42, refresh: time.Minute, bootUnixNS: now.UnixNano(), samplingRate: 4}
	r := Record{Key: Key{Source: [16]byte{10, 0, 0, 1}, Destination: [16]byte{10, 0, 0, 2},
		SourcePort: 1234, DestinationPort: 443, Protocol: 6, Family: 4, TOS: 0xb8},
		Interface: Interface{Index: 7, Name: "veth_app"}, Reason: 2,
		Counters: Counters{Packets: 11, Octets: 1100, First: 1000000, Last: 2000000, FlagCounts: [8]uint64{1, 1, 0, 0, 2}}}
	ip6 := r
	ip6.Family = 6
	ip6.Source, ip6.Destination = [16]byte{0x20, 1, 0xd, 0xb8, 0, 1}, [16]byte{0x20, 1, 0xd, 0xb8, 0, 2}
	if err := e.send([]Record{r, ip6}, now); err != nil {
		t.Fatal(err)
	}
	if len(out.packets) != 2 || e.sequence != 2 {
		t.Fatalf("messages=%d sequence=%d", len(out.packets), e.sequence)
	}
	for i, b := range out.packets {
		if len(b)+48 > 512 || int(binary.BigEndian.Uint16(b[2:4])) != len(b) ||
			binary.BigEndian.Uint16(b[:2]) != 10 ||
			binary.BigEndian.Uint32(b[4:8]) != uint32(now.Unix()) ||
			binary.BigEndian.Uint32(b[8:12]) != uint32(i) ||
			binary.BigEndian.Uint32(b[12:16]) != 42 {
			t.Fatal("invalid IPFIX message header")
		}
		ts := decodeTemplates(t, b)
		for id, fs := range ts {
			wantIDs := []uint16{8, 12, 7, 11, 4, 5, 6, 2, 1, 152, 153, 34, 35, 138, 82, 136}
			if id == 257 {
				wantIDs[0], wantIDs[1] = 27, 28
			}
			for j, f := range fs {
				if f.id != wantIDs[j] {
					t.Fatalf("wrong field order: %+v", fs)
				}
			}
		}
		got := singleRecord(t, b)
		for id, want := range map[uint16]uint64{2: 11, 1: 1100, 138: 7, 152: 1700000000001, 153: 1700000000002} {
			if binary.BigEndian.Uint64(got[id]) != want {
				t.Fatalf("IE %d: %x", id, got[id])
			}
		}
		if got[5][0] != 0xb8 || got[6][0] != 0x13 || got[35][0] != 1 ||
			binary.BigEndian.Uint32(got[34]) != 4 || got[136][0] != 2 ||
			string(bytes.TrimRight(got[82], "\x00")) != "veth_app" {
			t.Fatal("packet metadata encoding")
		}
	}
	if err := e.send(nil, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if len(out.packets) != 3 || e.sequence != 2 || len(decodeRecords(t, out.packets[2])) != 0 {
		t.Fatal("idle template refresh must not advance sequence")
	}
}

func TestIPFIXFailureAndSequenceWrap(t *testing.T) {
	out := &datagrams{fail: true}
	e := exporter{out: out, sequence: ^uint32(0), refresh: time.Minute, samplingRate: 1}
	r := Record{Key: Key{Family: 4}}
	now := time.Now()
	if err := e.send([]Record{r}, now); err == nil || !e.lastTemplate.IsZero() || e.sequence != ^uint32(0) {
		t.Fatal("failed write committed exporter state")
	}
	out.fail = false
	if err := e.send([]Record{r}, now); err != nil || e.sequence != 0 {
		t.Fatalf("wrap: %v", err)
	}
	got := singleRecord(t, out.packets[0])
	if binary.BigEndian.Uint64(got[152]) != 0 || binary.BigEndian.Uint64(got[153]) != 0 {
		t.Fatal("zero timestamps must still occupy eight bytes")
	}
	if err := e.send([]Record{{Key: Key{Family: 5}}}, now); err == nil {
		t.Fatal("invalid family accepted")
	}
}

func TestIPFIXBatchBounds(t *testing.T) {
	out := &datagrams{}
	e := exporter{out: out, refresh: time.Minute, samplingRate: 1}
	records := make([]Record, 100)
	for i := range records {
		records[i].Family = 6
	}
	if err := e.send(records, time.Now()); err != nil {
		t.Fatal(err)
	}
	total := 0
	for _, b := range out.packets {
		if len(b) > maxMessage {
			t.Fatalf("oversized message: %d", len(b))
		}
		if binary.BigEndian.Uint32(b[8:12]) != uint32(total) {
			t.Fatal("sequence must count records")
		}
		total += len(decodeRecords(t, b))
	}
	if e.sequence != 100 || total != 100 {
		t.Fatal("batching lost or duplicated records")
	}
}

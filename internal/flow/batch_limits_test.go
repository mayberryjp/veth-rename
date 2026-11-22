package flow

import (
	"encoding/binary"
	"strconv"
	"testing"
	"time"
)

func TestConfiguredByteLimits(t *testing.T) {
	for _, limit := range []int{156, 161, 176, 324, 464, 1200, 65507} {
		t.Run(strconv.Itoa(limit), func(t *testing.T) {
			out := &datagrams{}
			e := exporter{out: out, refresh: time.Minute, refreshPackets: 20, maxMessageSize: limit}
			records := make([]Record, 2000)
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
			var decoder recordDecoder
			total := 0
			for _, b := range out.packets {
				if len(b) > limit || int(binary.BigEndian.Uint16(b[2:4])) != len(b) ||
					binary.BigEndian.Uint32(b[8:12]) != uint32(total) {
					t.Fatalf("invalid boundary or sequence: size=%d limit=%d", len(b), limit)
				}
				for _, r := range decoder.decode(t, b) {
					total++
					if binary.BigEndian.Uint16(r[7]) != uint16(total) {
						t.Fatal("configured byte limit changed FIFO order")
					}
				}
			}
			if total != len(records) {
				t.Fatal("configured byte limit lost records")
			}
		})
	}
}

func TestTimedTemplateRefreshWithinOneBatch(t *testing.T) {
	start := time.Unix(1700000000, 0)
	now := start
	out := &datagrams{}
	e := exporter{out: out, refresh: 30 * time.Second, maxMessageSize: minimumMessageSize(),
		now: func() time.Time { now = now.Add(10 * time.Second); return now }}
	records := []Record{{Key: Key{Family: 4}}, {Key: Key{Family: 4}}, {Key: Key{Family: 4}}}
	if err := e.send(records, start); err != nil {
		t.Fatal(err)
	}
	if len(out.packets) != 5 || !e.lastTemplate.Equal(start.Add(30*time.Second)) || len(allRecords(t, out)) != 3 {
		t.Fatal("long batch delayed time-based template refresh")
	}
}

package firewall

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"
)

func analysisRecord(when time.Time, sourcePort, length int) string {
	return fmt.Sprintf("%s host veth-renamer[123]: DROP IF=\"veth app\" DIR=ingress SRC=10.0.0.1 DST=203.0.113.1 PROTO=6 SPT=%d DPT=443 LEN=%d RULE=\"deny\\nquoted\\\"\" REASON=rule-deny TIME=%s\n",
		when.Format(time.Stamp), sourcePort, length, when.Format(time.RFC3339Nano))
}

func TestAnalyzeDropsWindowAggregationAndRanking(t *testing.T) {
	now := time.Date(2026, 1, 2, 12, 0, 0, 0, time.UTC)
	input := analysisRecord(now.Add(-time.Hour), 40000, 40) +
		analysisRecord(now.Add(-24*time.Hour), 50000, 60) +
		analysisRecord(now.Add(-25*time.Hour), 50001, 70) +
		analysisRecord(now.Add(-7*24*time.Hour), 50002, 80) +
		analysisRecord(now.Add(-7*24*time.Hour-time.Second), 50003, 90) +
		analysisRecord(now.Add(time.Second), 50004, 100)
	other := strings.ReplaceAll(analysisRecord(now, 123, 500), "DPT=443", "DPT=80")
	input += other
	for _, tc := range []struct {
		window          time.Duration
		packets, octets uint64
	}{{24 * time.Hour, 2, 100}, {7 * 24 * time.Hour, 4, 250}} {
		rows, err := AnalyzeDrops(strings.NewReader(input), now, tc.window, "packets")
		if err != nil || len(rows) != 2 {
			t.Fatalf("analysis: %+v %v", rows, err)
		}
		if rows[0].DestinationPort != 443 || rows[0].Packets != tc.packets || rows[0].Bytes != tc.octets ||
			rows[0].Rule != "deny\nquoted\"" || rows[0].Interface != "veth app" ||
			!rows[0].LastSeen.Equal(now.Add(-time.Hour)) {
			t.Fatalf("wrong aggregate: %+v", rows[0])
		}
		rows, err = AnalyzeDrops(strings.NewReader(input), now, tc.window, "bytes")
		if err != nil || rows[0].DestinationPort != 80 || rows[0].Bytes != 500 {
			t.Fatalf("byte ranking: %+v %v", rows, err)
		}
		var out bytes.Buffer
		if err := WriteDropSummary(&out, rows, now); err != nil {
			t.Fatal(err)
		}
		if strings.Count(out.String(), "\n") != 3 || !strings.Contains(out.String(), `"deny\nquoted\""`) {
			t.Fatalf("unsafe or missing output: %q", out.String())
		}
	}
}

func TestAnalyzeDropsLastSeenOutOfOrder(t *testing.T) {
	now := time.Date(2026, 1, 2, 12, 0, 0, 0, time.UTC)
	latest := now.Add(-time.Minute + 123456789*time.Nanosecond)
	input := analysisRecord(latest.In(time.FixedZone("UTC+9", 9*60*60)), 40000, 40) +
		analysisRecord(now.Add(-10*time.Minute), 50000, 60) +
		analysisRecord(now.Add(-5*time.Minute), 50001, 70) +
		analysisRecord(now.Add(time.Second), 50002, 80)
	rows, err := AnalyzeDrops(strings.NewReader(input), now, 20*time.Minute, "packets")
	if err != nil || len(rows) != 1 {
		t.Fatalf("analysis: %+v %v", rows, err)
	}
	if rows[0].Packets != 3 || rows[0].Bytes != 170 || !rows[0].LastSeen.Equal(latest) {
		t.Fatalf("incorrect last seen or aggregate: %+v", rows[0])
	}
	var out bytes.Buffer
	if err := WriteDropSummary(&out, rows, now); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 2 || !strings.HasSuffix(lines[0], "LAST_SEEN") ||
		!strings.HasSuffix(lines[1], "0 minutes ago") {
		t.Fatalf("missing or incorrect last seen column: %q", out.String())
	}
}

func TestWriteDropSummaryRelativeLastSeen(t *testing.T) {
	now := time.Date(2026, 1, 2, 0, 5, 0, 0, time.UTC)
	for _, tc := range []struct {
		age  time.Duration
		want string
	}{
		{0, "0 minutes ago"},
		{59 * time.Second, "0 minutes ago"},
		{time.Minute, "1 minute ago"},
		{119 * time.Second, "1 minute ago"},
		{2 * time.Minute, "2 minutes ago"},
		{65 * time.Minute, "65 minutes ago"},
	} {
		t.Run(tc.want+"/"+tc.age.String(), func(t *testing.T) {
			lastSeen := now.Add(-tc.age).In(time.FixedZone("JST", 9*60*60))
			var out bytes.Buffer
			if err := WriteDropSummary(&out, []DropSummary{{LastSeen: lastSeen}}, now); err != nil {
				t.Fatal(err)
			}
			if !strings.HasSuffix(out.String(), tc.want+"\n") {
				t.Fatalf("incorrect relative last seen: %q", out.String())
			}
		})
	}
}

func TestAnalyzeDropsNormalizesReturnTraffic(t *testing.T) {
	now := time.Date(2026, 1, 2, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name, source, destination, direction, reverseDirection string
		protocol                                               int
	}{
		{"tcp-ingress", "10.0.0.1", "203.0.113.1", "ingress", "egress", 6},
		{"tcp-egress", "10.0.0.1", "203.0.113.1", "egress", "ingress", 6},
		{"udp-ipv6", "2001:db8::1", "2001:db8::2", "ingress", "egress", 17},
	} {
		t.Run(tc.name, func(t *testing.T) {
			record := func(source, destination, direction string, sourcePort, destinationPort, length int) string {
				return fmt.Sprintf("%s host veth-renamer[123]: WOULD_DROP IF=\"app\" DIR=%s SRC=%s DST=%s PROTO=%d SPT=%d DPT=%d LEN=%d RULE=\"default\" REASON=default-deny TIME=%s\n",
					now.Format(time.Stamp), direction, source, destination, tc.protocol, sourcePort, destinationPort, length, now.Format(time.RFC3339Nano))
			}
			input := record(tc.source, tc.destination, tc.direction, 40000, 443, 40) +
				record(tc.destination, tc.source, tc.reverseDirection, 443, 40000, 60) +
				record(tc.source, tc.destination, tc.direction, 50000, 443, 50) +
				record(tc.destination, tc.source, tc.reverseDirection, 443, 50000, 70)
			for _, sortBy := range []string{"packets", "bytes"} {
				rows, err := AnalyzeDrops(strings.NewReader(input), now, time.Hour, sortBy)
				if err != nil || len(rows) != 1 {
					t.Fatalf("analysis: %+v %v", rows, err)
				}
				row := rows[0]
				if row.Source != tc.source || row.Destination != tc.destination || row.DestinationPort != 443 ||
					row.Direction != tc.direction || row.Protocol != uint16(tc.protocol) || row.Packets != 4 || row.Bytes != 220 {
					t.Fatalf("incorrect normalized aggregate: %+v", row)
				}
			}
			rows, err := AnalyzeDrops(strings.NewReader(record(tc.destination, tc.source, tc.reverseDirection, 443, 60000, 80)), now, time.Hour, "packets")
			if err != nil || len(rows) != 1 || rows[0].Source != tc.source || rows[0].Destination != tc.destination ||
				rows[0].DestinationPort != 443 || rows[0].Direction != tc.direction || rows[0].Packets != 1 || rows[0].Bytes != 80 {
				t.Fatalf("return-only traffic: %+v %v", rows, err)
			}
		})
	}
}

func TestAnalyzeDropsPreservesEqualPortsAndNonTransportRecords(t *testing.T) {
	now := time.Date(2026, 1, 2, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name                   string
		protocol, sport, dport int
	}{
		{"equal-tcp", 6, 443, 443},
		{"equal-udp", 17, 53, 53},
		{"icmp-type-code", 1, 0, 2048},
		{"icmpv6-type-code", 58, 0, 32768},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := fmt.Sprintf("%s host veth-renamer[123]: DROP IF=\"app\" DIR=egress SRC=2001:db8::1 DST=2001:db8::2 PROTO=%d SPT=%d DPT=%d LEN=40 RULE=\"default\" REASON=default-deny TIME=%s\n",
				now.Format(time.Stamp), tc.protocol, tc.sport, tc.dport, now.Format(time.RFC3339Nano))
			rows, err := AnalyzeDrops(strings.NewReader(input), now, time.Hour, "packets")
			if err != nil || len(rows) != 1 || rows[0].Source != "2001:db8::1" ||
				rows[0].Destination != "2001:db8::2" || rows[0].DestinationPort != uint16(tc.dport) || rows[0].Direction != "egress" {
				t.Fatalf("record changed: %+v %v", rows, err)
			}
		})
	}
}

func TestAnalyzeDropsLegacyIPv6AndSeparateVerdicts(t *testing.T) {
	now := time.Date(2026, 1, 1, 1, 0, 0, 0, time.UTC)
	legacy := `Dec 31 23:00:00 host veth-renamer[1]: DROP IF="veth" DIR=egress SRC=2001:db8::1 DST=2001:db8::2 PROTO=17 SPT=123 DPT=53 LEN=48 RULE="default" REASON=default-deny` + "\n"
	audit := strings.Replace(legacy, ": DROP ", ": WOULD_DROP ", 1)
	current := strings.Replace(legacy, "Dec 31 23:00:00", "Jan  1 00:00:00", 1)
	future := strings.Replace(current, "00:00:00", "02:00:00", 1)
	rows, err := AnalyzeDrops(strings.NewReader(legacy+audit+current+future), now, 24*time.Hour, "packets")
	if err != nil || len(rows) != 2 || rows[0].Packets != 2 || rows[1].Packets != 1 ||
		rows[0].Action != "DROP" || rows[1].Action != "WOULD_DROP" || rows[0].Source != "2001:db8::1" ||
		!rows[0].LastSeen.Equal(now.Add(-time.Hour)) || !rows[1].LastSeen.Equal(now.Add(-2*time.Hour)) {
		t.Fatalf("legacy/audit: %+v %v", rows, err)
	}
	// Explicit years must not be reinterpreted as recent traffic.
	old := analysisRecord(now.AddDate(-2, 0, 0), 123, 40)
	rows, err = AnalyzeDrops(strings.NewReader(old), now, 24*time.Hour, "packets")
	if err != nil || len(rows) != 0 {
		t.Fatalf("historical record included: %+v %v", rows, err)
	}
	unknown := strings.ReplaceAll(strings.ReplaceAll(legacy, "2001:db8::1", "-"), "2001:db8::2", "-")
	if rows, err := AnalyzeDrops(strings.NewReader(unknown), now, 24*time.Hour, "packets"); err != nil || len(rows) != 1 {
		t.Fatalf("unknown family log: %+v %v", rows, err)
	}
}

type failedAnalysisReader struct{}

func (failedAnalysisReader) Read([]byte) (int, error) { return 0, errors.New("read failed") }

func TestAnalyzeDropsReportsErrors(t *testing.T) {
	now := time.Now()
	valid := analysisRecord(now, 123, 40)
	for _, input := range []string{
		"not a record\n",
		strings.Replace(valid, "PROTO=6", "PROTO=256", 1),
		strings.Replace(valid, "SPT=123", "SPT=65536", 1),
		strings.Replace(valid, "DST=203.0.113.1", "DST=bad", 1),
		strings.Replace(valid, "LEN=40", "LEN=4294967296", 1),
		strings.Replace(valid, "TIME=", "TIME=invalid", 1),
		valid[:len(valid)/2],
	} {
		if _, err := AnalyzeDrops(strings.NewReader(input), now, time.Hour, "packets"); err == nil || !strings.Contains(err.Error(), "line 1") {
			t.Fatalf("invalid input accepted: %q %v", input, err)
		}
	}
	if _, err := AnalyzeDrops(failedAnalysisReader{}, now, time.Hour, "packets"); err == nil || !strings.Contains(err.Error(), "read failed") {
		t.Fatalf("read failure hidden: %v", err)
	}
	if _, err := AnalyzeDrops(strings.NewReader(valid), now, time.Hour, "invalid"); err == nil {
		t.Fatal("invalid sort accepted")
	}
	rows, err := AnalyzeDrops(strings.NewReader(" \n"), now, time.Hour, "bytes")
	var out bytes.Buffer
	if err != nil || WriteDropSummary(&out, rows, now) != nil || strings.Count(out.String(), "\n") != 1 {
		t.Fatal("empty log should produce only a header")
	}
	if err := WriteDropSummary(io.Discard, rows, now); err != nil {
		t.Fatal(err)
	}
	if err := WriteDropSummary(failedAnalysisWriter{}, rows, now); err == nil {
		t.Fatal("output failure hidden")
	}
}

type failedAnalysisWriter struct{}

func (failedAnalysisWriter) Write([]byte) (int, error) { return 0, errors.New("write failed") }

func TestParseLookback(t *testing.T) {
	for input, want := range map[string]time.Duration{"24h": 24 * time.Hour, "7d": 168 * time.Hour, "30m": 30 * time.Minute} {
		if got, err := ParseLookback(input); err != nil || got != want {
			t.Fatalf("%s: %v %v", input, got, err)
		}
	}
	for _, input := range []string{"", "0", "0d", "-1d", "1.5d", "7days", "999999999d", "99999999999999999999999999999d"} {
		if _, err := ParseLookback(input); err == nil {
			t.Fatalf("accepted %q", input)
		}
	}
}

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
			rows[0].Rule != "deny\nquoted\"" || rows[0].Interface != "veth app" {
			t.Fatalf("wrong aggregate: %+v", rows[0])
		}
		rows, err = AnalyzeDrops(strings.NewReader(input), now, tc.window, "bytes")
		if err != nil || rows[0].DestinationPort != 80 || rows[0].Bytes != 500 {
			t.Fatalf("byte ranking: %+v %v", rows, err)
		}
		var out bytes.Buffer
		if err := WriteDropSummary(&out, rows); err != nil {
			t.Fatal(err)
		}
		if strings.Count(out.String(), "\n") != 3 || !strings.Contains(out.String(), `"deny\nquoted\""`) {
			t.Fatalf("unsafe or missing output: %q", out.String())
		}
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
		rows[0].Action != "DROP" || rows[1].Action != "WOULD_DROP" || rows[0].Source != "2001:db8::1" {
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
	if err != nil || WriteDropSummary(&out, rows) != nil || strings.Count(out.String(), "\n") != 1 {
		t.Fatal("empty log should produce only a header")
	}
	if err := WriteDropSummary(io.Discard, rows); err != nil {
		t.Fatal(err)
	}
	if err := WriteDropSummary(failedAnalysisWriter{}, rows); err == nil {
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

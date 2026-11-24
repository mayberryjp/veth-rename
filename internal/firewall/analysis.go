package firewall

import (
	"bufio"
	"fmt"
	"io"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"
)

// Legacy records have no year or timezone; new records carry an explicit TIME.
var dropRecord = regexp.MustCompile(`^([A-Z][a-z]{2} [ 0-9][0-9] [0-9:]{8}) \S+ (?:veth-manager|veth-renamer)\[[0-9]+\]: (DROP|WOULD_DROP) IF=("(?:\\.|[^"\\])*") DIR=(ingress|egress) SRC=(\S+) DST=(\S+) PROTO=([0-9]+) SPT=([0-9]+) DPT=([0-9]+) LEN=([0-9]+) RULE=("(?:\\.|[^"\\])*") REASON=(\S+)(?: TIME=(\S+))?$`)

type DropTuple struct {
	Interface, Direction, Action string
	Source, Destination          string
	DestinationPort, Protocol    uint16
	Rule, Reason                 string
}

type DropSummary struct {
	DropTuple
	Packets, Bytes uint64
	LastSeen       time.Time
}

func ParseLookback(value string) (time.Duration, error) {
	if strings.HasSuffix(value, "d") {
		days, err := strconv.ParseUint(strings.TrimSuffix(value, "d"), 10, 64)
		if err != nil || days == 0 || days > uint64((1<<63-1)/(24*time.Hour)) {
			return 0, fmt.Errorf("since must be a positive duration such as 24h or 7d")
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	duration, err := time.ParseDuration(value)
	if err != nil || duration <= 0 {
		return 0, fmt.Errorf("since must be a positive duration such as 24h or 7d")
	}
	return duration, nil
}

func parseDropRecord(line string, now time.Time) (DropTuple, uint64, time.Time, error) {
	m := dropRecord.FindStringSubmatch(line)
	if m == nil {
		return DropTuple{}, 0, time.Time{}, fmt.Errorf("invalid firewall drop record")
	}
	var when time.Time
	var err error
	if m[13] != "" {
		when, err = time.Parse(time.RFC3339Nano, m[13])
	} else {
		when, err = time.ParseInLocation("2006 Jan _2 15:04:05", fmt.Sprintf("%d %s", now.Year(), m[1]), now.Location())
		if err == nil && when.Month() > now.Month() {
			when = when.AddDate(-1, 0, 0)
		}
	}
	if err != nil {
		return DropTuple{}, 0, time.Time{}, fmt.Errorf("invalid timestamp: %w", err)
	}
	iface, err := strconv.Unquote(m[3])
	if err != nil {
		return DropTuple{}, 0, time.Time{}, fmt.Errorf("invalid interface: %w", err)
	}
	rule, err := strconv.Unquote(m[11])
	if err != nil {
		return DropTuple{}, 0, time.Time{}, fmt.Errorf("invalid rule: %w", err)
	}
	sourceText, destinationText := m[5], m[6]
	if sourceText != "-" || destinationText != "-" {
		source, err := netip.ParseAddr(sourceText)
		if err != nil {
			return DropTuple{}, 0, time.Time{}, fmt.Errorf("invalid source: %w", err)
		}
		destination, err := netip.ParseAddr(destinationText)
		if err != nil || source.Is4() != destination.Is4() {
			return DropTuple{}, 0, time.Time{}, fmt.Errorf("invalid destination or mismatched address families")
		}
		sourceText, destinationText = source.String(), destination.String()
	}
	var numbers [4]uint64
	for i, bits := range []int{8, 16, 16, 32} {
		numbers[i], err = strconv.ParseUint(m[7+i], 10, bits)
		if err != nil {
			return DropTuple{}, 0, time.Time{}, fmt.Errorf("invalid protocol, port or length: %w", err)
		}
	}
	tuple := DropTuple{
		Interface: iface, Direction: m[4], Action: m[2],
		Source: sourceText, Destination: destinationText,
		Protocol: uint16(numbers[0]), DestinationPort: uint16(numbers[2]),
		Rule: rule, Reason: m[12],
	}
	if (tuple.Protocol == 6 || tuple.Protocol == 17) && numbers[1] < numbers[2] {
		tuple.Source, tuple.Destination = tuple.Destination, tuple.Source
		tuple.DestinationPort = uint16(numbers[1])
		if tuple.Direction == "ingress" {
			tuple.Direction = "egress"
		} else {
			tuple.Direction = "ingress"
		}
	}
	return tuple, numbers[3], when, nil
}

func AnalyzeDrops(input io.Reader, now time.Time, lookback time.Duration, sortBy string) ([]DropSummary, error) {
	if lookback <= 0 {
		return nil, fmt.Errorf("lookback must be positive")
	}
	if sortBy != "packets" && sortBy != "bytes" {
		return nil, fmt.Errorf("sort must be packets or bytes")
	}
	totals := make(map[DropTuple]DropSummary)
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 4096), 1024*1024)
	lineNumber := 0
	start := now.Add(-lookback)
	for scanner.Scan() {
		lineNumber++
		if strings.TrimSpace(scanner.Text()) == "" {
			continue
		}
		key, octets, when, err := parseDropRecord(scanner.Text(), now)
		if err != nil {
			return nil, fmt.Errorf("firewall log line %d: %w", lineNumber, err)
		}
		if when.Before(start) || when.After(now) {
			continue
		}
		total := totals[key]
		if total.Packets == ^uint64(0) || octets > ^uint64(0)-total.Bytes {
			return nil, fmt.Errorf("firewall log line %d: counter overflow", lineNumber)
		}
		total.DropTuple = key
		if total.Packets == 0 || when.After(total.LastSeen) {
			total.LastSeen = when
		}
		total.Packets++
		total.Bytes += octets
		totals[key] = total
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read firewall log after line %d: %w", lineNumber, err)
	}
	rows := make([]DropSummary, 0, len(totals))
	for _, row := range totals {
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		if sortBy == "bytes" && a.Bytes != b.Bytes {
			return a.Bytes > b.Bytes
		}
		if a.Packets != b.Packets {
			return a.Packets > b.Packets
		}
		if a.Bytes != b.Bytes {
			return a.Bytes > b.Bytes
		}
		return fmt.Sprintf("%#v", a.DropTuple) < fmt.Sprintf("%#v", b.DropTuple)
	})
	return rows, nil
}

func WriteDropSummary(out io.Writer, rows []DropSummary, now time.Time) error {
	w := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	if _, err := fmt.Fprintln(w, "PACKETS\tBYTES\tSOURCE\tDESTINATION\tDPORT\tPROTO\tINTERFACE\tDIR\tACTION\tRULE\tREASON\tLAST_SEEN"); err != nil {
		return err
	}
	for _, row := range rows {
		minutes := int64(now.Sub(row.LastSeen) / time.Minute)
		unit := "minutes"
		if minutes == 1 {
			unit = "minute"
		}
		if _, err := fmt.Fprintf(w, "%d\t%d\t%s\t%s\t%d\t%d\t%q\t%s\t%s\t%q\t%s\t%s\n",
			row.Packets, row.Bytes, row.Source, row.Destination, row.DestinationPort, row.Protocol,
			row.Interface, row.Direction, row.Action, row.Rule, row.Reason, fmt.Sprintf("%d %s ago", minutes, unit)); err != nil {
			return err
		}
	}
	return w.Flush()
}

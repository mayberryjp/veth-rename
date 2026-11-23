package flow

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"veth-rename/internal/firewall"
)

func TestDropLogSyslogFormatAndEscaping(t *testing.T) {
	var out bytes.Buffer
	d := Drop{Key: Key{Family: 4, Protocol: 17, SourcePort: 1234, DestinationPort: 443},
		Direction: 1, Reason: 1, Rule: 1, Octets: 28}
	copy(d.Source[:], []byte{10, 0, 0, 1})
	copy(d.Destination[:], []byte{10, 0, 0, 2})
	p := &firewall.Policy{Rules: []firewall.Rule{{ID: "deny\nforged"}}}
	when := time.Date(2026, 11, 23, 12, 30, 0, 0, time.Local)
	if err := writeDrop(&out, "host", Interface{Name: "veth_app"}, p, d, when); err != nil {
		t.Fatal(err)
	}
	log := out.String()
	if !strings.HasPrefix(log, "Nov 23 12:30:00 host veth-renamer[") ||
		!strings.Contains(log, `DROP IF="veth_app" DIR=ingress SRC=10.0.0.1 DST=10.0.0.2 PROTO=17 SPT=1234 DPT=443 LEN=28 RULE="deny\nforged" REASON=rule-deny`) ||
		strings.Count(log, "\n") != 1 {
		t.Fatalf("syslog: %q", log)
	}
	d.Rule = 2
	if err := writeDrop(&out, "host", Interface{}, p, d, when); err == nil {
		t.Fatal("accepted bad rule index")
	}
}

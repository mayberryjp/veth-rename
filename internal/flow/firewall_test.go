package flow

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"veth-rename/internal/firewall"
)

type updatingFirewallMeter struct {
	fakeMeter
	updates   []*firewall.Policy
	updateErr error
}

func (m *updatingFirewallMeter) ReadDrops() ([]Drop, error) { return nil, nil }
func (m *updatingFirewallMeter) UpdateFirewall(p *firewall.Policy) error {
	if m.updateErr != nil {
		return m.updateErr
	}
	m.updates = append(m.updates, p)
	return nil
}

func TestServicePartitionsAndRefreshesEndpointRules(t *testing.T) {
	s, _, _, _, _ := testService(t)
	rules := make([]firewall.Rule, 600)
	for i := range rules {
		rules[i] = firewall.Rule{ID: fmt.Sprint(i), Direction: "both", Action: "allow",
			Source: fmt.Sprintf("10.0.%d.%d", i/250, i%250+1), Destination: "203.0.113.1",
			Protocol: "tcp", SandoMatch: true}
	}
	kernel, err := firewall.Compile(rules)
	if err != nil {
		t.Fatal(err)
	}
	s.options.firewall = &firewall.Policy{Config: firewall.Config{Enabled: true}, Rules: rules, Kernel: kernel}
	existing := &updatingFirewallMeter{}
	s.interfaces[7].meter = existing
	attachments := 0
	s.attach = func(iface Interface, options meterOptions) (meter, error) {
		attachments++
		if len(options.firewall.Kernel) != 1 || options.firewall.Kernel[0].ID != 600 {
			t.Fatalf("attached entire global policy: %+v", options.firewall.Kernel)
		}
		return &updatingFirewallMeter{}, nil
	}
	interfaces := []Interface{
		{Index: 7, Name: "veth_app", Identity: "c1/n1", IPv4: "10.0.0.1"},
		{Index: 8, Name: "veth_other", Identity: "c2/n2", IPv4: "10.0.2.100"},
	}
	if err := s.Sync(interfaces); err != nil {
		t.Fatal(err)
	}
	if attachments != 1 || len(existing.updates) != 1 || existing.updates[0].Kernel[0].ID != 1 {
		t.Fatalf("partitioning: attaches=%d updates=%+v", attachments, existing.updates)
	}
	if err := s.Sync(interfaces); err != nil || len(existing.updates) != 1 {
		t.Fatalf("unchanged address reloaded policy: %v", err)
	}
	interfaces[0].IPv4 = "10.0.0.2"
	existing.updateErr = errors.New("update blocked")
	if err := s.Sync(interfaces); err == nil || !strings.Contains(err.Error(), "update blocked") {
		t.Fatalf("failed update hidden: %v", err)
	}
	if s.interfaces[7].iface.IPv4 != "10.0.0.1" || existing.detached || existing.closed {
		t.Fatal("failed refresh discarded active policy or detached capture")
	}
	existing.updateErr = nil
	if err := s.Sync(interfaces); err != nil || s.interfaces[7].iface.IPv4 != "10.0.0.2" || len(existing.updates) != 2 {
		t.Fatalf("address refresh retry failed: %v", err)
	}
	interfaces[0].IPv4 = "203.0.113.1"
	interfaces = append(interfaces, Interface{Index: 9, Name: "veth_full", Identity: "c3/n3", IPv4: "203.0.113.1"})
	if err := s.Sync(interfaces); err == nil || !strings.Contains(err.Error(), "firewall veth_full") {
		t.Fatalf("per-veth capacity failure hidden: %v", err)
	}
	if attachments != 1 || len(existing.updates) != 2 || s.interfaces[7].iface.IPv4 != "10.0.0.2" {
		t.Fatal("over-capacity policy was installed or truncated")
	}
}

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
	out.Reset()
	d.Rule = 1
	p.Config.AuditMode = true
	if err := writeDrop(&out, "host", Interface{Name: "veth_app"}, p, d, when); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), ": WOULD_DROP IF=") || strings.Contains(out.String(), ": DROP ") {
		t.Fatalf("audit verdict mislabeled: %s", out.String())
	}
}

package flow

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"veth-manager/internal/firewall"
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

func TestReloadFirewallUpdatesOnlyChangedVethsAndRetries(t *testing.T) {
	s, _, _, _, _ := testService(t)
	makePolicy := func(rules []firewall.Rule) *firewall.Policy {
		t.Helper()
		kernel, err := firewall.Compile(rules)
		if err != nil {
			t.Fatal(err)
		}
		return &firewall.Policy{Config: firewall.Config{Enabled: true}, Rules: rules, Kernel: kernel, Generation: 1}
	}
	rules := []firewall.Rule{
		{ID: "a", Direction: "both", Action: "allow", Source: "10.0.0.1", Destination: "*", Protocol: "udp", SandoMatch: true},
		{ID: "b", Direction: "both", Action: "allow", Source: "10.0.0.2", Destination: "*", Protocol: "udp", SandoMatch: true},
	}
	initial := makePolicy(rules)
	s.options.firewall = initial
	first, second := &updatingFirewallMeter{}, &updatingFirewallMeter{}
	for i, m := range []*updatingFirewallMeter{first, second} {
		iface := Interface{Index: 7 + i, Name: fmt.Sprintf("veth_%d", i), IPv4: fmt.Sprintf("10.0.0.%d", i+1)}
		p, err := initial.ForEndpoint(iface.IPv4, "")
		if err != nil {
			t.Fatal(err)
		}
		s.interfaces[iface.Index] = &observed{iface: iface, meter: m, firewall: p}
	}
	saves := 0
	save := func() error { saves++; return nil }
	// Removing a shifts b's global index, but must not touch b's veth/state.
	next := makePolicy(rules[1:])
	if n, err := s.ReloadFirewall(next, save); err != nil || n != 1 {
		t.Fatalf("reload: updated=%d error=%v", n, err)
	}
	if len(first.updates) != 1 || first.updates[0].Generation != 2 || len(second.updates) != 0 ||
		s.interfaces[8].firewall.Rules[1].ID != "b" {
		t.Fatal("unaffected veth was reset or lost its log mapping")
	}
	rules[0].DestinationPort = "443"
	rules[1].DestinationPort = "444"
	next = makePolicy(rules)
	if _, err := s.ReloadFirewall(next, func() error { return errors.New("disk full") }); err == nil {
		t.Fatal("save error hidden")
	}
	if len(first.updates) != 1 || len(second.updates) != 0 {
		t.Fatal("applied rules before persistence succeeded")
	}
	second.updateErr = errors.New("kernel blocked")
	if n, err := s.ReloadFirewall(next, save); n != 1 || err == nil || !strings.Contains(err.Error(), "veth_1") {
		t.Fatalf("partial reload: updated=%d error=%v", n, err)
	}
	second.updateErr = nil
	if n, err := s.ReloadFirewall(next, save); n != 1 || err != nil {
		t.Fatalf("retry: updated=%d error=%v", n, err)
	}
	if len(first.updates) != 2 || len(second.updates) != 1 || first.detached || first.closed || second.detached || second.closed {
		t.Fatal("retry reset successful veths or detached capture")
	}
	if n, err := s.ReloadFirewall(next, save); n != 0 || err != nil {
		t.Fatalf("identical policy re-applied: updated=%d error=%v", n, err)
	}
	over := make([]firewall.Rule, firewall.MaxRulesPerVeth+1)
	for i := range over {
		over[i] = firewall.Rule{ID: fmt.Sprint(i), Direction: "both", Action: "allow", Source: "*", Destination: "*", Protocol: "udp"}
	}
	before := saves
	if _, err := s.ReloadFirewall(makePolicy(over), save); err == nil || !strings.Contains(err.Error(), "257 rules") {
		t.Fatalf("over-capacity reload: %v", err)
	}
	if saves != before || len(first.updates) != 2 || len(second.updates) != 1 {
		t.Fatal("invalid reload saved or applied a partial policy")
	}
}

func TestDropLogNeverAttributesOldGenerationToNewRule(t *testing.T) {
	var out bytes.Buffer
	p := &firewall.Policy{Generation: 3, Rules: []firewall.Rule{{ID: "new-rule"}}}
	drop := Drop{Generation: 1, Rule: 1, Direction: 1, Reason: 1}
	if err := writeDrop(&out, "host", Interface{}, p, drop, time.Now()); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "new-rule") || !strings.Contains(out.String(), "generation:1/rule:1") {
		t.Fatalf("old event mislabeled: %s", out.String())
	}
}

func TestPollingAddressRefreshRevokesChangedRulesWithoutResettingUnchangedRules(t *testing.T) {
	s, _, _, _, _ := testService(t)
	rules := []firewall.Rule{
		{ID: "one", Direction: "both", Action: "allow", Source: "10.0.0.0/24", Destination: "*", Protocol: "udp", SandoMatch: true},
		{ID: "two", Direction: "both", Action: "allow", Source: "10.0.1.1", Destination: "*", Protocol: "udp", SandoMatch: true},
	}
	kernel, err := firewall.Compile(rules)
	if err != nil {
		t.Fatal(err)
	}
	p := &firewall.Policy{Config: firewall.Config{Enabled: true, SandoPoll: true}, Rules: rules, Kernel: kernel, Generation: 1}
	s.options.firewall = p
	m := &updatingFirewallMeter{}
	o := s.interfaces[7]
	o.meter = m
	o.iface.IPv4 = "10.0.0.1"
	o.firewall, err = p.ForEndpoint(o.iface.IPv4, "")
	if err != nil {
		t.Fatal(err)
	}
	iface := o.iface
	iface.IPv4 = "10.0.0.2"
	if err := s.Sync([]Interface{iface}); err != nil || len(m.updates) != 0 {
		t.Fatalf("same effective rules reset state: %v", err)
	}
	iface.IPv4 = "10.0.1.1"
	if err := s.Sync([]Interface{iface}); err != nil || len(m.updates) != 1 || m.updates[0].Generation != 2 {
		t.Fatalf("changed address rules did not revoke state: %+v %v", m.updates, err)
	}
}

func TestFragmentDropLogAnalysis(t *testing.T) {
	for reason, name := range map[uint8]string{
		6: "fragment-unauthorized", 7: "fragment-invalid", 8: "fragment-table-full",
	} {
		t.Run(name, func(t *testing.T) {
			var out bytes.Buffer
			when := time.Now()
			drop := Drop{Key: Key{Family: 4, Protocol: 17}, Direction: 1, Reason: reason, Octets: 36}
			if err := writeDrop(&out, "host", Interface{Name: "veth_app"}, &firewall.Policy{}, drop, when); err != nil {
				t.Fatal(err)
			}
			rows, err := firewall.AnalyzeDrops(&out, when, time.Minute, "packets")
			if err != nil || len(rows) != 1 || rows[0].Reason != name || rows[0].Bytes != 36 {
				t.Fatalf("fragment reason round trip: %+v %v", rows, err)
			}
		})
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
	if !strings.HasPrefix(log, "Nov 23 12:30:00 host veth-manager[") ||
		!strings.Contains(log, `DROP IF="veth_app" DIR=ingress SRC=10.0.0.1 DST=10.0.0.2 PROTO=17 SPT=1234 DPT=443 LEN=28 RULE="deny\nforged" REASON=rule-deny`) ||
		strings.Count(log, "\n") != 1 {
		t.Fatalf("syslog: %q", log)
	}
	if !strings.Contains(log, " TIME="+when.Format(time.RFC3339Nano)+"\n") {
		t.Fatalf("missing unambiguous timestamp: %q", log)
	}
	rows, err := firewall.AnalyzeDrops(strings.NewReader(log), when, time.Hour, "packets")
	if err != nil || len(rows) != 1 || rows[0].Packets != 1 || rows[0].Bytes != 28 || rows[0].Rule != "deny\nforged" {
		t.Fatalf("drop log analysis round trip: %+v %v", rows, err)
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
	p.Config.AuditMode = false
	p.Config.EnforcementDirection = "egress"
	out.Reset()
	if err := writeDrop(&out, "host", Interface{}, p, d, when); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), ": WOULD_DROP IF=") {
		t.Fatalf("non-enforced ingress: %s", out.String())
	}
	d.Direction = 2
	out.Reset()
	if err := writeDrop(&out, "host", Interface{}, p, d, when); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), ": DROP IF=") {
		t.Fatalf("enforced egress: %s", out.String())
	}
}

package firewall

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fixture(t *testing.T) Config {
	t.Helper()
	dir := t.TempDir()
	c := Config{PermitAllICMP: true, SandoDirection: "both",
		ManualRules: filepath.Join(dir, "manual.yaml"), SandoRules: filepath.Join(dir, "sando.yaml")}
	for _, p := range []string{c.ManualRules, c.SandoRules} {
		if err := os.WriteFile(p, []byte("rules: []\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return c
}

func TestFirewallDefaultsAndDisabledConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "firewall.yaml")
	for _, content := range []string{"{}", "enabled: false\n", "enabled: true\nmanual_rules: manual.yaml\nsando_rules: sando.yaml\ndrop_log: drops.log\n"} {
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
		c, err := LoadConfig(path)
		if err != nil || !c.PermitAllICMP || c.AuditMode || c.EnforcementDirection != "both" || c.SandoAssignment != "endpoint" {
			t.Fatalf("defaults: %+v %v", c, err)
		}
		if content == "{}" && c.Enabled {
			t.Fatal("firewall enabled by default")
		}
	}
	for _, content := range []string{"enabled: \"false\"", "enabled: null", "enabled: true", "enabled: false\nenabled: true", "unknown: true", "permit_all_icmp: null", "audit_mode: \"true\"", "audit_mode: null", "audit_mode: 1", "enforcement_direction: outbound", "enforcement_direction: ''", "sando_assignment: unknown", "sando_assignment: null", "[]", "enabled: false\n---\n{}"} {
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadConfig(path); err == nil {
			t.Fatalf("accepted %q", content)
		}
		if err := os.WriteFile(path, []byte("enabled: false\naudit_mode: true\n"), 0600); err != nil {
			t.Fatal(err)
		}
		c, err := LoadConfig(path)
		if err != nil || c.Enabled || !c.AuditMode {
			t.Fatalf("explicit audit flag: %+v %v", c, err)
		}
	}
}

func TestSandoSyncPreservesSemanticsAndManualPrecedence(t *testing.T) {
	c := fixture(t)
	manual := "rules:\n  - id: manual-deny\n    direction: ingress\n    action: deny\n    source: '*'\n    destination: '*'\n    protocol: tcp\n    destination_port: '443'\n"
	if err := os.WriteFile(c.ManualRules, []byte(manual), 0600); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.URL.Path != "/api/ignorelist" {
			t.Errorf("request: %s %s", r.Method, r.URL.Path)
		}
		io := `[{"ignorelist_id":"icmp-zero","src_ip":"10.0.0.1","dst_ip":"*","dst_port":0,"protocol":1,"added":"ignored"},
{"ignorelist_id":"https","src_ip":"*","dst_ip":"2001:db8::1","dst_port":"443","protocol":"6"},
{"ignorelist_id":"wildcard","src_ip":"*","dst_ip":"*","dst_port":"*","protocol":"*"}]`
		_, _ = w.Write([]byte(io))
	}))
	defer server.Close()
	c.SandoEndpoint = server.URL
	out, err := Sync(context.Background(), c, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	p, err := LoadPolicy(c)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Kernel) != 4 || p.Rules[0].ID != "manual-deny" || p.Kernel[0].Action != 0 ||
		p.Kernel[1].DestinationPort != 0 || p.Kernel[1].Flags&2 == 0 ||
		p.Kernel[2].Family != 6 || p.Kernel[3].Flags != 24 {
		t.Fatalf("import: %+v\n%s", p.Kernel, out)
	}
	if data, _ := os.ReadFile(c.ManualRules); string(data) != manual {
		t.Fatal("sync overwrote manual rules")
	}
	saved, err := os.ReadFile(c.SandoRules)
	if err != nil || string(saved) != string(out) {
		t.Fatalf("output is not persisted: %v", err)
	}
}

func TestSandoSyncRejectsInvalidResponseWithoutReplacingPolicy(t *testing.T) {
	c := fixture(t)
	response := ""
	status := http.StatusOK
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(response))
	}))
	defer server.Close()
	c.SandoEndpoint = server.URL
	for _, body := range []string{
		`null`, `{}`, `[] trailing`,
		`[{"ignorelist_id":"x","src_ip":"*","dst_ip":"*","protocol":6,"dst_port":null}]`,
		`[{"ignorelist_id":"x","src_ip":"*","dst_ip":"*","protocol":6,"dst_port":true}]`,
		`[{"ignorelist_id":"x","src_ip":"*","dst_ip":"*","protocol":6,"dst_port":65536}]`,
		`[{"ignorelist_id":"x","src_ip":"not-an-ip","dst_ip":"*","protocol":6,"dst_port":443}]`,
		`[{"ignorelist_id":"","src_ip":"*","dst_ip":"*","protocol":6,"dst_port":443}]`,
	} {
		response = body
		if _, err := Sync(context.Background(), c, server.Client()); err == nil {
			t.Fatalf("accepted %s", body)
		}
		saved, err := os.ReadFile(c.SandoRules)
		if err != nil || string(saved) != "rules: []\n" {
			t.Fatal("failed sync replaced saved rules")
		}
	}
	status = http.StatusInternalServerError
	response = "[]"
	if _, err := Sync(context.Background(), c, server.Client()); err == nil {
		t.Fatal("accepted failed HTTP response")
	}
	status = http.StatusOK
	if _, err := Sync(context.Background(), c, server.Client()); err != nil {
		t.Fatal(err)
	}
	p, err := LoadPolicy(c)
	if err != nil || len(p.Rules) != 0 {
		t.Fatalf("empty sync: %+v %v", p, err)
	}
}

func TestSandoSyncLargePolicyPartitionsPerVeth(t *testing.T) {
	c := fixture(t)
	entries := make([]map[string]interface{}, 600)
	for i := range entries {
		entries[i] = map[string]interface{}{"ignorelist_id": fmt.Sprint(i),
			"src_ip": fmt.Sprintf("10.0.%d.%d", i/250, i%250+1),
			"dst_ip": "*", "dst_port": 443, "protocol": 6}
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewEncoder(w).Encode(entries); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	c.SandoEndpoint = server.URL
	if _, err := Sync(context.Background(), c, server.Client()); err != nil {
		t.Fatal(err)
	}
	p, err := LoadPolicy(c)
	if err != nil || len(p.Rules) != 600 {
		t.Fatalf("complete import: %v", err)
	}
	for _, endpoint := range []struct {
		ip string
		id uint32
	}{{"10.0.0.1", 1}, {"10.0.2.100", 600}} {
		selected, err := p.ForEndpoint(endpoint.ip, "")
		if err != nil || len(selected.Kernel) != 1 || selected.Kernel[0].ID != endpoint.id {
			t.Fatalf("endpoint %s: %+v %v", endpoint.ip, selected, err)
		}
	}
	if _, err := p.ForEndpoint("", ""); err == nil || !strings.Contains(err.Error(), "rules per veth") {
		t.Fatalf("unknown addresses must retain all applicable rules: %v", err)
	}
}

func TestSandoSyncRejectsInvalidDirectionForEmptyImport(t *testing.T) {
	c := fixture(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("[]"))
	}))
	defer server.Close()
	c.SandoEndpoint = server.URL
	for _, invalid := range []string{"", "outbound"} {
		c.SandoDirection = invalid
		if _, err := Sync(context.Background(), c, server.Client()); err == nil {
			t.Fatalf("accepted direction %q for empty import", invalid)
		}
		saved, err := os.ReadFile(c.SandoRules)
		if err != nil || string(saved) != "rules: []\n" {
			t.Fatalf("invalid direction replaced saved policy: %s %v", saved, err)
		}
	}
}

func TestEndpointSelectionKeepsGlobalManualAndBroadRules(t *testing.T) {
	rules := []Rule{
		{ID: "manual", Direction: "egress", Action: "deny", Source: "10.99.0.1", Destination: "*", Protocol: "*"},
		{ID: "other", Direction: "ingress", Action: "allow", Source: "10.0.0.2", Destination: "203.0.113.1", Protocol: "tcp", SandoMatch: true},
		{ID: "subnet", Direction: "egress", Action: "allow", Source: "10.0.0.0/24", Destination: "203.0.113.2", Protocol: "udp", SandoMatch: true},
		{ID: "reversed", Direction: "both", Action: "allow", Source: "203.0.113.3", Destination: "10.0.0.1", Protocol: "tcp", SandoMatch: true},
		{ID: "global", Direction: "both", Action: "allow", Source: "*", Destination: "203.0.113.4", Protocol: "tcp", SandoMatch: true},
	}
	kernel, err := Compile(rules)
	if err != nil {
		t.Fatal(err)
	}
	p := &Policy{Config: Config{SandoAssignment: "all_matches"}, Rules: rules, Kernel: kernel}
	selected, err := p.ForEndpoint("10.0.0.1", "")
	if err != nil {
		t.Fatal(err)
	}
	want := []uint32{1, 3, 4, 5}
	if len(selected.Kernel) != len(want) {
		t.Fatalf("selected: %+v", selected.Kernel)
	}
	for i, rule := range selected.Kernel {
		if rule.ID != want[i] || rule.Direction != kernel[want[i]-1].Direction {
			t.Fatalf("selection changed ordering, IDs or direction: %+v", selected.Kernel)
		}
	}
	for _, addresses := range [][2]string{{"not-an-ip", ""}, {"::1", ""}, {"", "10.0.0.1"}} {
		if _, err := p.ForEndpoint(addresses[0], addresses[1]); err == nil {
			t.Fatalf("accepted endpoint %v", addresses)
		}
	}
}

func TestEndpointAssignmentIgnoresWildcardSide(t *testing.T) {
	rules := []Rule{
		{ID: "source", Source: "10.0.0.18", Destination: "*"},
		{ID: "destination", Source: "*", Destination: "10.0.0.18"},
		{ID: "subnet", Source: "10.0.0.0/24", Destination: "*"},
		{ID: "global", Source: "*", Destination: "*"},
		{ID: "ipv6", Source: "*", Destination: "2001:db8:18::/64"},
		{ID: "ipv4-any", Source: "0.0.0.0/0", Destination: "10.0.0.18"},
		{ID: "ipv6-any", Source: "::/0", Destination: "2001:db8:18::1"},
	}
	for i := range rules {
		rules[i].Direction, rules[i].Action, rules[i].Protocol, rules[i].SandoMatch = "both", "allow", "*", true
	}
	kernel, err := Compile(rules)
	if err != nil {
		t.Fatal(err)
	}
	p := &Policy{Rules: rules, Kernel: kernel}
	for _, tc := range []struct {
		ip4, ip6 string
		want     []uint32
	}{
		{"10.0.0.18", "2001:db8:18::1", []uint32{1, 2, 3, 4, 5, 6, 7}},
		{"10.0.0.19", "2001:db8:19::1", []uint32{3, 4}},
		{"10.0.1.1", "2001:db8:19::1", []uint32{4}},
	} {
		selected, err := p.ForEndpoint(tc.ip4, tc.ip6)
		if err != nil {
			t.Fatal(err)
		}
		if len(selected.Kernel) != len(tc.want) {
			t.Fatalf("%s/%s: %+v", tc.ip4, tc.ip6, selected.Kernel)
		}
		for i, r := range selected.Kernel {
			if r.ID != tc.want[i] {
				t.Fatalf("%s/%s: %+v", tc.ip4, tc.ip6, selected.Kernel)
			}
		}
	}
	p.Config.SandoAssignment = "all_matches"
	selected, err := p.ForEndpoint("10.0.1.1", "2001:db8:19::1")
	if err != nil || len(selected.Kernel) != len(rules) {
		t.Fatalf("legacy assignment: %+v %v", selected, err)
	}
}

func TestEndpointIPv6AndPerVethLimit(t *testing.T) {
	rules := []Rule{
		{ID: "local", Direction: "both", Action: "allow", Source: "2001:db8::/64", Destination: "2001:db8:2::1", Protocol: "tcp", SandoMatch: true},
		{ID: "other", Direction: "both", Action: "allow", Source: "2001:db8:3::1", Destination: "2001:db8:4::1", Protocol: "tcp", SandoMatch: true},
		{ID: "link-local", Direction: "both", Action: "allow", Source: "fe80::1", Destination: "fe80::2", Protocol: "icmp6", SandoMatch: true},
	}
	kernel, err := Compile(rules)
	if err != nil {
		t.Fatal(err)
	}
	p := &Policy{Rules: rules, Kernel: kernel}
	selected, err := p.ForEndpoint("", "2001:db8::5")
	if err != nil || len(selected.Kernel) != 2 || selected.Kernel[1].ID != 3 {
		t.Fatalf("IPv6: %+v %v", selected, err)
	}
	global := make([]Rule, MaxRulesPerVeth+1)
	for i := range global {
		global[i] = Rule{ID: fmt.Sprint(i), Direction: "both", Action: "allow", Source: "*", Destination: "*", Protocol: "*", SandoMatch: true}
	}
	kernel, err = Compile(global)
	if err != nil {
		t.Fatal(err)
	}
	p = &Policy{Rules: global, Kernel: kernel}
	if _, err := p.ForEndpoint("10.0.0.1", "2001:db8::1"); err == nil || !strings.Contains(err.Error(), "257 rules") {
		t.Fatalf("global rules must count towards each veth: %v", err)
	}
}

func TestRuleConstraints(t *testing.T) {
	r := Rule{ID: "rule", Direction: "egress", Action: "allow", Source: "10.1.2.99/24",
		Destination: "*", Protocol: "udp", SourcePort: "0"}
	k, err := Compile([]Rule{r})
	if err != nil || k[0].Source[3] != 0 || k[0].SourcePrefix != 24 || k[0].Flags&1 == 0 || k[0].Direction != 2 {
		t.Fatalf("constraints: %+v %v", k, err)
	}
	for _, mutate := range []func(*Rule){
		func(r *Rule) { r.Direction = "" },
		func(r *Rule) { r.Action = "drop" },
		func(r *Rule) { r.Destination = "::1" },
		func(r *Rule) { r.SourcePort = "-1" },
		func(r *Rule) { r.Protocol = "256" },
		func(r *Rule) { r.SandoMatch = true },
	} {
		bad := r
		mutate(&bad)
		if _, err := Compile([]Rule{bad}); err == nil {
			t.Fatalf("accepted %+v", bad)
		}
	}
	if _, err := Compile([]Rule{r, r}); err == nil || !strings.Contains(err.Error(), "unique") {
		t.Fatalf("duplicate: %v", err)
	}
}

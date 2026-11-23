package firewall

import (
	"context"
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
		if err != nil || !c.PermitAllICMP {
			t.Fatalf("defaults: %+v %v", c, err)
		}
		if content == "{}" && c.Enabled {
			t.Fatal("firewall enabled by default")
		}
	}
	for _, content := range []string{"enabled: \"false\"", "enabled: null", "enabled: true", "enabled: false\nenabled: true", "unknown: true", "permit_all_icmp: null", "[]", "enabled: false\n---\n{}"} {
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadConfig(path); err == nil {
			t.Fatalf("accepted %q", content)
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

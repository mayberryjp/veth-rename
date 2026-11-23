package firewall

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestSandoPollingConditionalRequestsAndRetries(t *testing.T) {
	c := fixture(t)
	body := `[{"ignorelist_id":"one","src_ip":"10.0.0.1","dst_ip":"*","dst_port":443,"protocol":6}]`
	etag := `"v1"`
	requests := 0
	status := http.StatusOK
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if requests == 1 && r.Header.Get("If-None-Match") != "" {
			t.Error("initial poll must be unconditional")
		}
		if requests > 1 && r.Header.Get("If-None-Match") != `"v1"` {
			t.Errorf("validator advanced after failed response: %q", r.Header.Get("If-None-Match"))
		}
		w.Header().Set("ETag", etag)
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	defer server.Close()
	c.SandoEndpoint = server.URL
	poller := SandoPoller{Config: c, Client: server.Client()}
	first, err := poller.Poll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	saved, _ := os.ReadFile(c.SandoRules)
	if string(saved) != "rules: []\n" {
		t.Fatal("fetch wrote unvalidated live policy to disk")
	}
	// A save failure must be retryable even when the next response is 304.
	if err := os.Remove(c.SandoRules); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(c.SandoRules, 0700); err != nil {
		t.Fatal(err)
	}
	if err := first.Save(); err == nil {
		t.Fatal("save failure hidden")
	}
	if err := os.Remove(c.SandoRules); err != nil {
		t.Fatal(err)
	}
	status, body = http.StatusNotModified, ""
	cached, err := poller.Poll(context.Background())
	if err != nil || cached != first {
		t.Fatalf("304 lost pending policy: %v", err)
	}
	if err := cached.Save(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(c.SandoRules)
	if err != nil {
		t.Fatal(err)
	}
	if err := cached.Save(); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(c.SandoRules)
	if err != nil || !os.SameFile(info, after) {
		t.Fatal("unchanged policy was rewritten")
	}
	status, body, etag = http.StatusOK, "invalid", `"v2"`
	if _, err := poller.Poll(context.Background()); err == nil {
		t.Fatal("invalid update accepted")
	}
	status, body = http.StatusNotModified, ""
	if cached, err := poller.Poll(context.Background()); err != nil || cached != first {
		t.Fatalf("failed fetch lost previous policy/validator: %v", err)
	}
	status, body, etag = http.StatusOK, "[]", ""
	empty, err := poller.Poll(context.Background())
	if err != nil || len(empty.Policy.Rules) != 0 {
		t.Fatalf("rule deletion not detected: %+v %v", empty, err)
	}
	if err := empty.Save(); err != nil {
		t.Fatal(err)
	}
	saved, _ = os.ReadFile(c.SandoRules)
	if string(saved) != "rules: []\n" {
		t.Fatalf("empty list not persisted: %s", saved)
	}
}

func TestSandoPollingWithoutETag(t *testing.T) {
	c := fixture(t)
	body := "[]"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") != "" {
			t.Error("sent a validator without ETag support")
		}
		_, _ = w.Write([]byte(body))
	}))
	defer server.Close()
	c.SandoEndpoint = server.URL
	poller := SandoPoller{Config: c, Client: server.Client()}
	if _, err := poller.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	body = `[{"ignorelist_id":"new","src_ip":"*","dst_ip":"*","dst_port":"*","protocol":"*"}]`
	update, err := poller.Poll(context.Background())
	if err != nil || len(update.Policy.Rules) != 1 {
		t.Fatalf("unconditional polling missed update: %v", err)
	}
}

func TestSandoPollingConfiguration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "firewall.yaml")
	base := "enabled: true\nmanual_rules: manual.yaml\nsando_rules: sando.yaml\ndrop_log: drops.log\nsando_endpoint: http://localhost:8000\n"
	for _, tc := range []struct {
		extra string
		valid bool
	}{
		{"", true},
		{"sando_poll: true\n", true},
		{"sando_poll: true\nsando_poll_interval: 2m\n", true},
		{"sando_poll: \"true\"\n", false},
		{"sando_poll_interval: 0s\n", false},
		{"sando_poll_interval: 999ms\n", false},
		{"sando_poll_interval: invalid\n", false},
	} {
		if err := os.WriteFile(path, []byte(base+tc.extra), 0600); err != nil {
			t.Fatal(err)
		}
		config, err := LoadConfig(path)
		if (err == nil) != tc.valid {
			t.Fatalf("%q: %v", tc.extra, err)
		}
		if tc.extra == "" && (config.SandoPoll || config.SandoPollInterval != "60s") {
			t.Fatalf("polling defaults: %+v", config)
		}
	}
	for _, content := range []string{
		"sando_poll: true\n",
		"enabled: true\nmanual_rules: m.yaml\nsando_rules: s.yaml\ndrop_log: d.log\nsando_poll: true\n",
	} {
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadConfig(path); err == nil {
			t.Fatalf("accepted polling without firewall/endpoint: %s", content)
		}
	}
}

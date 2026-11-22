package flow

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestConfigYAML(t *testing.T) {
	c, err := readConfig(strings.NewReader("collector: '[2001:db8::1]:4739'\n"))
	if err != nil || c.active != time.Minute || c.idle != 15*time.Second ||
		c.poll != time.Second || c.refresh != 30*time.Second || c.MaxFlowsPerVeth != 65536 || c.SamplingRate != 1 ||
		c.MaxMessageSize != defaultMaxMessageSize || c.TemplateRefreshPackets != 20 {
		t.Fatalf("defaults: %+v %v", c, err)
	}
	for _, filter := range []string{"", "ip", "ip6", "tcp", "udp", "icmp", "icmp6"} {
		_, err := readConfig(strings.NewReader("collector: localhost:4739\nsampling_rate: 4\ncapture_filter: '" + filter + "'\n"))
		if err != nil {
			t.Fatalf("filter %q: %v", filter, err)
		}
	}
	for _, input := range []string{
		`{"collector":"localhost:4739"}`, "", "null", "[]", "collector: ':4739'", "collector: localhost:0",
		"collector: localhost:65536", "collector: localhost:4739\ntypo: true",
		"collector: localhost:4739\n---\ncollector: localhost:4739",
		"collector: localhost:4739\ncollector: other:4739",
		"collector: localhost:4739\nidle_timeout: 0s", "collector: localhost:4739\nactive_timeout: true",
		"collector: localhost:4739\npoll_interval: 20s", "collector: localhost:4739\nsampling_rate: 0",
		"collector: localhost:4739\nsampling_rate: 1000001", "collector: localhost:4739\nsampling_rate: '4'",
		"collector: localhost:4739\nsampling_rate: 1.5", "collector: localhost:4739\nmax_flows_per_veth: 0",
		"collector: localhost:4739\nmax_flows_per_veth: 1048577", "collector: localhost:4739\ntemplate_refresh: 11m",
		"collector: localhost:4739\ncapture_filter: 'udp port 53'", "collector: localhost:4739\nidle_timeout: null",
		"collector: 1234", "collector: &a localhost:4739\ncapture_filter: *a",
		"collector: localhost:4739\nmax_message_size: 155", "collector: localhost:4739\nmax_message_size: 65508",
		"collector: localhost:4739\nmax_message_size: '1200'", "collector: localhost:4739\nmax_message_size: 1200.5",
		"collector: localhost:4739\ntemplate_refresh_packets: -1", "collector: localhost:4739\ntemplate_refresh_packets: 1000001",
		"collector: localhost:4739\ntemplate_refresh_packets: '20'", "collector: localhost:4739\nmax_message_size: null",
	} {
		if _, err := readConfig(strings.NewReader(input)); err == nil {
			t.Errorf("accepted invalid YAML %q", input)
		}
	}
}

func TestConfigMessageAndTemplateLimits(t *testing.T) {
	for _, size := range []string{"156", "464", "1200", "65507"} {
		c, err := readConfig(strings.NewReader("collector: localhost:4739\nmax_message_size: " + size + "\ntemplate_refresh_packets: 0\n"))
		if err != nil || c.TemplateRefreshPackets != 0 {
			t.Fatalf("valid message limit %s rejected: %v", size, err)
		}
	}
}

func TestConfigMigration(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ipfix.yaml")
	if err := os.WriteFile(path, []byte("collector: localhost:4739\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(filepath.Join(dir, "ipfix.json")); err == nil || !strings.Contains(err.Error(), "migrate") {
		t.Fatal("JSON migration must fail explicitly")
	}
}

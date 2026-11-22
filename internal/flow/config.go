package flow

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Collector                   string `yaml:"collector"`
	ObservationDomainID         uint32 `yaml:"observation_domain_id"`
	ActiveTimeout               string `yaml:"active_timeout"`
	IdleTimeout                 string `yaml:"idle_timeout"`
	PollInterval                string `yaml:"poll_interval"`
	TemplateRefresh             string `yaml:"template_refresh"`
	MaxFlowsPerVeth             uint32 `yaml:"max_flows_per_veth"`
	SamplingRate                uint32 `yaml:"sampling_rate"`
	CaptureFilter               string `yaml:"capture_filter"`
	active, idle, poll, refresh time.Duration
}

func LoadConfig(path string) (Config, error) {
	if ext := filepath.Ext(path); ext != ".yaml" && ext != ".yml" {
		return Config{}, fmt.Errorf("IPFIX configuration must be a .yaml or .yml file; migrate existing JSON configuration")
	}
	f, err := os.Open(path)
	if err != nil {
		return Config{}, err
	}
	defer f.Close()
	return readConfig(f)
}

func readConfig(r io.Reader) (Config, error) {
	c := Config{ActiveTimeout: "60s", IdleTimeout: "15s", PollInterval: "1s",
		TemplateRefresh: "30s", MaxFlowsPerVeth: 65536, SamplingRate: 1}
	data, err := io.ReadAll(r)
	if err != nil {
		return c, err
	}
	if json.Valid(data) {
		return c, fmt.Errorf("JSON IPFIX configuration is no longer supported; migrate to YAML")
	}
	var document yaml.Node
	d := yaml.NewDecoder(bytes.NewReader(data))
	if err := d.Decode(&document); err != nil {
		return c, fmt.Errorf("IPFIX configuration: %w", err)
	}
	var extra yaml.Node
	if err := d.Decode(&extra); err != io.EOF {
		return c, fmt.Errorf("IPFIX configuration must contain one YAML document")
	}
	if len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode {
		return c, fmt.Errorf("IPFIX configuration must be a YAML mapping")
	}
	root := document.Content[0]
	for i := 0; i < len(root.Content); i += 2 {
		key, value := root.Content[i], root.Content[i+1]
		tag := "!!str"
		switch key.Value {
		case "observation_domain_id", "max_flows_per_veth", "sampling_rate":
			tag = "!!int"
		case "collector", "active_timeout", "idle_timeout", "poll_interval", "template_refresh", "capture_filter":
		default:
			return c, fmt.Errorf("unknown IPFIX configuration field %q", key.Value)
		}
		if key.Kind != yaml.ScalarNode || key.Tag != "!!str" || value.Kind != yaml.ScalarNode || value.Tag != tag {
			return c, fmt.Errorf("IPFIX field %q must have type %s", key.Value, tag)
		}
	}
	if err := root.Decode(&c); err != nil {
		return c, fmt.Errorf("IPFIX configuration: %w", err)
	}
	host, port, err := net.SplitHostPort(c.Collector)
	if err != nil || host == "" || port == "" {
		return c, fmt.Errorf("collector must be host:port or [IPv6]:port")
	}
	number, err := strconv.Atoi(port)
	if err != nil || number < 1 || number > 65535 {
		return c, fmt.Errorf("collector port must be between 1 and 65535")
	}
	for _, item := range []struct {
		name, text string
		out        *time.Duration
	}{
		{"active_timeout", c.ActiveTimeout, &c.active},
		{"idle_timeout", c.IdleTimeout, &c.idle},
		{"poll_interval", c.PollInterval, &c.poll},
		{"template_refresh", c.TemplateRefresh, &c.refresh},
	} {
		duration, err := time.ParseDuration(item.text)
		if err != nil || duration < time.Millisecond {
			return c, fmt.Errorf("%s must be a duration of at least 1ms", item.name)
		}
		*item.out = duration
	}
	if c.poll > c.idle || c.poll > c.active {
		return c, fmt.Errorf("poll_interval must not exceed either flow timeout")
	}
	if c.refresh > 10*time.Minute {
		return c, fmt.Errorf("template_refresh must not exceed 10m")
	}
	if c.MaxFlowsPerVeth < 1 || c.MaxFlowsPerVeth > 1048576 {
		return c, fmt.Errorf("max_flows_per_veth must be between 1 and 1048576")
	}
	if c.SamplingRate < 1 || c.SamplingRate > 1000000 {
		return c, fmt.Errorf("sampling_rate must be between 1 and 1000000")
	}
	if _, ok := captureFilters[c.CaptureFilter]; !ok {
		return c, fmt.Errorf("capture_filter must be empty, ip, ip6, tcp, udp, icmp or icmp6")
	}
	return c, nil
}

var captureFilters = map[string]uint32{"": 0, "ip": 1, "ip6": 2, "tcp": 3, "udp": 4, "icmp": 5, "icmp6": 6}

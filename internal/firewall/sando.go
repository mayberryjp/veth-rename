package firewall

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

type sandoEntry struct {
	ID          string          `json:"ignorelist_id"`
	Source      string          `json:"src_ip"`
	Destination string          `json:"dst_ip"`
	Port        json.RawMessage `json:"dst_port"`
	Protocol    json.RawMessage `json:"protocol"`
}

func constraint(data json.RawMessage, bits int) (string, error) {
	text := string(data)
	if len(data) > 0 && data[0] == '"' {
		if err := json.Unmarshal(data, &text); err != nil {
			return "", err
		}
	}
	if text == "*" {
		return text, nil
	}
	if _, err := number(text, bits); err != nil {
		return "", err
	}
	return text, nil
}

// Sync replaces only the generated file, after validating the complete combined policy.
func Sync(ctx context.Context, c Config, client *http.Client) ([]byte, error) {
	if c.ManualRules == "" || c.SandoRules == "" {
		return nil, fmt.Errorf("manual_rules and sando_rules are required for sync")
	}
	if c.SandoEndpoint == "" {
		return nil, fmt.Errorf("sando_endpoint is required for sync")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(c.SandoEndpoint, "/")+"/api/ignorelist", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	response, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch Sando ignore list: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Sando ignore list returned HTTP %d", response.StatusCode)
	}
	const limit = 4 << 20
	data, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if len(data) > limit {
		return nil, fmt.Errorf("Sando response exceeds 4 MiB")
	}
	if !strings.HasPrefix(strings.TrimSpace(string(data)), "[") {
		return nil, fmt.Errorf("Sando ignore list must be a JSON array")
	}
	var entries []sandoEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("decode Sando ignore list: %w", err)
	}
	file := RuleFile{Rules: make([]Rule, 0, len(entries))}
	for _, entry := range entries {
		port, err := constraint(entry.Port, 16)
		if err != nil {
			return nil, fmt.Errorf("Sando rule %q dst_port: %w", entry.ID, err)
		}
		protocol, err := constraint(entry.Protocol, 8)
		if err != nil {
			return nil, fmt.Errorf("Sando rule %q protocol: %w", entry.ID, err)
		}
		file.Rules = append(file.Rules, Rule{ID: "sando:" + entry.ID, Direction: c.SandoDirection,
			Action: "allow", Source: entry.Source, Destination: entry.Destination,
			Protocol: protocol, DestinationPort: port, SandoMatch: true})
		if entry.ID == "" {
			return nil, fmt.Errorf("Sando rule has empty ignorelist_id")
		}
	}
	var manual RuleFile
	if err := readYAML(c.ManualRules, &manual); err != nil {
		return nil, err
	}
	for _, r := range manual.Rules {
		if r.SandoMatch {
			return nil, fmt.Errorf("manual rules cannot use sando_match")
		}
	}
	if _, err := Compile(append(manual.Rules, file.Rules...)); err != nil {
		return nil, err
	}
	out, err := yaml.Marshal(file)
	if err != nil {
		return nil, err
	}
	if err := atomicWrite(c.SandoRules, out); err != nil {
		return nil, err
	}
	return out, nil
}

func atomicWrite(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".sando-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if err := f.Chmod(0644); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	return nil
}

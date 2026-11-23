package firewall

import (
	"bytes"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"

	"gopkg.in/yaml.v3"
)

const MaxRulesPerVeth = 256

type Config struct {
	Enabled        bool   `yaml:"enabled"`
	PermitAllICMP  bool   `yaml:"permit_all_icmp"`
	ManualRules    string `yaml:"manual_rules"`
	SandoRules     string `yaml:"sando_rules"`
	SandoEndpoint  string `yaml:"sando_endpoint"`
	SandoDirection string `yaml:"sando_direction"`
	DropLog        string `yaml:"drop_log"`
}

type Rule struct {
	ID              string `yaml:"id"`
	Direction       string `yaml:"direction"`
	Action          string `yaml:"action"`
	Source          string `yaml:"source"`
	Destination     string `yaml:"destination"`
	Protocol        string `yaml:"protocol"`
	SourcePort      string `yaml:"source_port,omitempty"`
	DestinationPort string `yaml:"destination_port,omitempty"`
	// Sando trusts either endpoint orientation and either endpoint's port.
	SandoMatch bool `yaml:"sando_match,omitempty"`
}

type RuleFile struct {
	Rules []Rule `yaml:"rules"`
}

type Policy struct {
	Config Config
	Rules  []Rule
	Kernel []KernelRule
}

type KernelRule struct {
	Source, Destination                               [16]byte
	SourcePort, DestinationPort                       uint16
	SourcePrefix, DestinationPrefix, Family, Protocol uint8
	Direction, Action, Flags, Padding                 uint8
	ID                                                uint32
}

func readYAML(path string, out interface{}) error {
	ext := filepath.Ext(path)
	if ext != ".yaml" && ext != ".yml" {
		return fmt.Errorf("firewall configuration %s must be YAML", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var document yaml.Node
	if err := yaml.Unmarshal(data, &document); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode || document.Content[0].Tag != "!!map" {
		return fmt.Errorf("%s must be a YAML mapping", path)
	}
	if err := validateNodes(&document); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	d := yaml.NewDecoder(bytes.NewReader(data))
	d.KnownFields(true)
	if err := d.Decode(out); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	var extra yaml.Node
	if err := d.Decode(&extra); err != io.EOF {
		return fmt.Errorf("%s must contain one YAML document", path)
	}
	return nil
}

func validateNodes(n *yaml.Node) error {
	if n.Tag == "!!null" || n.Kind == yaml.AliasNode {
		return fmt.Errorf("null values and YAML aliases are unsupported")
	}
	if n.Kind == yaml.MappingNode {
		for i := 0; i < len(n.Content); i += 2 {
			key, value := n.Content[i], n.Content[i+1]
			if key.Kind != yaml.ScalarNode || key.Tag != "!!str" {
				return fmt.Errorf("mapping keys must be strings")
			}
			if (key.Value == "enabled" || key.Value == "permit_all_icmp" || key.Value == "sando_match") &&
				(value.Kind != yaml.ScalarNode || value.Tag != "!!bool") {
				return fmt.Errorf("%s must be a boolean", key.Value)
			}
		}
	}
	for _, child := range n.Content {
		if err := validateNodes(child); err != nil {
			return err
		}
	}
	return nil
}

func LoadConfig(path string) (Config, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return Config{}, err
	}
	path = absolute
	c := Config{PermitAllICMP: true, SandoDirection: "both"}
	if err := readYAML(path, &c); err != nil {
		return c, err
	}
	if c.Enabled && (c.ManualRules == "" || c.SandoRules == "" || c.DropLog == "") {
		return c, fmt.Errorf("manual_rules, sando_rules and drop_log are required")
	}
	if _, err := direction(c.SandoDirection); err != nil {
		return c, fmt.Errorf("sando_direction: %w", err)
	}
	if c.SandoEndpoint != "" {
		u, err := url.Parse(c.SandoEndpoint)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" ||
			u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return c, fmt.Errorf("sando_endpoint must be an HTTP(S) base URL without credentials, query or fragment")
		}
	}
	for _, p := range []*string{&c.ManualRules, &c.SandoRules, &c.DropLog} {
		if *p == "" {
			continue
		}
		if !filepath.IsAbs(*p) {
			*p = filepath.Join(filepath.Dir(path), *p)
		}
		*p = filepath.Clean(*p)
	}
	if (c.ManualRules != "" && c.ManualRules == c.SandoRules) ||
		(c.DropLog != "" && (c.DropLog == c.ManualRules || c.DropLog == c.SandoRules)) ||
		c.ManualRules == filepath.Clean(path) || c.SandoRules == filepath.Clean(path) || c.DropLog == filepath.Clean(path) {
		return c, fmt.Errorf("firewall configuration, rule files and drop_log must use distinct paths")
	}
	return c, nil
}

func LoadPolicy(c Config) (*Policy, error) {
	p := &Policy{Config: c}
	for _, item := range []struct {
		path  string
		sando bool
	}{{c.ManualRules, false}, {c.SandoRules, true}} {
		var file RuleFile
		if err := readYAML(item.path, &file); err != nil {
			return nil, err
		}
		for _, r := range file.Rules {
			if item.sando != r.SandoMatch || (item.sando && r.Action != "allow") {
				return nil, fmt.Errorf("%s: only imported Sando allow rules may use sando_match", item.path)
			}
			p.Rules = append(p.Rules, r)
		}
	}
	var err error
	p.Kernel, err = Compile(p.Rules)
	if err != nil {
		return nil, err
	}
	return p, nil
}

func direction(s string) (uint8, error) {
	switch s {
	case "ingress":
		return 1, nil
	case "egress":
		return 2, nil
	case "both":
		return 0, nil
	default:
		return 0, fmt.Errorf("direction must be ingress, egress or both")
	}
}

func prefix(s string) ([16]byte, uint8, uint8, error) {
	var address [16]byte
	if s == "*" {
		return address, 0, 0, nil
	}
	p, err := netip.ParsePrefix(s)
	if err != nil {
		a, addrErr := netip.ParseAddr(s)
		if addrErr != nil || a.Is4In6() || a.Zone() != "" {
			return address, 0, 0, fmt.Errorf("invalid IP address or CIDR %q", s)
		}
		p = netip.PrefixFrom(a, a.BitLen())
	}
	if p.Addr().Is4In6() || p.Addr().Zone() != "" {
		return address, 0, 0, fmt.Errorf("IPv4-mapped IPv6 and scoped addresses are unsupported")
	}
	p = p.Masked()
	family := uint8(6)
	if p.Addr().Is4() {
		family = 4
		a := p.Addr().As4()
		copy(address[:], a[:])
	} else {
		address = p.Addr().As16()
	}
	return address, uint8(p.Bits()), family, nil
}

func number(s string, bits int) (uint64, error) {
	if s == "" {
		return 0, fmt.Errorf("empty numeric constraint")
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("invalid numeric constraint %q", s)
		}
	}
	return strconv.ParseUint(s, 10, bits)
}

func Compile(rules []Rule) ([]KernelRule, error) {
	if uint64(len(rules)) > uint64(^uint32(0)) {
		return nil, fmt.Errorf("policy exceeds the rule ID range")
	}
	out := make([]KernelRule, 0, len(rules))
	ids := make(map[string]bool)
	for i, r := range rules {
		if r.ID == "" || ids[r.ID] {
			return nil, fmt.Errorf("rule IDs must be nonempty and unique: %q", r.ID)
		}
		ids[r.ID] = true
		k, err := compileRule(r)
		if err != nil {
			return nil, fmt.Errorf("rule %q: %w", r.ID, err)
		}
		k.ID = uint32(i + 1)
		out = append(out, k)
	}
	return out, nil
}

// Manual rules are global. Sando rules are assigned by endpoint IP, not list position.
func (p *Policy) ForEndpoint(ipv4, ipv6 string) (*Policy, error) {
	var addresses [2]netip.Addr
	for i, text := range []string{ipv4, ipv6} {
		if text == "" {
			continue
		}
		a, err := netip.ParseAddr(text)
		if err != nil || a.Is4In6() || a.Zone() != "" || (i == 0 && !a.Is4()) || (i == 1 && !a.Is6()) {
			return nil, fmt.Errorf("invalid endpoint IPv%d address %q", 4+i*2, text)
		}
		if !a.IsUnspecified() {
			addresses[i] = a
		}
	}
	selected := &Policy{Config: p.Config, Rules: p.Rules}
	for _, rule := range p.Kernel {
		if rule.Flags&8 == 0 || relevant(rule, addresses) {
			selected.Kernel = append(selected.Kernel, rule)
		}
	}
	if len(selected.Kernel) > MaxRulesPerVeth {
		return nil, fmt.Errorf("%d rules apply to this veth; at most %d rules per veth are supported (IPv4=%q IPv6=%q)",
			len(selected.Kernel), MaxRulesPerVeth, ipv4, ipv6)
	}
	return selected, nil
}

func relevant(rule KernelRule, addresses [2]netip.Addr) bool {
	if rule.Family == 0 {
		return true
	}
	index := 0
	if rule.Family == 6 {
		index = 1
	}
	a := addresses[index]
	// Missing Docker metadata is not proof that traffic of this family is impossible.
	if !a.IsValid() {
		return true
	}
	for _, endpoint := range []struct {
		address [16]byte
		bits    uint8
	}{{rule.Source, rule.SourcePrefix}, {rule.Destination, rule.DestinationPrefix}} {
		network := netip.AddrFrom16(endpoint.address)
		unspecified := netip.IPv6Unspecified()
		if rule.Family == 4 {
			network = netip.AddrFrom4([4]byte(endpoint.address[:4]))
			unspecified = netip.IPv4Unspecified()
		}
		prefix := netip.PrefixFrom(network, int(endpoint.bits))
		if prefix.Contains(a) || prefix.Contains(unspecified) {
			return true
		}
		// Docker reports the primary global IPv6 address, not automatic link-local addresses.
		if rule.Family == 6 && prefix.Overlaps(netip.MustParsePrefix("fe80::/10")) {
			return true
		}
	}
	return false
}

func compileRule(r Rule) (KernelRule, error) {
	var k KernelRule
	var err error
	k.Direction, err = direction(r.Direction)
	if err != nil {
		return k, err
	}
	switch r.Action {
	case "allow":
		k.Action = 1
	case "deny":
	default:
		return k, fmt.Errorf("action must be allow or deny")
	}
	var sourceFamily, destinationFamily uint8
	k.Source, k.SourcePrefix, sourceFamily, err = prefix(r.Source)
	if err != nil {
		return k, err
	}
	k.Destination, k.DestinationPrefix, destinationFamily, err = prefix(r.Destination)
	if err != nil {
		return k, err
	}
	if sourceFamily != 0 && destinationFamily != 0 && sourceFamily != destinationFamily {
		return k, fmt.Errorf("source and destination IP families differ")
	}
	k.Family = max(sourceFamily, destinationFamily)
	if r.Protocol != "*" {
		text := r.Protocol
		switch text {
		case "tcp":
			text = "6"
		case "udp":
			text = "17"
		case "icmp":
			text = "1"
		case "icmp6":
			text = "58"
		case "sctp":
			text = "132"
		}
		value, err := number(text, 8)
		if err != nil {
			return k, err
		}
		k.Protocol = uint8(value)
		k.Flags |= 4
	}
	for _, port := range []struct {
		text  string
		value *uint16
		flag  uint8
	}{
		{r.SourcePort, &k.SourcePort, 1}, {r.DestinationPort, &k.DestinationPort, 2},
	} {
		if port.text == "" || port.text == "*" {
			continue
		}
		n, err := number(port.text, 16)
		if err != nil {
			return k, err
		}
		*port.value = uint16(n)
		k.Flags |= port.flag
	}
	if r.SandoMatch {
		if r.Action != "allow" || r.SourcePort != "" {
			return k, fmt.Errorf("Sando matching requires allow and no source_port")
		}
		k.Flags |= 8 | 16
	}
	return k, nil
}

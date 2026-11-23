package flow

import (
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"time"

	"veth-rename/internal/firewall"
)

type Drop struct {
	Key
	Time              uint64
	Rule, Octets      uint32
	Direction, Reason uint8
	Padding           [2]byte
	Generation        uint32
}

type firewallMeter interface {
	ReadDrops() ([]Drop, error)
	UpdateFirewall(*firewall.Policy) error
}

func (s *Service) firewallOptions(iface Interface) (meterOptions, error) {
	options := s.options
	if options.firewall != nil {
		selected, err := options.firewall.ForEndpoint(iface.IPv4, iface.IPv6)
		if err != nil {
			return options, fmt.Errorf("firewall %s: %w", iface.Name, err)
		}
		options.firewall = selected
	}
	return options, nil
}

func (s *Service) EnableFirewall(p *firewall.Policy) error {
	if !p.Config.Enabled {
		return nil
	}
	if len(s.interfaces) != 0 {
		return fmt.Errorf("firewall must be configured before attaching interfaces")
	}
	if s.dropLog != nil {
		return fmt.Errorf("firewall is already configured")
	}
	if err := validateFirewall(p); err != nil {
		return err
	}
	f, err := os.OpenFile(p.Config.DropLog, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("open firewall drop log: %w", err)
	}
	host, err := os.Hostname()
	if err != nil {
		return errors.Join(err, f.Close())
	}
	initial := *p
	initial.Generation = 1
	s.options.firewall = &initial
	s.dropLog = f
	s.logHost = host
	return nil
}

// equalFirewall ignores global rule indices: removing another endpoint's rule
// must not reset this endpoint's connection state or change its log mapping.
func equalFirewall(a, b *firewall.Policy) bool {
	if len(a.Kernel) != len(b.Kernel) {
		return false
	}
	for i, left := range a.Kernel {
		right := b.Kernel[i]
		if a.Rules[left.ID-1].ID != b.Rules[right.ID-1].ID {
			return false
		}
		left.ID, right.ID = 0, 0
		if left != right {
			return false
		}
	}
	return true
}

// ReloadFirewall is serialized with Sync and Poll by the daemon. Validate all
// endpoints before persisting, then replace only changed tables in place.
// Kernel failures are per-veth; successful replacements are retained on retry.
func (s *Service) ReloadFirewall(p *firewall.Policy, save func() error) (int, error) {
	if s.options.firewall == nil || p.Config != s.options.firewall.Config {
		return 0, fmt.Errorf("live reload requires an enabled firewall with unchanged configuration")
	}
	selected := make(map[int]*firewall.Policy)
	for _, index := range s.indices() {
		o := s.interfaces[index]
		if o.retiring {
			continue
		}
		next, err := p.ForEndpoint(o.iface.IPv4, o.iface.IPv6)
		if err != nil {
			return 0, fmt.Errorf("firewall %s: %w", o.iface.Name, err)
		}
		if o.firewall == nil {
			o.firewall, err = s.options.firewall.ForEndpoint(o.iface.IPv4, o.iface.IPv6)
			if err != nil {
				return 0, err
			}
		}
		if equalFirewall(o.firewall, next) {
			continue
		}
		if _, ok := o.meter.(firewallMeter); !ok {
			return 0, fmt.Errorf("meter %s has no firewall updater", o.iface.Name)
		}
		if o.firewall.Generation == ^uint32(0) {
			return 0, fmt.Errorf("firewall generation exhausted on %s; restart required", o.iface.Name)
		}
		next.Generation = o.firewall.Generation + 1
		// Generation zero is reserved for legacy/test policies and malformed packets.
		if next.Generation == 1 {
			next.Generation = 2
		}
		selected[index] = next
	}
	if err := save(); err != nil {
		return 0, fmt.Errorf("save Sando policy: %w", err)
	}
	desired := *p
	desired.Generation = 1
	s.options.firewall = &desired
	var errs []error
	updated := 0
	for _, index := range s.indices() {
		next, ok := selected[index]
		if !ok {
			continue
		}
		o := s.interfaces[index]
		if err := s.logDrops(o); err != nil {
			errs = append(errs, fmt.Errorf("drain firewall %s before reload: %w", o.iface.Name, err))
			continue
		}
		if err := o.meter.(firewallMeter).UpdateFirewall(next); err != nil {
			errs = append(errs, fmt.Errorf("reload firewall %s: %w", o.iface.Name, err))
			continue
		}
		o.previousFirewall, o.firewall = o.firewall, next
		updated++
	}
	return updated, errors.Join(errs...)
}

func address(a [16]byte, family uint8) string {
	switch family {
	case 4:
		return netip.AddrFrom4([4]byte(a[:4])).String()
	case 6:
		return netip.AddrFrom16(a).String()
	default:
		return "-"
	}
}

func writeDrop(out io.Writer, host string, iface Interface, policy *firewall.Policy, drop Drop, timestamp time.Time) error {
	rule := "default"
	if drop.Rule != 0 {
		if drop.Generation != policy.Generation {
			// A packet already in flight can emit after its table was replaced.
			rule = fmt.Sprintf("generation:%d/rule:%d", drop.Generation, drop.Rule)
		} else {
			if int(drop.Rule) > len(policy.Rules) {
				return fmt.Errorf("invalid firewall drop rule index %d", drop.Rule)
			}
			rule = policy.Rules[drop.Rule-1].ID
		}
	}
	direction := "ingress"
	if drop.Direction == 2 {
		direction = "egress"
	}
	reasons := [...]string{"default-deny", "rule-deny", "malformed", "unsupported-or-fragment", "state-table-full", "policy-unavailable"}
	if drop.Reason >= uint8(len(reasons)) || (drop.Direction != 1 && drop.Direction != 2) {
		return fmt.Errorf("invalid firewall drop direction or reason")
	}
	action := "DROP"
	if !policy.Config.Enforces(drop.Direction) {
		action = "WOULD_DROP"
	}
	_, err := fmt.Fprintf(out, "%s %s veth-renamer[%d]: %s IF=%q DIR=%s SRC=%s DST=%s PROTO=%d SPT=%d DPT=%d LEN=%d RULE=%q REASON=%s TIME=%s\n",
		timestamp.Local().Format(time.Stamp), host, os.Getpid(), action, iface.Name, direction,
		address(drop.Source, drop.Family), address(drop.Destination, drop.Family), drop.Protocol,
		drop.SourcePort, drop.DestinationPort, drop.Octets, rule, reasons[drop.Reason], timestamp.Format(time.RFC3339Nano))
	return err
}

func (s *Service) logDrops(o *observed) error {
	if s.options.firewall == nil {
		return nil
	}
	m, ok := o.meter.(firewallMeter)
	if !ok {
		return fmt.Errorf("meter %s has no firewall drop reader", o.iface.Name)
	}
	drops, readErr := m.ReadDrops()
	for i, drop := range drops {
		policy := o.firewall
		if policy == nil {
			policy = s.options.firewall
		}
		if drop.Generation != policy.Generation && o.previousFirewall != nil && drop.Generation == o.previousFirewall.Generation {
			policy = o.previousFirewall
		}
		timestamp := time.Unix(0, s.export.bootUnixNS+int64(drop.Time))
		if err := writeDrop(s.dropLog, s.logHost, o.iface, policy, drop, timestamp); err != nil {
			return errors.Join(readErr, fmt.Errorf("write firewall drop log: %w; unlogged_drops=%d", err, len(drops)-i))
		}
	}
	return readErr
}

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
	Padding           [6]byte
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
	s.options.firewall = p
	s.dropLog = f
	s.logHost = host
	return nil
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
		if int(drop.Rule) > len(policy.Rules) {
			return fmt.Errorf("invalid firewall drop rule index %d", drop.Rule)
		}
		rule = policy.Rules[drop.Rule-1].ID
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
	if policy.Config.AuditMode {
		action = "WOULD_DROP"
	}
	_, err := fmt.Fprintf(out, "%s %s veth-renamer[%d]: %s IF=%q DIR=%s SRC=%s DST=%s PROTO=%d SPT=%d DPT=%d LEN=%d RULE=%q REASON=%s\n",
		timestamp.Local().Format(time.Stamp), host, os.Getpid(), action, iface.Name, direction,
		address(drop.Source, drop.Family), address(drop.Destination, drop.Family), drop.Protocol,
		drop.SourcePort, drop.DestinationPort, drop.Octets, rule, reasons[drop.Reason])
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
		timestamp := time.Unix(0, s.export.bootUnixNS+int64(drop.Time))
		if err := writeDrop(s.dropLog, s.logHost, o.iface, s.options.firewall, drop, timestamp); err != nil {
			return errors.Join(readErr, fmt.Errorf("write firewall drop log: %w; unlogged_drops=%d", err, len(drops)-i))
		}
	}
	return readErr
}

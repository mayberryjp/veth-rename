package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

const labelKey = "host-veth-name"

type mapping struct {
	ContainerID   string `json:"container_id"`
	Container     string `json:"container"`
	Network       string `json:"network"`
	NetworkID     string `json:"network_id"`
	Bridge        string `json:"bridge"`
	Namespace     string `json:"namespace,omitempty"`
	IPv4          string `json:"ipv4"`
	IPv6          string `json:"ipv6"`
	Interface     string `json:"interface"`
	IfIndex       int    `json:"ifindex"`
	RequestedName string `json:"requested_name"`
	Status        string `json:"status"`
	Error         string `json:"error,omitempty"`
}

type snapshot struct {
	UpdatedAt time.Time `json:"updated_at"`
	Mode      string    `json:"mode"`
	DryRun    bool      `json:"dry_run"`
	Mappings  []mapping `json:"mappings"`
}

type reconciler struct {
	docker dockerAPI
	links  linkAPI
	mode   string
	dryRun bool
}

type candidate struct {
	record int
	c      container
	ep     endpoint
	pid    int
	parent string
}

func (p candidate) target(inner, host []link, bridge string) (link, error) {
	if p.pid > 0 {
		return findMacvlan(inner, host, p.ep.MacAddress, p.parent)
	}
	return findPeer(inner, host, p.ep.MacAddress, bridge)
}

func validName(name string) error {
	if len(name) < 1 || len(name) > 15 {
		return fmt.Errorf("interface name %q must contain 1-15 ASCII characters", name)
	}
	for _, ch := range name {
		if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '_' || ch == '-' || ch == '.') {
			return fmt.Errorf("interface name %q contains unsupported characters; use letters, digits, _, - or .", name)
		}
	}
	if name == "." || name == ".." {
		return fmt.Errorf("invalid interface name %q", name)
	}
	return nil
}

func desiredName(c container, networkName string) (string, bool, error) {
	if name, ok := c.Config.Labels[labelKey+"."+networkName]; ok {
		return name, true, validName(name)
	}
	base, ok := c.Config.Labels[labelKey]
	if !ok {
		return "", false, nil
	}
	if err := validName(base); err != nil {
		return base, true, err
	}
	if len(c.NetworkSettings.Networks) == 1 {
		return base, true, nil
	}
	// Hash the network name, not its ID, so recreation preserves the requested name.
	hash := sha256.Sum256([]byte(networkName))
	if len(base) > 8 {
		base = base[:8]
	}
	return base + "-" + hex.EncodeToString(hash[:3]), true, nil
}

func networkKind(n network) string {
	if strings.HasPrefix(n.Driver, "ghcr.io/claymore666/docker-net-dhcp:") {
		switch n.Options["mode"] {
		case "", "bridge":
			return "bridge"
		case "macvlan":
			return "macvlan"
		}
	}
	return n.Driver
}

func bridgeName(n network) (string, error) {
	if networkKind(n) != "bridge" {
		return "", fmt.Errorf("unsupported network driver %q", n.Driver)
	}
	if n.Driver != "bridge" {
		if name := n.Options["bridge"]; name != "" {
			return name, nil
		}
		return "", fmt.Errorf("DHCP bridge network has no bridge interface configured")
	}
	if name := n.Options["com.docker.network.bridge.name"]; name != "" {
		return name, nil
	}
	if n.Options["com.docker.network.bridge.default_bridge"] == "true" {
		return "docker0", nil
	}
	if len(n.ID) < 12 {
		return "", fmt.Errorf("invalid bridge network ID %q", n.ID)
	}
	return "br-" + n.ID[:12], nil
}

func (r reconciler) run(ctx context.Context) (snapshot, error) {
	result := snapshot{UpdatedAt: time.Now().UTC(), Mode: r.mode, DryRun: r.dryRun, Mappings: []mapping{}}
	ids, err := r.docker.containers(ctx)
	if err != nil {
		return result, err
	}
	sort.Strings(ids)
	var problems []error
	fail := func(i int, err error) {
		m := &result.Mappings[i]
		m.Status, m.Error = "error", err.Error()
		problems = append(problems, fmt.Errorf("%s/%s: %w", m.Container, m.Network, err))
	}
	host, err := r.links.host(ctx)
	if err != nil {
		return result, err
	}
	var candidates []candidate
	for _, id := range ids {
		c, err := r.docker.inspect(ctx, id)
		if err != nil {
			result.Mappings = append(result.Mappings, mapping{ContainerID: id, Container: id})
			fail(len(result.Mappings)-1, err)
			continue
		}
		if !c.State.Running || c.State.Pid <= 0 {
			continue
		}
		// Host/shared namespaces do not have a private endpoint that this container owns.
		if c.HostConfig.NetworkMode == "host" || strings.HasPrefix(c.HostConfig.NetworkMode, "container:") {
			continue
		}
		names := make([]string, 0, len(c.NetworkSettings.Networks))
		for name := range c.NetworkSettings.Networks {
			names = append(names, name)
		}
		sort.Strings(names)
		var inner []link
		var innerErr error
		loaded := false
		for _, name := range names {
			desired, managed, nameErr := desiredName(c, name)
			if !managed {
				continue
			}
			ep := c.NetworkSettings.Networks[name]
			i := len(result.Mappings)
			result.Mappings = append(result.Mappings, mapping{
				ContainerID: c.ID, Container: strings.TrimPrefix(c.Name, "/"),
				Network: name, NetworkID: ep.NetworkID, IPv4: ep.IPAddress,
				IPv6: ep.GlobalIPv6Address, RequestedName: desired,
			})
			if nameErr != nil {
				fail(i, nameErr)
				continue
			}
			n, err := r.docker.network(ctx, ep.NetworkID)
			if err != nil {
				fail(i, err)
				continue
			}
			plan := candidate{record: i, c: c, ep: ep}
			switch networkKind(n) {
			case "bridge":
				bridge, err := bridgeName(n)
				if err != nil {
					fail(i, err)
					continue
				}
				result.Mappings[i].Bridge = bridge
				result.Mappings[i].Namespace = "host"
			case "macvlan":
				plan.pid, plan.parent = c.State.Pid, n.Options["parent"]
				result.Mappings[i].Namespace = "container"
			default:
				result.Mappings[i].Status = "skipped"
				result.Mappings[i].Error = "unsupported network driver: " + n.Driver
				continue
			}
			if !loaded {
				inner, innerErr = r.links.namespace(ctx, c.State.Pid)
				loaded = true
			}
			if innerErr != nil {
				fail(i, innerErr)
				continue
			}
			h, err := plan.target(inner, host, result.Mappings[i].Bridge)
			if err != nil {
				fail(i, err)
				continue
			}
			result.Mappings[i].Interface, result.Mappings[i].IfIndex = h.Name, h.Index
			candidates = append(candidates, plan)
		}
	}
	claims := map[string]int{}
	for _, m := range result.Mappings {
		if m.RequestedName != "" {
			claims[m.RequestedName]++
		}
	}
	for _, plan := range candidates {
		m := &result.Mappings[plan.record]
		if claims[m.RequestedName] != 1 {
			fail(plan.record, fmt.Errorf("name %q requested by multiple endpoints; refusing all claimants", m.RequestedName))
			continue
		}
		if err := r.apply(ctx, plan, m); err != nil {
			fail(plan.record, err)
		}
	}
	return result, errors.Join(problems...)
}

func (r reconciler) apply(ctx context.Context, plan candidate, m *mapping) error {
	current, err := r.docker.inspect(ctx, plan.c.ID)
	if err != nil {
		return err
	}
	ep, ok := current.NetworkSettings.Networks[m.Network]
	if !current.State.Running || current.State.Pid != plan.c.State.Pid || !ok ||
		current.HostConfig.NetworkMode != plan.c.HostConfig.NetworkMode ||
		ep.EndpointID != plan.ep.EndpointID || ep.NetworkID != plan.ep.NetworkID ||
		ep.MacAddress != plan.ep.MacAddress {
		return fmt.Errorf("container endpoint changed during reconciliation; will retry")
	}
	inner, err := r.links.namespace(ctx, current.State.Pid)
	if err != nil {
		return err
	}
	host, err := r.links.host(ctx)
	if err != nil {
		return err
	}
	h, err := plan.target(inner, host, m.Bridge)
	if err != nil {
		return err
	}
	if h.Index != m.IfIndex || h.Name != m.Interface {
		return fmt.Errorf("%s interface changed during reconciliation; will retry", m.Namespace)
	}
	available := host
	if plan.pid > 0 {
		available = inner
	}
	for _, other := range available {
		if ownsName(other, m.RequestedName) && other.Index != h.Index {
			return fmt.Errorf("name %q is already owned by interface %q", m.RequestedName, other.Name)
		}
	}
	if h.Name == m.RequestedName || r.mode == "alternative" && ownsName(h, m.RequestedName) {
		m.Status = "unchanged"
		return nil
	}
	if ownsName(h, m.RequestedName) {
		return fmt.Errorf("requested primary name is already an alternative name on this interface; remove it manually first")
	}
	if r.dryRun {
		m.Status = "would-change"
		return nil
	}
	if err := r.links.apply(ctx, plan.pid, h.Name, m.RequestedName, r.mode); err != nil {
		return fmt.Errorf("apply %s name (links are never taken down; UP links commonly reject primary renames): %w", r.mode, err)
	}
	var after []link
	if plan.pid > 0 {
		after, err = r.links.namespace(ctx, plan.pid)
	} else {
		after, err = r.links.host(ctx)
	}
	if err != nil {
		return fmt.Errorf("name command succeeded but verification failed: %w", err)
	}
	for _, changed := range after {
		if changed.Index == h.Index && changed.Peer == h.Peer && changed.Master == h.Master &&
			changed.Info.Kind == h.Info.Kind && strings.EqualFold(changed.Address, h.Address) &&
			(r.mode == "primary" && changed.Name == m.RequestedName || r.mode == "alternative" && ownsName(changed, m.RequestedName)) {
			m.Interface, m.Status = changed.Name, "applied"
			return nil
		}
	}
	return fmt.Errorf("interface disappeared or name was not present after applying it; will retry")
}

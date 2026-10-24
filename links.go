package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

type link struct {
	Index    int      `json:"ifindex"`
	Name     string   `json:"ifname"`
	Peer     int      `json:"link_index"`
	Address  string   `json:"address"`
	Master   string   `json:"master"`
	AltNames []string `json:"altnames"`
	PeerName string   `json:"link"`
	Flags    []string `json:"flags"`
	NetNSID  *int     `json:"link_netnsid"`
	Info     struct {
		Kind string `json:"info_kind"`
	} `json:"linkinfo"`
}

type linkAPI interface {
	host(context.Context) ([]link, error)
	namespace(context.Context, int) ([]link, error)
	apply(context.Context, int, string, string, string) error
}

type commandLinks struct {
	ip      string
	nsenter string
}

func command(ctx context.Context, program string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, program, args...).CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("%s %s: %w: %s", program, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return out, nil
}

func readLinks(ctx context.Context, program string, args ...string) ([]link, error) {
	out, err := command(ctx, program, args...)
	if err != nil {
		return nil, err
	}
	var links []link
	if err := json.Unmarshal(out, &links); err != nil {
		return nil, fmt.Errorf("decode ip link output: %w", err)
	}
	return links, nil
}

func (l commandLinks) host(ctx context.Context) ([]link, error) {
	return readLinks(ctx, l.ip, "-j", "-d", "link", "show")
}

func (l commandLinks) namespace(ctx context.Context, pid int) ([]link, error) {
	// Query rtnetlink inside the netns; host-mounted sysfs can describe the wrong namespace.
	return readLinks(ctx, l.nsenter, "-t", strconv.Itoa(pid), "-n", "--", l.ip, "-j", "-d", "link", "show")
}

func (l commandLinks) nameCommand(pid int, current, desired, mode string) (string, []string) {
	var args []string
	if mode == "alternative" {
		args = []string{"link", "property", "add", "dev", current, "altname", desired}
	} else {
		args = []string{"link", "set", "dev", current, "name", desired}
	}
	if pid > 0 {
		return l.nsenter, append([]string{"-t", strconv.Itoa(pid), "-n", "--", l.ip}, args...)
	}
	return l.ip, args
}

func (l commandLinks) apply(ctx context.Context, pid int, current, desired, mode string) error {
	program, args := l.nameCommand(pid, current, desired, mode)
	_, err := command(ctx, program, args...)
	return err
}

func sameLink(current, expected link) bool {
	return current.Index == expected.Index && current.Name == expected.Name &&
		current.Peer == expected.Peer && current.PeerName == expected.PeerName &&
		current.Master == expected.Master && current.Info.Kind == expected.Info.Kind &&
		strings.EqualFold(current.Address, expected.Address)
}

func (l commandLinks) change(ctx context.Context, expected link, action, value string) error {
	links, err := l.host(ctx)
	if err != nil {
		return err
	}
	found := false
	for _, current := range links {
		if sameLink(current, expected) {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("interface identity changed before %s %q; refusing mutation", action, value)
	}
	var args []string
	switch action {
	case "state":
		if value != "up" && value != "down" {
			return fmt.Errorf("invalid link state %q", value)
		}
		args = []string{"link", "set", "dev", expected.Name, value}
	case "name":
		if err := validName(value); err != nil {
			return err
		}
		args = []string{"link", "set", "dev", expected.Name, "name", value}
	case "del-altname", "add-altname":
		verb := "del"
		if action == "add-altname" {
			verb = "add"
		}
		args = []string{"link", "property", verb, "dev", expected.Name, "altname", value}
	default:
		return fmt.Errorf("unsupported repair operation %q", action)
	}
	_, err = command(ctx, l.ip, args...)
	return err
}

func ownsName(l link, name string) bool {
	if l.Name == name {
		return true
	}
	for _, alt := range l.AltNames {
		if alt == name {
			return true
		}
	}
	return false
}

func findPeer(inner, host []link, mac, bridge string) (link, error) {
	if mac == "" {
		return link{}, fmt.Errorf("Docker endpoint has no MAC address yet")
	}
	var matches []link
	for _, in := range inner {
		if !strings.EqualFold(in.Address, mac) || in.Info.Kind != "veth" || in.Peer <= 0 {
			continue
		}
		for _, h := range host {
			if h.Index == in.Peer && h.Peer == in.Index && h.Info.Kind == "veth" && h.Master == bridge {
				matches = append(matches, h)
			}
		}
	}
	if len(matches) != 1 {
		return link{}, fmt.Errorf("expected one reciprocal veth peer on bridge %q for MAC %s; found %d", bridge, mac, len(matches))
	}
	return matches[0], nil
}

func findMacvlan(inner, host []link, mac, parent string) (link, error) {
	if mac == "" {
		return link{}, fmt.Errorf("Docker endpoint has no MAC address yet")
	}
	if parent == "" {
		return link{}, fmt.Errorf("macvlan network has no parent interface configured")
	}
	var parents []link
	for _, h := range host {
		if ownsName(h, parent) && h.Index > 0 {
			parents = append(parents, h)
		}
	}
	if len(parents) != 1 {
		return link{}, fmt.Errorf("expected one host parent interface %q; found %d", parent, len(parents))
	}
	var matches []link
	for _, in := range inner {
		if strings.EqualFold(in.Address, mac) && in.Info.Kind == "macvlan" && in.Peer == parents[0].Index {
			matches = append(matches, in)
		}
	}
	if len(matches) != 1 {
		return link{}, fmt.Errorf("expected one macvlan interface on parent %q for MAC %s; found %d", parent, mac, len(matches))
	}
	return matches[0], nil
}

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
	Info     struct {
		Kind string `json:"info_kind"`
	} `json:"linkinfo"`
}

type linkAPI interface {
	host(context.Context) ([]link, error)
	namespace(context.Context, int) ([]link, error)
	apply(context.Context, string, string, string) error
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
		return nil, fmt.Errorf("%s %s: %w: %s", program, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
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

func (l commandLinks) apply(ctx context.Context, current, desired, mode string) error {
	var err error
	if mode == "alternative" {
		_, err = command(ctx, l.ip, "link", "property", "add", "dev", current, "altname", desired)
	} else {
		_, err = command(ctx, l.ip, "link", "set", "dev", current, "name", desired)
	}
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

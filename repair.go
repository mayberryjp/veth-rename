package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

type repairAPI interface {
	host(context.Context) ([]link, error)
	change(context.Context, link, string, string) error
}

func hasFlag(target link, flag string) bool {
	for _, value := range target.Flags {
		if value == flag {
			return true
		}
	}
	return false
}

func hostPeer(links []link, target link) (link, bool) {
	if target.NetNSID != nil {
		return link{}, false
	}
	for _, peer := range links {
		if target.Peer > 0 && peer.Index == target.Peer || target.Peer == 0 && target.PeerName != "" && peer.Name == target.PeerName {
			return peer, true
		}
	}
	return link{}, false
}

func staleDHCPName(links []link, target, stale link, endpointMAC string) (string, error) {
	peer, found := hostPeer(links, stale)
	back, reciprocal := hostPeer(links, peer)
	if !found || !reciprocal || back.Index != stale.Index || stale.Index == target.Index ||
		stale.Info.Kind != "veth" || peer.Info.Kind != "veth" ||
		stale.Master != target.Master || peer.Master != "" ||
		len(stale.Flags) == 0 || hasFlag(stale, "LOWER_UP") || hasFlag(stale, "UP") && !hasFlag(stale, "NO-CARRIER") ||
		len(peer.Flags) == 0 || hasFlag(peer, "UP") ||
		!strings.EqualFold(peer.Address, endpointMAC) {
		return "", fmt.Errorf("conflicting interface is not a proven disconnected DHCP veth pair")
	}
	identity := strings.TrimSuffix(peer.Name, "-dh")
	decoded, err := hex.DecodeString(identity)
	if !strings.HasSuffix(peer.Name, "-dh") || err != nil || len(decoded) != 6 {
		return "", fmt.Errorf("disconnected peer has no recognized DHCP endpoint name")
	}
	original := "dh-" + identity
	for _, other := range links {
		if ownsName(other, original) {
			return "", fmt.Errorf("original DHCP name %q is already occupied", original)
		}
	}
	return original, nil
}

func repairPrimary(ctx context.Context, links repairAPI, target link, desired string, stale *link, staleName, endpointMAC string, validate func(context.Context, link) error) (result link, problem error) {
	result = target
	current := target
	original := target
	var movedStale *link
	var staleOriginal link
	committed := false
	liveTouched := false
	removedAlt := false
	defer func() {
		if committed {
			return
		}
		recovery, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		if liveTouched && current.Name != original.Name {
			if err := links.change(recovery, current, "state", "down"); err != nil {
				problem = errors.Join(problem, fmt.Errorf("rollback down: %w", err))
			} else if err := links.change(recovery, current, "name", original.Name); err != nil {
				problem = errors.Join(problem, fmt.Errorf("rollback name: %w", err))
			} else {
				current.Name = original.Name
			}
		}
		if liveTouched && hasFlag(original, "UP") {
			if err := links.change(recovery, current, "state", "up"); err != nil {
				problem = errors.Join(problem, fmt.Errorf("restore live interface UP: %w", err))
			}
		}
		if removedAlt && current.Name == original.Name {
			if err := links.change(recovery, current, "add-altname", desired); err != nil {
				problem = errors.Join(problem, fmt.Errorf("restore original alternative name: %w", err))
			}
		}
		if movedStale != nil && current.Name != desired {
			if movedStale.Name != staleOriginal.Name {
				if err := links.change(recovery, *movedStale, "state", "down"); err != nil {
					problem = errors.Join(problem, fmt.Errorf("rollback stale down: %w", err))
				} else if err := links.change(recovery, *movedStale, "name", staleOriginal.Name); err != nil {
					problem = errors.Join(problem, fmt.Errorf("rollback stale name: %w", err))
				} else {
					movedStale.Name = staleOriginal.Name
				}
			}
			if hasFlag(staleOriginal, "UP") {
				if err := links.change(recovery, *movedStale, "state", "up"); err != nil {
					problem = errors.Join(problem, fmt.Errorf("restore stale interface state: %w", err))
				}
			}
		}
	}()
	if err := validate(ctx, current); err != nil {
		return result, err
	}
	if stale != nil {
		staleOriginal = *stale
		moved := *stale
		movedStale = &moved
		checkStale := func() error {
			fresh, err := links.host(ctx)
			if err != nil {
				return err
			}
			for _, actual := range fresh {
				if sameLink(actual, moved) {
					originalName, err := staleDHCPName(fresh, target, actual, endpointMAC)
					if err == nil && originalName == staleName {
						return nil
					}
					return fmt.Errorf("disconnected pair changed before reclamation: %v", err)
				}
			}
			return fmt.Errorf("stale interface identity changed before reclamation")
		}
		if err := checkStale(); err != nil {
			movedStale = nil
			return result, err
		}
		if hasFlag(moved, "UP") {
			if err := links.change(ctx, moved, "state", "down"); err != nil {
				return result, err
			}
		}
		if err := checkStale(); err != nil {
			return result, err
		}
		if err := links.change(ctx, moved, "name", staleName); err != nil {
			return result, err
		}
		moved.Name = staleName
		if hasFlag(staleOriginal, "UP") {
			if err := links.change(ctx, moved, "state", "up"); err != nil {
				return result, err
			}
		}
	}
	if err := validate(ctx, current); err != nil {
		return result, err
	}
	if hasFlag(current, "UP") {
		liveTouched = true
		if err := links.change(ctx, current, "state", "down"); err != nil {
			return result, err
		}
	}
	if ownsName(current, desired) && current.Name != desired {
		if err := links.change(ctx, current, "del-altname", desired); err != nil {
			return result, err
		}
		removedAlt = true
	}
	liveTouched = true
	if err := links.change(ctx, current, "name", desired); err != nil {
		return result, err
	}
	current.Name = desired
	if hasFlag(original, "UP") {
		if err := links.change(ctx, current, "state", "up"); err != nil {
			return result, err
		}
	}
	if err := validate(ctx, current); err != nil {
		return result, fmt.Errorf("repair verification failed: %w", err)
	}
	fresh, err := links.host(ctx)
	if err != nil {
		return result, err
	}
	verified := false
	for _, actual := range fresh {
		if sameLink(actual, current) && hasFlag(actual, "UP") == hasFlag(original, "UP") {
			result, verified = actual, true
			break
		}
	}
	if !verified {
		return result, fmt.Errorf("primary repair name/state readback failed")
	}
	committed = true
	return result, nil
}

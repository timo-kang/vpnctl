// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayapply

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

type deploymentKernel struct{ kernel }

func deploymentOwner(l object, e DeploymentEntry) bool {
	return kind(l) == "wireguard" && n(l, "ifindex") == e.LinkIndex && n(l, "group") == e.Group && (str(l, "ifalias") == e.Alias || e.Phase != "applied" && str(l, "ifalias") == "")
}
func deploymentRoute(r object, e DeploymentEntry, p DeploymentPeer) bool {
	return n(r, "table") == 254 && n(r, "protocol") == 186 && n(r, "metric") == e.Group && str(r, "dev") == e.Interface && (str(r, "dst") == p.Address || str(r, "dst") == strings.TrimSuffix(p.Address, "/32")) && (str(r, "type") == "" || str(r, "type") == "unicast" || str(r, "type") == "1") && (str(r, "scope") == "link" || str(r, "scope") == "253") && only(r, "table", "protocol", "metric", "dev", "dst", "type", "scope", "flags")
}
func (k deploymentKernel) inventory(ctx context.Context, e DeploymentEntry, fresh bool) (snapshot, object, bool, int, error) {
	s, err := k.snapshot(ctx)
	if err != nil {
		return s, nil, false, 0, err
	}
	l, exists := getLink(s, e.Interface)
	for _, x := range s.links {
		if n(x, "ifindex") == e.LinkIndex && (fresh || str(x, "ifname") != e.Interface) {
			return s, l, exists, 0, ErrConflict
		}
	}
	if exists && (fresh || !deploymentOwner(l, e)) {
		return s, l, exists, 0, ErrConflict
	}
	count := 0
	seen := map[string]bool{}
	for _, r := range s.routes {
		matched := false
		for _, p := range e.Peers {
			if str(r, "dst") != p.Address && str(r, "dst") != strings.TrimSuffix(p.Address, "/32") {
				continue
			}
			if fresh || !exists || !deploymentRoute(r, e, p) || seen[p.Address] {
				return s, l, exists, 0, ErrConflict
			}
			seen[p.Address] = true
			matched = true
			count++
		}
		if str(r, "dev") == e.Interface && !matched {
			return s, l, exists, 0, ErrConflict
		}
	}
	// Refuse another WG listener on the same local UDP port. External NAT
	// mappings and policy routing remain deployment responsibilities.
	b, err := k.run(ctx, "", "wg", "show", "all", "listen-port")
	if err != nil {
		return s, l, exists, 0, err
	}
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if line == "" {
			continue
		}
		f := strings.Fields(line)
		if len(f) != 2 {
			return s, l, exists, 0, errors.New("invalid WG listener inventory")
		}
		port, x := strconv.Atoi(f[1])
		if x != nil || port < 0 || port > 65535 {
			return s, l, exists, 0, errors.New("invalid WG listener inventory")
		}
		if port == e.ListenPort && (fresh || f[0] != e.Interface) {
			return s, l, exists, 0, ErrConflict
		}
	}
	return s, l, exists, count, nil
}
func (k deploymentKernel) wire(ctx context.Context, e DeploymentEntry) (bool, error) {
	a, err := k.list(ctx, "-j", "address", "show", "dev", e.Interface)
	if err != nil {
		return false, err
	}
	if len(a) != 1 {
		return false, ErrConflict
	}
	addresses, ok := a[0]["addr_info"].([]any)
	if !ok || addresses == nil || len(addresses) > 16 {
		return false, ErrConflict
	}
	for _, v := range addresses {
		x, ok := v.(map[string]any)
		if !ok || str(x, "family") != "inet6" || str(x, "scope") != "link" {
			return false, ErrConflict
		}
	}
	// Even an unrelated IPv6 route prevents deleting an externally used link.
	v6, err := k.list(ctx, "-j", "-N", "-6", "route", "show", "table", "all")
	if err != nil {
		return false, err
	}
	for _, r := range v6 {
		// An up WG link gets this local multicast route even without an IPv6
		// address. It is kernel-generated, not an operator-owned return route.
		multicast := str(r, "dst") == "ff00::/8" && n(r, "type") == 5 && n(r, "table") == 255 && n(r, "protocol") == 2 && n(r, "metric") == 256 && only(r, "dst", "dev", "type", "table", "protocol", "metric", "flags", "pref")
		if str(r, "dev") == e.Interface && !multicast && !(n(r, "protocol") == 2 && strings.HasPrefix(str(r, "dst"), "fe80:")) {
			return false, ErrConflict
		}
	}
	b, err := k.run(ctx, "", "wg", "show", e.Interface, "dump")
	if err != nil {
		return false, err
	}
	// dump includes private material. Never persist or include it in errors;
	// the validator consumes and clears the owned command output buffer.
	return validateDeploymentWire(b, e)
}

func (k deploymentKernel) Check(ctx context.Context, e DeploymentEntry, fresh bool) (bool, error) {
	if e.PolicyVersion == 1 {
		present, err := k.policyRead(ctx, e)
		if err != nil || fresh && present {
			return false, errors.Join(err, ErrConflict)
		}
		if !fresh && !present {
			return false, errors.New("relay forwarding policy missing")
		}
	}
	if fresh && e.LeaseVersion >= 1 {
		if _, exists, err := k.leaseRead(ctx, e); err != nil {
			return false, err
		} else if exists {
			return false, ErrConflict
		}
		if err := k.noFlowtables(ctx); err != nil {
			return false, err
		}
	}
	s, l, exists, count, err := k.inventory(ctx, e, fresh)
	if err != nil || fresh || !exists {
		return false, err
	}
	if s.marks[e.Interface] != 0 {
		return false, ErrConflict
	}
	complete, err := k.wire(ctx, e)
	return err == nil && complete && count == len(e.Peers) && hasFlag(l, "UP") && n(l, "mtu") == 1280 && str(l, "ifalias") == e.Alias, err
}
func (k deploymentKernel) Step(ctx context.Context, e DeploymentEntry, step, key string) error {
	if step == "guard" {
		if err := k.leaseCreate(ctx, e); err != nil {
			return err
		}
		return k.policyCreate(ctx, e)
	}
	_, _, exists, _, err := k.inventory(ctx, e, step == "link")
	if err != nil {
		return err
	}
	if step != "link" {
		if !exists {
			return ErrConflict
		}
		if _, err = k.wire(ctx, e); err != nil {
			return err
		}
	}
	name, input, args := "ip", "", []string{}
	switch step {
	case "link":
		args = []string{"link", "add", "name", e.Interface, "index", decimal(e.LinkIndex), "group", decimal(e.Group), "mtu", "1280", "type", "wireguard"}
	case "tag":
		args = []string{"link", "set", "dev", e.Interface, "alias", e.Alias}
	case "wg":
		name = "wg"
		args = []string{"setconf", e.Interface, "/dev/stdin"}
		input = fmt.Sprintf("[Interface]\nPrivateKey = %s\nListenPort = %d\nFwMark = 0\n", key, e.ListenPort)
		for _, p := range e.Peers {
			input += fmt.Sprintf("[Peer]\nPublicKey = %s\nAllowedIPs = %s\nPersistentKeepalive = 0\n", p.PublicKey, p.Address)
		}
	case "routes":
		if len(e.Peers) == 0 {
			return nil
		}
		args = []string{"-4", "-batch", "/dev/stdin"}
		for _, p := range e.Peers {
			input += fmt.Sprintf("route add %s dev %s scope link table 254 proto 186 metric %d\n", p.Address, e.Interface, e.Group)
		}
	case "up":
		args = []string{"link", "set", "dev", e.Interface, "up"}
	default:
		return errors.New("invalid deployment step")
	}
	_, err = k.run(ctx, input, name, args...)
	return err
}
func (k deploymentKernel) Down(ctx context.Context, e DeploymentEntry) error {
	var guardErr error
	if e.LeaseVersion >= 1 {
		guardErr = k.leaseBlock(ctx, e)
	}
	_, l, exists, _, err := k.inventory(ctx, e, false)
	if err != nil || !exists {
		return errors.Join(guardErr, err)
	}
	if _, err = k.wire(ctx, e); err != nil {
		return errors.Join(guardErr, err)
	}
	if !hasFlag(l, "UP") {
		return guardErr
	}
	_, err = k.run(ctx, "", "ip", "link", "set", "dev", e.Interface, "down")
	return errors.Join(guardErr, err)
}
func (k deploymentKernel) Remove(ctx context.Context, e DeploymentEntry) error {
	// A changed firewall belongs to an external operator: block the lease,
	// preserve the journal and refuse destructive cleanup.
	if e.PolicyVersion == 1 {
		if _, err := k.policyRead(ctx, e); err != nil {
			return err
		}
	}
	_, _, exists, _, err := k.inventory(ctx, e, false)
	if err != nil {
		return err
	}
	if !exists {
		if e.LeaseVersion >= 1 {
			if err := k.leaseRemove(ctx, e); err != nil {
				return err
			}
			return k.policyRemove(ctx, e)
		}
		return nil
	}
	if _, err = k.wire(ctx, e); err != nil {
		return err
	}
	// Removing the owned link removes only its already-checked /32 routes.
	if _, err = k.run(ctx, "", "ip", "link", "del", "dev", e.Interface); err != nil {
		return err
	}
	if e.LeaseVersion >= 1 {
		if err = k.leaseRemove(ctx, e); err != nil {
			return err
		}
	}
	if err = k.policyRemove(ctx, e); err != nil {
		return err
	}
	_, err = k.Check(ctx, e, true)
	return err
}

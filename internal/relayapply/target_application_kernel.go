// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayapply

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"vpnctl/internal/relaycatalog"
)

type targetApplicationBackend interface {
	SetRoutes(context.Context, TargetGuard, []Entry, *TargetRoute) error
	CheckRoutes(context.Context, TargetGuard, []Entry, *TargetRoute) error
	ProbeApplication(context.Context, TargetGuard, Entry, relaycatalog.Target) (ApplicationProof, error)
}

// Candidate checks tolerate only routes described by this same private journal.
// Their complete target reservation must still be present; arbitrary routes on
// the WireGuard device remain conflicts, including routes in another table.
func candidateApplicationSnapshot(s snapshot, entry Entry, targets []TargetGuard) (snapshot, error) {
	filtered := s
	filtered.routes = make([]object, 0, len(s.routes))
	for _, r := range s.routes {
		owned := false
		for _, g := range targets {
			for _, ref := range []*TargetRoute{g.Active, g.Pending} {
				if ref == nil || !sameTargetRoute(ref, routeForEntry(entry)) || applicationRoutePrefix(r, g, ref) == "" {
					continue
				}
				guard, rules, err := targetGuardOwnership(s, g, false)
				if err != nil || !guard || len(rules) != len(g.Prefixes) {
					return s, errors.Join(ErrConflict, err)
				}
				owned = true
			}
		}
		if !owned {
			filtered.routes = append(filtered.routes, r)
		}
	}
	return filtered, nil
}

func applicationRoutePrefix(o object, g TargetGuard, r *TargetRoute) string {
	if r == nil || n(o, "table") != g.Table || n(o, "metric") != g.Metric || n(o, "protocol") != 186 || str(o, "dev") != r.Interface || str(o, "prefsrc") != r.Source || str(o, "scope") != "link" && str(o, "scope") != "253" || str(o, "type") != "" && str(o, "type") != "unicast" && str(o, "type") != "1" || !only(o, "type", "dst", "table", "protocol", "metric", "dev", "prefsrc", "scope", "flags") {
		return ""
	}
	for _, p := range g.Prefixes {
		if str(o, "dst") == p || str(o, "dst") == strings.TrimSuffix(p, "/32") {
			return p
		}
	}
	return ""
}
func applicationRouteArgs(g TargetGuard, r TargetRoute, prefix, verb string) []string {
	return []string{"-4", "route", verb, prefix, "table", decimal(g.Table), "proto", protocol, "metric", decimal(g.Metric), "dev", r.Interface, "src", r.Source, "scope", "link"}
}
func targetApplicationRoutes(s snapshot, g TargetGuard, want *TargetRoute) (bool, error) {
	if _, _, err := targetGuardOwnership(s, g, false); err != nil {
		return false, err
	}
	count := 0
	for _, o := range s.routes {
		if n(o, "table") != g.Table || guardRouteMatches(o, g) {
			continue
		}
		if applicationRoutePrefix(o, g, want) == "" {
			return false, nil
		}
		count++
	}
	if want == nil {
		return count == 0, nil
	}
	return count == len(g.Prefixes), nil
}
func (k targetKernel) CheckRoutes(ctx context.Context, g TargetGuard, entries []Entry, want *TargetRoute) error {
	s, err := k.snapshot(ctx)
	if err != nil {
		return err
	}
	ready, err := targetGuardConflicts(s, g, entries, false)
	if err != nil || !ready {
		return errors.Join(ErrConflict, err)
	}
	ready, err = targetApplicationRoutes(s, g, want)
	if err != nil || !ready {
		return errors.Join(ErrRecovery, err)
	}
	return nil
}

// SetRoutes never uses route replace/flush. It deletes only the exact old tuple
// and exclusively adds the new tuple. The terminal unreachable default remains
// installed between these steps and across every prefix of an interrupted switch.
// nil entries means explicit release: preserve foreign state without claiming
// routing precedence over it; only ownership is required to remove our routes.
func (k targetKernel) SetRoutes(ctx context.Context, g TargetGuard, entries []Entry, want *TargetRoute) error {
	if want != nil && !sameTargetRoute(want, g.Active) && !sameTargetRoute(want, g.Pending) {
		return ErrConflict
	}
	for _, prefix := range g.Prefixes {
		for step := 0; step < 2; step++ {
			s, err := k.snapshot(ctx)
			if err != nil {
				return err
			}
			guard, rules, err := targetGuardOwnership(s, g, false)
			if err != nil {
				return err
			}
			if want != nil {
				ready, err := targetGuardConflicts(s, g, entries, false)
				if err != nil || !ready {
					return errors.Join(ErrConflict, err)
				}
			}
			if !guard || len(rules) != len(g.Prefixes) {
				// Cleanup may still remove our unicast route after external deletion
				// of a guard/rule, but must never open another route in that state.
				if want != nil {
					return ErrConflict
				}
			}
			var installed *TargetRoute
			for _, o := range s.routes {
				if applicationRoutePrefix(o, g, g.Active) == prefix {
					installed = g.Active
				} else if applicationRoutePrefix(o, g, g.Pending) == prefix {
					installed = g.Pending
				}
			}
			if sameTargetRoute(installed, want) {
				break
			}
			if installed != nil {
				if _, err = k.run(ctx, "", "ip", applicationRouteArgs(g, *installed, prefix, "del")...); err != nil {
					return err
				}
			} else if want != nil {
				if _, err = k.run(ctx, "", "ip", applicationRouteArgs(g, *want, prefix, "add")...); err != nil {
					return err
				}
			}
		}
	}
	s, err := k.snapshot(ctx)
	if err != nil {
		return err
	}
	ready, err := targetApplicationRoutes(s, g, want)
	if err != nil || !ready {
		return errors.Join(ErrRecovery, err)
	}
	return nil
}

func (k targetKernel) appRoute(ctx context.Context, g TargetGuard, entry Entry, target relaycatalog.Target) error {
	rows, err := k.list(ctx, "-j", "-N", "-4", "route", "get", target.ProbeAddress, "mark", "0")
	if err != nil {
		return err
	}
	if len(rows) != 1 {
		return ErrConflict
	}
	r := rows[0]
	if str(r, "dev") != entry.Candidate.Pin.WGInterface || str(r, "prefsrc") != strings.TrimSuffix(entry.Candidate.InnerAddress, "/32") || n(r, "table") != g.Table || str(r, "gateway") != "" || str(r, "type") != "" && str(r, "type") != "unicast" && str(r, "type") != "1" {
		return errors.New("unbound application lookup escaped target table/source/device")
	}
	return nil
}
func (k targetKernel) ProbeApplication(ctx context.Context, g TargetGuard, entry Entry, target relaycatalog.Target) (ApplicationProof, error) {
	out := ApplicationProof{Evidence: "unbound_tcp_connect", Interface: entry.Candidate.Pin.WGInterface, Source: strings.TrimSuffix(entry.Candidate.InnerAddress, "/32")}
	if err := k.appRoute(ctx, g, entry, target); err != nil {
		return out, err
	}
	before, err := k.targetCounters(ctx, entry)
	if err != nil {
		return out, err
	}
	// No LocalAddr, SO_BINDTODEVICE or nonzero mark: exercise an ordinary app.
	start := time.Now()
	dial := net.Dialer{}
	c, err := dial.DialContext(ctx, "tcp4", net.JoinHostPort(target.ProbeAddress, fmt.Sprint(target.Port)))
	if err != nil {
		return out, classifyTargetConnect(err)
	}
	defer c.Close()
	connectTime := time.Since(start)
	local, ok := c.LocalAddr().(*net.TCPAddr)
	if !ok || local.IP.String() != out.Source {
		return out, errors.New("unbound application used unexpected source")
	}
	if err := k.appRoute(ctx, g, entry, target); err != nil {
		return out, err
	}
	after, err := k.targetCounters(ctx, entry)
	if err != nil || after.handshake <= 0 || after.rx <= before.rx || after.tx <= before.tx {
		return out, errors.Join(errors.New("unbound TCP lacks selected WG evidence"), err)
	}
	out.ObservedAt, out.ConnectTime = time.Now(), connectTime
	return out, nil
}

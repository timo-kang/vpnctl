// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relaycache

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"
	"time"

	"vpnctl/internal/relaycatalog"
	"vpnctl/internal/relayguard"
)

// ApprovalWitness is a durable upper bound, never permission to reopen a
// stopped kernel lease. RequestAt/RequestBootNS precede the authenticated RPC.
type ApprovalWitness struct {
	Controller    string    `json:"controller_id"`
	Node          string    `json:"node_id"`
	Generation    uint64    `json:"generation"`
	Domain        string    `json:"kernel_domain"`
	RequestAt     time.Time `json:"request_at"`
	RequestBootNS uint64    `json:"request_boot_ns"`
	ExpiresAt     time.Time `json:"expires_at"`
	UntilBootNS   uint64    `json:"until_boot_ns"`
}

type approvalStamp struct {
	at     time.Time
	boot   uint64
	domain string
}

// KernelDomain prevents carrying a BOOTTIME value across boot or netns changes.
func KernelDomain() (string, error) {
	b, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return "", err
	}
	st, err := os.Stat("/proc/self/ns/net")
	if err != nil {
		return "", err
	}
	s, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return "", errors.New("network namespace identity unavailable")
	}
	return fmt.Sprintf("%s:%d:%d", strings.TrimSpace(string(b)), s.Dev, s.Ino), nil
}

func (s *Store) requestStamp() approvalStamp {
	d, err := KernelDomain()
	if err != nil {
		return approvalStamp{}
	}
	// BOOTTIME first: a pause between clock reads can only shorten validity.
	b, err := relayguard.Now()
	if err != nil {
		return approvalStamp{}
	}
	return approvalStamp{s.now(), b, d}
}

func (s *Store) witness(v relaycatalog.View, start approvalStamp) *ApprovalWitness {
	old := s.state.Approval
	if old != nil && old.Controller == v.ControllerID && old.Generation == v.Generation && (start.domain == "" || old.Domain == start.domain) {
		// Keep the original anchor immutable. New authenticated requests provide
		// transient rearm evidence, not a new lifetime for the same response.
		copy := *old
		return &copy
	}
	remaining := v.ExpiresAt.Sub(start.at)
	if start.boot == 0 || start.domain == "" || remaining <= 0 || uint64(remaining) > ^uint64(0)-start.boot {
		return nil
	}
	w := &ApprovalWitness{v.ControllerID, s.nodeID, v.Generation, start.domain, start.at.UTC(), start.boot, v.ExpiresAt, start.boot + uint64(remaining)}
	if old != nil && old.Controller == w.Controller && old.Domain == w.Domain {
		// Binding or policy changes can advance generation without extending
		// ExpiresAt. Preserve the earlier clock mapping across that transition.
		delta := w.ExpiresAt.Sub(old.ExpiresAt)
		if delta >= 0 && uint64(delta) <= ^uint64(0)-old.UntilBootNS {
			w.UntilBootNS = min(w.UntilBootNS, old.UntilBootNS+uint64(delta))
		} else if delta < 0 {
			if uint64(-delta) >= old.UntilBootNS {
				return nil
			}
			w.UntilBootNS = min(w.UntilBootNS, old.UntilBootNS-uint64(-delta))
		}
	}
	return w
}

func validateWitness(w *ApprovalWitness, v diskState) error {
	if w == nil {
		return nil
	} // Old caches must refresh before using protection.
	remaining := w.ExpiresAt.Sub(w.RequestAt)
	if v.Catalog == nil || w.Controller != v.Catalog.ControllerID || w.Node != v.NodeID || w.Generation != v.Catalog.Generation || !w.ExpiresAt.Equal(v.Catalog.ExpiresAt) || w.Domain == "" || len(w.Domain) > 128 || w.RequestAt.IsZero() || w.RequestBootNS == 0 || w.UntilBootNS == 0 || remaining <= 0 || uint64(remaining) > ^uint64(0)-w.RequestBootNS || w.UntilBootNS > w.RequestBootNS+uint64(remaining) {
		return ErrCorrupt
	}
	return nil
}

// LeaseApproval returns a persisted bound and, separately, process-local proof
// of this Refresh's accepted request. Fresh proof is deliberately lost on Open.
// Neither a last-success timestamp nor the persisted RequestAt can rearm a lease.
func (s *Store) LeaseApproval() (ApprovalWitness, time.Time, uint64, error) {
	if !s.mu.TryLock() {
		return ApprovalWitness{}, time.Time{}, 0, ErrBusy
	}
	defer s.mu.Unlock()
	if s.closed || s.uncertain || !s.report().UsableCache || s.state.Approval == nil {
		return ApprovalWitness{}, time.Time{}, 0, errors.New("node lease approval unavailable")
	}
	w := *s.state.Approval
	stamp := s.stamp()
	if stamp.domain != w.Domain || stamp.boot < w.RequestBootNS || stamp.boot >= w.UntilBootNS || !stamp.at.Before(w.ExpiresAt) {
		return ApprovalWitness{}, time.Time{}, 0, errors.New("node approval domain changed or expired")
	}
	return w, s.fresh.at, s.fresh.boot, nil
}

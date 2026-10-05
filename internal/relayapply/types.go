// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

// Package relayapply prepares inactive, approved WireGuard candidates. It does
// not select application routes or infer end-to-end health from kernel state.
package relayapply

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"time"

	"vpnctl/internal/relaycache"
	"vpnctl/internal/relaycatalog"
	"vpnctl/internal/relayplan"
)

const MaxDuration = 60 * time.Second
const maxEntries = relaycatalog.MaxPathsPerNode

var ErrConflict = errors.New("candidate resource ownership conflict")
var ErrRecovery = errors.New("candidate recovery required")

type Entry struct {
	LeaseVersion   int                 `json:"lease_version,omitempty"`
	ApprovalBootNS uint64              `json:"approval_boot_ns,omitempty"`
	ProbeScope     int                 `json:"probe_scope,omitempty"` // 1: device-bound application candidates
	ProbeRouting   bool                `json:"probe_routing,omitempty"`
	Controller     string              `json:"controller_id"`
	Node           string              `json:"node_id"`
	Generation     uint64              `json:"generation"`
	ApprovalUntil  time.Time           `json:"approval_until"`
	Candidate      relayplan.Candidate `json:"candidate"`
	Alias          string              `json:"alias"`
	Metric         uint32              `json:"metric"`
	LinkIndex      uint32              `json:"link_index"`
	Phase          string              `json:"phase"`
}
type Journal struct {
	Version int           `json:"version"`
	Node    string        `json:"node_id"`
	Domain  string        `json:"kernel_domain"`
	Entries []Entry       `json:"entries"`
	Targets []TargetGuard `json:"targets,omitempty"`
}
type Result struct {
	SchemaVersion int          `json:"schema_version"`
	State         string       `json:"state"`
	PathID        string       `json:"path_id,omitempty"`
	Reason        string       `json:"reason,omitempty"`
	KernelReady   bool         `json:"kernel_ready"`
	UplinkHealth  string       `json:"uplink_health"`
	Paths         []PathResult `json:"paths"`
}
type PathResult struct {
	PathID      string           `json:"path_id"`
	Phase       string           `json:"phase"`
	KernelReady bool             `json:"kernel_ready"`
	Reason      string           `json:"reason,omitempty"`
	Lease       *DeploymentLease `json:"lease,omitempty"`
}
type backend interface {
	Check(context.Context, Entry, bool) (bool, error)
	Step(context.Context, Entry, string, string) error
	Remove(context.Context, Entry) error
}
type Engine struct {
	cache     *relaycache.Store
	journal   Journal
	backend   backend
	targets   targetBackend
	underlays []relayplan.Underlay
	collector relayplan.Collector
	unlock    func()
	save      func([]byte) error
	uncertain bool
	probe     func(context.Context, Entry, relaycatalog.Target) (targetProof, error)
	appProbe  func(context.Context, TargetGuard, Entry, relaycatalog.Target) (ApplicationProof, error)
}

func token() (string, uint32, uint32, error) {
	var b [16]byte
	if _, e := rand.Read(b[:]); e != nil {
		return "", 0, 0, e
	}
	m := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	i := uint32(b[4])<<24 | uint32(b[5])<<16 | uint32(b[6])<<8 | uint32(b[7])
	return "vpnctl:" + hex.EncodeToString(b[:]), 100000 + (m & 0x3fffffff), 100000 + (i & 0x3fffffff), nil
}

func validateEntry(e Entry, node string) error {
	if e.ProbeScope < 0 || e.ProbeScope > 1 || e.ProbeScope == 1 && (!e.ProbeRouting || e.LeaseVersion != 3) {
		return errors.New("invalid probe scope")
	}
	if e.LeaseVersion != 0 && e.LeaseVersion != 3 || (e.LeaseVersion == 0) != (e.ApprovalBootNS == 0) {
		return errors.New("invalid node lease version or approval bound")
	}
	p, c := e.Candidate.Pin, e.Candidate
	if e.Node != node || e.Controller == "" || e.Generation == 0 || e.ApprovalUntil.IsZero() || p == nil || c.PathID == "" || len(c.PathID) > 64 || len(c.Targets) == 0 || len(c.Targets) > relaycatalog.MaxTargets {
		return errors.New("invalid apply journal entry")
	}
	if e.Phase != "preparing" && e.Phase != "prepared" && e.Phase != "releasing" {
		return errors.New("invalid apply phase")
	}
	if len(e.Alias) != 39 || e.Alias[:7] != "vpnctl:" {
		return errors.New("invalid resource owner")
	}
	if _, err := hex.DecodeString(e.Alias[7:]); err != nil {
		return errors.New("invalid resource owner")
	}
	if e.Metric < 100000 || e.Metric > 0x3fffffff+100000 || e.LinkIndex < 100000 || e.LinkIndex > 0x3fffffff+100000 {
		return errors.New("invalid route metric")
	}
	if len(p.Owner) != 64 || len(p.WGInterface) != 14 || p.WGInterface[:2] != "vr" || p.Table < 100000 || p.Table > 624287 || p.RulePriority < 20000 || p.RulePriority > 27999 || p.FWMark&0xff000000 != 0x76000000 || p.IfIndex <= 0 || p.Source == "" || !p.TerminalUnreachable || !p.RequiresOwnershipCheck {
		return errors.New("invalid candidate resources")
	}
	if _, err := hex.DecodeString(p.Owner); err != nil {
		return errors.New("invalid owner digest")
	}
	if _, err := hex.DecodeString(p.WGInterface[2:]); err != nil {
		return errors.New("invalid candidate interface")
	}
	if err := relayplan.ValidateUnderlays([]relayplan.Underlay{{ID: c.UnderlayID, Interface: p.Interface, Kind: "ethernet", SourceIPv4: p.Source}}); err != nil {
		return err
	}
	if p.Gateway != "" {
		if err := relayplan.ValidateUnderlays([]relayplan.Underlay{{ID: c.UnderlayID, Interface: p.Interface, Kind: "ethernet", SourceIPv4: p.Gateway}}); err != nil {
			return err
		}
	}
	ep, err := netip.ParseAddrPort(c.Endpoint)
	if err != nil || !ep.Addr().Is4() || ep.Port() == 0 || p.EndpointPrefix != ep.Addr().String()+"/32" {
		return errors.New("invalid endpoint")
	}
	ip, err := netip.ParsePrefix(c.InnerAddress)
	if err != nil || !ip.Addr().Is4() || ip.Bits() != 32 || ip.String() != c.InnerAddress {
		return errors.New("invalid inner address")
	}
	if relaycatalog.ValidatePublicKey(c.PublicKey) != nil || relaycatalog.ValidatePublicKey(c.RelayPublicKey) != nil {
		return errors.New("invalid candidate public key")
	}
	for _, t := range c.Targets {
		for _, s := range t.Prefixes {
			q, err := netip.ParsePrefix(s)
			if err != nil || !q.Addr().Is4() || q != q.Masked() || q.Bits() == 0 {
				return errors.New("invalid target prefix")
			}
		}
	}
	return nil
}
func prefixes(e Entry) []string {
	v := []string{}
	for _, t := range e.Candidate.Targets {
		for _, p := range t.Prefixes {
			if !slices.Contains(v, p) {
				v = append(v, p)
			}
		}
	}
	slices.Sort(v)
	return v
}
func result(state, path, reason string) Result {
	return Result{SchemaVersion: 1, State: state, PathID: path, Reason: reason, UplinkHealth: "unknown", Paths: []PathResult{}}
}
func (e *Engine) persist() error {
	if e.uncertain {
		return relaycache.ErrUncertain
	}
	b, err := json.Marshal(envelope{Journal: e.journal, Digest: digest(e.journal)})
	if err != nil {
		return err
	}
	err = e.save(b)
	if err != nil {
		e.uncertain = true
	}
	return err
}
func (e *Engine) index(path string) int {
	for i, p := range e.journal.Entries {
		if p.Candidate.PathID == path {
			return i
		}
	}
	return -1
}
func (e *Engine) Close() {
	if e.unlock != nil {
		e.unlock()
		e.unlock = nil
	}
}
func failure(path, reason string, err error) (Result, error) {
	return result("blocked", path, reason), fmt.Errorf("%s: %w", reason, err)
}

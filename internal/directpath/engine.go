// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
// Package directpath verifies and supervises node-to-node VPN paths. UDP
// underlay readiness only admits a trial; it never proves a working WG path.
package directpath

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"vpnctl/internal/atomicfile"
	"vpnctl/internal/config"
	"vpnctl/internal/relaycatalog"
	"vpnctl/internal/wireguard"
)

const MaxPeers = 32
const Cooldown = 5 * time.Second
const MaxCooldown = Cooldown + 2*time.Second

// Initial peers need overlapping installation windows despite worker skew.
// Include one further probe cycle when the first WG handshake completes at a
// nonce deadline. This never delays removal after a path has reached active.
const InitialTrialWindow = 3 * time.Second
const CandidateMaxAge = 2 * time.Minute

type Candidate struct {
	ID         string `json:"id"`
	Key        string `json:"public_key"`
	Endpoint   string `json:"endpoint"`
	Address    string `json:"address"`
	ProbePort  int    `json:"probe_port"`
	Keepalive  int    `json:"keepalive"`
	Generation string `json:"generation"`
}
type Status struct {
	ID         string `json:"id"`
	State      string `json:"state"`
	Reason     string `json:"reason,omitempty"`
	Generation string `json:"generation,omitempty"`
}
type journal struct {
	Version   int                  `json:"version"`
	Domain    string               `json:"domain"`
	Interface string               `json:"interface"`
	Identity  identity             `json:"identity"`
	Relay     string               `json:"relay"`
	Config    string               `json:"baseline_config_sha256"`
	Peers     map[string]Candidate `json:"peers"`
}
type envelope struct {
	Journal journal `json:"journal"`
	Digest  string  `json:"sha256"`
}
type Engine struct {
	relayVerified time.Time
	poisoned      bool
	j             journal
	cfg           config.NodeConfig
	backend       backend
	save          func(journal) error
	unlock        func()
	retrySequence uint64
	trialStarted  map[string]time.Time
	successes     map[string]int
	cooldown      map[string]time.Time
	now           func() time.Time
}

func statePath(cfg config.NodeConfig) string { return cfg.WGConfigPath + ".direct.json" }
func domain() (string, error) {
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
func digest(j journal) string {
	b, _ := json.Marshal(j)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// Only public baseline inputs belong in this digest. Controller transport,
// credentials, probe timing and direct policy may change without rewriting WG.
// A service restart must not silently ignore changed address/endpoint/routes.
func baselineConfig(cfg config.NodeConfig) string {
	prefixes := append([]string{}, cfg.ServerAllowedIPs...)
	for i, prefix := range prefixes {
		if p, err := netip.ParsePrefix(prefix); err == nil {
			prefixes[i] = p.Masked().String()
		}
	}
	sort.Strings(prefixes)
	v := struct {
		Address, PublicKey, Relay, Endpoint, PolicyCIDR              string
		Prefixes                                                     []string
		ListenPort, MTU, RelayKeepalive, PolicyTable, PolicyPriority int
		PolicyEnabled                                                bool
	}{cfg.VPNIP, cfg.WGPublicKey, cfg.ServerPublicKey, cfg.ServerEndpoint, cfg.PolicyRoutingCIDR, prefixes, cfg.WGListenPort, cfg.MTU, cfg.ServerKeepaliveSec, cfg.PolicyRoutingTable, cfg.PolicyRoutingPriority, config.PolicyRoutingEnabled(&cfg)}
	b, _ := json.Marshal(v)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func Open(ctx context.Context, cfg config.NodeConfig) (*Engine, error) {
	if cfg.WGConfigPath == "" || cfg.WGInterface == "" || relaycatalog.ValidatePublicKey(cfg.WGPublicKey) != nil || relaycatalog.ValidatePublicKey(cfg.ServerPublicKey) != nil {
		return nil, errors.New("direct dataplane requires configured interface, config path and public keys")
	}
	local, err := netip.ParsePrefix(cfg.VPNIP)
	if err != nil || !local.Addr().Is4() {
		return nil, errors.New("invalid local VPN address")
	}
	unlock, err := wireguard.LockInterface(cfg.WGInterface)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*Engine, error) { unlock(); return nil, err }
	d, err := domain()
	if err != nil {
		return fail(err)
	}
	k := newKernel(cfg.WGInterface, local.Addr().String())
	s, err := k.Snapshot(ctx)
	if err != nil {
		return fail(err)
	}
	if s.Identity.PublicKey != cfg.WGPublicKey {
		return fail(errors.New("interface public key conflict"))
	}
	j := journal{Version: 1, Domain: d, Interface: cfg.WGInterface, Identity: s.Identity, Relay: cfg.ServerPublicKey, Config: baselineConfig(cfg), Peers: map[string]Candidate{}}
	path := statePath(cfg)
	if st, err := os.Lstat(path); err == nil {
		if !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 || st.Size() > 128<<10 {
			return fail(errors.New("unsafe direct journal"))
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return fail(err)
		}
		var v envelope
		dec := json.NewDecoder(bytes.NewReader(b))
		dec.DisallowUnknownFields()
		if dec.Decode(&v) != nil || dec.Decode(new(any)) != io.EOF || v.Digest != digest(v.Journal) || v.Journal.Version != 1 || v.Journal.Interface != cfg.WGInterface || v.Journal.Peers == nil || len(v.Journal.Peers) > MaxPeers {
			return fail(errors.New("invalid direct journal"))
		}
		j, err = recoverJournal(cfg, j, v.Journal, s)
		if err != nil {
			return fail(err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fail(err)
	}
	if err = atomicfile.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fail(err)
	}
	save := func(v journal) error {
		b, err := json.Marshal(envelope{v, digest(v)})
		if err != nil {
			return err
		}
		return atomicfile.Write(path, b, 0600)
	}
	e := newEngine(cfg, j, k, save)
	e.unlock = unlock
	if err = save(j); err != nil {
		return fail(err)
	}
	return e, nil
}

// A replaced interface can retire old metadata only when all old keys are
// absent. Old candidates are validated against the current config only when
// recovering the same baseline: changed prefixes/relay must allow explicit
// dedicated-interface recreation, without adopting peers on that new device.
func recoverJournal(cfg config.NodeConfig, current, prior journal, s snapshot) (journal, error) {
	if relaycatalog.ValidatePublicKey(prior.Relay) != nil {
		return current, errors.New("invalid journal relay")
	}
	for key, c := range prior.Peers {
		if key != c.Key || relaycatalog.ValidatePublicKey(key) != nil {
			return current, errors.New("invalid journal peer")
		}
	}
	if prior.Domain != current.Domain || prior.Identity != current.Identity {
		for key := range prior.Peers {
			if _, exists := s.Peers[key]; exists {
				return current, errors.New("direct journal interface identity conflict")
			}
		}
		return current, nil
	}
	if prior.Config != current.Config || prior.Relay != current.Relay {
		return current, errors.New("direct baseline configuration changed; stop service and explicitly recreate its dedicated baseline")
	}
	for _, c := range prior.Peers {
		if validate(cfg, c) != nil {
			return current, errors.New("invalid journal peer")
		}
	}
	return prior, nil
}

// RecoverExisting preserves an installed journaled baseline on node serve retry.
// A missing interface (including reboot) still needs explicit baseline creation.
// An existing but conflicted interface must not be replaced by legacy syncconf.
func RecoverExisting(ctx context.Context, cfg config.NodeConfig) (bool, error) {
	if cfg.WGConfigPath == "" {
		return false, nil
	}
	if _, err := os.Lstat(statePath(cfg)); errors.Is(err, os.ErrNotExist) {
		return false, nil
	} else if err != nil {
		return true, err
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return true, err
	}
	exists := false
	for _, iface := range interfaces {
		exists = exists || iface.Name == cfg.WGInterface
	}
	if !exists {
		return false, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	e, err := Open(ctx, cfg)
	if err != nil {
		return true, err
	}
	defer e.Close()
	if err = e.Reset(ctx); err != nil {
		return true, err
	}
	s, err := e.inspect(ctx)
	if err != nil {
		return true, err
	}
	if !e.relayOK(s) {
		return true, errors.New("installed relay baseline changed")
	}
	return true, nil
}

func newEngine(cfg config.NodeConfig, j journal, b backend, save func(journal) error) *Engine {
	return &Engine{j: j, cfg: cfg, backend: b, save: save, successes: map[string]int{}, trialStarted: map[string]time.Time{}, cooldown: map[string]time.Time{}, now: time.Now}
}
func (e *Engine) persist(next journal) error {
	err := e.save(next)
	if err == nil || atomicfile.Replaced(err) {
		e.j = next
	}
	if err != nil {
		e.poisoned = true
	}
	return err
}
func (e *Engine) Close() {
	if e.unlock != nil {
		e.unlock()
		e.unlock = nil
	}
}
func validate(cfg config.NodeConfig, c Candidate) error {
	addr, err := netip.ParseAddr(c.Address)
	if err != nil || !addr.Is4() || addr.IsUnspecified() || addr.IsMulticast() {
		return errors.New("invalid direct VPN address")
	}
	endpoint, err := netip.ParseAddrPort(c.Endpoint)
	if err != nil || !endpoint.Addr().Is4() || endpoint.Port() == 0 || endpoint.Addr().IsUnspecified() || endpoint.Addr().IsMulticast() {
		return errors.New("invalid direct endpoint")
	}
	if c.ID == "" || len(c.ID) > 128 || c.Generation == "" || len(c.Generation) > 128 || c.Key == cfg.ServerPublicKey || c.Key == cfg.WGPublicKey || relaycatalog.ValidatePublicKey(c.Key) != nil || c.ProbePort < 1 || c.ProbePort > 65535 || c.Keepalive < 0 || c.Keepalive > 65535 {
		return errors.New("invalid direct candidate")
	}
	local, _ := netip.ParsePrefix(cfg.VPNIP)
	if local.Addr() == addr {
		return errors.New("direct candidate is local node")
	}
	covered := false
	for _, raw := range cfg.ServerAllowedIPs {
		p, err := netip.ParsePrefix(raw)
		if err != nil || !p.Addr().Is4() {
			return errors.New("invalid relay prefixes")
		}
		if p.Bits() == 32 && p.Contains(addr) {
			return errors.New("direct destination would steal the relay host prefix")
		}
		covered = covered || p.Contains(addr)
	}
	if !covered {
		return errors.New("direct candidate has no relay baseline")
	}
	return nil
}
func ValidateCandidates(cfg config.NodeConfig, candidates []Candidate) error {
	if len(candidates) > MaxPeers {
		return errors.New("too many direct candidates")
	}
	keys, ids, addresses := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, c := range candidates {
		if err := validate(cfg, c); err != nil {
			return err
		}
		if keys[c.Key] || ids[c.ID] || addresses[c.Address] {
			return errors.New("duplicate direct identity or address")
		}
		keys[c.Key], ids[c.ID], addresses[c.Address] = true, true, true
	}
	return nil
}
func owned(p kernelPeer, c Candidate) bool {
	return p.Key == c.Key && !p.PSK && p.Keepalive == c.Keepalive && len(p.Prefixes) == 1 && p.Prefixes[0] == c.Address+"/32"
}

// Endpoint is mutable WireGuard roaming state. Drift invalidates verification,
// but cannot strand a journaled peer during fallback. Immutable ownership
// attributes (key, prefix, PSK absence and keepalive) must still match.
func matches(p kernelPeer, c Candidate) bool { return owned(p, c) && p.Endpoint == c.Endpoint }
func (e *Engine) inspect(ctx context.Context) (snapshot, error) {
	s, err := e.backend.Snapshot(ctx)
	if err != nil {
		return s, err
	}
	if s.Identity != e.j.Identity {
		return s, errors.New("direct interface identity changed")
	}
	return s, nil
}
func (e *Engine) relayOK(s snapshot) bool {
	p, ok := s.Peers[e.cfg.ServerPublicKey]
	if !ok || p.PSK {
		return false
	}
	a, b := append([]string{}, p.Prefixes...), append([]string{}, e.cfg.ServerAllowedIPs...)
	for i, raw := range a {
		p, err := netip.ParsePrefix(raw)
		if err != nil {
			return false
		}
		a[i] = p.Masked().String()
	}
	for i, raw := range b {
		p, err := netip.ParsePrefix(raw)
		if err != nil {
			return false
		}
		b[i] = p.Masked().String()
	}
	sort.Strings(a)
	sort.Strings(b)
	return reflect.DeepEqual(a, b)
}
func (e *Engine) remove(ctx context.Context, keys []string) error {
	if len(keys) == 0 {
		return nil
	}
	s, err := e.inspect(ctx)
	if err != nil {
		return err
	}
	var safe, installed []string
	var errs []error
	for _, key := range keys {
		c, exists := e.j.Peers[key]
		if !exists {
			continue
		}
		if p, exists := s.Peers[key]; exists {
			if !owned(p, c) {
				errs = append(errs, errors.New("direct peer ownership conflict"))
				continue
			}
			installed = append(installed, key)
		}
		safe = append(safe, key)
	}
	if len(installed) != 0 {
		if err = e.backend.Remove(ctx, installed); err != nil {
			return errors.Join(append(errs, err)...)
		}
		s, err = e.inspect(ctx)
		if err != nil {
			return errors.Join(append(errs, err)...)
		}
		for _, key := range installed {
			if _, exists := s.Peers[key]; exists {
				return errors.Join(append(errs, errors.New("direct removal readback failed"))...)
			}
		}
	}
	if len(safe) == 0 {
		return errors.Join(errs...)
	}
	for _, key := range safe {
		delete(e.successes, key)
		delete(e.trialStarted, key)
	}
	if e.poisoned {
		// Kernel quiescence remains possible with a failed journal. Retain all
		// durable intents for idempotent recovery after storage is repaired.
		return errors.Join(append(errs, errors.New("direct peers quiesced; journal repair/reopen required"))...)
	}
	next := e.j
	next.Peers = clone(e.j.Peers)
	for _, key := range safe {
		delete(next.Peers, key)
	}
	return errors.Join(append(errs, e.persist(next))...)
}
func clone(p map[string]Candidate) map[string]Candidate {
	out := make(map[string]Candidate, len(p))
	for k, v := range p {
		out[k] = v
	}
	return out
}

// Reset recovers only journaled peers, preserving the relay and foreign state.
// Run it on startup before contacting the controller and on orderly shutdown.
func (e *Engine) Reset(ctx context.Context) error {
	return e.remove(ctx, sortedKeys(e.j.Peers))
}
func sortedKeys(m map[string]Candidate) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
func (e *Engine) add(ctx context.Context, candidates []Candidate) error {
	if len(candidates) == 0 {
		return nil
	}
	s, err := e.inspect(ctx)
	if err != nil {
		return err
	}
	if !e.relayOK(s) {
		return errors.New("relay baseline changed")
	}
	for _, c := range candidates {
		if _, exists := s.Peers[c.Key]; exists {
			return errors.New("unowned direct peer already exists")
		}
		addr := netip.MustParseAddr(c.Address)
		for key, p := range s.Peers {
			if key == e.cfg.ServerPublicKey {
				continue
			}
			for _, raw := range p.Prefixes {
				prefix, err := netip.ParsePrefix(raw)
				if err != nil || prefix.Contains(addr) {
					return errors.New("foreign peer owns direct destination")
				}
			}
		}
	}
	next := e.j
	next.Peers = clone(e.j.Peers)
	for _, c := range candidates {
		next.Peers[c.Key] = c
	}
	if err = e.persist(next); err != nil {
		return err
	}
	// One durable batch intent precedes all mutations. A partial command result
	// remains recoverable; no per-peer subprocess/readback/fsync storm at N² scale.
	started := e.now()
	if err = e.backend.Add(ctx, candidates); err != nil {
		return err
	}
	s, err = e.inspect(ctx)
	if err != nil {
		return err
	}
	for _, c := range candidates {
		if !matches(s.Peers[c.Key], c) {
			return errors.New("direct installation readback failed")
		}
		e.trialStarted[c.Key] = started
	}
	return nil
}

// verifyRelay initializes the standby WG transport before a direct trial.
// Address selection follows the existing hub probe contract: the first usable
// address of the first non-default IPv4 VPN prefix. Cache only a short proof;
// this is not evidence that an application's target or another node is healthy.
func (e *Engine) verifyRelay(ctx context.Context) error {
	if age := e.now().Sub(e.relayVerified); !e.relayVerified.IsZero() && age >= 0 && age < 30*time.Second {
		return nil
	}
	var address netip.Addr
	for _, raw := range e.cfg.ServerAllowedIPs {
		p, err := netip.ParsePrefix(raw)
		if err == nil && p.Addr().Is4() && p.Bits() > 0 && p.Bits() < 32 {
			address = p.Masked().Addr().Next()
			break
		}
	}
	if !address.IsValid() {
		return errors.New("relay probe address undetermined")
	}
	port := e.cfg.ServerProbePort
	if port == 0 {
		port = config.DefaultProbePort
	}
	before, err := e.inspect(ctx)
	if err != nil {
		return err
	}
	if !e.relayOK(before) {
		return errors.New("relay baseline changed")
	}
	for key, peer := range before.Peers {
		if key == e.cfg.ServerPublicKey {
			continue
		}
		for _, raw := range peer.Prefixes {
			p, err := netip.ParsePrefix(raw)
			if err != nil || p.Contains(address) {
				return errors.New("relay probe destination conflict")
			}
		}
	}
	if err = e.backend.Probe(ctx, Candidate{Key: e.cfg.ServerPublicKey, Address: address.String(), ProbePort: port}); err != nil {
		return err
	}
	after, err := e.inspect(ctx)
	if err != nil {
		return err
	}
	p, old := after.Peers[e.cfg.ServerPublicKey], before.Peers[e.cfg.ServerPublicKey]
	if !e.relayOK(after) || p.Handshake <= 0 || p.RX <= old.RX || p.TX <= old.TX {
		return errors.New("relay dataplane proof missing")
	}
	e.relayVerified = e.now()
	return nil
}

// Vary retries by local identity, candidate key and attempt so two workers
// cannot remain phase-locked when their initial trial windows do not overlap.
// This is scheduling jitter, not a security nonce. The base cooldown is retained.
func (e *Engine) retryDelay(c Candidate) time.Duration {
	e.retrySequence++
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s:%s:%d", e.cfg.WGPublicKey, c.Key, e.retrySequence)))
	return Cooldown + time.Duration(binary.BigEndian.Uint64(sum[:8])%uint64(MaxCooldown-Cooldown+1))
}

// Step is single-owner. Network verification is bounded and concurrent so a
// silent peer cannot delay local removal of all other failed peers by a full
// controller reporting round. No controller call occurs in this method.
func (e *Engine) Step(ctx context.Context, candidates []Candidate) ([]Status, error) {
	if e.poisoned {
		return nil, errors.New("direct journal durability uncertain; reopen required")
	}
	if len(candidates) > MaxPeers {
		return nil, errors.New("too many direct candidates")
	}
	desired := map[string]Candidate{}
	addresses := map[string]bool{}
	ids := map[string]bool{}
	for _, c := range candidates {
		if err := validate(e.cfg, c); err != nil {
			return nil, err
		}
		if _, dup := desired[c.Key]; dup || addresses[c.Address] || ids[c.ID] {
			return nil, errors.New("duplicate direct identity or address")
		}
		desired[c.Key] = c
		addresses[c.Address] = true
		ids[c.ID] = true
	}
	var withdrawn []string
	for _, key := range sortedKeys(e.j.Peers) {
		if c, ok := desired[key]; !ok || c != e.j.Peers[key] {
			withdrawn = append(withdrawn, key)
		}
	}
	if err := e.remove(ctx, withdrawn); err != nil {
		return nil, err
	}
	statuses := []Status{}
	trials := map[string]Candidate{}
	var additions []Candidate
	var relayChecked bool
	var relayErr error
	for _, key := range sortedKeys(desired) {
		c := desired[key]
		if e.now().Before(e.cooldown[c.ID]) {
			statuses = append(statuses, Status{c.ID, "cooldown", "local_dataplane_failure", c.Generation})
			continue
		}
		if _, ok := e.j.Peers[key]; !ok {
			if !relayChecked {
				relayErr = e.verifyRelay(ctx)
				relayChecked = true
			}
			if relayErr != nil {
				statuses = append(statuses, Status{c.ID, "relay_unverified", "relay_baseline_unverified", c.Generation})
				continue
			}
			additions = append(additions, c)
		}
		trials[key] = c
	}
	if err := e.add(ctx, additions); err != nil {
		return statuses, err
	}
	before, err := e.inspect(ctx)
	if err != nil {
		return statuses, err
	}
	for key, c := range trials {
		if !matches(before.Peers[key], c) {
			return statuses, errors.New("direct peer changed before verification")
		}
	}
	results := make(map[string]error, len(trials))
	var mu sync.Mutex
	var wg sync.WaitGroup
	for key, c := range trials {
		probeCtx := ctx
		cancel := func() {}
		if started, initial := e.trialStarted[key]; initial && e.successes[key] == 0 {
			// A nearly expired trial must not start another full one-second
			// request. Bound unverified occupancy from before kernel install.
			probeCtx, cancel = context.WithTimeout(ctx, InitialTrialWindow-e.now().Sub(started))
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer cancel()
			err := e.backend.Probe(probeCtx, c)
			mu.Lock()
			results[key] = err
			mu.Unlock()
		}()
	}
	wg.Wait()
	if ctx.Err() != nil {
		return statuses, ctx.Err()
	}
	after, err := e.inspect(ctx)
	if err != nil {
		return statuses, err
	}
	var failed []string
	for _, key := range sortedKeys(trials) {
		c := trials[key]
		p := after.Peers[key]
		old := before.Peers[key]
		if !matches(p, c) {
			return statuses, errors.New("direct peer changed during verification")
		}
		if results[key] != nil || p.Handshake <= 0 || p.RX <= old.RX || p.TX <= old.TX {
			reason := "direct_traffic_not_observed"
			if p.Handshake <= 0 {
				reason = "direct_handshake_missing"
			}
			if results[key] != nil {
				reason = "overlay_probe_failed"
				var netErr net.Error
				if errors.As(results[key], &netErr) && netErr.Timeout() {
					reason = "overlay_probe_timeout"
				}
				if p.Handshake <= 0 {
					reason += "_no_handshake"
				}
			}
			started, initial := e.trialStarted[key]
			age := e.now().Sub(started)
			if initial && e.successes[key] < 2 && age >= 0 && age < InitialTrialWindow {
				e.successes[key] = 0
				statuses = append(statuses, Status{c.ID, "probing", reason, c.Generation})
				continue
			}
			failed = append(failed, key)
			e.cooldown[c.ID] = e.now().Add(e.retryDelay(c))
			statuses = append(statuses, Status{c.ID, "relay_unverified", reason, c.Generation})
		} else {
			e.successes[key] = min(2, e.successes[key]+1)
			state := "probing"
			if e.successes[key] >= 2 {
				state = "active"
			}
			statuses = append(statuses, Status{c.ID, state, "", c.Generation})
		}
	}
	if err := e.remove(ctx, failed); err != nil {
		return nil, err
	}
	// Bounded memory across key churn; expired inactive cooldowns are disposable.
	for id, until := range e.cooldown {
		if !e.now().Before(until) {
			delete(e.cooldown, id)
		}
	}
	return statuses, nil
}

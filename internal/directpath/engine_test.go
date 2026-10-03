// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package directpath

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"

	"vpnctl/internal/atomicfile"
	"vpnctl/internal/config"
)

type fakeKernel struct {
	mu            sync.Mutex
	s             snapshot
	mode          string
	adds, removes int
	saved         *journal
	probeHook     func()
	relaySilent   bool
}

func (k *fakeKernel) Snapshot(context.Context) (snapshot, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	s := k.s
	s.Peers = map[string]kernelPeer{}
	for key, p := range k.s.Peers {
		s.Peers[key] = p
	}
	return s, nil
}
func (k *fakeKernel) Add(_ context.Context, candidates []Candidate) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	for _, c := range candidates {
		if k.saved == nil || k.saved.Peers[c.Key] != c {
			return errors.New("mutation before durable intent")
		}
		k.adds++
		k.s.Peers[c.Key] = kernelPeer{Key: c.Key, Endpoint: c.Endpoint, Prefixes: []string{c.Address + "/32"}, Keepalive: c.Keepalive}
		if k.mode == "add-error" {
			return errors.New("lost command response")
		}
	}
	return nil
}
func (k *fakeKernel) Remove(_ context.Context, keys []string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.mode == "remove-error" {
		return errors.New("remove failed")
	}
	for _, key := range keys {
		k.removes++
		delete(k.s.Peers, key)
	}
	return nil
}
func (k *fakeKernel) Probe(ctx context.Context, c Candidate) error {
	if k.probeHook != nil {
		k.probeHook()
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.mode == "silent" || (k.relaySilent && c.Key == key(2)) {
		return errors.New("timeout")
	}
	if k.mode == "cancel" {
		return ctx.Err()
	}
	p := k.s.Peers[c.Key]
	if k.mode != "no-handshake" {
		p.Handshake = 10
	}
	if k.mode != "no-rx" {
		p.RX += 100
	}
	if k.mode != "no-tx" {
		p.TX += 100
	}
	if k.mode == "foreign" {
		p.Keepalive++
	}
	k.s.Peers[c.Key] = p
	return nil
}
func key(n byte) string { b := make([]byte, 32); b[0] = n; return base64.StdEncoding.EncodeToString(b) }
func fixture(t *testing.T) (*Engine, *fakeKernel, Candidate) {
	t.Helper()
	cfg := config.NodeConfig{WGInterface: "wg0", WGPublicKey: key(1), ServerPublicKey: key(2), ServerAllowedIPs: []string{"10.7.0.0/24"}, VPNIP: "10.7.0.2/32"}
	k := &fakeKernel{s: snapshot{Identity: identity{Index: 7, PublicKey: key(1)}, Peers: map[string]kernelPeer{key(2): {Key: key(2), Prefixes: []string{"10.7.0.0/24"}}}}}
	j := journal{Version: 1, Interface: "wg0", Domain: "boot:netns", Identity: k.s.Identity, Relay: key(2), Peers: map[string]Candidate{}}
	save := func(j journal) error {
		b, _ := json.Marshal(j)
		var copy journal
		json.Unmarshal(b, &copy)
		k.saved = &copy
		return nil
	}
	e := newEngine(cfg, j, k, save)
	e.relayVerified = time.Now()
	c := Candidate{ID: "other", Key: key(3), Endpoint: "192.0.2.3:51820", Address: "10.7.0.3", ProbePort: 51900, Keepalive: 25, Generation: "g1"}
	return e, k, c
}
func TestActiveRequiresOverlayRoundTripAndPeerTraffic(t *testing.T) {
	for _, mode := range []string{"healthy", "silent", "no-handshake", "no-rx", "no-tx"} {
		t.Run(mode, func(t *testing.T) {
			e, k, c := fixture(t)
			k.mode = mode
			for attempt := 0; attempt < 2; attempt++ {
				r, err := e.Step(context.Background(), []Candidate{c})
				if err != nil {
					t.Fatal(err)
				}
				want := "probing"
				if attempt == 1 {
					want = "active"
				}
				if mode != "healthy" {
					want = "relay_unverified"
					if attempt == 1 {
						want = "cooldown"
					}
				}
				if len(r) != 1 || r[0].State != want {
					t.Fatal(r, want)
				}
			}
			_, exists := k.s.Peers[c.Key]
			if exists != (mode == "healthy") {
				t.Fatal("failed direct remains installed")
			}
			if _, exists := k.s.Peers[key(2)]; !exists {
				t.Fatal("relay was removed")
			}
		})
	}
}
func TestLocalFailureRecoversWithoutControllerAndRequiresCooldown(t *testing.T) {
	e, k, c := fixture(t)
	now := time.Now()
	e.now = func() time.Time { return now }
	for i := 0; i < 2; i++ {
		if _, err := e.Step(context.Background(), []Candidate{c}); err != nil {
			t.Fatal(err)
		}
	}
	k.mode = "silent"
	r, err := e.Step(context.Background(), []Candidate{c})
	if err != nil || r[0].State != "relay_unverified" {
		t.Fatal(r, err)
	}
	k.mode = "healthy"
	old := k.adds
	if _, err = e.Step(context.Background(), []Candidate{c}); err != nil || k.adds != old {
		t.Fatal("cooldown bypassed", err)
	}
	now = now.Add(Cooldown)
	r, err = e.Step(context.Background(), []Candidate{c})
	if err != nil || r[0].State != "probing" {
		t.Fatal("old success reused", r, err)
	}
	r, err = e.Step(context.Background(), []Candidate{c})
	if err != nil || r[0].State != "active" {
		t.Fatal(r, err)
	}
}
func TestUnknownOrChangedResourcesAreNeverDeleted(t *testing.T) {
	for _, mode := range []string{"unowned-key", "overlap", "psk", "changed-interface", "changed-relay", "foreign-during-probe"} {
		t.Run(mode, func(t *testing.T) {
			e, k, c := fixture(t)
			if mode == "unowned-key" {
				k.s.Peers[c.Key] = kernelPeer{Key: c.Key, Prefixes: []string{c.Address + "/32"}}
			} else if mode == "overlap" {
				k.s.Peers[key(4)] = kernelPeer{Key: key(4), Prefixes: []string{"10.7.0.0/25"}}
			} else if mode == "changed-relay" {
				delete(k.s.Peers, key(2))
			} else {
				if _, err := e.Step(context.Background(), []Candidate{c}); err != nil {
					t.Fatal(err)
				}
				p := k.s.Peers[c.Key]
				switch mode {
				case "psk":
					p.PSK = true
				case "changed-endpoint":
					p.Endpoint = "192.0.2.9:1"
				case "changed-interface":
					k.s.Identity.Index++
				case "foreign-during-probe":
					k.mode = "foreign"
				}
				k.s.Peers[c.Key] = p
			}
			before := k.removes
			if _, err := e.Step(context.Background(), []Candidate{c}); err == nil {
				t.Fatal("conflict accepted")
			}
			if k.removes != before {
				t.Fatal("foreign resource removed")
			}
			if mode != "unowned-key" && mode != "overlap" && mode != "changed-relay" {
				if err := e.Reset(context.Background()); err == nil {
					t.Fatal("conflicted reset succeeded")
				}
			}
		})
	}
}
func TestRestartRecoveryAndWithdrawalPreserveForeignPeers(t *testing.T) {
	e, k, c := fixture(t)
	foreign := kernelPeer{Key: key(4), Prefixes: []string{"172.16.0.4/32"}, Endpoint: "192.0.2.4:99", PSK: true}
	k.s.Peers[foreign.Key] = foreign
	if _, err := e.Step(context.Background(), []Candidate{c}); err != nil {
		t.Fatal(err)
	}
	reopened := newEngine(e.cfg, *k.saved, k, e.save)
	if err := reopened.Reset(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, exists := k.s.Peers[c.Key]; exists {
		t.Fatal("journaled peer survived recovery")
	}
	if !reflect.DeepEqual(k.s.Peers[foreign.Key], foreign) {
		t.Fatal("foreign peer changed")
	}
	if len(k.saved.Peers) != 0 {
		t.Fatal("journal not cleared after readback")
	}
	if _, err := reopened.Step(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
}
func TestIntentSurvivesCommandsAndDurabilityFailures(t *testing.T) {
	for _, mode := range []string{"intent-save", "visible-save", "add-error", "remove-error", "remove-save"} {
		t.Run(mode, func(t *testing.T) {
			e, k, c := fixture(t)
			save := e.save
			switch mode {
			case "intent-save":
				e.save = func(journal) error { return errors.New("disk full") }
			case "visible-save":
				e.save = func(j journal) error { save(j); return &atomicfile.CommitError{Err: errors.New("fsync")} }
			case "add-error":
				k.mode = mode
			}
			_, err := e.Step(context.Background(), []Candidate{c})
			if mode == "remove-error" || mode == "remove-save" {
				if err != nil {
					t.Fatal(err)
				}
				if mode == "remove-error" {
					k.mode = mode
				} else {
					e.save = func(journal) error { return errors.New("disk full") }
				}
				err = e.Reset(context.Background())
			}
			if err == nil {
				t.Fatal("injected failure ignored")
			}
			if mode == "intent-save" || mode == "visible-save" {
				if k.adds != 0 {
					t.Fatal("mutation with uncertain intent")
				}
			}
			if mode == "add-error" || mode == "remove-error" || mode == "remove-save" {
				if k.saved.Peers[c.Key] != c {
					t.Fatal("recovery intent lost")
				}
			}
			if e.poisoned {
				if _, err := e.Step(context.Background(), nil); err == nil {
					t.Fatal("continued with uncertain journal")
				}
			}
		})
	}
}
func TestGenerationChangesReverifyAndRejectMalformedSets(t *testing.T) {
	e, k, c := fixture(t)
	for i := 0; i < 2; i++ {
		e.Step(context.Background(), []Candidate{c})
	}
	c.Generation = "g2"
	r, err := e.Step(context.Background(), []Candidate{c})
	if err != nil || r[0].State != "probing" || k.removes != 1 {
		t.Fatal("generation reused readiness", r, err)
	}
	for _, set := range [][]Candidate{{c, c}, {{ID: "bad"}}, make([]Candidate, MaxPeers+1)} {
		before := k.adds
		if _, err = e.Step(context.Background(), set); err == nil || k.adds != before {
			t.Fatal("invalid desired set mutated kernel")
		}
	}
}

func TestColdRelayMustBeVerifiedBeforeDirectTrial(t *testing.T) {
	for _, mode := range []string{"healthy", "silent", "no-handshake", "no-rx", "no-tx"} {
		t.Run(mode, func(t *testing.T) {
			e, k, c := fixture(t)
			e.relayVerified = time.Time{}
			k.mode = mode
			r, err := e.Step(context.Background(), []Candidate{c})
			if err != nil {
				t.Fatal(err)
			}
			if mode == "healthy" {
				if k.adds != 1 || r[0].State != "probing" {
					t.Fatal(r, k.adds)
				}
			} else if k.adds != 0 || r[0].Reason != "relay_baseline_unverified" {
				t.Fatal("unverified standby admitted direct", r, k.adds)
			}
		})
	}
}
func TestUncertainJournalStillQuiescesAllOwnedPeers(t *testing.T) {
	e, k, c := fixture(t)
	other := c
	other.ID = "fourth"
	other.Key = key(4)
	other.Address = "10.7.0.4"
	if _, err := e.Step(context.Background(), []Candidate{c, other}); err != nil {
		t.Fatal(err)
	}
	e.save = func(journal) error { return errors.New("disk full") }
	if err := e.Reset(context.Background()); err == nil {
		t.Fatal("persistence failure lost")
	}
	if len(k.s.Peers) != 1 || k.s.Peers[e.cfg.ServerPublicKey].Key == "" {
		t.Fatal("owned peers not quiesced", k.s.Peers)
	}
	if len(k.saved.Peers) != 2 {
		t.Fatal("intent lost")
	}
	if _, err := e.Step(context.Background(), []Candidate{c}); err == nil {
		t.Fatal("uncertain writer resumed")
	}
}
func TestKeyChurnCannotBypassPeerCooldown(t *testing.T) {
	e, k, c := fixture(t)
	for i := 0; i < 2; i++ {
		if _, err := e.Step(context.Background(), []Candidate{c}); err != nil {
			t.Fatal(err)
		}
	}
	k.mode = "silent"
	if _, err := e.Step(context.Background(), []Candidate{c}); err != nil {
		t.Fatal(err)
	}
	c.Key = key(4)
	c.Generation = "g2"
	k.mode = "healthy"
	r, err := e.Step(context.Background(), []Candidate{c})
	if err != nil || k.adds != 1 || r[0].State != "cooldown" {
		t.Fatal(r, err, k.adds)
	}
}
func TestMaximumMeshConcurrentFailureAndRepeatedRecovery(t *testing.T) {
	e, k, c := fixture(t)
	candidates := make([]Candidate, MaxPeers)
	for i := range candidates {
		n := c
		n.ID = fmt.Sprint(i)
		n.Key = key(byte(i + 3))
		n.Address = fmt.Sprintf("10.7.0.%d", i+3)
		candidates[i] = n
	}
	now := time.Now()
	e.now = func() time.Time { return now }
	for round := 0; round < 10; round++ {
		k.mode = "healthy"
		e.relayVerified = now
		for i := 0; i < 2; i++ {
			r, err := e.Step(context.Background(), candidates)
			if err != nil || len(r) != MaxPeers {
				t.Fatal(r, err)
			}
		}
		k.mode = "silent"
		if _, err := e.Step(context.Background(), candidates); err != nil {
			t.Fatal(err)
		}
		if len(k.s.Peers) != 1 {
			t.Fatal("failed mesh peers remain")
		}
		now = now.Add(Cooldown)
	}
}

func TestRoamingEndpointInvalidatesProofButDoesNotStrandOwnedPeer(t *testing.T) {
	e, k, c := fixture(t)
	if _, err := e.Step(context.Background(), []Candidate{c}); err != nil {
		t.Fatal(err)
	}
	p := k.s.Peers[c.Key]
	p.Endpoint = "192.0.2.9:52123"
	k.s.Peers[c.Key] = p
	if _, err := e.Step(context.Background(), []Candidate{c}); err == nil {
		t.Fatal("old endpoint proof retained")
	}
	if err := e.Reset(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, ok := k.s.Peers[c.Key]; ok {
		t.Fatal("roaming stranded owned peer")
	}
}

func TestBatchIntentRecoversPartialInstallation(t *testing.T) {
	e, k, c := fixture(t)
	other := c
	other.ID = "next"
	other.Key = key(4)
	other.Address = "10.7.0.4"
	k.mode = "add-error"
	if _, err := e.Step(context.Background(), []Candidate{c, other}); err == nil {
		t.Fatal("partial command accepted")
	}
	if len(k.saved.Peers) != 2 || k.adds != 1 {
		t.Fatal("batch intent missing before first mutation")
	}
	recovered := newEngine(e.cfg, *k.saved, k, e.save)
	if err := recovered.Reset(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(k.s.Peers) != 1 || len(k.saved.Peers) != 0 {
		t.Fatal("partial batch not recovered")
	}
}
func TestConflictDoesNotPreventOtherOwnedPeerCleanup(t *testing.T) {
	e, k, c := fixture(t)
	other := c
	other.ID = "next"
	other.Key = key(4)
	other.Address = "10.7.0.4"
	if _, err := e.Step(context.Background(), []Candidate{c, other}); err != nil {
		t.Fatal(err)
	}
	p := k.s.Peers[c.Key]
	p.PSK = true
	k.s.Peers[c.Key] = p
	if err := e.Reset(context.Background()); err == nil {
		t.Fatal("foreign conflict ignored")
	}
	if _, ok := k.s.Peers[other.Key]; ok {
		t.Fatal("unconflicted peer stranded")
	}
	if !k.s.Peers[c.Key].PSK || len(k.saved.Peers) != 1 {
		t.Fatal("foreign state or intent changed")
	}
}

func TestDirectHostPrefixCannotStealRelayOwnership(t *testing.T) {
	for _, withNetwork := range []bool{false, true} {
		e, k, c := fixture(t)
		e.cfg.ServerAllowedIPs = []string{c.Address + "/32"}
		if withNetwork {
			e.cfg.ServerAllowedIPs = append(e.cfg.ServerAllowedIPs, "10.7.0.0/24")
		}
		if _, err := e.Step(context.Background(), []Candidate{c}); err == nil || k.adds != 0 {
			t.Fatal("relay host prefix stolen", err)
		}
	}
}
func TestRelayPrefixComparisonUsesCanonicalNetwork(t *testing.T) {
	e, k, c := fixture(t)
	e.cfg.ServerAllowedIPs = []string{"10.7.0.1/24"}
	if !e.relayOK(k.s) {
		t.Fatal("equivalent relay network rejected")
	}
	if _, err := e.Step(context.Background(), []Candidate{c}); err != nil {
		t.Fatal(err)
	}
}
func TestEarlyActiveFailureIsNeverDeferred(t *testing.T) {
	e, k, c := fixture(t)
	for i := 0; i < 2; i++ {
		if _, err := e.Step(context.Background(), []Candidate{c}); err != nil {
			t.Fatal(err)
		}
	}
	k.mode = "silent"
	r, err := e.Step(context.Background(), []Candidate{c})
	if err != nil || r[0].State != "relay_unverified" {
		t.Fatal(r, err)
	}
	if _, ok := k.s.Peers[c.Key]; ok {
		t.Fatal("failed active peer remains")
	}
}

func TestMissingRelayResponderDoesNotInvalidateHealthyDirectOrAdmitNewTrial(t *testing.T) {
	e, k, c := fixture(t)
	now := time.Now()
	e.now = func() time.Time { return now }
	for i := 0; i < 2; i++ {
		if _, err := e.Step(context.Background(), []Candidate{c}); err != nil {
			t.Fatal(err)
		}
	}
	now = now.Add(31 * time.Second)
	k.relaySilent = true
	r, err := e.Step(context.Background(), []Candidate{c})
	if err != nil || r[0].State != "active" {
		t.Fatal("API/probe outage removed healthy direct", r, err)
	}
	k.mode = "silent"
	if _, err = e.Step(context.Background(), []Candidate{c}); err != nil {
		t.Fatal(err)
	}
	now = now.Add(Cooldown)
	k.mode = "healthy"
	adds := k.adds
	r, err = e.Step(context.Background(), []Candidate{c})
	if err != nil || r[0].Reason != "relay_baseline_unverified" || k.adds != adds {
		t.Fatal("unverified standby admitted new direct", r, err)
	}
}

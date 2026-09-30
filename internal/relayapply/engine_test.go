// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayapply

import (
	"context"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"vpnctl/internal/api"

	"vpnctl/internal/relaycache"
	"vpnctl/internal/relaycatalog"
	"vpnctl/internal/relayplan"
)

func public(label string) string {
	h := sha256.Sum256([]byte(label))
	key, _ := ecdh.X25519().NewPrivateKey(h[:])
	return base64.StdEncoding.EncodeToString(key.PublicKey().Bytes())
}

type issuer struct {
	s   *relaycatalog.State
	env relaycatalog.Environment
}

func (f *issuer) RelayCatalog(_ context.Context, node string) (relaycatalog.View, error) {
	return f.s.NodeView(node), nil
}
func (f *issuer) BindRelayPath(_ context.Context, r relaycatalog.BindRequest) (relaycatalog.View, error) {
	n, e := relaycatalog.Bind(f.s, r, f.env, time.Now())
	if e == nil {
		f.s = n
	}
	return f.s.NodeView(r.NodeID), e
}

type inventory struct{ down bool }

func (c *inventory) Collect(_ context.Context, u relayplan.Underlay, endpoints []string) relayplan.Inventory {
	yes := true
	v := relayplan.Inventory{Underlay: u, Check: relayplan.Check{State: "up"}, ObservedAt: time.Now().UTC(), IfIndex: 7, Present: &yes, AdminUp: &yes, Carrier: &yes, Addresses: []string{"192.0.2.10"}}
	if c.down {
		v.State = "down"
		v.Reason = "link_down"
		return v
	}
	for _, ep := range endpoints {
		v.Routes = append(v.Routes, relayplan.Route{Check: relayplan.Check{State: "up"}, Endpoint: ep, Source: "192.0.2.10"})
	}
	return v
}

type fakeKernel struct {
	onCheck                           func()
	objects                           map[string][]string
	fail                              string
	after, crash, foreign, removeFail bool
	steps                             int
}

func (k *fakeKernel) Check(_ context.Context, e Entry, fresh bool) (bool, error) {
	if k.onCheck != nil {
		k.onCheck()
	}
	v := k.objects[e.Candidate.PathID]
	if k.foreign || fresh && len(v) > 0 {
		return false, ErrConflict
	}
	return len(v) == 8, nil
}
func (k *fakeKernel) Step(_ context.Context, e Entry, step, key string) error {
	k.steps++
	if step == "wg" {
		raw, err := base64.StdEncoding.DecodeString(key)
		if err != nil {
			return err
		}
		p, err := ecdh.X25519().NewPrivateKey(raw)
		if err != nil || base64.StdEncoding.EncodeToString(p.PublicKey().Bytes()) != e.Candidate.PublicKey {
			return errors.New("wrong key")
		}
	} else if key != "" {
		return errors.New("key exposed to non WG command")
	}
	if step == k.fail && !k.after {
		return errors.New("injected before mutation")
	}
	k.objects[e.Candidate.PathID] = append(k.objects[e.Candidate.PathID], step)
	if step == k.fail {
		if k.crash {
			panic("simulated process death")
		}
		return errors.New("injected after mutation")
	}
	return nil
}
func (k *fakeKernel) Remove(_ context.Context, e Entry) error {
	if k.foreign {
		return ErrConflict
	}
	if k.removeFail {
		return errors.New("cleanup failure")
	}
	delete(k.objects, e.Candidate.PathID)
	return nil
}
func fixture(t *testing.T, node string) (*Engine, *fakeKernel, string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	spec := relaycatalog.Spec{SchemaVersion: 1, PoolCIDR: "10.78.0.0/24", Relays: []relaycatalog.Relay{{ID: "r", PublicKey: public("relay"), KeyGeneration: 1, Endpoints: []relaycatalog.Endpoint{{ID: "e", Address: "192.0.2.1:51820"}}}}, Targets: []relaycatalog.Target{{ID: "app", Prefixes: []string{"198.18.0.2/32"}, ProbeAddress: "198.18.0.2", Protocol: "tcp", Port: 443}}}
	spec.Relays = append(spec.Relays, relaycatalog.Relay{ID: "r2", PublicKey: public("relay2"), KeyGeneration: 1, Endpoints: []relaycatalog.Endpoint{{ID: "e", Address: "192.0.2.2:51820"}}})
	for i := 0; i < 8; i++ {
		relay := "r"
		if i%2 == 1 {
			relay = "r2"
		}
		spec.Paths = append(spec.Paths, relaycatalog.Path{ID: fmt.Sprintf("p%d", i), NodeID: node, RelayID: relay, EndpointID: "e", UnderlayID: fmt.Sprintf("lan%d", i/2), TargetIDs: []string{"app"}})
	}
	u := []relayplan.Underlay{}
	for i := 0; i < 4; i++ {
		u = append(u, relayplan.Underlay{ID: fmt.Sprintf("lan%d", i), Interface: fmt.Sprintf("wan%d", i), Kind: "ethernet"})
	}
	env := relaycatalog.Environment{Nodes: map[string]bool{node: true}, VPNCIDR: "10.7.0.0/24"}
	s, err := relaycatalog.Apply(nil, relaycatalog.Update{Spec: spec, TTLSeconds: 3600}, env, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	cache, err := relaycache.Open(dir, relaycache.Options{NodeID: node, Create: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cache.Close() })
	if _, err = cache.Refresh(context.Background(), &issuer{s, env}); err != nil {
		t.Fatal(err)
	}
	k := &fakeKernel{objects: map[string][]string{}}
	e, err := open(cache, u, "boot:ns", k)
	if err != nil {
		t.Fatal(err)
	}
	e.collector = &inventory{}
	return e, k, dir
}
func reopen(t *testing.T, e *Engine, dir string) *Engine {
	t.Helper()
	e.cache.Close()
	c, err := relaycache.Open(dir, relaycache.Options{NodeID: e.journal.Node})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	n, err := open(c, e.underlays, e.journal.Domain, e.backend)
	if err != nil {
		t.Fatal(err)
	}
	n.collector = e.collector
	return n
}
func TestPrepareEveryCommandFailureAndCrash(t *testing.T) {
	for _, step := range []string{"link", "tag", "guard", "endpoint", "rule", "address", "wg", "up"} {
		for _, mode := range []string{"before", "after", "crash"} {
			t.Run(step+"/"+mode, func(t *testing.T) {
				e, k, dir := fixture(t, "robot")
				k.fail = step
				k.after = mode != "before"
				k.crash = mode == "crash"
				if k.crash {
					func() {
						defer func() {
							if recover() == nil {
								t.Error("crash did not occur")
							}
						}()
						e.Prepare(context.Background(), "p0", "")
					}()
					if len(k.objects["p0"]) == 0 {
						t.Fatal("crash not after mutation")
					}
					e = reopen(t, e, dir)
					if out, err := e.Recover(context.Background()); err != nil || out.State != "empty" {
						t.Fatal(out, err)
					}
				} else {
					out, err := e.Prepare(context.Background(), "p0", "")
					if err == nil || out.Reason != "prepare_failed_rolled_back" {
						t.Fatal(out, err)
					}
				}
				if len(k.objects) != 0 || len(e.journal.Entries) != 0 {
					t.Fatal("partial resources leaked")
				}
				k.fail = ""
				k.crash = false
				if out, err := e.Prepare(context.Background(), "p0", ""); err != nil || !out.KernelReady {
					t.Fatal(out, err)
				}
			})
		}
	}
}
func TestPreparedVariableFleetAndReplay(t *testing.T) {
	for _, size := range []int{1, 3, 8, 32} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			for i := 0; i < size; i++ {
				t.Run(fmt.Sprint(i), func(t *testing.T) {
					t.Parallel()
					e, k, dir := fixture(t, fmt.Sprintf("robot%d", i))
					for p := 0; p < 8; p++ {
						if out, err := e.Prepare(context.Background(), fmt.Sprintf("p%d", p), ""); err != nil || !out.KernelReady {
							t.Fatal(out, err)
						}
					}
					if k.steps != 64 {
						t.Fatal(k.steps)
					}
					e = reopen(t, e, dir)
					if out, err := e.Prepare(context.Background(), "p0", ""); err != nil || !out.KernelReady || k.steps != 64 {
						t.Fatal("non-idempotent replay", out, err)
					}
					if out, err := e.Inspect(context.Background()); err != nil || len(out.Paths) != 8 || out.UplinkHealth != "unknown" {
						t.Fatal(out, err)
					}
					for p := 0; p < 8; p++ {
						if _, err := e.Release(context.Background(), fmt.Sprintf("p%d", p)); err != nil {
							t.Fatal(err)
						}
					}
					if len(k.objects) != 0 {
						t.Fatal("resources remain")
					}
				})
			}
		})
	}
}
func TestJournalAndOwnershipFailures(t *testing.T) {
	for _, mode := range []string{"first-save", "final-save", "rollback", "foreign", "changed-inventory", "lost-journal", "corrupt", "wrong-domain", "release-save"} {
		t.Run(mode, func(t *testing.T) {
			e, k, dir := fixture(t, "robot")
			switch mode {
			case "first-save":
				e.save = func([]byte) error { return errors.New("disk full") }
			case "final-save":
				original := e.save
				calls := 0
				e.save = func(b []byte) error {
					calls++
					if calls == 2 {
						return errors.New("sync failed")
					}
					return original(b)
				}
			case "rollback":
				k.fail = "wg"
				k.after = true
				k.removeFail = true
			case "foreign":
				k.foreign = true
			case "changed-inventory":
				e.collector = &inventory{down: true}
			}
			out, err := e.Prepare(context.Background(), "p0", "")
			switch mode {
			case "first-save", "foreign", "changed-inventory":
				if err == nil || k.steps != 0 {
					t.Fatal("mutated before validation/durability", out, err)
				}
			case "final-save", "rollback":
				if err == nil {
					t.Fatal("failure hidden")
				}
				if mode == "final-save" {
					if out, err := e.Inspect(context.Background()); err == nil || out.KernelReady {
						t.Fatal("uncertain journal advertised ready")
					}
				}
				e = reopen(t, e, dir)
				k.removeFail = false
				if _, err = e.Recover(context.Background()); err != nil || len(k.objects) > 0 {
					t.Fatal(err)
				}
			default:
				if err != nil {
					t.Fatal(err)
				}
				switch mode {
				case "release-save":
					e.save = func([]byte) error { return errors.New("disk full") }
					if _, err = e.Release(context.Background(), "p0"); err == nil || len(k.objects) == 0 {
						t.Fatal("cleanup without durable intent")
					}
				case "lost-journal":
					if err = os.Remove(filepath.Join(dir, "apply.json")); err != nil {
						t.Fatal(err)
					}
					if _, err = e.cache.ApplyJournal(); err == nil {
						t.Fatal("lost journal accepted")
					}
				case "corrupt":
					if err = os.WriteFile(filepath.Join(dir, "apply.json"), []byte(`{"journal":{}}`), 0600); err != nil {
						t.Fatal(err)
					}
					if _, err = open(e.cache, e.underlays, "boot:ns", k); err == nil {
						t.Fatal("corrupt journal accepted")
					}
				case "wrong-domain":
					if _, err = open(e.cache, e.underlays, "different-boot:ns", k); err == nil {
						t.Fatal("foreign namespace accepted")
					}
				}
			}
		})
	}
}
func TestKernelNamespaceLock(t *testing.T) {
	name := fmt.Sprintf("@vpnctl.relay-apply.test.%d", os.Getpid())
	u, err := namedKernelLock(name)
	if err != nil {
		t.Fatal(err)
	}
	if second, e := namedKernelLock(name); e == nil {
		second()
		u()
		t.Fatal("concurrent kernel writer accepted")
	}
	u()
	u, err = namedKernelLock(name)
	if err != nil {
		t.Fatal(err)
	}
	u()
}
func TestJournalContainsNoPrivateKeys(t *testing.T) {
	e, _, dir := fixture(t, "robot")
	if _, err := e.Prepare(context.Background(), "p0", ""); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "apply.json"))
	if err != nil {
		t.Fatal(err)
	}
	entry := e.journal.Entries[0]
	if err = e.cache.WithPathKey(entry.Controller, entry.Generation, "p0", entry.Candidate.PublicKey, func(key string) error {
		if strings.Contains(string(b), key) || strings.Contains(string(b), "private_key") {
			t.Fatal("secret in journal")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

type inventoryFunc func(context.Context, relayplan.Underlay, []string) relayplan.Inventory

func (f inventoryFunc) Collect(ctx context.Context, u relayplan.Underlay, v []string) relayplan.Inventory {
	return f(ctx, u, v)
}

type deniedIssuer struct{}

func (deniedIssuer) RelayCatalog(context.Context, string) (relaycatalog.View, error) {
	return relaycatalog.View{}, &api.HTTPError{StatusCode: 403}
}
func (deniedIssuer) BindRelayPath(context.Context, relaycatalog.BindRequest) (relaycatalog.View, error) {
	return relaycatalog.View{}, errors.New("not called")
}
func TestApprovalAndInventoryAreRecheckedAfterReadback(t *testing.T) {
	t.Run("inspection_denial_during_collection", func(t *testing.T) {
		e, _, _ := fixture(t, "robot")
		if _, err := e.Prepare(context.Background(), "p0", ""); err != nil {
			t.Fatal(err)
		}
		called := false
		e.collector = inventoryFunc(func(ctx context.Context, u relayplan.Underlay, v []string) relayplan.Inventory {
			called = true
			if _, err := e.cache.Refresh(ctx, deniedIssuer{}); err == nil {
				t.Fatal("denial not stored")
			}
			return (&inventory{}).Collect(ctx, u, v)
		})
		out, err := e.Inspect(context.Background())
		if !called || err == nil || out.KernelReady || out.Paths[0].KernelReady {
			t.Fatal("late denial advertised ready", out, err)
		}
	})
	t.Run("repeat_prepare_inventory_changes_during_readback", func(t *testing.T) {
		e, k, _ := fixture(t, "robot")
		if _, err := e.Prepare(context.Background(), "p0", ""); err != nil {
			t.Fatal(err)
		}
		inv := e.collector.(*inventory)
		k.onCheck = func() { inv.down = true }
		out, err := e.Prepare(context.Background(), "p0", "")
		if err == nil || out.KernelReady || k.steps != 8 {
			t.Fatal("changed inventory advertised ready", out, err)
		}
	})
}

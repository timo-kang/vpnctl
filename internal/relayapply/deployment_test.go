// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayapply

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"vpnctl/internal/api"
	"vpnctl/internal/relaycache"
	"vpnctl/internal/relaycatalog"
)

type deployIssuer struct {
	view relaycatalog.DeploymentView
	err  error
}

func (f *deployIssuer) RelayDeployment(context.Context, string, string) (relaycatalog.DeploymentView, error) {
	return f.view, f.err
}

type deployedFake struct {
	entry DeploymentEntry
	steps int
	up    bool
	lease DeploymentLease
}
type deploymentFake struct {
	objects               map[string]deployedFake
	fail                  string
	after, crash, foreign bool
	hook                  func(string)
	checkHook             func()
	now                   func() time.Time
}

func (k *deploymentFake) currentTime() time.Time {
	if k.now != nil {
		return k.now()
	}
	return time.Now().UTC()
}

func (k *deploymentFake) Check(_ context.Context, e DeploymentEntry, fresh bool) (bool, error) {
	if !fresh && k.checkHook != nil {
		k.checkHook()
	}
	v, ok := k.objects[e.Endpoint]
	if k.foreign || fresh && ok {
		return false, ErrConflict
	}
	return ok && v.steps == 6 && v.up, nil
}
func (k *deploymentFake) Step(_ context.Context, e DeploymentEntry, step, key string) error {
	if k.hook != nil {
		k.hook(step)
	}
	if (step == "wg") != (key != "") {
		return errors.New("secret channel mismatch")
	}
	if step == k.fail && !k.after {
		return errors.New("before step")
	}
	v := k.objects[e.Endpoint]
	v.entry = e
	v.steps++
	v.up = v.up || step == "up"
	k.objects[e.Endpoint] = v
	if step == k.fail {
		if k.crash {
			panic("process death")
		}
		return errors.New("after step")
	}
	return nil
}
func (k *deploymentFake) Down(_ context.Context, e DeploymentEntry) error {
	if v, ok := k.objects[e.Endpoint]; ok {
		v.lease = DeploymentLease{}
		k.objects[e.Endpoint] = v
	}
	if k.foreign {
		return ErrConflict
	}
	if v, ok := k.objects[e.Endpoint]; ok {
		v.up = false
		k.objects[e.Endpoint] = v
	}
	return nil
}
func (k *deploymentFake) Lease(_ context.Context, e DeploymentEntry, until, authenticatedAt time.Time) (DeploymentLease, error) {
	v := k.objects[e.Endpoint]
	now := k.currentTime()
	deadline, err := leaseDeadline(v.lease.Active && now.Before(v.lease.Deadline), until, authenticatedAt, now)
	if err != nil {
		return v.lease, err
	}
	v.lease = DeploymentLease{Active: true, Deadline: deadline}
	k.objects[e.Endpoint] = v
	return v.lease, nil
}
func (k *deploymentFake) LeaseStatus(_ context.Context, e DeploymentEntry) (DeploymentLease, error) {
	v := k.objects[e.Endpoint].lease
	v.Active = v.Active && k.currentTime().Before(v.Deadline)
	return v, nil
}
func (k *deploymentFake) Remove(_ context.Context, e DeploymentEntry) error {
	if k.foreign {
		return ErrConflict
	}
	delete(k.objects, e.Endpoint)
	return nil
}

func deploymentFixture(t *testing.T, nodes int) (*DeploymentEngine, *deploymentFake, *relaycache.DeploymentStore, *deployIssuer, DeploymentOptions, string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	seed := sha256.Sum256([]byte("relay"))
	key := filepath.Join(dir, "relay.key")
	if err := os.WriteFile(key, []byte(base64.StdEncoding.EncodeToString(seed[:])+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	env := relaycatalog.Environment{Nodes: map[string]bool{}, VPNCIDR: "10.77.0.0/24"}
	spec := relaycatalog.Spec{SchemaVersion: 1, PoolCIDR: "10.78.0.0/16", Relays: []relaycatalog.Relay{{ID: "r", PublicKey: public("relay"), KeyGeneration: 1, Endpoints: []relaycatalog.Endpoint{{ID: "ep0", Address: "192.0.2.1:51820"}, {ID: "ep1", Address: "198.51.100.1:51821"}}}}, Targets: []relaycatalog.Target{{ID: "app", Prefixes: []string{"198.18.0.2/32"}, ProbeAddress: "198.18.0.2", Port: 443, Protocol: "tcp"}}}
	for n := 0; n < nodes; n++ {
		node := fmt.Sprintf("node-%d", n)
		env.Nodes[node] = true
		for p := 0; p < 4; p++ {
			spec.Paths = append(spec.Paths, relaycatalog.Path{ID: fmt.Sprintf("p-%d-%d", n, p), NodeID: node, RelayID: "r", EndpointID: fmt.Sprintf("ep%d", p%2), UnderlayID: fmt.Sprintf("lan%d", p), TargetIDs: []string{"app"}})
		}
	}
	now := time.Now().UTC()
	state, err := relaycatalog.Apply(nil, relaycatalog.Update{TTLSeconds: 3600, Spec: spec}, env, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range spec.Paths {
		state, err = relaycatalog.Bind(state, relaycatalog.BindRequest{SchemaVersion: 1, ControllerID: state.ControllerID, ExpectedGeneration: state.Generation, NodeID: p.NodeID, PathID: p.ID, PublicKey: public(p.ID)}, env, now)
		if err != nil {
			t.Fatal(err)
		}
	}
	state, err = relaycatalog.SetRecipient(state, relaycatalog.RecipientUpdate{ControllerID: state.ControllerID, ExpectedGeneration: state.Generation, RelayID: "r", PrincipalID: "node-0"}, env)
	if err != nil {
		t.Fatal(err)
	}
	v, _ := state.DeploymentFor("node-0", "r")
	f := &deployIssuer{view: v}
	cacheDir := filepath.Join(dir, "cache")
	c, err := relaycache.OpenDeployment(cacheDir, relaycache.DeploymentOptions{PrincipalID: "node-0", RelayID: "r", Create: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	if _, err = c.Refresh(context.Background(), f); err != nil {
		t.Fatal(err)
	}
	k := &deploymentFake{objects: map[string]deployedFake{}}
	e, err := openDeploymentEngine(c, "boot:net", k)
	if err != nil {
		t.Fatal(err)
	}
	return e, k, c, f, DeploymentOptions{EndpointID: "ep0", KeyFile: key, KeyGeneration: 1, ListenPort: 51820}, cacheDir
}
func reopenDeployment(t *testing.T, e *DeploymentEngine, c *relaycache.DeploymentStore, dir string) (*DeploymentEngine, *relaycache.DeploymentStore) {
	t.Helper()
	c.Close()
	n, err := relaycache.OpenDeployment(dir, relaycache.DeploymentOptions{PrincipalID: "node-0", RelayID: "r"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { n.Close() })
	e, err = openDeploymentEngine(n, "boot:net", e.backend)
	if err != nil {
		t.Fatal(err)
	}
	return e, n
}
func TestRelayDeploymentEveryStepFailureAndCrash(t *testing.T) {
	for _, step := range []string{"guard", "link", "tag", "wg", "routes", "up"} {
		for _, mode := range []string{"before", "after", "crash"} {
			t.Run(step+"/"+mode, func(t *testing.T) {
				e, k, c, _, o, dir := deploymentFixture(t, 1)
				k.fail = step
				k.after = mode != "before"
				k.crash = mode == "crash"
				if k.crash {
					func() {
						defer func() {
							if recover() == nil {
								t.Error("no crash")
							}
						}()
						e.Apply(context.Background(), o)
					}()
					e, c = reopenDeployment(t, e, c, dir)
					if _, err := e.Recover(context.Background()); err != nil {
						t.Fatal(err)
					}
				} else if r, err := e.Apply(context.Background(), o); err == nil || r.Reason != "apply_failed_rolled_back" {
					t.Fatal(r, err)
				}
				if len(k.objects) != 0 || len(e.journal.Entries) != 0 {
					t.Fatal("owned resources survived rollback")
				}
			})
		}
	}
}
func TestRelayDeploymentScaleReopenAndWithdraw(t *testing.T) {
	for _, size := range []int{1, 3, 8, 32} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			e, k, c, f, o, dir := deploymentFixture(t, size)
			for n := 0; n < 2; n++ {
				o.EndpointID = fmt.Sprintf("ep%d", n)
				o.ListenPort = 51820 + n
				for retry := 0; retry < 4; retry++ {
					r, err := e.Apply(context.Background(), o)
					if err != nil || !r.KernelReady {
						t.Fatal(r, err)
					}
				}
				if len(k.objects[o.EndpointID].entry.Peers) != size*2 {
					t.Fatal("wrong peer population")
				}
			}
			e, c = reopenDeployment(t, e, c, dir)
			if r, err := e.Inspect(context.Background()); err != nil || !r.KernelReady || len(r.Endpoints) != 2 {
				t.Fatal(r, err)
			}
			f.err = &api.HTTPError{StatusCode: 403}
			if _, err := c.Refresh(context.Background(), f); err == nil {
				t.Fatal("denial succeeded")
			}
			if r, err := e.Inspect(context.Background()); err == nil || r.KernelReady || len(k.objects) != 0 {
				t.Fatal("revocation did not block", r, err)
			}
			f.err = io.EOF
			c.Refresh(context.Background(), f)
			if _, err := e.Apply(context.Background(), o); err == nil || len(k.objects) != 0 {
				t.Fatal("outage restored peers")
			}
			f.err = nil
			c.Refresh(context.Background(), f)
			if r, err := e.Apply(context.Background(), o); err != nil || !r.KernelReady {
				t.Fatal(r, err)
			}
		})
	}
}
func TestRelayDeploymentKeySafetyAndLocalGeneration(t *testing.T) {
	for _, kind := range []string{"mismatch", "generation", "mode", "symlink", "hardlink", "oversize"} {
		t.Run(kind, func(t *testing.T) {
			e, k, _, _, o, _ := deploymentFixture(t, 1)
			switch kind {
			case "mismatch":
				seed := sha256.Sum256([]byte("wrong"))
				os.WriteFile(o.KeyFile, []byte(base64.StdEncoding.EncodeToString(seed[:])), 0600)
			case "generation":
				o.KeyGeneration = 2
			case "mode":
				os.Chmod(o.KeyFile, 0644)
			case "symlink":
				os.Rename(o.KeyFile, o.KeyFile+".real")
				os.Symlink(o.KeyFile+".real", o.KeyFile)
			case "hardlink":
				os.Link(o.KeyFile, o.KeyFile+".link")
			case "oversize":
				os.WriteFile(o.KeyFile, []byte(strings.Repeat("x", 100)), 0600)
			}
			if _, err := e.Apply(context.Background(), o); err == nil || len(k.objects) != 0 {
				t.Fatal("unsafe key applied")
			}
		})
	}
}

type failingDeploymentCache struct {
	deploymentCache
	failAt, calls int
	after         bool
}

func (c *failingDeploymentCache) SaveDeploymentJournal(b []byte) error {
	c.calls++
	if c.calls == c.failAt {
		if c.after {
			if err := c.deploymentCache.SaveDeploymentJournal(b); err != nil {
				return err
			}
		}
		return errors.New("disk full")
	}
	return c.deploymentCache.SaveDeploymentJournal(b)
}
func TestRelayDeploymentSaveFailureQuiescesAndRecovers(t *testing.T) {
	for _, at := range []int{1, 2} {
		for _, after := range []bool{false, true} {
			t.Run(fmt.Sprintf("save-%d-after-%v", at, after), func(t *testing.T) {
				e, k, c, _, o, dir := deploymentFixture(t, 1)
				e.cache = &failingDeploymentCache{deploymentCache: c, failAt: at, after: after}
				if _, err := e.Apply(context.Background(), o); err == nil {
					t.Fatal("save succeeded")
				}
				for _, v := range k.objects {
					if v.up {
						t.Fatal("uncertain completed apply left traffic enabled")
					}
				}
				e, c = reopenDeployment(t, e, c, dir)
				// A post-rename final commit may be complete on disk but quiesced; it
				// must not be silently re-enabled by recovery.
				r, err := e.Recover(context.Background())
				if at == 2 && after {
					if err == nil || r.KernelReady {
						t.Fatal("uncertain traffic restored")
					}
					if _, err = e.Release(context.Background(), o.EndpointID); err != nil {
						t.Fatal(err)
					}
				} else if err != nil {
					t.Fatal(err)
				}
				if len(k.objects) != 0 {
					t.Fatal("resources not recovered")
				}
			})
		}
	}
}
func TestRelayDeploymentExpiryRemovalAndForeignResources(t *testing.T) {
	e, k, c, f, o, _ := deploymentFixture(t, 1)
	if _, err := e.Apply(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	f.err = &api.HTTPError{StatusCode: 503, Code: "relay_catalog_expired"}
	c.Refresh(context.Background(), f)
	k.foreign = true
	if r, err := e.Inspect(context.Background()); err == nil || r.KernelReady || len(k.objects) != 1 {
		t.Fatal("foreign resources changed", r, err)
	}
	k.foreign = false
	if _, err := e.Inspect(context.Background()); err == nil || len(k.objects) != 0 {
		t.Fatal("expired peers retained")
	}
	f.err = nil
	c.Refresh(context.Background(), f)
	if _, err := e.Apply(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	f.view.Generation++
	f.view.Spec.Paths = nil
	f.view.Spec.Targets = nil
	f.view.Bindings = nil
	if _, err := c.Refresh(context.Background(), f); err != nil {
		t.Fatal(err)
	}
	if r, err := e.Inspect(context.Background()); err != nil || r.State != "empty" || len(k.objects) != 0 {
		t.Fatal("removed peers retained", r, err)
	}
}
func TestRelayDeploymentJournalIntegrity(t *testing.T) {
	for _, kind := range []string{"domain", "corrupt", "missing", "marker"} {
		t.Run(kind, func(t *testing.T) {
			e, _, c, _, o, dir := deploymentFixture(t, 1)
			if _, err := e.Apply(context.Background(), o); err != nil {
				t.Fatal(err)
			}
			domain := "boot:net"
			switch kind {
			case "domain":
				domain = "new-boot:net"
			case "corrupt":
				os.WriteFile(filepath.Join(dir, "peers.json"), []byte(`{"private_key":"must-not-print"}`), 0600)
			case "missing":
				os.Remove(filepath.Join(dir, "peers.json"))
			case "marker":
				os.WriteFile(filepath.Join(dir, "peers-initialized"), []byte("bad"), 0600)
			}
			if _, err := openDeploymentEngine(c, domain, e.backend); err == nil || strings.Contains(err.Error(), "must-not-print") {
				t.Fatal("invalid journal accepted or disclosed", err)
			}
		})
	}
}

type expiringDeploymentCache struct {
	deploymentCache
	expired bool
}

func (c *expiringDeploymentCache) Status() (relaycache.DeploymentReport, error) {
	r, err := c.deploymentCache.Status()
	if c.expired {
		r.ApprovalValid = false
		r.Validity = "expired"
		r.Deployment.ExpiresAt = time.Now().Add(-time.Second)
	}
	return r, err
}
func TestRelayDeploymentExpiryDuringEveryStepAndInspection(t *testing.T) {
	for _, step := range []string{"guard", "link", "tag", "wg", "routes", "up", "inspect"} {
		t.Run(step, func(t *testing.T) {
			e, k, c, _, o, _ := deploymentFixture(t, 1)
			if _, err := e.Apply(context.Background(), o); err != nil {
				t.Fatal(err)
			}
			clock := &expiringDeploymentCache{deploymentCache: c}
			e.cache = clock
			var out DeploymentResult
			var err error
			if step == "inspect" {
				k.checkHook = func() { clock.expired = true }
				out, err = e.Inspect(context.Background())
			} else {
				k.hook = func(s string) {
					if s == step {
						clock.expired = true
					}
				}
				o.EndpointID = "ep1"
				o.ListenPort = 51821
				out, err = e.Apply(context.Background(), o)
			}
			if err == nil || out.KernelReady || len(k.objects) != 0 || len(e.journal.Entries) != 0 {
				t.Fatal("expiry retained peers or reported ready", out, err)
			}
		})
	}
}

func TestRelayDeploymentKeyRotationAndEmptyEndpoint(t *testing.T) {
	e, k, c, f, o, dir := deploymentFixture(t, 3)
	if _, err := e.Apply(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	f.view.Generation++
	f.view.Spec.Relays[0].KeyGeneration++
	f.view.Spec.Relays[0].PublicKey = public("rotated")
	for i := range f.view.Bindings {
		for _, p := range f.view.Spec.Paths {
			if p.ID == f.view.Bindings[i].PathID {
				f.view.Bindings[i].DefinitionHash = relaycatalog.DefinitionHash(f.view.Spec, p)
			}
		}
	}
	if _, err := c.Refresh(context.Background(), f); err != nil {
		t.Fatal(err)
	}
	if r, err := e.Inspect(context.Background()); err != nil || r.State != "empty" || len(k.objects) != 0 {
		t.Fatal("rotation retained old peers", r, err)
	}
	if _, err := e.Apply(context.Background(), o); err == nil {
		t.Fatal("old generation restored")
	}
	o.KeyGeneration = 2
	if _, err := e.Apply(context.Background(), o); err == nil {
		t.Fatal("old private key restored")
	}
	seed := sha256.Sum256([]byte("rotated"))
	if err := os.WriteFile(o.KeyFile, []byte(base64.StdEncoding.EncodeToString(seed[:])), 0600); err != nil {
		t.Fatal(err)
	}
	if r, err := e.Apply(context.Background(), o); err != nil || !r.KernelReady {
		t.Fatal(r, err)
	}
	e, c = reopenDeployment(t, e, c, dir)
	f.view.Generation++
	f.view.Spec.Paths = nil
	f.view.Spec.Targets = nil
	f.view.Bindings = nil
	if _, err := c.Refresh(context.Background(), f); err != nil {
		t.Fatal(err)
	}
	if r, err := e.Apply(context.Background(), o); err != nil || !r.KernelReady || len(k.objects[o.EndpointID].entry.Peers) != 0 {
		t.Fatal("empty approval retained peers", r, err)
	}
}

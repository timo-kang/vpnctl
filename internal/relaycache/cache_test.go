// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relaycache

import (
	"context"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"vpnctl/internal/api"
	"vpnctl/internal/relaycatalog"
)

func testPublic(label string) string {
	seed := sha256.Sum256([]byte(label))
	k, _ := ecdh.X25519().NewPrivateKey(seed[:])
	return base64.StdEncoding.EncodeToString(k.PublicKey().Bytes())
}
func testSpec() relaycatalog.Spec {
	return relaycatalog.Spec{SchemaVersion: 1, PoolCIDR: "10.78.0.0/24", Relays: []relaycatalog.Relay{
		{ID: "r1", PublicKey: testPublic("r1"), KeyGeneration: 1, Endpoints: []relaycatalog.Endpoint{{ID: "e", Address: "192.0.2.1:51820"}}},
		{ID: "r2", PublicKey: testPublic("r2"), KeyGeneration: 1, Endpoints: []relaycatalog.Endpoint{{ID: "e", Address: "192.0.2.2:51820"}}},
	}, Targets: []relaycatalog.Target{{ID: "app", Prefixes: []string{"198.18.0.2/32"}, ProbeAddress: "198.18.0.2", Protocol: "tcp", Port: 443}}, Paths: []relaycatalog.Path{
		{ID: "p1", NodeID: "robot", RelayID: "r1", EndpointID: "e", UnderlayID: "wifi", TargetIDs: []string{"app"}},
		{ID: "p2", NodeID: "robot", RelayID: "r2", EndpointID: "e", UnderlayID: "lan", TargetIDs: []string{"app"}},
	}}
}
func env() relaycatalog.Environment {
	return relaycatalog.Environment{VPNCIDR: "10.7.0.0/24", Nodes: map[string]bool{"robot": true}}
}

type fakeController struct {
	state          *relaycatalog.State
	now            time.Time
	getError       error
	get            func(context.Context) (relaycatalog.View, error)
	afterBindError error
	conflict       bool
	requests       []relaycatalog.BindRequest
}

func newController(t *testing.T) *fakeController {
	t.Helper()
	now := time.Now().UTC()
	state, e := relaycatalog.Apply(nil, relaycatalog.Update{TTLSeconds: 3600, Spec: testSpec()}, env(), now)
	if e != nil {
		t.Fatal(e)
	}
	return &fakeController{state: state, now: now}
}
func (f *fakeController) RelayCatalog(ctx context.Context, node string) (relaycatalog.View, error) {
	if f.get != nil {
		return f.get(ctx)
	}
	if f.getError != nil {
		return relaycatalog.View{}, f.getError
	}
	return f.state.NodeView(node), nil
}
func (f *fakeController) BindRelayPath(ctx context.Context, r relaycatalog.BindRequest) (relaycatalog.View, error) {
	f.requests = append(f.requests, r)
	if f.conflict {
		next, e := relaycatalog.Apply(f.state, relaycatalog.Update{ControllerID: f.state.ControllerID, ExpectedGeneration: f.state.Generation, TTLSeconds: 3600, Spec: f.state.Spec}, env(), f.now)
		if e != nil {
			return relaycatalog.View{}, e
		}
		f.state = next
		return relaycatalog.View{}, &api.HTTPError{StatusCode: 409, Code: "relay_catalog_conflict"}
	}
	next, e := relaycatalog.Bind(f.state, r, env(), f.now)
	if e != nil {
		return relaycatalog.View{}, e
	}
	f.state = next
	if f.afterBindError != nil {
		e = f.afterBindError
		f.afterBindError = nil
		return relaycatalog.View{}, e
	}
	return f.state.NodeView(r.NodeID), nil
}
func privateTempDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if e := os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	return dir
}
func openCache(t *testing.T, dir string) *Store {
	t.Helper()
	s, e := Open(dir, Options{NodeID: "robot", Create: true, LegacyPublicKeys: []string{testPublic("legacy")}})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Close() })
	return s
}
func ready(t *testing.T, s *Store, f *fakeController) Report {
	t.Helper()
	r, e := s.Refresh(context.Background(), f)
	if e != nil {
		t.Fatal(e)
	}
	if !r.UsableCache || r.Preparation != "complete" || r.Refresh.Result != "success" {
		t.Fatalf("not prepared: validity=%s preparation=%s reason=%s", r.Validity, r.Preparation, r.BlockedReason)
	}
	return r
}

func TestDurableKeysOfflineStatusAndRestart(t *testing.T) {
	dir := filepath.Join(privateTempDir(t), "cache")
	s := openCache(t, dir)
	f := newController(t)
	r := ready(t, s, f)
	if len(r.Paths) != 2 || len(f.state.Bindings) != 2 || r.RetainedKeys != 2 {
		t.Fatal("wrong candidate population")
	}
	keys := cloneState(s.state).Keys
	public, _ := json.Marshal(r)
	for _, k := range keys {
		if strings.Contains(string(public), k.PrivateKey) || !strings.Contains(string(public), k.PublicKey) {
			t.Fatal("report leaked secret or hid binding")
		}
	}
	if _, e := Open(dir, Options{NodeID: "robot"}); !errors.Is(e, ErrBusy) {
		t.Fatal("second owner", e)
	}
	s.Close()
	s = openCache(t, dir)
	f.getError = io.EOF
	r, e := s.Refresh(context.Background(), f)
	if e == nil || !r.UsableCache || r.Refresh.Result != "unavailable" || r.Validity != "valid" {
		t.Fatal("outage confused with invalid cache", e)
	}
	if !same(keys, s.state.Keys) {
		t.Fatal("restart/outage changed keys")
	}
	f.getError = nil
	ready(t, s, f)
	if len(f.requests) != 2 || len(f.state.Bindings) != 2 {
		t.Fatal("repeated refresh allocated again")
	}
}
func TestLostBindingResponseReusesPersistedKey(t *testing.T) {
	dir := filepath.Join(privateTempDir(t), "cache")
	s := openCache(t, dir)
	f := newController(t)
	f.afterBindError = io.EOF
	r, e := s.Refresh(context.Background(), f)
	if e == nil || r.Preparation != "partial" || r.UsableCache || len(f.state.Bindings) != 1 {
		t.Fatal("ambiguous binding acknowledged", e)
	}
	public := s.state.Keys[0].PublicKey
	private := s.state.Keys[0].PrivateKey
	s.Close()
	s = openCache(t, dir)
	ready(t, s, f)
	if s.state.Keys[0].PublicKey != public || s.state.Keys[0].PrivateKey != private || len(f.requests) != 2 || len(f.state.Bindings) != 2 {
		t.Fatal("lost response generated another key/binding")
	}
}
func TestCachePersistenceFaultBoundaries(t *testing.T) {
	for _, phase := range []string{"revision", "key", "binding", "completion"} {
		for _, after := range []bool{false, true} {
			t.Run(phase+map[bool]string{false: "_before", true: "_after"}[after], func(t *testing.T) {
				dir := filepath.Join(privateTempDir(t), "cache")
				s := openCache(t, dir)
				f := newController(t)
				original := s.writeState
				injected := false
				s.writeState = func(raw []byte) error {
					var n diskState
					if e := json.Unmarshal(raw, &n); e != nil {
						return e
					}
					match := phase == "revision" && n.Generation == 1 && n.Catalog == nil || phase == "key" && len(n.Keys) == 1 && n.Keys[0].Binding == nil || phase == "binding" && n.Catalog != nil && len(n.Catalog.Bindings) == 1 || phase == "completion" && n.Refresh.Result == "success"
					if match && !injected {
						injected = true
						if !after {
							return syscall.ENOSPC
						}
						syncDir := s.syncDir
						s.syncDir = func() error { return syscall.EIO }
						defer func() { s.syncDir = syncDir }()
						return original(raw)
					}
					return original(raw)
				}
				r, e := s.Refresh(context.Background(), f)
				if e == nil || !injected || r.Validity != "uncertain" || r.UsableCache {
					t.Fatal("storage fault reported success", e)
				}
				if (phase == "key" || phase == "revision") && len(f.requests) != 0 {
					t.Fatal("sent key before durable local commit")
				}
				retained := map[string]string{}
				for _, k := range s.state.Keys {
					retained[k.PathID] = k.PrivateKey
				}
				s.Close()
				s = openCache(t, dir)
				ready(t, s, f)
				if len(f.state.Bindings) != 2 || len(s.state.Keys) != 2 {
					t.Fatal("fault retry population changed")
				}
				for _, k := range s.state.Keys {
					if old, ok := retained[k.PathID]; ok && old != k.PrivateKey {
						t.Fatal("durable private key replaced")
					}
				}
			})
		}
	}
}
func TestRejectedIdentityAndRevisionRemainBlockedOffline(t *testing.T) {
	for _, mode := range []string{"denied", "rollback", "controller", "same_generation", "unknown_binding", "changed_binding", "schema", "foreign_node", "foreign_key"} {
		t.Run(mode, func(t *testing.T) {
			dir := filepath.Join(privateTempDir(t), "cache")
			s := openCache(t, dir)
			f := newController(t)
			ready(t, s, f)
			previous := f.state
			before := cloneState(s.state)
			switch mode {
			case "denied":
				f.getError = &api.HTTPError{StatusCode: 403}
			case "rollback":
				v := f.state.NodeView("robot")
				v.Generation--
				f.get = func(context.Context) (relaycatalog.View, error) { return v, nil }
			case "controller":
				v := f.state.NodeView("robot")
				v.ControllerID = strings.Repeat("b", 32)
				f.get = func(context.Context) (relaycatalog.View, error) { return v, nil }
			case "same_generation":
				v := f.state.NodeView("robot")
				v.Spec.Paths[0].Cost++
				f.get = func(context.Context) (relaycatalog.View, error) { return v, nil }
			case "changed_binding":
				v := f.state.NodeView("robot")
				v.Generation += 10
				v.Bindings[0].InnerAddress = "10.78.0.100/32"
				f.get = func(context.Context) (relaycatalog.View, error) { return v, nil }
			case "schema", "foreign_node", "foreign_key":
				v := f.state.NodeView("robot")
				if mode == "schema" {
					v.Spec.SchemaVersion = 99
				}
				if mode == "foreign_node" {
					v.NodeID = "someone-else"
				}
				if mode == "foreign_key" {
					v.Bindings[0].PublicKey = v.Bindings[1].PublicKey
				}
				f.get = func(context.Context) (relaycatalog.View, error) { return v, nil }
			case "unknown_binding":
				spec := cloneView(f.state.NodeView("robot")).Spec
				spec.Paths = append(spec.Paths, relaycatalog.Path{ID: "third", NodeID: "robot", RelayID: "r1", EndpointID: "e", UnderlayID: "other", TargetIDs: []string{"app"}})
				var e error
				f.state, e = relaycatalog.Apply(f.state, relaycatalog.Update{ControllerID: f.state.ControllerID, ExpectedGeneration: f.state.Generation, TTLSeconds: 3600, Spec: spec}, env(), f.now)
				if e != nil {
					t.Fatal(e)
				}
				f.state, e = relaycatalog.Bind(f.state, relaycatalog.BindRequest{SchemaVersion: 1, ControllerID: f.state.ControllerID, ExpectedGeneration: f.state.Generation, NodeID: "robot", PathID: "third", PublicKey: testPublic("external-key")}, env(), f.now)
				if e != nil {
					t.Fatal(e)
				}
			}
			r, e := s.Refresh(context.Background(), f)
			if e == nil || r.UsableCache || r.BlockedReason == "" || !same(before.Catalog, s.state.Catalog) || !same(before.Keys, s.state.Keys) {
				t.Fatal("rejected response overwrote usable state", e)
			}
			if mode == "unknown_binding" || mode == "changed_binding" {
				if s.state.Generation <= before.Generation {
					t.Fatal("did not retain rejected higher revision")
				}
				f.get = nil
				f.getError = nil
				f.state = previous
				if r, e = s.Refresh(context.Background(), f); e == nil || r.UsableCache {
					t.Fatal("accepted older revision after newer rejected binding", e)
				}
			}
			f.get = nil
			f.getError = io.EOF
			if r, e = s.Refresh(context.Background(), f); e == nil || r.UsableCache || r.BlockedReason == "" {
				t.Fatal("outage cleared security rejection", e)
			}
			s.Close()
			s = openCache(t, dir)
			r, e = s.Status()
			if e != nil || r.UsableCache || r.BlockedReason == "" {
				t.Fatal("restart cleared rejection", e)
			}
		})
	}
}
func TestDrainRemovalExpiryAndClockRollback(t *testing.T) {
	s := openCache(t, filepath.Join(privateTempDir(t), "cache"))
	f := newController(t)
	ready(t, s, f)
	apply := func(spec relaycatalog.Spec) {
		t.Helper()
		var e error
		f.state, e = relaycatalog.Apply(f.state, relaycatalog.Update{ControllerID: f.state.ControllerID, ExpectedGeneration: f.state.Generation, TTLSeconds: 3600, Spec: spec}, env(), f.now)
		if e != nil {
			t.Fatal(e)
		}
	}
	spec := cloneView(f.state.NodeView("robot")).Spec
	spec.Paths[0].Drain = true
	apply(spec)
	drained := ready(t, s, f)
	if drained.Paths[0].State != "draining" || len(f.requests) != 2 {
		t.Fatal("drain changed keys or was not reflected")
	}
	spec.Paths[0].Disabled = true
	apply(spec)
	r := ready(t, s, f)
	if r.Paths[0].State != "disabled" {
		t.Fatal("disabled not reflected")
	}
	spec = cloneView(f.state.NodeView("robot")).Spec
	spec.Paths = spec.Paths[1:]
	apply(spec)
	r = ready(t, s, f)
	if r.RetiredKeys != 1 || r.RetainedKeys != 2 || len(f.requests) != 2 {
		t.Fatal("removal discarded key or rebound")
	}
	later := f.state.ExpiresAt.Add(time.Second)
	s.now = func() time.Time { return later }
	r, e := s.Status()
	if e != nil || r.Validity != "expired" || r.UsableCache {
		t.Fatal("expired cache usable", e)
	}
	s.now = func() time.Time { return later.Add(-2 * time.Second) }
	r, e = s.Status()
	if e != nil || r.Validity != "expired" || r.UsableCache {
		t.Fatal("small clock correction resurrected expired cache", e)
	}
	s.now = func() time.Time { return f.now }
	r, e = s.Status()
	if e != nil || r.Validity != "clock_skew" || r.UsableCache {
		t.Fatal("clock rollback resurrected expired cache", e)
	}
}
func TestCASContentionIsBoundedAndCancellationReleasesOwner(t *testing.T) {
	s := openCache(t, filepath.Join(privateTempDir(t), "cache"))
	f := newController(t)
	f.conflict = true
	s.wait = func(context.Context, int) error { return nil }
	r, e := s.Refresh(context.Background(), f)
	if e == nil || r.Refresh.Reason != "contention_limit" || len(f.requests) != MaxConflicts+1 || len(s.state.Keys) != 1 {
		t.Fatal("unbounded/confused contention", e, len(f.requests))
	}
	for _, req := range f.requests {
		if req.PublicKey != s.state.Keys[0].PublicKey {
			t.Fatal("contention regenerated key")
		}
	}
	f.conflict = false
	ready(t, s, f)
	entered := make(chan struct{})
	f.get = func(ctx context.Context) (relaycatalog.View, error) {
		close(entered)
		<-ctx.Done()
		return relaycatalog.View{}, ctx.Err()
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, e := s.Refresh(ctx, f); done <- e }()
	<-entered
	if _, e = s.Status(); !errors.Is(e, ErrBusy) {
		t.Fatal("concurrent status did not fail boundedly", e)
	}
	if _, e = s.Refresh(context.Background(), f); !errors.Is(e, ErrBusy) {
		t.Fatal("concurrent refresh did not fail boundedly", e)
	}
	cancel()
	select {
	case e = <-done:
		if !errors.Is(e, context.Canceled) {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation stalled")
	}
	if _, e = s.Status(); e != nil {
		t.Fatal("cancellation retained lock", e)
	}
}
func TestUnsafeAndMissingCacheFilesFailClosed(t *testing.T) {
	for _, mode := range []string{"missing", "bad_json", "public_state", "state_symlink", "state_hardlink", "state_fifo", "public_directory", "directory_symlink", "writable_ancestor", "wrong_node", "key_pair", "oversized"} {
		t.Run(mode, func(t *testing.T) {
			base := privateTempDir(t)
			dir := filepath.Join(base, "cache")
			s := openCache(t, dir)
			if mode == "key_pair" {
				ready(t, s, newController(t))
			}
			s.Close()
			path := filepath.Join(dir, stateFile)
			switch mode {
			case "oversized":
				os.WriteFile(path, []byte(strings.Repeat(" ", maxStateBytes+1)), 0600)
			case "missing":
				os.Remove(path)
			case "bad_json":
				os.WriteFile(path, []byte(`{"private_key":"must-not-print"`), 0600)
			case "public_state":
				os.Chmod(path, 0644)
			case "state_symlink":
				os.Rename(path, filepath.Join(dir, "other"))
				os.Symlink("other", path)
			case "state_hardlink":
				os.Link(path, filepath.Join(dir, "other"))
			case "state_fifo":
				os.Remove(path)
				if e := syscall.Mkfifo(path, 0600); e != nil {
					t.Fatal(e)
				}
			case "public_directory":
				os.Chmod(dir, 0755)
			case "directory_symlink":
				os.Rename(dir, dir+"-real")
				os.Symlink(dir+"-real", dir)
			case "writable_ancestor":
				os.Chmod(base, 0777)
				defer os.Chmod(base, 0700)
			case "key_pair":
				raw, e := os.ReadFile(path)
				if e != nil {
					t.Fatal(e)
				}
				var n diskState
				json.Unmarshal(raw, &n)
				n.Keys[0].PrivateKey = n.Keys[1].PrivateKey
				raw, _ = json.Marshal(n)
				os.WriteFile(path, raw, 0600)
			}
			id := "robot"
			if mode == "wrong_node" {
				id = "different"
			}
			opened, e := Open(dir, Options{NodeID: id, Create: true})
			if e == nil {
				opened.Close()
				t.Fatal("unsafe/missing cache silently accepted")
			}
			if strings.Contains(e.Error(), "must-not-print") {
				t.Fatal("secret bytes printed in decode error")
			}
		})
	}
}

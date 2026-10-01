// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relaycache

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"vpnctl/internal/api"
	"vpnctl/internal/relaycatalog"
)

type deploymentClient func(context.Context, string, string) (relaycatalog.DeploymentView, error)

func (f deploymentClient) RelayDeployment(ctx context.Context, p, r string) (relaycatalog.DeploymentView, error) {
	return f(ctx, p, r)
}
func deploymentResponse(v relaycatalog.DeploymentView, e error) deploymentClient {
	return func(context.Context, string, string) (relaycatalog.DeploymentView, error) { return v, e }
}
func deploymentFixture(t *testing.T) relaycatalog.DeploymentView {
	t.Helper()
	f := newController(t)
	c, e := relaycatalog.Bind(f.state, relaycatalog.BindRequest{SchemaVersion: 1, ControllerID: f.state.ControllerID, ExpectedGeneration: f.state.Generation, NodeID: "robot", PathID: "p1", PublicKey: testPublic("p1")}, env(), f.now)
	if e != nil {
		t.Fatal(e)
	}
	c, e = relaycatalog.SetRecipient(c, relaycatalog.RecipientUpdate{ControllerID: c.ControllerID, ExpectedGeneration: c.Generation, RelayID: "r1", PrincipalID: "robot"}, env())
	if e != nil {
		t.Fatal(e)
	}
	v, ok := c.DeploymentFor("robot", "r1")
	if !ok || v.Validate("robot", "r1", f.now) != nil {
		t.Fatal("invalid fixture")
	}
	return v
}
func openDeployment(t *testing.T, dir string) *DeploymentStore {
	t.Helper()
	s, e := OpenDeployment(dir, DeploymentOptions{PrincipalID: "robot", RelayID: "r1", Create: true})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Close() })
	return s
}
func approveDeployment(t *testing.T, s *DeploymentStore, v relaycatalog.DeploymentView) DeploymentReport {
	t.Helper()
	r, e := s.Refresh(context.Background(), deploymentResponse(v, nil))
	if e != nil || !r.ApprovalValid {
		t.Fatalf("approval failed: %+v %v", r, e)
	}
	return r
}
func resealDeployment(v *relaycatalog.DeploymentView) {
	for i := range v.Bindings {
		v.Bindings[i].DefinitionHash = relaycatalog.DefinitionHash(v.Spec, v.Spec.Paths[i])
	}
}

func TestDeploymentPersistenceAndEmptyApproval(t *testing.T) {
	dir := privateTempDir(t)
	s := openDeployment(t, dir)
	v := deploymentFixture(t)
	r := approveDeployment(t, s, v)
	r.Deployment.Spec.Relays[0].PublicKey = "mutated"
	v.Spec.Relays[0].Endpoints[0].Address = "mutated"
	s.Close()
	s = openDeployment(t, dir)
	r, e := s.Status()
	if e != nil || !r.ApprovalValid || r.Deployment.Spec.Relays[0].PublicKey == "mutated" || r.Deployment.Spec.Relays[0].Endpoints[0].Address == "mutated" {
		t.Fatal("cache aliased or lost", e)
	}
	v = copyDeployment(*r.Deployment)
	v.Generation++
	v.Spec.Paths, v.Spec.Targets, v.Bindings = nil, nil, nil
	r = approveDeployment(t, s, v)
	if len(r.Deployment.Bindings) != 0 {
		t.Fatal("empty approval retained removed peers")
	}
	for _, name := range []string{stateFile, markerFile, "cache.lock"} {
		st, e := os.Stat(filepath.Join(dir, name))
		if e != nil || st.Mode().Perm() != 0600 {
			t.Fatal("unsafe file", name, e)
		}
	}
	raw, _ := os.ReadFile(filepath.Join(dir, stateFile))
	if strings.Contains(string(raw), "private_key") {
		t.Fatal("deployment cache must not contain private keys")
	}
}

func TestDeploymentRevisionAndIdentityRejection(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*relaycatalog.DeploymentView)
	}{
		{"controller", func(v *relaycatalog.DeploymentView) { v.ControllerID = strings.Repeat("a", 32) }},
		{"backwards", func(v *relaycatalog.DeploymentView) { v.Generation-- }},
		{"same_generation", func(v *relaycatalog.DeploymentView) { v.ExpiresAt = v.ExpiresAt.Add(time.Second) }},
		{"foreign_principal", func(v *relaycatalog.DeploymentView) { v.PrincipalID = "other" }},
		{"foreign_relay", func(v *relaycatalog.DeploymentView) { v.RelayID = "r2" }},
		{"schema", func(v *relaycatalog.DeploymentView) { v.SchemaVersion++ }},
		{"binding", func(v *relaycatalog.DeploymentView) { v.Generation++; v.Bindings[0].InnerAddress = "0.0.0.0/0" }},
		{"future", func(v *relaycatalog.DeploymentView) {
			v.Generation++
			v.IssuedAt = time.Now().Add(time.Hour)
			v.ExpiresAt = v.IssuedAt.Add(time.Hour)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := privateTempDir(t)
			s := openDeployment(t, dir)
			v := deploymentFixture(t)
			approveDeployment(t, s, v)
			bad := copyDeployment(v)
			tc.mutate(&bad)
			r, e := s.Refresh(context.Background(), deploymentResponse(bad, nil))
			if e == nil || r.ApprovalValid || r.BlockedReason == "" {
				t.Fatal("bad response accepted", e)
			}
			s.Close()
			s = openDeployment(t, dir)
			r, e = s.Refresh(context.Background(), deploymentResponse(relaycatalog.DeploymentView{}, io.EOF))
			if e == nil || r.ApprovalValid || r.BlockedReason == "" {
				t.Fatal("outage cleared rejection", e)
			}
			approveDeployment(t, s, v)
		})
	}
}

func TestDeploymentHigherRejectedRevisionPinsFloor(t *testing.T) {
	for _, kind := range []string{"pool", "key_generation", "key_without_generation"} {
		t.Run(kind, func(t *testing.T) {
			dir := privateTempDir(t)
			s := openDeployment(t, dir)
			v := deploymentFixture(t)
			v.Spec.Relays[0].KeyGeneration = 2
			resealDeployment(&v)
			approveDeployment(t, s, v)
			bad := copyDeployment(v)
			bad.Generation++
			switch kind {
			case "pool":
				bad.Spec.PoolCIDR = "10.79.0.0/24"
				bad.Bindings[0].InnerAddress = "10.79.0.1/32"
			case "key_generation":
				bad.Spec.Relays[0].KeyGeneration--
			case "key_without_generation":
				bad.Spec.Relays[0].PublicKey = testPublic("replacement")
			}
			resealDeployment(&bad)
			if e := bad.Validate("robot", "r1", time.Now()); e != nil {
				t.Fatal("fixture must be structurally valid", e)
			}
			r, e := s.Refresh(context.Background(), deploymentResponse(bad, nil))
			if e == nil || r.ApprovalValid || r.ObservedGeneration != bad.Generation || r.Deployment.Generation != v.Generation {
				t.Fatal("lost observed revision", e)
			}
			s.Close()
			s = openDeployment(t, dir)
			if r, e = s.Refresh(context.Background(), deploymentResponse(v, nil)); e == nil || r.ApprovalValid {
				t.Fatal("older response restored approval")
			}
			v.Generation = bad.Generation + 1
			approveDeployment(t, s, v)
		})
	}
}

func TestDeploymentRemoteFailuresAndStickyDenial(t *testing.T) {
	for _, tc := range []struct {
		name    string
		err     error
		blocked bool
	}{
		{"timeout", context.DeadlineExceeded, false}, {"cancel", context.Canceled, false}, {"eof", io.EOF, false},
		{"network", &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}, false},
		{"server", &api.HTTPError{StatusCode: 503}, false}, {"quota", &api.HTTPError{StatusCode: 429}, false},
		{"unauthenticated", &api.HTTPError{StatusCode: 401}, true}, {"withdrawn", &api.HTTPError{StatusCode: 403, Code: "relay_recipient_denied"}, true},
		{"uncertain", &api.HTTPError{StatusCode: 503, Code: "relay_catalog_uncertain"}, true},
		{"expired", &api.HTTPError{StatusCode: 409, Code: "relay_catalog_expired"}, true},
		{"invalid", errors.New("malformed JSON"), true},
		{"tls_verification", &tls.CertificateVerificationError{Err: errors.New("bad CA")}, true},
		{"tls_denied", &net.OpError{Op: "remote error", Err: errors.New("bad certificate")}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := privateTempDir(t)
			s := openDeployment(t, dir)
			v := deploymentFixture(t)
			approveDeployment(t, s, v)
			r, e := s.Refresh(context.Background(), deploymentResponse(relaycatalog.DeploymentView{}, tc.err))
			if e == nil || r.ApprovalValid == tc.blocked {
				t.Fatalf("wrong failure state: %+v %v", r, e)
			}
			s.Close()
			s = openDeployment(t, dir)
			r, e = s.Refresh(context.Background(), deploymentResponse(relaycatalog.DeploymentView{}, io.EOF))
			if e == nil || r.ApprovalValid == tc.blocked {
				t.Fatal("restart/outage changed authorization")
			}
			approveDeployment(t, s, v)
		})
	}
}

func TestDeploymentExpiryAndClockWatermark(t *testing.T) {
	dir := privateTempDir(t)
	s := openDeployment(t, dir)
	v := deploymentFixture(t)
	approveDeployment(t, s, v)
	s.now = func() time.Time { return v.ExpiresAt }
	r, e := s.Status()
	if e != nil || r.ApprovalValid || r.Validity != "expired" {
		t.Fatal(r, e)
	}
	s.Close()
	s = openDeployment(t, dir)
	s.now = func() time.Time { return v.ExpiresAt.Add(-time.Second) }
	r, e = s.Status()
	if e != nil || r.ApprovalValid || r.Validity != "expired" {
		t.Fatal("small rollback resurrected expired approval", r, e)
	}
	s.now = func() time.Time { return v.ExpiresAt.Add(-time.Minute) }
	r, e = s.Refresh(context.Background(), deploymentResponse(v, nil))
	if e == nil || r.ApprovalValid || r.Validity != "clock_skew" {
		t.Fatal("clock regression accepted", r, e)
	}
}

func TestDeploymentDenialWriteFailureCannotResurrect(t *testing.T) {
	for _, afterRename := range []bool{false, true} {
		t.Run(map[bool]string{false: "before_rename", true: "after_rename"}[afterRename], func(t *testing.T) {
			dir := privateTempDir(t)
			s := openDeployment(t, dir)
			v := deploymentFixture(t)
			approveDeployment(t, s, v)
			write := s.writeState
			syncDir := s.syncDir
			calls := 0
			s.writeState = func(b []byte) error {
				calls++
				if calls == 2 {
					if !afterRename {
						return syscall.ENOSPC
					}
					s.syncDir = func() error { return syscall.EIO }
					defer func() { s.syncDir = syncDir }()
				}
				return write(b)
			}
			r, e := s.Refresh(context.Background(), deploymentResponse(relaycatalog.DeploymentView{}, &api.HTTPError{StatusCode: 403}))
			if e == nil || r.ApprovalValid || r.Validity != "uncertain" {
				t.Fatal("uncertain state used", r, e)
			}
			if r, e = s.Status(); !errors.Is(e, ErrUncertain) || r.ApprovalValid {
				t.Fatal("status ignored uncertainty")
			}
			s.Close()
			s = openDeployment(t, dir)
			r, e = s.Refresh(context.Background(), deploymentResponse(relaycatalog.DeploymentView{}, io.EOF))
			if e == nil || r.ApprovalValid || r.BlockedReason == "" {
				t.Fatal("lost denial resurrected approval", r, e)
			}
			approveDeployment(t, s, v)
		})
	}
}

func TestDeploymentLockAndConcurrentAccess(t *testing.T) {
	dir := privateTempDir(t)
	s := openDeployment(t, dir)
	if other, e := OpenDeployment(dir, DeploymentOptions{PrincipalID: "robot", RelayID: "r1"}); !errors.Is(e, ErrBusy) {
		if other != nil {
			other.Close()
		}
		t.Fatal(e)
	}
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	v := deploymentFixture(t)
	go func() {
		_, e := s.Refresh(context.Background(), deploymentClient(func(context.Context, string, string) (relaycatalog.DeploymentView, error) {
			close(entered)
			<-release
			return v, nil
		}))
		done <- e
	}()
	<-entered
	if r, e := s.Status(); !errors.Is(e, ErrBusy) || r.ApprovalValid {
		t.Fatal("concurrent status", e)
	}
	if r, e := s.Refresh(context.Background(), deploymentResponse(v, nil)); !errors.Is(e, ErrBusy) || r.ApprovalValid {
		t.Fatal("concurrent refresh", e)
	}
	close(release)
	if e := <-done; e != nil {
		t.Fatal(e)
	}
}

func TestDeploymentInterruptedProcess(t *testing.T) {
	if dir := os.Getenv("VPNCTL_DEPLOYMENT_CHILD_DIR"); dir != "" {
		s := openDeployment(t, dir)
		s.Refresh(context.Background(), deploymentClient(func(context.Context, string, string) (relaycatalog.DeploymentView, error) {
			os.Exit(23)
			return relaycatalog.DeploymentView{}, nil
		}))
		os.Exit(24)
	}
	dir := privateTempDir(t)
	s := openDeployment(t, dir)
	v := deploymentFixture(t)
	approveDeployment(t, s, v)
	s.Close()
	cmd := exec.Command(os.Args[0], "-test.run=^TestDeploymentInterruptedProcess$")
	cmd.Env = append(os.Environ(), "VPNCTL_DEPLOYMENT_CHILD_DIR="+dir)
	var exited *exec.ExitError
	if e := cmd.Run(); !errors.As(e, &exited) || exited.ExitCode() != 23 {
		t.Fatal("child did not interrupt refresh", e)
	}
	s = openDeployment(t, dir)
	r, e := s.Status()
	if e != nil || r.ApprovalValid || r.Refresh.Result != "in_progress" {
		t.Fatal("interrupted refresh became valid", r, e)
	}
	r, e = s.Refresh(context.Background(), deploymentResponse(relaycatalog.DeploymentView{}, io.EOF))
	if e == nil || r.ApprovalValid {
		t.Fatal("timeout cleared interrupted refresh")
	}
	approveDeployment(t, s, v)
}

func TestDeploymentUnsafeOrCorruptStorage(t *testing.T) {
	for _, kind := range []string{"missing", "truncated", "unknown", "oversized", "symlink", "hardlink", "fifo", "mode", "wrong_identity", "wrong_relay", "node_cache"} {
		t.Run(kind, func(t *testing.T) {
			dir := privateTempDir(t)
			s := openDeployment(t, dir)
			approveDeployment(t, s, deploymentFixture(t))
			s.Close()
			path := filepath.Join(dir, stateFile)
			opts := DeploymentOptions{PrincipalID: "robot", RelayID: "r1", Create: true}
			switch kind {
			case "missing":
				os.Remove(path)
			case "truncated":
				os.WriteFile(path, []byte("{"), 0600)
			case "unknown":
				raw, _ := os.ReadFile(path)
				var v map[string]any
				json.Unmarshal(raw, &v)
				v["extra"] = true
				raw, _ = json.Marshal(v)
				os.WriteFile(path, raw, 0600)
			case "oversized":
				os.WriteFile(path, []byte(strings.Repeat(" ", maxStateBytes+1)), 0600)
			case "symlink":
				os.Rename(path, path+".real")
				os.Symlink(path+".real", path)
			case "hardlink":
				os.Link(path, path+".link")
			case "fifo":
				os.Remove(path)
				syscall.Mkfifo(path, 0600)
			case "mode":
				os.Chmod(path, 0644)
			case "wrong_identity":
				opts.PrincipalID = "other"
			case "wrong_relay":
				opts.RelayID = "r2"
			case "node_cache":
				os.Remove(path)
				os.Remove(filepath.Join(dir, markerFile))
				n := openCache(t, dir)
				n.Close()
			}
			other, e := OpenDeployment(dir, opts)
			if e == nil {
				other.Close()
				t.Fatal("unsafe cache accepted", kind)
			}
		})
	}
}

func TestDeploymentCancelledResponseAndClosedStore(t *testing.T) {
	s := openDeployment(t, privateTempDir(t))
	v := deploymentFixture(t)
	approveDeployment(t, s, v)
	ctx, cancel := context.WithCancel(context.Background())
	r, e := s.Refresh(ctx, deploymentClient(func(context.Context, string, string) (relaycatalog.DeploymentView, error) {
		cancel()
		v.Generation++
		return v, nil
	}))
	if e == nil || r.ObservedGeneration == v.Generation {
		t.Fatal("late response accepted")
	}
	s.Close()
	if _, e = s.Status(); e == nil {
		t.Fatal("closed status accepted")
	}
	if _, e = s.Refresh(context.Background(), deploymentResponse(v, nil)); e == nil {
		t.Fatal("closed refresh accepted")
	}
}

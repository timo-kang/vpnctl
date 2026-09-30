// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relaycache

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"sync"
	"syscall"
	"time"
	"unicode"

	"vpnctl/internal/atomicfile"
	"vpnctl/internal/relaycatalog"
)

type DeploymentOptions struct {
	PrincipalID string
	RelayID     string
	Create      bool
}

// ValidateDeploymentIdentity also protects relay IDs used as directory names.
func ValidateDeploymentIdentity(principal, relay string) error {
	if principal == "" || len(principal) > 256 || !validPathID(relay) {
		return errors.New("valid deployment principal and relay ID required")
	}
	for _, r := range principal {
		if unicode.IsControl(r) {
			return errors.New("invalid deployment principal")
		}
	}
	return nil
}

type deploymentState struct {
	Version       int                          `json:"version"`
	Kind          string                       `json:"kind"`
	PrincipalID   string                       `json:"principal_id"`
	RelayID       string                       `json:"relay_id"`
	ControllerID  string                       `json:"controller_id"`
	Generation    uint64                       `json:"generation"`
	ViewDigest    string                       `json:"view_digest"`
	ObservedAt    time.Time                    `json:"observed_at"`
	Deployment    *relaycatalog.DeploymentView `json:"deployment,omitempty"`
	Refresh       refreshState                 `json:"refresh"`
	BlockedReason string                       `json:"blocked_reason,omitempty"`
}

// DeploymentStore persists public approval metadata only. It neither owns a
// relay private key nor installs peers. The process lock shares the node cache's
// hardened file implementation, but the disk formats are deliberately distinct.
type DeploymentStore struct {
	*files
	mu                sync.Mutex
	lock              *os.File
	state             deploymentState
	principal, relay  string
	closed, uncertain bool
	now               func() time.Time
	writeState        func([]byte) error
}

func OpenDeployment(dir string, opts DeploymentOptions) (*DeploymentStore, error) {
	if e := ValidateDeploymentIdentity(opts.PrincipalID, opts.RelayID); e != nil {
		return nil, e
	}
	root, e := openDirectory(dir, opts.Create)
	if e != nil {
		return nil, e
	}
	s := &DeploymentStore{files: &files{root: root}, principal: opts.PrincipalID, relay: opts.RelayID, now: time.Now}
	s.syncDir = func() error { return syncRoot(root) }
	s.writeState = func(b []byte) error { return s.writeFile(stateFile, b) }
	ok := false
	defer func() {
		if !ok {
			s.Close()
		}
	}()
	s.lock, e = s.openFile("cache.lock", os.O_CREATE|os.O_RDWR)
	if e != nil {
		return nil, e
	}
	if e = syscall.Flock(int(s.lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		if errors.Is(e, syscall.EWOULDBLOCK) {
			return nil, ErrBusy
		}
		return nil, e
	}
	raw, e := s.readFile(stateFile)
	if os.IsNotExist(e) {
		if _, markerErr := s.readFile(markerFile); !os.IsNotExist(markerErr) {
			return nil, ErrCorrupt
		}
		if !opts.Create {
			return nil, ErrMissing
		}
		s.state = deploymentState{Version: 1, Kind: "relay_deployment", PrincipalID: s.principal, RelayID: s.relay, ObservedAt: s.now().UTC(), Refresh: refreshState{Result: "never"}}
		data, _ := json.Marshal(s.state)
		if e = s.writeState(data); e != nil {
			return nil, storageError(e)
		}
	} else if e != nil {
		return nil, e
	} else if e = s.decode(raw); e != nil {
		return nil, e
	}
	marker, e := s.readFile(markerFile)
	if os.IsNotExist(e) {
		if e = s.writeFile(markerFile, []byte("1")); e != nil {
			return nil, storageError(e)
		}
	} else if e != nil {
		return nil, e
	} else if string(marker) != "1" {
		return nil, ErrCorrupt
	}
	if e = s.syncDir(); e != nil {
		return nil, ErrUncertain
	}
	ok = true
	return s, nil
}

func (s *DeploymentStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	var e error
	if s.lock != nil {
		e = s.lock.Close()
	}
	if s.root != nil {
		e = errors.Join(e, s.root.Close())
	}
	return e
}

func deploymentDigest(v relaycatalog.DeploymentView) string {
	b, _ := json.Marshal(v)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func copyDeployment(v relaycatalog.DeploymentView) relaycatalog.DeploymentView {
	b, _ := json.Marshal(v)
	var n relaycatalog.DeploymentView
	_ = json.Unmarshal(b, &n)
	return n
}
func (s *DeploymentStore) validate(v deploymentState) error {
	if v.Version != 1 || v.Kind != "relay_deployment" || v.PrincipalID != s.principal || v.RelayID != s.relay || v.ObservedAt.IsZero() {
		return ErrCorrupt
	}
	switch v.Refresh.Result {
	case "never", "in_progress", "success", "unavailable", "denied", "rejected":
	default:
		return ErrCorrupt
	}
	if v.ControllerID == "" {
		if v.Generation != 0 || v.ViewDigest != "" || v.Deployment != nil {
			return ErrCorrupt
		}
	} else {
		id, e := hex.DecodeString(v.ControllerID)
		h, e2 := hex.DecodeString(v.ViewDigest)
		if e != nil || len(id) != 16 || hex.EncodeToString(id) != v.ControllerID || e2 != nil || len(h) != 32 || hex.EncodeToString(h) != v.ViewDigest || v.Generation == 0 || v.Generation == ^uint64(0) {
			return ErrCorrupt
		}
	}
	if d := v.Deployment; d != nil {
		// Expiry is reported separately, never treated as file corruption.
		if d.Validate(s.principal, s.relay, d.IssuedAt) != nil || d.ControllerID != v.ControllerID || d.Generation > v.Generation || d.Generation < v.Generation && v.BlockedReason == "" {
			return ErrCorrupt
		}
		if d.Generation == v.Generation && deploymentDigest(*d) != v.ViewDigest {
			return ErrCorrupt
		}
	}
	if v.Refresh.Result == "success" && (v.Deployment == nil || v.BlockedReason != "" || v.Refresh.LastSuccessAt.IsZero()) {
		return ErrCorrupt
	}
	return nil
}
func (s *DeploymentStore) decode(raw []byte) error {
	var v deploymentState
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&v) != nil || d.Decode(new(any)) != io.EOF {
		return ErrCorrupt
	}
	if e := s.validate(v); e != nil {
		return e
	}
	s.state = v
	return nil
}
func (s *DeploymentStore) save(next deploymentState) error {
	if next.ObservedAt.Before(s.state.ObservedAt) {
		next.ObservedAt = s.state.ObservedAt
	}
	if now := s.now().UTC(); now.After(next.ObservedAt) {
		next.ObservedAt = now
	}
	if e := s.validate(next); e != nil {
		return e
	}
	f, e := s.openFile(stateFile, os.O_RDONLY)
	if e != nil {
		s.uncertain = true
		return storageError(e)
	}
	f.Close()
	raw, e := json.Marshal(next)
	if e != nil {
		return ErrCorrupt
	}
	e = s.writeState(raw)
	if e == nil || atomicfile.Replaced(e) {
		s.state = next
	}
	if e != nil {
		s.uncertain = true
		return storageError(e)
	}
	return nil
}
func (s *DeploymentStore) repair() error {
	if e := s.syncDir(); e != nil {
		return ErrUncertain
	}
	raw, e := s.readFile(stateFile)
	if e != nil {
		return e
	}
	if e = s.decode(raw); e != nil {
		return e
	}
	s.uncertain = false
	return nil
}

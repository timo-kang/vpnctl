// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

// Package relaycache persists node path keys and scoped node/relay approval
// snapshots. It performs no OS networking and does not assert uplink health.
package relaycache

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os"
	"sync"
	"syscall"
	"time"

	"vpnctl/internal/atomicfile"
	"vpnctl/internal/relaycatalog"
)

type Options struct {
	NodeID           string
	Create           bool
	LegacyPublicKeys []string
}
type pathKey struct {
	PathID         string                `json:"path_id"`
	PrivateKey     string                `json:"private_key"`
	PublicKey      string                `json:"public_key"`
	DefinitionHash string                `json:"definition_hash"`
	Binding        *relaycatalog.Binding `json:"binding,omitempty"`
	Retired        bool                  `json:"retired"`
}
type refreshState struct {
	Result        string    `json:"result"`
	Reason        string    `json:"reason,omitempty"`
	AttemptedAt   time.Time `json:"attempted_at"`
	CompletedAt   time.Time `json:"completed_at"`
	LastSuccessAt time.Time `json:"last_success_at"`
}
type diskState struct {
	ControllerID  string             `json:"controller_id"`
	Generation    uint64             `json:"generation"`
	ViewDigest    string             `json:"view_digest"`
	ObservedAt    time.Time          `json:"observed_at"`
	Version       int                `json:"version"`
	NodeID        string             `json:"node_id"`
	Catalog       *relaycatalog.View `json:"catalog,omitempty"`
	Keys          []pathKey          `json:"keys"`
	Refresh       refreshState       `json:"refresh"`
	BlockedReason string             `json:"blocked_reason,omitempty"`
}

// Store owns the cache's nonblocking process lock until Close. Public results
// contain only Report, never diskState or private keys.
type Store struct {
	*files
	wait       func(context.Context, int) error
	mu         sync.Mutex
	lock       *os.File
	state      diskState
	nodeID     string
	reserved   map[string]bool
	uncertain  bool
	closed     bool
	writeState func([]byte) error
	now        func() time.Time
}

func Open(dir string, opts Options) (*Store, error) {
	if opts.NodeID == "" || len(opts.NodeID) > 256 {
		return nil, ErrCorrupt
	}
	root, e := openDirectory(dir, opts.Create)
	if e != nil {
		return nil, e
	}
	s := &Store{files: &files{root: root}, nodeID: opts.NodeID, reserved: map[string]bool{}, now: time.Now, wait: backoff}
	success := false
	defer func() {
		if !success {
			s.Close()
		}
	}()
	for _, k := range opts.LegacyPublicKeys {
		if k != "" {
			s.reserved[relaycatalog.PublicKeyID(k)] = true
		}
	}
	s.syncDir = func() error { return syncRoot(root) }
	s.writeState = func(b []byte) error { return s.writeFile(stateFile, b) }
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
		s.state = diskState{Version: 1, ObservedAt: s.now().UTC(), NodeID: opts.NodeID, Refresh: refreshState{Result: "never"}}
		data, _ := json.Marshal(s.state)
		if e = s.writeState(data); e != nil {
			return nil, storageError(e)
		}
	} else if e != nil {
		return nil, e
	} else {
		if e = s.decode(raw); e != nil {
			return nil, e
		}
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
	// A successful directory sync repairs a previous post-rename uncertainty.
	if e = s.syncDir(); e != nil {
		return nil, ErrUncertain
	}
	success = true
	return s, nil
}
func (s *Store) Close() error {
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
func (s *Store) decode(raw []byte) error {
	var v diskState
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
func cloneState(v diskState) diskState {
	// One bounded, typed copy keeps private-key and catalog slices out of mutable
	// published state until the entire new record has been committed.
	raw, _ := json.Marshal(v)
	var n diskState
	_ = json.Unmarshal(raw, &n)
	return n
}
func (s *Store) validate(v diskState) error {
	if v.ObservedAt.IsZero() || v.Version != 1 || v.NodeID != s.nodeID || len(v.Keys) > relaycatalog.MaxPathIDs {
		return ErrCorrupt
	}
	switch v.Refresh.Result {
	case "never", "in_progress", "success", "unavailable", "denied", "rejected", "partial":
	default:
		return ErrCorrupt
	}
	if v.ControllerID == "" {
		if v.Generation != 0 || v.ViewDigest != "" || v.Catalog != nil || len(v.Keys) != 0 {
			return ErrCorrupt
		}
	} else {
		id, e := hex.DecodeString(v.ControllerID)
		digest, e2 := hex.DecodeString(v.ViewDigest)
		if e != nil || len(id) != 16 || hex.EncodeToString(id) != v.ControllerID || e2 != nil || len(digest) != 32 || hex.EncodeToString(digest) != v.ViewDigest || v.Generation == 0 || v.Generation == ^uint64(0) {
			return ErrCorrupt
		}
	}
	if v.Catalog == nil {
		if len(v.Keys) != 0 {
			return ErrCorrupt
		}
		return nil
	}
	if v.Catalog.ControllerID != v.ControllerID || v.Catalog.Generation > v.Generation || (v.Catalog.Generation < v.Generation && v.BlockedReason == "") {
		return ErrCorrupt
	}
	if v.Catalog.Generation == v.Generation {
		h := digest(*v.Catalog)
		if hex.EncodeToString(h[:]) != v.ViewDigest {
			return ErrCorrupt
		}
	}
	// Expiry is a status, not disk corruption. Structural validation uses the
	// approval's own issuance time; current wall clock is checked by Report/Refresh.
	if e := v.Catalog.Validate(s.nodeID, v.Catalog.IssuedAt); e != nil {
		return ErrCorrupt
	}
	pool, _ := netip.ParsePrefix(v.Catalog.Spec.PoolCIDR)
	leases := map[string]bool{}
	keys := map[string]pathKey{}
	pubs := map[string]bool{}
	for _, r := range v.Catalog.Spec.Relays {
		pubs[r.PublicKey] = true
	}
	for _, k := range v.Keys {
		b, e := base64.StdEncoding.DecodeString(k.PrivateKey)
		if e != nil || len(b) != 32 || base64.StdEncoding.EncodeToString(b) != k.PrivateKey {
			return ErrCorrupt
		}
		private, e := ecdh.X25519().NewPrivateKey(b)
		if e != nil || base64.StdEncoding.EncodeToString(private.PublicKey().Bytes()) != k.PublicKey || relaycatalog.ValidatePublicKey(k.PublicKey) != nil || pubs[k.PublicKey] || s.reserved[k.PublicKey] {
			return ErrCorrupt
		}
		if _, ok := keys[k.PathID]; ok || !validPathID(k.PathID) {
			return ErrCorrupt
		}
		hash, e := hex.DecodeString(k.DefinitionHash)
		if e != nil || len(hash) != 32 || hex.EncodeToString(hash) != k.DefinitionHash {
			return ErrCorrupt
		}
		if k.Binding != nil {
			b := k.Binding
			address, err := netip.ParsePrefix(b.InnerAddress)
			if err != nil || !address.Addr().Is4() || address.Bits() != 32 || address.String() != b.InnerAddress || !pool.Contains(address.Addr()) || leases[b.InnerAddress] || b.CreatedAt.IsZero() {
				return ErrCorrupt
			}
			leases[b.InnerAddress] = true
			if b.PathID != k.PathID || b.NodeID != s.nodeID || b.PublicKey != k.PublicKey || b.DefinitionHash != k.DefinitionHash || !b.RetiredAt.IsZero() {
				return ErrCorrupt
			}
		}
		keys[k.PathID] = k
		pubs[k.PublicKey] = true
	}
	paths := map[string]bool{}
	for _, p := range v.Catalog.Spec.Paths {
		paths[p.ID] = true
		if k, ok := keys[p.ID]; ok && (k.Retired || k.DefinitionHash != relaycatalog.DefinitionHash(v.Catalog.Spec, p)) {
			return ErrCorrupt
		}
	}
	bindings := map[string]relaycatalog.Binding{}
	for _, b := range v.Catalog.Bindings {
		k, ok := keys[b.PathID]
		if !ok || k.Retired || k.Binding == nil || !same(k.Binding, &b) {
			return ErrCorrupt
		}
		bindings[b.PathID] = b
	}
	for _, k := range v.Keys {
		if k.Retired == paths[k.PathID] {
			return ErrCorrupt
		}
		if !k.Retired && k.Binding != nil {
			if _, ok := bindings[k.PathID]; !ok {
				return ErrCorrupt
			}
		}
	}
	return nil
}
func validPathID(s string) bool {
	if s == "" || len(s) > 64 || s == "." || s == ".." {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-' || r == '.') {
			return false
		}
	}
	return true
}
func same(a, b any) bool                  { x, _ := json.Marshal(a); y, _ := json.Marshal(b); return bytes.Equal(x, y) }
func digest(v relaycatalog.View) [32]byte { b, _ := json.Marshal(v); return sha256.Sum256(b) }
func (s *Store) save(next diskState) error {
	if next.ObservedAt.Before(s.state.ObservedAt) {
		next.ObservedAt = s.state.ObservedAt
	}
	if now := s.now().UTC(); now.After(next.ObservedAt) {
		next.ObservedAt = now
	}

	if e := s.validate(next); e != nil {
		return e
	}
	// Missing an initialized file is never an invitation to reinitialize it.
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
func (s *Store) repair() error {
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
func generateKey() (string, string, error) {
	k, e := ecdh.X25519().GenerateKey(rand.Reader)
	if e != nil {
		return "", "", e
	}
	return base64.StdEncoding.EncodeToString(k.Bytes()), base64.StdEncoding.EncodeToString(k.PublicKey().Bytes()), nil
}

// Copyright 2025 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package pki

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"syscall"
)

// GenerateToken returns a bootstrap token with format "vpnctl-bootstrap-" + 16 random hex bytes.
func GenerateToken() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "vpnctl-bootstrap-" + hex.EncodeToString(b), nil
}

// TokenStore manages active bootstrap tokens with persistence. Reads reload the
// file so token CLI changes take effect in a running controller. Mutations also
// use a process-shared lock to avoid lost updates between controller and CLI.
type TokenStore struct {
	mu     sync.Mutex
	path   string
	tokens map[string]bool
}

// OpenTokenStore loads tokens from file or creates an empty store if file doesn't exist.
func OpenTokenStore(path string) (*TokenStore, error) {
	store := &TokenStore{path: path, tokens: make(map[string]bool)}
	if err := store.reloadLocked(); err != nil {
		return nil, err
	}
	return store, nil
}

// Create generates and durably stores a token. A persistence failure leaves
// the in-memory active set unchanged.
func (ts *TokenStore) Create() (string, error) {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	var token string
	err := ts.withMutationLock(func() error {
		if err := ts.reloadLocked(); err != nil {
			return err
		}
		generated, err := GenerateToken()
		if err != nil {
			return err
		}
		ts.tokens[generated] = true
		if err := ts.saveLocked(); err != nil {
			delete(ts.tokens, generated)
			return err
		}
		token = generated
		return nil
	})
	if err != nil {
		return "", err
	}
	return token, nil
}

// Validate reloads persisted token state and checks whether token is active.
// Reload failures are returned so callers can fail closed without reporting a
// bad credential when token storage itself is unavailable.
func (ts *TokenStore) Validate(token string) (bool, error) {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	if err := ts.reloadLocked(); err != nil {
		return false, err
	}
	return ts.tokens[token], nil
}

// Revoke durably removes a token. A persistence failure restores the token to
// the in-memory active set so callers never observe a false successful revoke.
func (ts *TokenStore) Revoke(token string) error {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	return ts.withMutationLock(func() error {
		if err := ts.reloadLocked(); err != nil {
			return err
		}
		if !ts.tokens[token] {
			return nil
		}
		delete(ts.tokens, token)
		if err := ts.saveLocked(); err != nil {
			ts.tokens[token] = true
			return err
		}
		return nil
	})
}

// List reloads and returns all active tokens in deterministic order.
func (ts *TokenStore) List() ([]string, error) {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	if err := ts.reloadLocked(); err != nil {
		return nil, err
	}
	return ts.listLocked(), nil
}

func (ts *TokenStore) reloadLocked() error {
	data, err := os.ReadFile(ts.path)
	if err != nil {
		if os.IsNotExist(err) {
			ts.tokens = make(map[string]bool)
			return nil
		}
		return err
	}

	var tokenList []string
	if err := json.Unmarshal(data, &tokenList); err != nil {
		return err
	}
	tokens := make(map[string]bool, len(tokenList))
	for _, token := range tokenList {
		tokens[token] = true
	}
	ts.tokens = tokens
	return nil
}

func (ts *TokenStore) listLocked() []string {
	tokens := make([]string, 0, len(ts.tokens))
	for token := range ts.tokens {
		tokens = append(tokens, token)
	}
	sort.Strings(tokens)
	return tokens
}

func (ts *TokenStore) saveLocked() error {
	data, err := json.Marshal(ts.listLocked())
	if err != nil {
		return err
	}

	dir := filepath.Dir(ts.path)
	tmp, err := os.CreateTemp(dir, filepath.Base(ts.path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, ts.path)
}

func (ts *TokenStore) withMutationLock(fn func() error) error {
	lock, err := os.OpenFile(ts.path+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer func() { _ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN) }()
	return fn()
}

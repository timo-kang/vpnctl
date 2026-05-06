// Copyright 2025 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package pki

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"sync"
)

// GenerateToken returns a bootstrap token with format "vpnctl-bootstrap-" + 16 random hex bytes.
func GenerateToken() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return "vpnctl-bootstrap-" + hex.EncodeToString(b)
}

// TokenStore manages active bootstrap tokens with persistence.
type TokenStore struct {
	mu     sync.Mutex
	path   string
	tokens map[string]bool
}

// OpenTokenStore loads tokens from file or creates an empty store if file doesn't exist.
func OpenTokenStore(path string) (*TokenStore, error) {
	store := &TokenStore{
		path:   path,
		tokens: make(map[string]bool),
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return store, nil
		}
		return nil, err
	}

	var tokenList []string
	if err := json.Unmarshal(data, &tokenList); err != nil {
		return nil, err
	}

	for _, token := range tokenList {
		store.tokens[token] = true
	}

	return store, nil
}

// Create generates a token, adds it to the active set, saves to file, and returns the token.
func (ts *TokenStore) Create() string {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	token := GenerateToken()
	ts.tokens[token] = true
	_ = ts.save()
	return token
}

// Validate checks if a token is in the active set.
func (ts *TokenStore) Validate(token string) bool {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	return ts.tokens[token]
}

// Revoke removes a token from the active set and saves.
func (ts *TokenStore) Revoke(token string) {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	delete(ts.tokens, token)
	_ = ts.save()
}

// List returns all active tokens.
func (ts *TokenStore) List() []string {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	tokens := make([]string, 0, len(ts.tokens))
	for token := range ts.tokens {
		tokens = append(tokens, token)
	}
	return tokens
}

// save marshals active tokens as JSON array and writes to file with mode 0600.
func (ts *TokenStore) save() error {
	tokenList := make([]string, 0, len(ts.tokens))
	for token := range ts.tokens {
		tokenList = append(tokenList, token)
	}

	data, err := json.Marshal(tokenList)
	if err != nil {
		return err
	}

	return os.WriteFile(ts.path, data, 0o600)
}

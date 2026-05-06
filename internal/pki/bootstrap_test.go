// Copyright 2025 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package pki_test

import (
	"os"
	"testing"

	"vpnctl/internal/pki"
)

func TestGenerateToken(t *testing.T) {
	token := pki.GenerateToken()

	if len(token) < 20 {
		t.Errorf("expected token length >= 20, got %d", len(token))
	}

	expectedPrefix := "vpnctl-bootstrap-"
	if len(token) < len(expectedPrefix) || token[:len(expectedPrefix)] != expectedPrefix {
		t.Errorf("expected token to start with %q, got %q", expectedPrefix, token)
	}
}

func TestTokenStore_CreateAndValidate(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/tokens.json"

	store, err := pki.OpenTokenStore(path)
	if err != nil {
		t.Fatalf("OpenTokenStore failed: %v", err)
	}

	token := store.Create()

	if !store.Validate(token) {
		t.Error("expected Validate(token) to return true")
	}

	if store.Validate("bogus-token") {
		t.Error("expected Validate(bogus-token) to return false")
	}
}

func TestTokenStore_Revoke(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/tokens.json"

	store, err := pki.OpenTokenStore(path)
	if err != nil {
		t.Fatalf("OpenTokenStore failed: %v", err)
	}

	token := store.Create()

	if !store.Validate(token) {
		t.Error("expected Validate(token) to return true before revoke")
	}

	store.Revoke(token)

	if store.Validate(token) {
		t.Error("expected Validate(token) to return false after revoke")
	}
}

func TestTokenStore_Persistence(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/tokens.json"

	store1, err := pki.OpenTokenStore(path)
	if err != nil {
		t.Fatalf("OpenTokenStore failed: %v", err)
	}

	token := store1.Create()

	if !store1.Validate(token) {
		t.Error("expected Validate(token) to return true in store1")
	}

	store2, err := pki.OpenTokenStore(path)
	if err != nil {
		t.Fatalf("OpenTokenStore (store2) failed: %v", err)
	}

	if !store2.Validate(token) {
		t.Error("expected Validate(token) to return true in store2 (loaded from file)")
	}

	stat, err := os.Stat(path)
	if err != nil {
		t.Fatalf("os.Stat failed: %v", err)
	}

	mode := stat.Mode() & 0o777
	if mode != 0o600 {
		t.Errorf("expected file mode 0600, got %o", mode)
	}
}

func TestTokenStore_List(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/tokens.json"

	store, err := pki.OpenTokenStore(path)
	if err != nil {
		t.Fatalf("OpenTokenStore failed: %v", err)
	}

	token1 := store.Create()
	token2 := store.Create()

	tokens := store.List()

	if len(tokens) != 2 {
		t.Errorf("expected 2 tokens, got %d", len(tokens))
	}

	tokenMap := make(map[string]bool)
	for _, token := range tokens {
		tokenMap[token] = true
	}

	if !tokenMap[token1] {
		t.Error("expected token1 in list")
	}
	if !tokenMap[token2] {
		t.Error("expected token2 in list")
	}
}

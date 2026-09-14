// Copyright 2025 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package pki_test

import (
	"os"
	"path/filepath"
	"sync"
	"testing"

	"vpnctl/internal/pki"
)

func createToken(t *testing.T, store *pki.TokenStore) string {
	t.Helper()
	token, err := store.Create()
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	return token
}

func validateToken(t *testing.T, store *pki.TokenStore, token string) bool {
	t.Helper()
	valid, err := store.Validate(token)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	return valid
}

func listTokens(t *testing.T, store *pki.TokenStore) []string {
	t.Helper()
	tokens, err := store.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	return tokens
}

func TestGenerateToken(t *testing.T) {
	token, err := pki.GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	const prefix = "vpnctl-bootstrap-"
	if len(token) != len(prefix)+32 || token[:len(prefix)] != prefix {
		t.Fatalf("unexpected token format %q", token)
	}
}

func TestTokenStoreCreateValidateRevokeAndPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tokens.json")
	store, err := pki.OpenTokenStore(path)
	if err != nil {
		t.Fatalf("OpenTokenStore: %v", err)
	}
	token := createToken(t, store)
	if !validateToken(t, store, token) || validateToken(t, store, "bogus-token") {
		t.Fatal("unexpected token validation result")
	}

	reopened, err := pki.OpenTokenStore(path)
	if err != nil {
		t.Fatalf("OpenTokenStore reopened: %v", err)
	}
	if !validateToken(t, reopened, token) {
		t.Fatal("reopened store did not load token")
	}
	if err := reopened.Revoke(token); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if validateToken(t, store, token) {
		t.Fatal("original store did not observe external revoke")
	}

	stat, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if mode := stat.Mode() & 0o777; mode != 0o600 {
		t.Fatalf("token file mode=%o", mode)
	}
}

func TestTokenStoresObserveExternalCreateAndRevoke(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tokens.json")
	first, err := pki.OpenTokenStore(path)
	if err != nil {
		t.Fatalf("OpenTokenStore first: %v", err)
	}
	second, err := pki.OpenTokenStore(path)
	if err != nil {
		t.Fatalf("OpenTokenStore second: %v", err)
	}

	firstToken := createToken(t, first)
	if !validateToken(t, second, firstToken) {
		t.Fatal("second store did not observe external create")
	}
	secondToken := createToken(t, second)
	if got := listTokens(t, first); len(got) != 2 || got[0] == got[1] {
		t.Fatalf("tokens=%v", got)
	}
	if err := second.Revoke(firstToken); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if validateToken(t, first, firstToken) || !validateToken(t, first, secondToken) {
		t.Fatal("first store did not observe external revoke")
	}
}

func TestConcurrentTokenMutationsDoNotLoseUpdates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tokens.json")
	const count = 64
	tokens := make(chan string, count)
	errorsCh := make(chan error, count)
	var group sync.WaitGroup
	for index := 0; index < count; index++ {
		group.Add(1)
		go func() {
			defer group.Done()
			store, err := pki.OpenTokenStore(path)
			if err != nil {
				errorsCh <- err
				return
			}
			token, err := store.Create()
			if err != nil {
				errorsCh <- err
				return
			}
			tokens <- token
		}()
	}
	group.Wait()
	close(tokens)
	close(errorsCh)
	for err := range errorsCh {
		t.Errorf("concurrent create: %v", err)
	}

	store, err := pki.OpenTokenStore(path)
	if err != nil {
		t.Fatalf("OpenTokenStore final: %v", err)
	}
	persisted := listTokens(t, store)
	if len(persisted) != count {
		t.Fatalf("persisted tokens=%d, want %d", len(persisted), count)
	}
	seen := make(map[string]struct{}, count)
	for token := range tokens {
		if _, duplicate := seen[token]; duplicate {
			t.Fatalf("duplicate generated token %q", token)
		}
		seen[token] = struct{}{}
	}
	if len(seen) != count {
		t.Fatalf("created tokens=%d, want %d", len(seen), count)
	}
}

func TestTokenStoreCreateFailureDoesNotActivateToken(t *testing.T) {
	dir := t.TempDir()
	store, err := pki.OpenTokenStore(filepath.Join(dir, "missing", "tokens.json"))
	if err != nil {
		t.Fatalf("OpenTokenStore: %v", err)
	}
	token, err := store.Create()
	if err == nil || token != "" {
		t.Fatalf("Create token=%q err=%v, expected persistence error", token, err)
	}
	if got := listTokens(t, store); len(got) != 0 {
		t.Fatalf("failed create changed active tokens: %v", got)
	}
}

func TestTokenStoreRevokeFailurePreservesPersistedToken(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tokens.json")
	store, err := pki.OpenTokenStore(path)
	if err != nil {
		t.Fatalf("OpenTokenStore: %v", err)
	}
	token := createToken(t, store)

	moved := dir + "-moved"
	if err := os.Rename(dir, moved); err != nil {
		t.Fatalf("Rename away: %v", err)
	}
	if err := store.Revoke(token); err == nil {
		t.Fatal("expected revoke persistence error")
	}
	if err := os.Rename(moved, dir); err != nil {
		t.Fatalf("Rename back: %v", err)
	}
	if !validateToken(t, store, token) {
		t.Fatal("failed revoke removed persisted token")
	}
}

func TestTokenStoreFailsClosedOnCorruptPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tokens.json")
	store, err := pki.OpenTokenStore(path)
	if err != nil {
		t.Fatalf("OpenTokenStore: %v", err)
	}
	token := createToken(t, store)
	if err := os.WriteFile(path, []byte("not-json"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if valid, err := store.Validate(token); err == nil || valid {
		t.Fatalf("Validate valid=%v err=%v", valid, err)
	}
}

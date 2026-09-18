// Copyright 2025 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package pki

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"syscall"
	"time"

	"vpnctl/internal/atomicfile"
)

// GenerateToken returns a bootstrap token with format "vpnctl-bootstrap-" + 16 random hex bytes.
func GenerateToken() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "vpnctl-bootstrap-" + hex.EncodeToString(b), nil
}

// TokenStore persists token policy and admission history. Reloads and a shared
// mutation lock serialize independent store instances; production CLI operations
// are owned by the running controller through local admin IPC.
type TokenStore struct {
	mu     sync.Mutex
	path   string
	tokens map[string]TokenRecord
	write  func(string, []byte, os.FileMode) error
}

// OpenTokenStore loads tokens from file or creates an empty store if file doesn't exist.
func OpenTokenStore(path string) (*TokenStore, error) {
	store := &TokenStore{path: path, tokens: make(map[string]TokenRecord), write: atomicfile.Write}
	if err := store.reloadLocked(); err != nil {
		return nil, err
	}
	return store, nil
}

// TokenRecord retains admission history even after expiry, consumption or revocation.
type TokenRecord struct {
	Token        string        `json:"token"`
	RequestID    string        `json:"request_id,omitempty"`
	RequestedTTL time.Duration `json:"requested_ttl_ns,omitempty"`
	CreatedAt    time.Time     `json:"created_at"`
	ExpiresAt    time.Time     `json:"expires_at"`
	SingleUse    bool          `json:"single_use"`
	UseCount     uint64        `json:"use_count"`
	LastUsedAt   time.Time     `json:"last_used_at"`
	LastUsedBy   string        `json:"last_used_by,omitempty"`
	RevokedAt    time.Time     `json:"revoked_at"`
}

var ErrInvalidToken = errors.New("bootstrap token is invalid, expired, revoked or consumed")

func (r TokenRecord) active(now time.Time) bool {
	return r.RevokedAt.IsZero() && (r.ExpiresAt.IsZero() || now.Before(r.ExpiresAt)) && (!r.SingleUse || r.UseCount == 0)
}

// Create preserves the legacy non-expiring reusable-token API.
func (ts *TokenStore) Create() (string, error) { return ts.CreateWithOptions(0, false) }

// CreateWithOptions stores a token with an optional positive TTL; zero means no expiry.
func (ts *TokenStore) CreateWithOptions(ttl time.Duration, singleUse bool) (string, error) {
	return ts.create(ttl, singleUse, "")
}

var ErrRequestIDConflict = errors.New("request ID already used with different token options")
var ErrRequestNotFound = errors.New("no committed token creation for request ID")

// ValidateRequestID bounds persisted lookup keys; identifiers contain no secrets.
func ValidateRequestID(id string) error {
	if len(id) < 1 || len(id) > 128 {
		return fmt.Errorf("request ID must contain 1 to 128 ASCII letters, digits, hyphens or underscores")
	}
	for _, c := range id {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return fmt.Errorf("invalid request ID")
		}
	}
	return nil
}

// CreateIdempotent commits the request ID and token together. Retrying an expired,
// consumed or revoked result returns the original token, never a fresh credential.
func (ts *TokenStore) CreateIdempotent(ttl time.Duration, singleUse bool, requestID string) (string, error) {
	if err := ValidateRequestID(requestID); err != nil {
		return "", err
	}
	return ts.create(ttl, singleUse, requestID)
}

func (ts *TokenStore) CreationResult(requestID string) (TokenRecord, error) {
	if err := ValidateRequestID(requestID); err != nil {
		return TokenRecord{}, err
	}
	ts.mu.Lock()
	defer ts.mu.Unlock()
	var result TokenRecord
	err := ts.withMutationLock(func() error {
		if err := ts.reloadLocked(); err != nil {
			return err
		}
		for _, record := range ts.tokens {
			if record.RequestID == requestID {
				// Confirm a previously uncertain rename before reporting a durable result.
				if err := atomicfile.SyncDir(filepath.Dir(ts.path)); err != nil {
					return err
				}
				result = record
				return nil
			}
		}
		return ErrRequestNotFound
	})
	return result, err
}

func (ts *TokenStore) create(ttl time.Duration, singleUse bool, requestID string) (string, error) {
	if ttl < 0 {
		return "", fmt.Errorf("token TTL must not be negative")
	}
	ts.mu.Lock()
	defer ts.mu.Unlock()
	var token string
	err := ts.withMutationLock(func() error {
		if err := ts.reloadLocked(); err != nil {
			return err
		}
		if requestID != "" {
			for _, record := range ts.tokens {
				if record.RequestID != requestID {
					continue
				}
				if record.RequestedTTL != ttl || record.SingleUse != singleUse {
					return ErrRequestIDConflict
				}
				// A previous response may have failed after rename but before directory fsync.
				if err := atomicfile.SyncDir(filepath.Dir(ts.path)); err != nil {
					return err
				}
				token = record.Token
				return nil
			}
		}
		generated, err := GenerateToken()
		if err != nil {
			return err
		}
		record := TokenRecord{Token: generated, CreatedAt: time.Now().UTC(), SingleUse: singleUse, RequestID: requestID, RequestedTTL: ttl}
		if ttl > 0 {
			record.ExpiresAt = record.CreatedAt.Add(ttl)
		}
		ts.tokens[generated] = record
		if err := ts.saveLocked(); err != nil {
			if !atomicfile.Replaced(err) {
				delete(ts.tokens, generated)
			}
			return err
		}
		token = generated
		return nil
	})
	return token, err
}

// Use serializes admission with revoke across processes. The admission record is
// committed BEFORE fn, so a crash or a failed enrollment cannot replay a single-use
// token. UseCount counts admitted attempts, not successfully returned certificates.
func (ts *TokenStore) Use(token, nodeID string, fn func() error) error {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	return ts.withMutationLock(func() error {
		if err := ts.reloadLocked(); err != nil {
			return err
		}
		record, ok := ts.tokens[token]
		now := time.Now().UTC()
		if !ok || !record.active(now) {
			return ErrInvalidToken
		}
		previous := record
		record.UseCount++
		record.LastUsedAt, record.LastUsedBy = now, nodeID
		ts.tokens[token] = record
		if err := ts.saveLocked(); err != nil {
			if !atomicfile.Replaced(err) {
				ts.tokens[token] = previous
			}
			return err
		}
		return fn()
	})
}

// Records includes inactive tokens so administrators can inspect admission history.
func (ts *TokenStore) Records() ([]TokenRecord, error) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	if err := ts.reloadLocked(); err != nil {
		return nil, err
	}
	return ts.recordsLocked(), nil
}

func (ts *TokenStore) recordsLocked() []TokenRecord {
	records := make([]TokenRecord, 0, len(ts.tokens))
	for _, record := range ts.tokens {
		records = append(records, record)
	}
	sort.Slice(records, func(i, j int) bool { return records[i].Token < records[j].Token })
	return records
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
	record, ok := ts.tokens[token]
	return ok && record.active(time.Now()), nil
}

// Revoke durably marks a token inactive while retaining its admission history.
// Pre-replacement failures restore memory; uncertain commits retain visible state.
func (ts *TokenStore) Revoke(token string) error {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	return ts.withMutationLock(func() error {
		if err := ts.reloadLocked(); err != nil {
			return err
		}
		record, ok := ts.tokens[token]
		if !ok {
			return nil
		}
		if !record.RevokedAt.IsZero() {
			return atomicfile.SyncDir(filepath.Dir(ts.path))
		}
		previous := record
		record.RevokedAt = time.Now().UTC()
		ts.tokens[token] = record
		if err := ts.saveLocked(); err != nil {
			if !atomicfile.Replaced(err) {
				ts.tokens[token] = previous
			}
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
			ts.tokens = make(map[string]TokenRecord)
			return nil
		}
		return err
	}

	return ts.decode(data)
}

func ValidateTokenSnapshot(data []byte) error {
	return (&TokenStore{}).decode(data)
}

func (ts *TokenStore) decode(data []byte) error {
	tokens := make(map[string]TokenRecord)
	if bytes.HasPrefix(bytes.TrimSpace(data), []byte("[")) {
		var legacy []string
		if err := json.Unmarshal(data, &legacy); err != nil {
			return err
		}
		for _, token := range legacy {
			tokens[token] = TokenRecord{Token: token}
		}
	} else {
		var file struct {
			Version int           `json:"version"`
			Tokens  []TokenRecord `json:"tokens"`
		}
		if err := json.Unmarshal(data, &file); err != nil {
			return err
		}
		if file.Version != 1 {
			return fmt.Errorf("unsupported token store version %d", file.Version)
		}
		requests := make(map[string]bool)
		for _, record := range file.Tokens {
			if record.Token == "" {
				return fmt.Errorf("empty token in store")
			}
			if _, exists := tokens[record.Token]; exists {
				return fmt.Errorf("duplicate token in store")
			}
			if record.RequestID != "" {
				if err := ValidateRequestID(record.RequestID); err != nil {
					return err
				}
				if requests[record.RequestID] || record.RequestedTTL < 0 {
					return fmt.Errorf("invalid or duplicate token creation request")
				}
				requests[record.RequestID] = true
				if record.CreatedAt.IsZero() || (record.RequestedTTL == 0 && !record.ExpiresAt.IsZero()) || (record.RequestedTTL > 0 && !record.ExpiresAt.Equal(record.CreatedAt.Add(record.RequestedTTL))) {
					return fmt.Errorf("token creation options differ from record")
				}
			}
			tokens[record.Token] = record
		}
	}
	ts.tokens = tokens
	return nil
}

func (ts *TokenStore) listLocked() []string {
	tokens := make([]string, 0, len(ts.tokens))
	for token, record := range ts.tokens {
		if record.active(time.Now()) {
			tokens = append(tokens, token)
		}
	}
	sort.Strings(tokens)
	return tokens
}

func (ts *TokenStore) saveLocked() error {
	data, err := json.Marshal(struct {
		Version int           `json:"version"`
		Tokens  []TokenRecord `json:"tokens"`
	}{Version: 1, Tokens: ts.recordsLocked()})
	if err != nil {
		return err
	}

	return ts.write(ts.path, data, 0600)
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

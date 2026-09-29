// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relaycatalog

import "sync"

// Key point validity is immutable and independent of ownership, revocation,
// catalog revision and expiry. Those contextual checks still run on every view.
// Keep only successful exact encodings, with a fixed memory bound and FIFO
// eviction. Unknown encodings always run the full canonical/low-order check.
const maxValidatedPublicKeys = 2048

var validatedPublicKeys = keyValidationCache{limit: maxValidatedPublicKeys}

type keyValidationCache struct {
	mu    sync.RWMutex
	keys  map[string]bool
	order []string
	next  int
	limit int
}

func ValidatePublicKey(s string) error { return validatedPublicKeys.validate(s) }

func (c *keyValidationCache) validate(s string) error {
	// Bound work before hashing an untrusted input for lookup.
	if len(s) != 44 {
		return invalid("public key must be canonical base64 X25519")
	}
	c.mu.RLock()
	known := c.keys[s]
	c.mu.RUnlock()
	if known {
		return nil
	}
	if e := validatePublicKey(s); e != nil {
		return e
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.keys == nil {
		c.keys = make(map[string]bool)
	}
	if c.keys[s] {
		return nil
	}
	if len(c.order) < c.limit {
		c.order = append(c.order, s)
	} else {
		delete(c.keys, c.order[c.next])
		c.order[c.next] = s
		c.next = (c.next + 1) % c.limit
	}
	c.keys[s] = true
	return nil
}

// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relaycatalog

import (
	"encoding/base64"
	"fmt"
	"sync"
	"testing"
)

func TestPublicKeyMemoPreservesValidationUnderConcurrentEviction(t *testing.T) {
	cache := keyValidationCache{limit: 4}
	keys := make([]string, 12)
	for i := range keys {
		keys[i] = testKey(fmt.Sprint("memo-", i))
	}
	invalidKeys := []string{"bad", base64.StdEncoding.EncodeToString(make([]byte, 32))}
	raw, _ := base64.StdEncoding.DecodeString(keys[0])
	raw[31] |= 128
	invalidKeys = append(invalidKeys, base64.StdEncoding.EncodeToString(raw))
	low := make([]byte, 32)
	low[0] = 1
	invalidKeys = append(invalidKeys, base64.StdEncoding.EncodeToString(low))
	var wg sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for pass := 0; pass < 3; pass++ {
				for _, key := range keys {
					if e := cache.validate(key); e != nil {
						t.Error("valid key rejected after eviction", e)
					}
				}
				for _, key := range invalidKeys {
					if e := cache.validate(key); e == nil {
						t.Error("warm memo accepted malformed, noncanonical or low-order key")
					}
				}
			}
		}()
	}
	wg.Wait()
	if len(cache.keys) != cache.limit || len(cache.order) != cache.limit {
		t.Fatal("unbounded public key memo")
	}
	for _, key := range invalidKeys {
		if cache.keys[key] {
			t.Fatal("invalid key memoized")
		}
	}
	// Evicting a previously valid entry must revalidate, rather than dropping it
	// from the accepted key domain or inheriting a neighboring entry's result.
	for _, key := range keys {
		if e := cache.validate(key); e != nil {
			t.Fatal(e)
		}
	}
}

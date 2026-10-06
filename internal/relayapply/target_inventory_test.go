// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayapply

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestObservationInventoryCannotReusePreProofOrFailedEvidence(t *testing.T) {
	now := time.Second
	calls := 0
	value := "before"
	fail := false
	run := observationInventory(func(context.Context, string, string, ...string) ([]byte, error) {
		calls++
		if fail {
			return nil, errors.New("unreadable")
		}
		return []byte(value), nil
	}, func() (time.Duration, error) { return now, nil })
	query := func(ctx context.Context) ([]byte, error) { return run(ctx, "", "ip", "-j", "-N", "-4", "rule", "show") }
	ctx := context.Background()
	b, err := query(ctx)
	if err != nil {
		t.Fatal(err)
	}
	b[0] = 'X'
	now = 2 * time.Second
	value = "after TCP"
	b, err = query(ctx)
	if err != nil || string(b) != "before" || calls != 1 {
		t.Fatal(string(b), err, calls)
	}
	post := context.WithValue(ctx, observationFloorKey{}, now)
	now = 2500 * time.Millisecond
	b, err = query(post)
	if err != nil || string(b) != "after TCP" || calls != 2 {
		t.Fatal("pre-proof evidence reused", string(b), err, calls)
	}
	_, _ = query(post)
	if calls != 2 {
		t.Fatal("identical public snapshot repeated", calls)
	}
	// A later TCP cannot use the earlier postcheck, even within the same wave.
	now = 2700 * time.Millisecond
	later := context.WithValue(ctx, observationFloorKey{}, now)
	fail = true
	if _, err = query(later); err == nil {
		t.Fatal("failed fresh read accepted")
	}
	// Failure invalidates the cache even for a candidate whose proof ended earlier.
	if _, err = query(post); err == nil || calls != 4 {
		t.Fatal("old evidence survived a failed refresh", err, calls)
	}
	fail = false
	now = 2600 * time.Millisecond
	if _, err = query(later); err == nil {
		t.Fatal("BOOTTIME rollback before TCP accepted")
	}
	now = 10 * time.Second
	value = "after suspend"
	b, err = query(ctx)
	if err != nil || string(b) != "after suspend" || calls != 5 {
		t.Fatal(string(b), err, calls)
	}
}
func TestObservationInventoryNeverSharesLeasePrivateOrInterfaceState(t *testing.T) {
	calls := 0
	run := observationInventory(func(context.Context, string, string, ...string) ([]byte, error) {
		calls++
		return []byte("opaque"), nil
	}, func() (time.Duration, error) { return time.Second, nil })
	for _, q := range []struct {
		name string
		args []string
	}{
		{"nft", []string{"-j", "list", "table", "inet", "lease"}},
		{"wg", []string{"show", "vr0", "preshared-keys"}},
		{"wg", []string{"show", "vr0", "dump"}},
		{"ip", []string{"-j", "address", "show", "dev", "vr0"}},
	} {
		before := calls
		for i := 0; i < 2; i++ {
			if _, err := run(context.Background(), "", q.name, q.args...); err != nil {
				t.Fatal(err)
			}
		}
		if calls-before != 2 {
			t.Fatal("non-public/per-interface state reused", q.name, q.args)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	before := calls
	if _, err := run(ctx, "", "ip", "-j", "-N", "-4", "rule", "show"); !errors.Is(err, context.Canceled) || calls != before {
		t.Fatal(err, calls)
	}
}

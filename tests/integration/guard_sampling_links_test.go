//go:build integration

// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package integration

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/vishvananda/netlink"
)

func TestGuardSamplingDiscardsInterruptedInventory(t *testing.T) {
	old := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "old"}}
	current := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "current"}}
	calls := 0
	links, err := guardSamplingLinks(context.Background(), func() ([]netlink.Link, error) {
		calls++
		if calls == 1 {
			return []netlink.Link{old}, fmt.Errorf("enumeration: %w", netlink.ErrDumpInterrupted)
		}
		return []netlink.Link{current}, nil
	})
	if err != nil || calls != 2 || len(links) != 1 || links[0] != current {
		t.Fatal("incomplete dump retained or fresh inventory lost", calls, err)
	}
}

func TestGuardSamplingBoundsEnumerationFailures(t *testing.T) {
	denied := errors.New("permission denied")
	for _, tc := range []struct {
		name  string
		err   error
		calls int
	}{
		{"permanent", denied, 1},
		{"interrupted", netlink.ErrDumpInterrupted, 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			links, err := guardSamplingLinks(context.Background(), func() ([]netlink.Link, error) {
				calls++
				return []netlink.Link{&netlink.Dummy{}}, tc.err
			})
			if !errors.Is(err, tc.err) || links != nil || calls != tc.calls {
				t.Fatal("failed enumeration admitted or retry bound changed", calls, err)
			}
		})
	}
}

func TestGuardSamplingCancellationDiscardsInventory(t *testing.T) {
	for _, cancelBefore := range []bool{true, false} {
		ctx, cancel := context.WithCancel(context.Background())
		if cancelBefore {
			cancel()
		}
		calls := 0
		links, err := guardSamplingLinks(ctx, func() ([]netlink.Link, error) {
			calls++
			cancel()
			return []netlink.Link{&netlink.Dummy{}}, nil
		})
		cancel()
		if !errors.Is(err, context.Canceled) || links != nil || cancelBefore && calls != 0 || !cancelBefore && calls != 1 {
			t.Fatal("cancelled inventory accepted", cancelBefore, calls, err)
		}
	}
}

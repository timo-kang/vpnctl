// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayapply

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

var inventoryRoutes = []string{"-j", "-N", "-4", "route", "show", "table", "all"}

func TestInventoryDecodingRereadsAndRejectsChangedOrFailedEvidence(t *testing.T) {
	ctx := withInventoryDecoding(context.Background())
	data := []byte(`[{"dst":"default","table":100,"flags":["onlink"],"nested":{"metric":1}}]`)
	calls := 0
	var readErr error
	k := kernel{run: func(context.Context, string, string, ...string) ([]byte, error) { calls++; return data, readErr }}
	first, err := k.list(ctx, inventoryRoutes...)
	if err != nil {
		t.Fatal(err)
	}
	// Neither a caller nor a reused command output buffer may mutate saved rows.
	first[0]["table"] = float64(999)
	first[0]["flags"].([]any)[0] = "changed"
	first[0]["nested"].(map[string]any)["metric"] = float64(9)
	again, err := k.list(ctx, inventoryRoutes...)
	if err != nil || n(again[0], "table") != 100 || again[0]["flags"].([]any)[0] != "onlink" || n(object(again[0]["nested"].(map[string]any)), "metric") != 1 || calls != 2 {
		t.Fatal("reused mutable rows or skipped read", again, calls, err)
	}
	copy(data, bytes.ReplaceAll(data, []byte("100"), []byte("200")))
	changed, err := k.list(ctx, inventoryRoutes...)
	if err != nil || n(changed[0], "table") != 200 || calls != 3 {
		t.Fatal("old snapshot survived changed read", changed, calls, err)
	}
	readErr = errors.New("kernel unavailable")
	if _, err = k.list(ctx, inventoryRoutes...); !errors.Is(err, readErr) {
		t.Fatal("old snapshot hid failed read", err)
	}
	readErr = nil
	data = []byte(`[{"table":`)
	if _, err = k.list(ctx, inventoryRoutes...); err == nil {
		t.Fatal("old snapshot hid malformed read")
	}
	data = []byte(`[{"table":300}]`)
	if rows, err := k.list(ctx, inventoryRoutes...); err != nil || n(rows[0], "table") != 300 {
		t.Fatal(rows, err)
	}
}

func TestInventoryDecodingKeepsOriginalBoundsAndShape(t *testing.T) {
	for _, raw := range []string{"null", "{}", "[null]", "[1]", "[] trailing", strings.Repeat(" ", 512<<10) + "[]", "[" + strings.Repeat("{},", 4096) + "{}]"} {
		for _, cached := range []bool{false, true} {
			ctx := context.Background()
			if cached {
				ctx = withInventoryDecoding(ctx)
			}
			k := kernel{run: func(context.Context, string, string, ...string) ([]byte, error) { return []byte(raw), nil }}
			if _, err := k.list(ctx, inventoryRoutes...); err == nil {
				t.Fatalf("accepted invalid inventory cached=%v bytes=%d", cached, len(raw))
			}
		}
	}
	for _, raw := range []string{"[]", `[{"unknown":{"nested":[null,true,3,"s"]}}]`} {
		ctx := withInventoryDecoding(context.Background())
		k := kernel{run: func(context.Context, string, string, ...string) ([]byte, error) { return []byte(raw), nil }}
		for range 2 {
			if _, err := k.list(ctx, inventoryRoutes...); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestInventoryDecodingConcurrentReadersOwnTheirRows(t *testing.T) {
	ctx := withInventoryDecoding(context.Background())
	data := []byte(`[{"table":100,"nested":{"flags":["up"]}}]`)
	k := kernel{run: func(context.Context, string, string, ...string) ([]byte, error) { return data, nil }}
	var workers sync.WaitGroup
	for range 8 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for range 20 {
				rows, err := k.list(ctx, inventoryRoutes...)
				if err != nil {
					t.Error(err)
					return
				}
				if n(rows[0], "table") != 100 {
					t.Error("reader mutation escaped")
				}
				rows[0]["table"] = float64(200)
				rows[0]["nested"].(map[string]any)["flags"].([]any)[0] = "changed"
			}
		}()
	}
	workers.Wait()
}

func TestInventoryDecodingPreservesObservationRefreshBoundaries(t *testing.T) {
	ctx := withInventoryDecoding(context.Background())
	now := time.Second
	calls := 0
	var readErr, clockErr error
	k := kernel{run: observationInventory(func(context.Context, string, string, ...string) ([]byte, error) {
		calls++
		return []byte(fmt.Sprintf(`[{"table":%d}]`, calls)), readErr
	}, func() (time.Duration, error) { return now, clockErr })}
	check := func(ctx context.Context, want int) {
		t.Helper()
		rows, err := k.list(ctx, inventoryRoutes...)
		if err != nil || n(rows[0], "table") != uint32(want) || calls != want {
			t.Fatal("wrong observation", rows, calls, want, err)
		}
	}
	check(ctx, 1)
	now = 2 * time.Second
	check(ctx, 1)
	post := context.WithValue(ctx, observationFloorKey{}, now)
	check(post, 2) // A post-TCP floor forces a fresh read despite parsed rows.
	now += targetObservationWaveDuration
	check(post, 3) // Exact expiry must also force a fresh read.
	clockErr = errors.New("clock unavailable")
	if _, err := k.list(post, inventoryRoutes...); !errors.Is(err, clockErr) {
		t.Fatal("cached parsing hid clock failure", err)
	}
	clockErr = nil
	now = time.Second
	if _, err := k.list(post, inventoryRoutes...); err == nil {
		t.Fatal("clock rollback accepted")
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := k.list(cancelled, inventoryRoutes...); !errors.Is(err, context.Canceled) {
		t.Fatal("cached parsing hid cancellation", err)
	}
	now = 20 * time.Second
	readErr = errors.New("fresh read failed")
	if _, err := k.list(ctx, inventoryRoutes...); !errors.Is(err, readErr) {
		t.Fatal("cached parsing hid refresh failure", err)
	}
	readErr = nil
	check(ctx, 5)
}

func TestInventoryDecodingRetainsOnlyBoundedPublicInventories(t *testing.T) {
	ctx := withInventoryDecoding(context.Background())
	cache := ctx.Value(inventoryDecodingKey{}).(*inventoryDecoding)
	k := kernel{run: func(context.Context, string, string, ...string) ([]byte, error) {
		return []byte(`[{"table":100}]`), nil
	}}
	for _, query := range [][]string{inventoryRoutes, {"-j", "-N", "-4", "rule", "show"},
		{"-j", "-N", "-6", "route", "show", "table", "all"}, {"-j", "-N", "-d", "link", "show"}} {
		if _, err := k.list(ctx, query...); err != nil {
			t.Fatal(err)
		}
	}
	for i := range 100 {
		for _, query := range [][]string{{"-j", "address", "show", "dev", fmt.Sprint(i)},
			{"-j", "-4", "route", "get", fmt.Sprint(i)}, {"-j", "route", "show", "table", fmt.Sprint(i)}} {
			if _, err := k.list(ctx, query...); err != nil {
				t.Fatal(err)
			}
		}
	}
	if len(cache.entries) != 4 {
		t.Fatal("retained per-device/private state", len(cache.entries))
	}
	next := withInventoryDecoding(ctx).Value(inventoryDecodingKey{}).(*inventoryDecoding)
	if next == cache || len(next.entries) != 0 {
		t.Fatal("decoder survived its ownership scope")
	}
}

func BenchmarkKernelInventoryDecoding(b *testing.B) {
	for _, paths := range []int{4, 8, 32} {
		var rows []string
		for i := range paths * 8 {
			rows = append(rows, fmt.Sprintf(`{"dst":"198.18.%d.%d/32","dev":"wg%d","table":%d,"protocol":186,"metric":123,"scope":"link","flags":[]}`, i/256, i%256, i%paths, 1000+i))
		}
		data := []byte("[" + strings.Join(rows, ",") + "]")
		k := kernel{run: func(context.Context, string, string, ...string) ([]byte, error) { return data, nil }}
		for _, cached := range []bool{false, true} {
			b.Run(fmt.Sprintf("paths=%d/cached=%v", paths, cached), func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					ctx := context.Background()
					if cached {
						ctx = withInventoryDecoding(ctx)
					}
					// Each iteration is a new ownership scope; no cross-cycle warm cache.
					for range paths {
						if _, err := k.list(ctx, inventoryRoutes...); err != nil {
							b.Fatal(err)
						}
					}
				}
			})
		}
	}
}

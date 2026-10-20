// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayapply

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
)

type inventoryDecodingKey struct{}
type decodedInventory struct {
	raw  []byte
	rows []object
}
type inventoryDecoding struct {
	mu      sync.Mutex
	entries map[string]decodedInventory
}

// Each maintenance sweep or observation wave owns its decoder. Every read still
// goes through the original command/inventory wrapper, including its clock,
// post-probe floor, error and cancellation checks. Only byte-identical public
// inventories share parsing; no observation lifetime or authority is extended.
func withInventoryDecoding(ctx context.Context) context.Context {
	return context.WithValue(ctx, inventoryDecodingKey{}, &inventoryDecoding{entries: map[string]decodedInventory{}})
}

func inventoryRows(ctx context.Context, args []string, raw []byte) ([]object, error) {
	cache, _ := ctx.Value(inventoryDecodingKey{}).(*inventoryDecoding)
	key := "ip\x00" + strings.Join(args, "\x00")
	// The fixed allowlist bounds retained entries and excludes per-device state,
	// route-get proofs, private WireGuard dumps, nft policies and lease timers.
	if cache == nil || !sharedMaintenanceInventory(key) {
		return parseInventory(raw)
	}
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if previous, ok := cache.entries[key]; ok && bytes.Equal(raw, previous.raw) {
		return cloneInventory(previous.rows), nil
	}
	delete(cache.entries, key)
	rows, err := parseInventory(raw)
	if err != nil {
		return nil, err
	}
	cache.entries[key] = decodedInventory{raw: bytes.Clone(raw), rows: rows}
	// snapshot normalizes omitted main-route tables and callers can filter rows.
	// Never expose the retained maps/slices to any such caller mutation.
	return cloneInventory(rows), nil
}

func parseInventory(raw []byte) ([]object, error) {
	var rows []object
	if len(raw) > 512<<10 || json.Unmarshal(raw, &rows) != nil || rows == nil || len(rows) > 4096 {
		return nil, errors.New("invalid kernel inventory")
	}
	for _, row := range rows {
		if row == nil {
			return nil, errors.New("null kernel inventory")
		}
	}
	return rows, nil
}

func cloneInventory(rows []object) []object {
	out := make([]object, len(rows))
	for i, row := range rows {
		out[i] = make(object, len(row))
		for key, value := range row {
			out[i][key] = cloneInventoryValue(value)
		}
	}
	return out
}
func cloneInventoryValue(value any) any {
	switch v := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(v))
		for key, item := range v {
			out[key] = cloneInventoryValue(item)
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, item := range v {
			out[i] = cloneInventoryValue(item)
		}
		return out
	default:
		return value // JSON scalar values are immutable.
	}
}

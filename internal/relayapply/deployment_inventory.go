// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayapply

import (
	"context"
	"errors"
	"strings"
	"time"
)

// Query the exact live table first. Only an unsuccessful read needs an inventory
// to distinguish absence from an unreadable existing table. Never infer absence
// from a command error alone, and never cache policy contents or lease timers.
func (k deploymentKernel) readNFTTable(ctx context.Context, name string) ([]object, bool, error) {
	rows, readErr := k.nftRows(ctx, "list", "table", "inet", name)
	if readErr == nil {
		return rows, true, nil
	}
	if ctx.Err() != nil {
		return nil, false, readErr
	}
	tables, err := k.nftRows(ctx, "list", "tables")
	if err != nil {
		return nil, false, errors.Join(readErr, err)
	}
	for _, row := range tables {
		if len(row) != 1 {
			return nil, false, errors.New("invalid nft table inventory")
		}
		if _, ok := row["metainfo"]; ok {
			continue
		}
		table, ok := row["table"].(map[string]any)
		if !ok || str(table, "name") == "" || str(table, "family") == "" {
			return nil, false, errors.New("invalid nft table inventory")
		}
		if str(table, "family") == "inet" && str(table, "name") == name {
			return nil, true, readErr
		}
	}
	return nil, false, nil
}

type deploymentCheck func(context.Context, DeploymentEntry, bool) (bool, error)

// Only the maintenance ownership checks share these public, namespace-wide
// observations. A new factory is created after enforcement on every cycle.
// Lease/readback, policy, per-interface WG/address and every mutation retain
// fresh commands; in particular no timer, BPF state or private dump is cached.
func maintenanceInventory(run commandFunc) commandFunc {
	return maintenanceInventoryAt(run, leaseBootTime)
}

func maintenanceInventoryAt(run commandFunc, clock func() (time.Duration, error)) commandFunc {
	type observation struct {
		data []byte
		at   time.Duration
	}
	cache := map[string]observation{}
	return func(ctx context.Context, input, name string, args ...string) ([]byte, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		key := name + "\x00" + strings.Join(args, "\x00")
		shared := input == "" && sharedMaintenanceInventory(key)
		var observed time.Duration
		if shared {
			var err error
			observed, err = clock()
			if err != nil {
				return nil, err
			}
			if previous, ok := cache[key]; ok && observed >= previous.at && observed-previous.at < 5*time.Second {
				return append([]byte(nil), previous.data...), nil
			}
		}
		b, err := run(ctx, input, name, args...)
		if err == nil && shared {
			if len(b) > 512<<10 {
				return nil, errors.New("maintenance inventory exceeds limit")
			}
			cache[key] = observation{append([]byte(nil), b...), observed}
		}
		return b, err
	}
}
func sharedMaintenanceInventory(key string) bool {
	switch key {
	case "ip\x00-j\x00-N\x00-d\x00link\x00show",
		"ip\x00-j\x00-N\x00-4\x00route\x00show\x00table\x00all",
		"ip\x00-j\x00-N\x00-4\x00rule\x00show",
		"ip\x00-j\x00-N\x00-6\x00route\x00show\x00table\x00all",
		"wg\x00show\x00all\x00fwmark", "wg\x00show\x00all\x00listen-port":
		return true
	}
	return false
}
func (k deploymentKernel) maintenanceCheck() deploymentCheck {
	k.run = maintenanceInventory(k.run)
	return k.Check
}
func (k bootDeploymentKernel) maintenanceCheck() deploymentCheck {
	k.run = maintenanceInventory(k.run)
	return k.Check // Retain the BOOTTIME guard ownership/readback check.
}

// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"fmt"
	"os"
	"path/filepath"
	"vpnctl/internal/atomicfile"
	"vpnctl/internal/store"
)

const registryMarker = "registry.initialized"

func loadControllerRegistry(dir string) (*store.Registry, bool, error) {
	marker, err := os.ReadFile(filepath.Join(dir, registryMarker))
	initialized := err == nil
	if err != nil && !os.IsNotExist(err) {
		return nil, false, err
	}
	if initialized && string(marker) != "1" {
		return nil, false, fmt.Errorf("invalid registry initialization marker; restore controller state")
	}
	reg, err := store.LoadRegistry(filepath.Join(dir, "registry.yaml"))
	if err == nil {
		return reg, false, nil
	}
	if !os.IsNotExist(err) || initialized {
		return nil, false, fmt.Errorf("registry unavailable; restore controller state: %w", err)
	}
	// Legacy PKI/history proves this is not an unused controller directory. Never
	// infer a first installation from the absence of security-critical state alone.
	entries, readErr := os.ReadDir(dir)
	if readErr != nil && !os.IsNotExist(readErr) {
		return nil, false, readErr
	}
	for _, entry := range entries {
		if entry.Name() == "pki" || entry.Name() == "metrics.csv" {
			return nil, false, fmt.Errorf("registry missing from existing controller state; restore controller state")
		}
	}
	return &store.Registry{Nodes: []store.NodeInfo{}}, true, nil
}

func markRegistryInitialized(dir string) error {
	// Replacing also repairs an interrupted marker commit's durability on retry.
	return atomicfile.Write(filepath.Join(dir, registryMarker), []byte("1"), 0600)
}

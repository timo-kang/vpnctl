// Copyright 2025 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"

	"vpnctl/internal/atomicfile"
)

// Registry persists registered nodes and their metadata.
type Registry struct {
	Version      int                  `yaml:"version"`
	UpdatedAt    time.Time            `yaml:"updated_at"`
	Nodes        []NodeInfo           `yaml:"nodes"`
	RemovedNodes map[string]time.Time `yaml:"removed_nodes,omitempty"`
}

// NodeInfo is a minimal snapshot for controller persistence.
type NodeInfo struct {
	EnrollmentPending bool      `yaml:"enrollment_pending,omitempty"`
	ID                string    `yaml:"id"`
	Name              string    `yaml:"name"`
	PubKey            string    `yaml:"pub_key"`
	VPNIP             string    `yaml:"vpn_ip"`
	Endpoint          string    `yaml:"endpoint"`
	ProbePort         int       `yaml:"probe_port"`
	LastSeenAt        time.Time `yaml:"last_seen_at"`
	Status            string    `yaml:"status"`
	NATType           string    `yaml:"nat_type"`
	PublicAddr        string    `yaml:"public_addr"`
}

// LoadRegistry never substitutes an empty registry for missing or malformed state.
// First-time creation is owned by controller initialization, not by the reader.
func LoadRegistry(path string) (*Registry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	if len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, fmt.Errorf("invalid registry: expected a mapping with nodes")
	}
	hasNodes := false
	for n := 0; n < len(doc.Content[0].Content); n += 2 {
		if doc.Content[0].Content[n].Value == "nodes" {
			hasNodes = true
		}
	}
	if !hasNodes {
		return nil, fmt.Errorf("invalid registry: nodes field missing")
	}
	var reg Registry
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&reg); err != nil {
		return nil, err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("invalid registry: expected a single document")
	}
	if reg.Version < 0 || reg.Version > 1 {
		return nil, fmt.Errorf("unsupported registry version %d", reg.Version)
	}
	return &reg, nil
}

// SaveRegistry writes the registry to disk.
func SaveRegistry(path string, reg *Registry) error {
	if reg == nil {
		return nil
	}
	reg.Version = 1
	reg.UpdatedAt = time.Now().UTC()
	data, err := yaml.Marshal(reg)
	if err != nil {
		return err
	}

	if err := atomicfile.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}

	// Registry contains public keys and network metadata; keep it owner-readable by default.
	return atomicfile.Write(path, data, 0o600)
}

// RemoveNode removes a node by name and persists the replacement registry.
// The loaded registry is never mutated, so a failed save leaves the caller's
// in-memory view and the on-disk registry unchanged.
func RemoveNode(path, name string) (bool, error) {
	return removeNode(path, name, LoadRegistry, SaveRegistry)
}

func removeNode(
	path string,
	name string,
	load func(string) (*Registry, error),
	save func(string, *Registry) error,
) (bool, error) {
	reg, err := load(path)
	if err != nil {
		return false, err
	}

	filtered := make([]NodeInfo, 0, len(reg.Nodes))
	found := false
	for _, node := range reg.Nodes {
		if node.Name == name {
			found = true
			continue
		}
		filtered = append(filtered, node)
	}
	if !found {
		return false, nil
	}

	next := *reg
	next.Nodes = filtered
	if err := save(path, &next); err != nil {
		return true, err
	}
	return true, nil
}

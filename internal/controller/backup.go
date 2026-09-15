// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
	"vpnctl/internal/config"
	"vpnctl/internal/pki"
	"vpnctl/internal/store"
)

type controllerBackup struct {
	Version   int                     `json:"version"`
	CreatedAt time.Time               `json:"created_at"`
	Config    config.ControllerConfig `json:"config"`
	Registry  *store.Registry         `json:"registry"`
	Authority json.RawMessage         `json:"authority"`
	Tokens    json.RawMessage         `json:"tokens"`
}

// Caller holds stateMu exclusively. Token administration, bootstrap, registry
// mutations and background CA/server maintenance all participate in this gate.
func (s *Server) backupLocked() ([]byte, error) {
	state, err := s.authority.Snapshot()
	if err != nil {
		return nil, err
	}
	records, err := s.tokenStore.Records()
	if err != nil {
		return nil, err
	}
	tokens, err := json.Marshal(struct {
		Version int               `json:"version"`
		Tokens  []pki.TokenRecord `json:"tokens"`
	}{Version: 1, Tokens: records})
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	reg := cloneRegistry(s.reg)
	s.mu.Unlock()
	return json.Marshal(controllerBackup{Version: 1, CreatedAt: time.Now().UTC(), Config: s.cfg, Registry: reg, Authority: state, Tokens: tokens})
}

// RestoreBackup restores only a fresh directory, or resumes the same interrupted
// restore. A durable marker blocks controller startup until every file is ready.
func RestoreBackup(data []byte, dataDir string) (config.Config, error) {
	var out config.Config
	result := "failed"
	defer func() {
		slog.Info("PKI restore", "actor", fmt.Sprintf("uid:%d/pid:%d", os.Geteuid(), os.Getpid()), "target", dataDir, "result", result)
	}()
	if dataDir == "" {
		return out, fmt.Errorf("restore data directory required")
	}
	var backup controllerBackup
	if err := json.Unmarshal(data, &backup); err != nil {
		return out, err
	}
	if backup.Version != 1 || backup.Registry == nil || backup.Config.PKI == nil {
		return out, fmt.Errorf("invalid controller backup")
	}
	if err := pki.ValidateAuthoritySnapshot(backup.Authority); err != nil {
		return out, err
	}
	if err := pki.ValidateTokenSnapshot(backup.Tokens); err != nil {
		return out, err
	}
	if err := validateRegistryNodeMetadata(backup.Registry); err != nil {
		return out, err
	}
	for _, node := range backup.Registry.Nodes {
		if _, removed := backup.Registry.RemovedNodes[node.ID]; removed {
			return out, fmt.Errorf("backup identity both active and removed")
		}
	}
	for id := range backup.Registry.RemovedNodes {
		if _, err := pki.NodeIdentityURI(id); err != nil {
			return out, err
		}
	}
	allocator, err := newIPAM(backup.Config.VPNCIDR, backup.Config.WGAddress, backup.Config.ReservedVPNIPs)
	if err != nil {
		return out, err
	}
	if _, err := allocator.validateAndNormalizeRegistry(backup.Registry); err != nil {
		return out, err
	}
	target, err := filepath.Abs(dataDir)
	if err != nil {
		return out, err
	}
	ownership, err := AcquireStateLock(target)
	if err != nil {
		return out, err
	}
	defer ownership.Close()
	marker := filepath.Join(target, "restore.pending")
	digest := fmt.Sprintf("%x", sha256.Sum256(data))
	pending, err := os.ReadFile(marker)
	if err == nil {
		if string(pending) != digest {
			return out, fmt.Errorf("interrupted restore belongs to a different backup")
		}
	} else if os.IsNotExist(err) {
		entries, err := os.ReadDir(target)
		if err != nil {
			return out, err
		}
		for _, entry := range entries {
			if entry.Name() != "run" {
				return out, fmt.Errorf("restore requires a fresh data directory")
			}
		}
		if err := pki.WriteAtomic(marker, []byte(digest), 0600); err != nil {
			return out, err
		}
	} else {
		return out, err
	}
	pkiDir := filepath.Join(target, "pki")
	if err := os.MkdirAll(pkiDir, 0700); err != nil {
		return out, err
	}
	if err := pki.WriteAtomic(filepath.Join(pkiDir, "authority.json"), backup.Authority, 0600); err != nil {
		return out, err
	}
	if err := pki.WriteAtomic(filepath.Join(pkiDir, "bootstrap-tokens.json"), backup.Tokens, 0600); err != nil {
		return out, err
	}
	if err := pki.WriteAtomic(filepath.Join(pkiDir, "authority.initialized"), []byte("1"), 0600); err != nil {
		return out, err
	}
	registry, err := yaml.Marshal(backup.Registry)
	if err != nil {
		return out, err
	}
	if err := pki.WriteAtomic(filepath.Join(target, "registry.yaml"), registry, 0600); err != nil {
		return out, err
	}
	if err := os.Remove(marker); err != nil {
		return out, err
	}
	dir, err := os.Open(target)
	if err != nil {
		return out, err
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil {
		return out, err
	}
	backup.Config.DataDir = target
	// Metrics history is not part of this security/state snapshot.
	if backup.Config.MetricsPath != "" {
		backup.Config.MetricsPath = filepath.Join(target, "metrics.csv")
	}
	out.Controller = &backup.Config
	result = "success"
	return out, nil
}

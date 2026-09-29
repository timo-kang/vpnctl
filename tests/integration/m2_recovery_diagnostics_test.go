//go:build integration

// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package integration

import "time"

// A bounded final record per node is saved on recovery failure. Exclude private
// credentials, configuration, process command lines and bulk measurement bodies.
type soakRecoveryDiagnostic struct {
	Phase               string     `json:"phase"`
	Node                string     `json:"node"`
	CheckedAt           time.Time  `json:"checked_at"`
	RequiredAfter       time.Time  `json:"required_after"`
	Deadline            time.Time  `json:"deadline"`
	Error               string     `json:"error"`
	ObservationAt       time.Time  `json:"observation_at"`
	WireGuardObservedAt *time.Time `json:"wireguard_observed_at"`
	UplinkObservedAt    *time.Time `json:"uplink_observed_at"`
	RegisteredNodes     int        `json:"registered_nodes"`
	WireGuardPeers      int        `json:"wireguard_peers"`
	ExpectedPeers       []string   `json:"expected_peers"`
	ObservedPeers       []string   `json:"observed_peers"`
	StorageValidity     string     `json:"storage_validity"`
	StorageStale        bool       `json:"storage_stale"`
}

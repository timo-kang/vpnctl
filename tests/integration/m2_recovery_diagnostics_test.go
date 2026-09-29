//go:build integration

// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package integration

import (
	"context"
	"errors"
	"testing"
	"time"
)

// A bounded final record per node is saved on recovery failure. Exclude private
// credentials, configuration, process command lines and bulk measurement bodies.
type soakRecoveryDiagnostic struct {
	Phase                string     `json:"phase"`
	Node                 string     `json:"node"`
	CheckedAt            time.Time  `json:"checked_at"`
	LastSuccessfulReadAt time.Time  `json:"last_successful_read_at"`
	RequiredAfter        time.Time  `json:"required_after"`
	Deadline             time.Time  `json:"deadline"`
	Error                string     `json:"error"`
	LastReadinessError   string     `json:"last_readiness_error"`
	ObservationAt        time.Time  `json:"observation_at"`
	WireGuardObservedAt  *time.Time `json:"wireguard_observed_at"`
	UplinkObservedAt     *time.Time `json:"uplink_observed_at"`
	RegisteredNodes      int        `json:"registered_nodes"`
	WireGuardPeers       int        `json:"wireguard_peers"`
	ExpectedPeers        []string   `json:"expected_peers"`
	ObservedPeers        []string   `json:"observed_peers"`
	StorageValidity      string     `json:"storage_validity"`
	StorageStale         bool       `json:"storage_stale"`
}

// A final read may fail because the shared recovery deadline expired. Keep the
// last observed state so that this transport failure cannot erase its cause.
func (d *soakRecoveryDiagnostic) recordRead(v soakObservation, readErr, readinessErr error, checkedAt time.Time) {
	d.CheckedAt = checkedAt
	d.Error = boundedSoakError(readErr)
	if readErr != nil {
		return
	}
	d.LastReadinessError = boundedSoakError(readinessErr)
	d.Error = d.LastReadinessError
	d.LastSuccessfulReadAt = checkedAt
	d.ObservationAt = v.At
	d.WireGuardObservedAt = v.WGObservedAt
	d.UplinkObservedAt = v.UplinkObservedAt
	d.RegisteredNodes = v.RegisteredNodes
	d.WireGuardPeers = v.WGPeers
	d.ObservedPeers = v.WGPeerNodes
	d.StorageValidity = v.Storage.Validity
	d.StorageStale = v.Storage.Stale
}

func TestSoakReadinessDiagnosticsKeepLastReadWhenDeadlineExpires(t *testing.T) {
	at := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	stale := at.Add(-2 * time.Minute)
	var d soakRecoveryDiagnostic
	d.recordRead(soakObservation{}, context.DeadlineExceeded, nil, at)
	if !d.LastSuccessfulReadAt.IsZero() {
		t.Fatal("failed read invented an observation")
	}
	d.recordRead(soakObservation{At: at, UplinkObservedAt: &stale, RegisteredNodes: 3, WGPeerNodes: []string{"peer"}}, nil, errors.New("uplink collection is stale"), at)
	d.recordRead(soakObservation{}, context.DeadlineExceeded, nil, at.Add(time.Second))
	if !d.LastSuccessfulReadAt.Equal(at) || !d.ObservationAt.Equal(at) || d.UplinkObservedAt == nil || !d.UplinkObservedAt.Equal(stale) || d.RegisteredNodes != 3 || d.LastReadinessError != "uplink collection is stale" || d.Error != context.DeadlineExceeded.Error() || len(d.ObservedPeers) != 1 || !d.CheckedAt.Equal(at.Add(time.Second)) {
		t.Fatal("deadline erased the last successfully read producer state", d)
	}
	d.recordRead(soakObservation{At: at.Add(2 * time.Second)}, nil, errors.New("producer not ready"), at.Add(2*time.Second))
	if d.LastReadinessError != "producer not ready" || d.Error != d.LastReadinessError || d.UplinkObservedAt != nil || d.RegisteredNodes != 0 || len(d.ObservedPeers) != 0 || !d.LastSuccessfulReadAt.Equal(at.Add(2*time.Second)) {
		t.Fatal("successful unknown observation retained old values", d)
	}
	d.recordRead(soakObservation{At: at, WGObservedAt: &at, UplinkObservedAt: &at, RegisteredNodes: 3}, nil, nil, at.Add(3*time.Second))
	if d.LastReadinessError != "" || d.Error != "" {
		t.Fatal("recovered observation retained a failure", d)
	}
}

func boundedSoakError(err error) string {
	if err == nil {
		return ""
	}
	message := err.Error()
	if len(message) > 1024 {
		message = message[:1024]
	}
	return message
}

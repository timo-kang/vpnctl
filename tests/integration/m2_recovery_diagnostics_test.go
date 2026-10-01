//go:build integration

// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package integration

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"vpnctl/internal/api"
	"vpnctl/internal/config"
)

// A bounded final record per node is saved on recovery failure. Exclude private
// credentials, configuration, process command lines and bulk measurement bodies.
type soakRecoveryDiagnostic struct {
	PeerDiagnostic       *soakPeerDiagnostic `json:"peer_diagnostic,omitempty"`
	Phase                string              `json:"phase"`
	Node                 string              `json:"node"`
	CheckedAt            time.Time           `json:"checked_at"`
	LastSuccessfulReadAt time.Time           `json:"last_successful_read_at"`
	RequiredAfter        time.Time           `json:"required_after"`
	Deadline             time.Time           `json:"deadline"`
	Error                string              `json:"error"`
	LastReadinessError   string              `json:"last_readiness_error"`
	ObservationAt        time.Time           `json:"observation_at"`
	WireGuardObservedAt  *time.Time          `json:"wireguard_observed_at"`
	UplinkObservedAt     *time.Time          `json:"uplink_observed_at"`
	RegisteredNodes      int                 `json:"registered_nodes"`
	WireGuardPeers       int                 `json:"wireguard_peers"`
	ExpectedPeers        []string            `json:"expected_peers"`
	ObservedPeers        []string            `json:"observed_peers"`
	StorageValidity      string              `json:"storage_validity"`
	StorageStale         bool                `json:"storage_stale"`
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
	d.PeerDiagnostic = nil
	if v.PeerDiagnostic != nil {
		copy := *v.PeerDiagnostic
		copy.Ready = maps.Clone(copy.Ready)
		copy.KernelPeerNodes = slices.Clone(copy.KernelPeerNodes)
		d.PeerDiagnostic = &copy
	}
}

// Sequential, bounded diagnostic reads distinguish withdrawn controller
// readiness, current kernel membership and the asynchronously stored WG sample.
// They are not an atomic snapshot and never participate in the pass condition.
type soakPeerDiagnostic struct {
	At              time.Time       `json:"at"`
	Error           string          `json:"error,omitempty"`
	Ready           map[string]bool `json:"controller_direct_ready,omitempty"`
	KernelPeerNodes []string        `json:"kernel_peer_nodes"`
}

func collectSoakPeerDiagnostic(ctx context.Context, client *api.Client, cfg config.NodeConfig, output func(context.Context, string, ...string) (string, error)) soakPeerDiagnostic {
	d := soakPeerDiagnostic{At: time.Now().UTC()}
	candidates, e := client.Candidates(ctx, cfg.Name)
	if e != nil {
		d.Error = "candidates_unavailable"
		return d
	}
	if len(candidates.Peers) > 128 {
		d.Error = "candidate_limit"
		return d
	}
	known := map[string]string{cfg.ServerPublicKey: ""}
	d.Ready = map[string]bool{}
	for _, p := range candidates.Peers {
		known[p.PubKey] = p.ID
		d.Ready[p.ID] = p.P2PReady
	}
	raw, e := output(ctx, "wg", "show", cfg.WGInterface, "peers")
	if e != nil {
		d.Error = "kernel_peers_unavailable"
		return d
	}
	keys := strings.Fields(raw)
	if len(keys) > 129 {
		d.Error = "kernel_peer_limit"
		return d
	}
	d.KernelPeerNodes = []string{}
	for _, key := range keys {
		id, ok := known[key]
		if !ok {
			id = "unmapped"
		}
		d.KernelPeerNodes = append(d.KernelPeerNodes, id)
	}
	slices.Sort(d.KernelPeerNodes)
	d.At = time.Now().UTC()
	return d
}

func TestSoakPeerDiagnosticRedactsKeysAndKeepsReadinessSeparate(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(api.CandidatesResponse{Peers: []api.PeerCandidate{{ID: "a", PubKey: "public-a", P2PReady: true}, {ID: "b", PubKey: "public-b"}}})
	}))
	defer server.Close()
	c := api.NewClient(server.URL)
	defer c.CloseIdleConnections()
	d := collectSoakPeerDiagnostic(context.Background(), c, config.NodeConfig{Name: "node", WGInterface: "wg0", ServerPublicKey: "public-controller"}, func(_ context.Context, name string, args ...string) (string, error) {
		if name != "wg" || strings.Join(args, " ") != "show wg0 peers" {
			t.Fatal("unsafe diagnostic command")
		}
		return "public-controller\npublic-b\npublic-unmapped\n", nil
	})
	if d.Error != "" || !d.Ready["a"] || d.Ready["b"] || !slices.Equal(d.KernelPeerNodes, []string{"", "b", "unmapped"}) {
		t.Fatal(d)
	}
	raw, _ := json.Marshal(d)
	if strings.Contains(string(raw), "public-") {
		t.Fatal("key escaped diagnostic")
	}
	var saved soakRecoveryDiagnostic
	saved.recordRead(soakObservation{PeerDiagnostic: &d}, nil, errors.New("peer missing"), time.Now())
	d.Ready["a"] = false
	d.KernelPeerNodes[0] = "changed"
	saved.recordRead(soakObservation{}, context.DeadlineExceeded, nil, time.Now())
	if saved.PeerDiagnostic == nil || !saved.PeerDiagnostic.Ready["a"] || saved.PeerDiagnostic.KernelPeerNodes[0] != "" {
		t.Fatal("diagnostic lost or aliased")
	}
	d = collectSoakPeerDiagnostic(context.Background(), c, config.NodeConfig{Name: "node"}, func(context.Context, string, ...string) (string, error) {
		return "", errors.New("private command error")
	})
	if d.Error != "kernel_peers_unavailable" || d.KernelPeerNodes != nil {
		t.Fatal("unknown kernel membership fabricated", d)
	}
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

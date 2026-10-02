// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package integration

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"vpnctl/internal/pki"
)

// Record only public metadata for the fixture's nodes, never key material,
// renewal PEM responses, or the unbounded certificate issuance history.
type caNodeObservation struct {
	NodeID       string                 `json:"node_id"`
	Ack          *pki.TrustAck          `json:"ack,omitempty"`
	Acknowledged *pki.CertificateRecord `json:"acknowledged_certificate,omitempty"`
	Latest       *pki.CertificateRecord `json:"latest_certificate,omitempty"`
}

type caStatusObservation struct {
	Generation       uint64              `json:"generation"`
	Phase            string              `json:"phase"`
	Active           string              `json:"active"`
	Previous         string              `json:"previous,omitempty"`
	Pending          string              `json:"pending,omitempty"`
	OverlapUntil     time.Time           `json:"overlap_until"`
	CertificateCount int                 `json:"certificate_count"`
	Nodes            []caNodeObservation `json:"nodes"`
}

type caTransitionObservation struct {
	Operation  string               `json:"operation"`
	At         time.Time            `json:"at"`
	DurationMS int64                `json:"duration_ms"`
	Error      string               `json:"error,omitempty"`
	Status     *caStatusObservation `json:"status,omitempty"`
}

type caTransitionTrace struct {
	Operation    string                    `json:"operation"`
	StartedAt    time.Time                 `json:"started_at"`
	DurationMS   int64                     `json:"duration_ms"`
	Error        string                    `json:"error,omitempty"`
	Dropped      int                       `json:"dropped_observations"`
	Observations []caTransitionObservation `json:"observations"`
}

const caTraceLimit = 320 // 15s / 100ms retry spacing, with two RPCs per attempt.

func (trace *caTransitionTrace) record(operation string, began time.Time, status *pki.AuthorityStatus, err error, nodes int) {
	entry := caTransitionObservation{Operation: operation, At: began.UTC(), DurationMS: time.Since(began).Milliseconds()}
	if err != nil {
		entry.Error = err.Error()
	}
	if status != nil {
		observation := &caStatusObservation{
			Generation: status.Generation, Phase: status.Phase, Active: status.Active,
			Previous: status.Previous, Pending: status.Pending, OverlapUntil: status.OverlapUntil,
			CertificateCount: len(status.Certificates),
		}
		byFingerprint := make(map[string]pki.CertificateRecord, len(status.Certificates))
		latest := make(map[string]pki.CertificateRecord, nodes)
		for _, cert := range status.Certificates {
			byFingerprint[cert.Fingerprint] = cert
			if prev, ok := latest[cert.NodeID]; !ok || cert.IssuedAt.After(prev.IssuedAt) || (cert.IssuedAt.Equal(prev.IssuedAt) && cert.Fingerprint > prev.Fingerprint) {
				latest[cert.NodeID] = cert
			}
		}
		for i := 0; i < nodes; i++ {
			node := caNodeObservation{NodeID: fmt.Sprintf("node-%d", i)}
			if ack, ok := status.Acks[node.NodeID]; ok {
				node.Ack = &ack
				if cert, ok := byFingerprint[ack.Fingerprint]; ok {
					node.Acknowledged = &cert
				}
			}
			if cert, ok := latest[node.NodeID]; ok {
				node.Latest = &cert
			}
			observation.Nodes = append(observation.Nodes, node)
		}
		entry.Status = observation
	}
	if len(trace.Observations) < caTraceLimit {
		trace.Observations = append(trace.Observations, entry)
	} else {
		// Retain the initial context and the final observation even if the
		// retry policy changes. Explicitly report omitted intermediate RPCs.
		trace.Observations[caTraceLimit-1] = entry
		trace.Dropped++
	}
}

func TestCATransitionTraceIsBoundedAndPreservesAckEvidence(t *testing.T) {
	now := time.Now().UTC()
	status := &pki.AuthorityStatus{
		Generation: 3, Phase: "overlap", Active: "new", Previous: "old", CACert: "excluded-ca-pem",
		Acks: map[string]pki.TrustAck{"node-0": {Generation: 2, Fingerprint: "old-cert", At: now}},
		Certificates: []pki.CertificateRecord{
			{NodeID: "node-0", Fingerprint: "old-cert", Issuer: "old", IssuedAt: now.Add(-time.Minute)},
			{NodeID: "node-0", Fingerprint: "new-cert", Issuer: "new", IssuedAt: now},
			{NodeID: "unrelated", Fingerprint: "excluded-history", IssuedAt: now},
		},
	}
	var trace caTransitionTrace
	trace.record("pki.status", now, status, nil, 2)
	first := trace.Observations[0].Status
	if first.CertificateCount != 3 || len(first.Nodes) != 2 || first.Nodes[0].Ack.Generation != 2 || first.Nodes[0].Acknowledged.Issuer != "old" || first.Nodes[0].Latest.Issuer != "new" || first.Nodes[1].Ack != nil {
		t.Fatalf("lost ACK/issuance evidence: %+v", first)
	}
	status.Acks["node-0"] = pki.TrustAck{Generation: 4}
	status.Certificates[0].Issuer = "mutated"
	if first.Nodes[0].Ack.Generation != 2 || first.Nodes[0].Acknowledged.Issuer != "old" {
		t.Fatal("observation aliases mutable response")
	}
	for i := 0; i < caTraceLimit; i++ {
		trace.record("pki.status", now, nil, errors.New("status timeout"), 2)
	}
	if len(trace.Observations) != caTraceLimit || trace.Dropped != 1 || trace.Observations[caTraceLimit-1].Error != "status timeout" {
		t.Fatal("trace lost its bound or last RPC")
	}
	raw, err := json.Marshal(trace)
	if err != nil || strings.Contains(string(raw), "excluded-") {
		t.Fatal("trace leaked omitted material", err)
	}
}

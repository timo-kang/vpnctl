// Copyright 2025 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package monitor

import (
	"path/filepath"
	"testing"
	"time"
)

func TestStore_InsertAndQuery(t *testing.T) {
	dir := t.TempDir()
	s, err := OpenStore(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer s.Close()

	now := time.Now().UTC()
	r := ProbeResult{
		Timestamp: now,
		PeerKey:   "abc123",
		PeerIP:    "10.0.0.2",
		RTTus:     1234,
		Success:   true,
	}

	if err := s.Insert(r); err != nil {
		t.Fatalf("Insert: %v", err)
	}

	results, err := s.Query("abc123", 5*time.Minute)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	got := results[0]
	if got.PeerKey != r.PeerKey {
		t.Errorf("PeerKey: want %q, got %q", r.PeerKey, got.PeerKey)
	}
	if got.PeerIP != r.PeerIP {
		t.Errorf("PeerIP: want %q, got %q", r.PeerIP, got.PeerIP)
	}
	if got.RTTus != r.RTTus {
		t.Errorf("RTTus: want %d, got %d", r.RTTus, got.RTTus)
	}
	if got.Success != r.Success {
		t.Errorf("Success: want %v, got %v", r.Success, got.Success)
	}
	// Timestamp is stored at microsecond precision (Unix seconds * 1e6)
	if got.Timestamp.Unix() != r.Timestamp.Unix() {
		t.Errorf("Timestamp seconds: want %d, got %d", r.Timestamp.Unix(), got.Timestamp.Unix())
	}
}

func TestStore_Retention(t *testing.T) {
	dir := t.TempDir()
	s, err := OpenStore(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer s.Close()

	now := time.Now().UTC()

	old := ProbeResult{
		Timestamp: now.Add(-48 * time.Hour),
		PeerKey:   "peer1",
		PeerIP:    "10.0.0.2",
		RTTus:     500,
		Success:   true,
	}
	recent := ProbeResult{
		Timestamp: now.Add(-1 * time.Hour),
		PeerKey:   "peer1",
		PeerIP:    "10.0.0.2",
		RTTus:     600,
		Success:   true,
	}

	if err := s.Insert(old); err != nil {
		t.Fatalf("Insert old: %v", err)
	}
	if err := s.Insert(recent); err != nil {
		t.Fatalf("Insert recent: %v", err)
	}

	removed, err := s.Cleanup(24 * time.Hour)
	if err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
	if removed != 1 {
		t.Errorf("Cleanup: want 1 removed, got %d", removed)
	}

	results, err := s.QueryAll(72 * time.Hour)
	if err != nil {
		t.Fatalf("QueryAll: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("after cleanup: expected 1 result, got %d", len(results))
	}
	if results[0].RTTus != 600 {
		t.Errorf("expected recent probe RTTus=600, got %d", results[0].RTTus)
	}
}

func TestStore_Summary(t *testing.T) {
	dir := t.TempDir()
	s, err := OpenStore(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer s.Close()

	now := time.Now().UTC()
	peer := "peerXYZ"
	ip := "10.0.0.3"

	probes := []ProbeResult{
		{Timestamp: now.Add(-2 * time.Minute), PeerKey: peer, PeerIP: ip, RTTus: 1000, Success: true},
		{Timestamp: now.Add(-1 * time.Minute), PeerKey: peer, PeerIP: ip, RTTus: 2000, Success: true},
		{Timestamp: now, PeerKey: peer, PeerIP: ip, RTTus: 0, Success: false},
	}

	for _, p := range probes {
		if err := s.Insert(p); err != nil {
			t.Fatalf("Insert: %v", err)
		}
	}

	summaries, err := s.Summarize(5 * time.Minute)
	if err != nil {
		t.Fatalf("Summarize: %v", err)
	}

	if len(summaries) != 1 {
		t.Fatalf("expected 1 summary, got %d", len(summaries))
	}

	sum := summaries[0]
	if sum.PeerKey != peer {
		t.Errorf("PeerKey: want %q, got %q", peer, sum.PeerKey)
	}
	if sum.Count != 3 {
		t.Errorf("Count: want 3, got %d", sum.Count)
	}
	// loss pct should be ~33.33%
	if sum.LossPct < 33.0 || sum.LossPct > 34.0 {
		t.Errorf("LossPct: want ~33.33, got %f", sum.LossPct)
	}
	if sum.AvgRTTus != 1500 {
		t.Errorf("AvgRTTus: want 1500, got %d", sum.AvgRTTus)
	}
	if sum.MinRTTus != 1000 {
		t.Errorf("MinRTTus: want 1000, got %d", sum.MinRTTus)
	}
	if sum.MaxRTTus != 2000 {
		t.Errorf("MaxRTTus: want 2000, got %d", sum.MaxRTTus)
	}
}

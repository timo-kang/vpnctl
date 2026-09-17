// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package monitor

import (
	"encoding/json"
	"net/http"
	"time"
)

// QualityResponse version 1 replaces the unversioned, per-probe array.
type QualityResponse struct {
	SchemaVersion   int           `json:"schema_version"`
	ObservedAt      *time.Time    `json:"observed_at"`
	Window          float64       `json:"window"`
	StaleAfter      float64       `json:"stale_after"`
	MinSamples      int           `json:"min_samples"`
	RecoverySamples int           `json:"recovery_samples"`
	Stale           bool          `json:"stale"`
	ErrorReason     string        `json:"error_reason"`
	StorageError    string        `json:"storage_error"`
	Peers           []PeerQuality `json:"peers"`
}

func (m *Monitor) QualityResponse() QualityResponse {
	snap := m.Latest()
	response := QualityResponse{
		SchemaVersion:   1,
		Window:          m.cfg.Quality.Window.Seconds(),
		StaleAfter:      m.cfg.Quality.StaleAfter.Seconds(),
		MinSamples:      m.cfg.Quality.MinSamples,
		RecoverySamples: m.cfg.Quality.RecoverySamples,
		Stale:           snap.Stale,
		ErrorReason:     snap.ErrorReason,
		StorageError:    snap.StorageError,
		Peers:           make([]PeerQuality, 0, len(snap.Peers)),
	}
	if !snap.Time.IsZero() {
		response.ObservedAt = ptr(snap.Time)
	}
	for _, p := range snap.Peers {
		response.Peers = append(response.Peers, p.Quality)
	}
	return response
}

func (m *Monitor) QualityHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(m.QualityResponse())
}

// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

// Package relayobserve defines the local observation contract shared by selection and application.
package relayobserve

import "time"

// ProbeFailure identifies a failed proof boundary, not reachability or authority.
// All fields are fixed diagnostic enums; no error text or kernel output is kept.
// ContextState describes the context at failure, not necessarily its cause.
type ProbeFailure struct {
	Stage        string `json:"stage"`
	Cause        string `json:"cause"`
	ContextState string `json:"context_state"`
}

// TargetObservation proves TCP connect reachability only. It is neither an
// application protocol health check nor evidence that an unbound app uses this path.
type TargetObservation struct {
	PathID             string        `json:"path_id"`
	RelayID            string        `json:"relay_id"`
	UnderlayID         string        `json:"underlay_id"`
	Priority           int           `json:"priority"`
	Cost               int           `json:"cost"`
	Fingerprint        string        `json:"fingerprint,omitempty"`
	UnderlayGeneration string        `json:"underlay_generation,omitempty"`
	State              string        `json:"state"` // reachable, unreachable, unknown, excluded
	Reason             string        `json:"reason,omitempty"`
	ObservedAt         time.Time     `json:"observed_at"`
	ConnectTime        time.Duration `json:"connect_time_ns"`
	Handshake          int64         `json:"wg_handshake_unix,omitempty"`
	RXDelta            uint64        `json:"wg_rx_delta,omitempty"`
	TXDelta            uint64        `json:"wg_tx_delta,omitempty"`
	ProbeFailure       *ProbeFailure `json:"probe_failure,omitempty"`
}

type TargetReport struct {
	SchemaVersion int                 `json:"schema_version"`
	ControllerID  string              `json:"controller_id"`
	NodeID        string              `json:"node_id"`
	Generation    uint64              `json:"generation"`
	TargetID      string              `json:"target_id"`
	StartedAt     time.Time           `json:"started_at"`
	ObservedAt    time.Time           `json:"observed_at"`
	BootTime      time.Duration       `json:"boot_time_ns"`
	ApprovalUntil time.Time           `json:"approval_until"`
	Valid         bool                `json:"valid"`
	Reason        string              `json:"reason,omitempty"`
	Paths         []TargetObservation `json:"paths"`
	Diagnostics   *Diagnostics        `json:"diagnostics,omitempty"`
}

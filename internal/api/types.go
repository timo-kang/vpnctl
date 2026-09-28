// Copyright 2025 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"time"

	"vpnctl/internal/history"
	"vpnctl/internal/model"
	"vpnctl/internal/uplink"
)

// RegisterRequest is sent by a node when joining the controller.
type RegisterRequest struct {
	Name       string `json:"name"`
	PubKey     string `json:"pub_key"`
	VPNIP      string `json:"vpn_ip"`
	Endpoint   string `json:"endpoint"`
	PublicAddr string `json:"public_addr"`
	NATType    string `json:"nat_type"`
	DirectMode string `json:"direct_mode"`
	ProbePort  int    `json:"probe_port"`
}

// PeerCandidate describes a peer for direct/relay selection.
type PeerCandidate struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	PubKey     string `json:"pub_key"`
	VPNIP      string `json:"vpn_ip"`
	Endpoint   string `json:"endpoint"`
	PublicAddr string `json:"public_addr"`
	NATType    string `json:"nat_type"`
	ProbePort  int    `json:"probe_port"`
	// P2PReady is set by the controller when recent mutual direct probe success exists.
	// Nodes should only inject /32 WireGuard peers when this is true to avoid blackholing relay traffic.
	P2PReady bool `json:"p2p_ready"`
}

// RegisterResponse returns the assigned node ID and peers list.
type RegisterResponse struct {
	NodeID string          `json:"node_id"`
	Peers  []PeerCandidate `json:"peers"`
	VPNIP  string          `json:"vpn_ip"`
}

// CandidatesResponse returns peer candidates for a node.
type CandidatesResponse struct {
	Peers []PeerCandidate `json:"peers"`
}

// MetricsRequest submits one or more samples.
type MetricsRequest struct {
	NodeID       string                `json:"node_id"`
	Samples      []model.Metric        `json:"samples,omitempty"`
	Observations []history.Observation `json:"observations,omitempty"`
}

// NATProbeRequest submits NAT discovery results.
type NATProbeRequest struct {
	NodeID     string `json:"node_id"`
	NATType    string `json:"nat_type"`
	PublicAddr string `json:"public_addr"`
}

// DirectResultRequest submits a direct path attempt result.
type DirectResultRequest struct {
	NodeID  string  `json:"node_id"`
	PeerID  string  `json:"peer_id"`
	Success bool    `json:"success"`
	RTTMs   float64 `json:"rtt_ms"`
	Reason  string  `json:"reason"`
}

// WGConfigResponse supplies server peer information for nodes.
type WGConfigResponse struct {
	ServerPublicKey    string   `json:"server_public_key"`
	ServerEndpoint     string   `json:"server_endpoint"`
	ServerAllowedIPs   []string `json:"server_allowed_ips"`
	ServerKeepaliveSec int      `json:"server_keepalive_sec"`
	ServerProbePort    int      `json:"server_probe_port,omitempty"`
}

// FleetNodeStatus describes the current status of a single fleet node.
type UplinkRequest struct {
	NodeID   string          `json:"node_id"`
	Snapshot uplink.Snapshot `json:"snapshot"`
}

// EventRequest submits one immutable diagnostic or state-transition event.
type EventRequest struct {
	NodeID string        `json:"node_id"`
	Event  history.Event `json:"event"`
}

type FleetEventHistory = history.EventHistory
type FleetAlert = history.Alert

type FleetNodeStatus struct {
	UplinkObservation *uplink.Snapshot `json:"uplink_observation,omitempty"`
	history.Measurement
	Status       string                `json:"status"`
	Name         string                `json:"name"`
	VPNIP        string                `json:"vpn_ip"`
	NATType      string                `json:"nat_type"`
	LastSeen     string                `json:"last_seen"`
	Measurements []history.Measurement `json:"measurements"`
}

type FleetStatusResponse struct {
	SchemaVersion int               `json:"schema_version"`
	Nodes         []FleetNodeStatus `json:"nodes"`
}

type FleetHistoryBucket = history.Bucket

type FleetNodeHistory struct {
	NodeID  string               `json:"node_id"`
	Name    string               `json:"name"`
	Buckets []FleetHistoryBucket `json:"buckets"`
}

type FleetHistoryResponse struct {
	Tiering          *history.PageInfo    `json:"tiering,omitempty"`
	Storage          *history.TieredStats `json:"storage,omitempty"`
	SchemaVersion    int                  `json:"schema_version"`
	Start            time.Time            `json:"start"`
	End              time.Time            `json:"end"`
	BucketSeconds    float64              `json:"bucket_seconds"`
	RetentionSeconds float64              `json:"retention_seconds"`
	Nodes            []FleetNodeHistory   `json:"nodes"`
}

// BootstrapRequest is sent by a node during initial enrollment.
type BootstrapRequest struct {
	Token string `json:"token"`
	Name  string `json:"name"`
	CSR   string `json:"csr"` // PEM-encoded CSR
}

// BootstrapResponse returns the CA cert and signed client cert.
type BootstrapResponse struct {
	Generation uint64 `json:"generation"`
	CACert     string `json:"ca_cert"`     // PEM
	ClientCert string `json:"client_cert"` // PEM
	NodeID     string `json:"node_id"`
	VPNIP      string `json:"vpn_ip"`
}

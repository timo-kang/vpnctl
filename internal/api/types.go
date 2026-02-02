package api

import "vpnctl/internal/model"

// RegisterRequest is sent by a node when joining the controller.
type RegisterRequest struct {
	Name       string `json:"name"`
	PubKey     string `json:"pub_key"`
	VPNIP      string `json:"vpn_ip"`
	Endpoint   string `json:"endpoint"`
	PublicAddr string `json:"public_addr"`
	NATType    string `json:"nat_type"`
	DirectMode string `json:"direct_mode"`
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
	NodeID  string         `json:"node_id"`
	Samples []model.Metric `json:"samples"`
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
}

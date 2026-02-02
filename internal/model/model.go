package model

import "time"

// Node represents a registered device in the fleet.
type Node struct {
	ID         string
	Name       string
	PubKey     string
	VPNIP      string
	Endpoint   string
	LastSeenAt time.Time
	Status     string
	NATType    string
	PublicAddr string
}

// Metric is a single measurement sample.
type Metric struct {
	Timestamp       time.Time
	NodeID          string
	PeerID          string
	Path            string // direct|relay
	RTTMs           float64
	JitterMs        float64
	LossPct         float64
	ThroughputMbps  float64
	MTU             int
	NATType         string
	PublicAddr      string
	RelayReason     string
}


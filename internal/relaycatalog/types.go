// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

// Package relaycatalog defines approved candidate paths and durable key/lease
// ownership. It neither probes a target nor changes WireGuard or routing state.
package relaycatalog

import (
	"errors"
	"time"
)

const (
	SchemaVersion    = 1
	MaxRelays        = 4
	MaxNodes         = 32
	MaxPathsPerNode  = 8
	MaxTargets       = 32
	MaxPathIDs       = 1024
	MaxRelayIDs      = 64
	MaxRelayKeys     = 128
	MaxDocumentBytes = 1 << 20
)

var (
	ErrInvalid  = errors.New("invalid relay catalog")
	ErrConflict = errors.New("relay catalog conflict")
	ErrNotFound = errors.New("relay catalog or path not found")
	ErrExpired  = errors.New("relay catalog expired")
	ErrCapacity = errors.New("relay catalog capacity exhausted")
)

type Endpoint struct {
	ID      string `json:"id" yaml:"id"`
	Address string `json:"address" yaml:"address"`
}
type Relay struct {
	ID            string     `json:"id" yaml:"id"`
	Site          string     `json:"site" yaml:"site"`
	PublicKey     string     `json:"public_key" yaml:"public_key"`
	KeyGeneration uint64     `json:"key_generation" yaml:"key_generation"`
	Endpoints     []Endpoint `json:"endpoints" yaml:"endpoints"`
}
type Target struct {
	ID           string   `json:"id" yaml:"id"`
	Prefixes     []string `json:"prefixes" yaml:"prefixes"`
	ProbeAddress string   `json:"probe_address" yaml:"probe_address"`
	Protocol     string   `json:"protocol" yaml:"protocol"`
	Port         uint16   `json:"port" yaml:"port"`
}
type Path struct {
	ID         string   `json:"id" yaml:"id"`
	NodeID     string   `json:"node_id" yaml:"node_id"`
	RelayID    string   `json:"relay_id" yaml:"relay_id"`
	EndpointID string   `json:"endpoint_id" yaml:"endpoint_id"`
	UnderlayID string   `json:"underlay_id" yaml:"underlay_id"`
	TargetIDs  []string `json:"target_ids" yaml:"target_ids"`
	Priority   int      `json:"priority" yaml:"priority"`
	Cost       int      `json:"cost" yaml:"cost"`
	Drain      bool     `json:"drain" yaml:"drain"`
	Disabled   bool     `json:"disabled" yaml:"disabled"`
}
type Spec struct {
	SchemaVersion int      `json:"schema_version" yaml:"schema_version"`
	PoolCIDR      string   `json:"pool_cidr" yaml:"pool_cidr"`
	ReservedIPs   []string `json:"reserved_ips" yaml:"reserved_ips"`
	Relays        []Relay  `json:"relays" yaml:"relays"`
	Targets       []Target `json:"targets" yaml:"targets"`
	Paths         []Path   `json:"paths" yaml:"paths"`
}
type Binding struct {
	PathID         string    `json:"path_id" yaml:"path_id"`
	NodeID         string    `json:"node_id" yaml:"node_id"`
	PublicKey      string    `json:"public_key" yaml:"public_key"`
	InnerAddress   string    `json:"inner_address" yaml:"inner_address"`
	DefinitionHash string    `json:"definition_hash" yaml:"definition_hash"`
	CreatedAt      time.Time `json:"created_at" yaml:"created_at"`
	RetiredAt      time.Time `json:"retired_at,omitempty" yaml:"retired_at,omitempty"`
}

// State is immutable once published. Mutators return a deep copy. Retired keys,
// leases and IDs remain reserved; they are not automatically reused after delete.
type State struct {
	// RecipientSchema is sticky after the first explicit relay grant. Old
	// registries have no grants; older binaries must not silently drop them.
	RecipientSchema   int              `json:"recipient_schema,omitempty" yaml:"recipient_schema,omitempty"`
	Recipients        []RecipientGrant `json:"recipients,omitempty" yaml:"recipients,omitempty"`
	ReservedRelayKeys []string         `json:"reserved_relay_keys" yaml:"reserved_relay_keys"`
	ControllerID      string           `json:"controller_id" yaml:"controller_id"`
	Generation        uint64           `json:"generation" yaml:"generation"`
	IssuedAt          time.Time        `json:"issued_at" yaml:"issued_at"`
	ExpiresAt         time.Time        `json:"expires_at" yaml:"expires_at"`
	Spec              Spec             `json:"spec" yaml:"spec"`
	Bindings          []Binding        `json:"bindings" yaml:"bindings"`
	RetiredPathIDs    []string         `json:"retired_path_ids" yaml:"retired_path_ids"`
	RetiredRelayIDs   []string         `json:"retired_relay_ids" yaml:"retired_relay_ids"`
}

// RecipientGrant is an administrator-owned association, not a certificate role.
// Certificate renewal preserves it; identity removal deletes it atomically.
type RecipientGrant struct {
	RelayID     string `json:"relay_id" yaml:"relay_id"`
	PrincipalID string `json:"principal_id" yaml:"principal_id"`
}

type RecipientUpdate struct {
	ControllerID       string `json:"controller_id"`
	ExpectedGeneration uint64 `json:"expected_generation"`
	RelayID            string `json:"relay_id"`
	// Empty means withdraw. It is never inferred from the relay ID or key.
	PrincipalID string `json:"principal_id"`
}

// DeploymentView contains only bound, enabled paths assigned to this relay.
// Draining paths retain their existing bindings. It contains no grant list,
// retirement ledger, other relay descriptors or private keys.
type DeploymentView struct {
	SchemaVersion int       `json:"schema_version"`
	ControllerID  string    `json:"controller_id"`
	Generation    uint64    `json:"generation"`
	IssuedAt      time.Time `json:"issued_at"`
	ExpiresAt     time.Time `json:"expires_at"`
	PrincipalID   string    `json:"principal_id"`
	RelayID       string    `json:"relay_id"`
	Spec          Spec      `json:"spec"`
	Bindings      []Binding `json:"bindings"`
}
type Update struct {
	ControllerID       string `json:"controller_id"`
	ExpectedGeneration uint64 `json:"expected_generation"`
	TTLSeconds         int    `json:"ttl_seconds"`
	Spec               Spec   `json:"spec"`
}
type BindRequest struct {
	SchemaVersion      int    `json:"schema_version"`
	ControllerID       string `json:"controller_id"`
	ExpectedGeneration uint64 `json:"expected_generation"`
	NodeID             string `json:"node_id"`
	PathID             string `json:"path_id"`
	PublicKey          string `json:"public_key"`
}

// View contains only this node's approved paths, their relay/target descriptors,
// and active bindings. It never includes other nodes or the retirement ledger.
type View struct {
	ControllerID string    `json:"controller_id"`
	Generation   uint64    `json:"generation"`
	IssuedAt     time.Time `json:"issued_at"`
	ExpiresAt    time.Time `json:"expires_at"`
	NodeID       string    `json:"node_id"`
	Spec         Spec      `json:"spec"`
	Bindings     []Binding `json:"bindings"`
}

// Environment supplies the existing identity and legacy tunnel namespace.
// ReservedKeys includes existing node and controller WireGuard keys.
type Environment struct {
	VPNCIDR      string
	Nodes        map[string]bool
	ReservedKeys map[string]bool
}

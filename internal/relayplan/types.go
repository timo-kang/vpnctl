// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

// Package relayplan joins approved path bindings with current local IPv4
// inventory. It never installs routes, creates tunnels or claims packet health.
package relayplan

import (
	"context"
	"fmt"
	"net/netip"
	"regexp"
	"time"

	"gopkg.in/yaml.v3"
	"vpnctl/internal/relaycatalog"
)

const (
	MaxUnderlays   = 4
	MaxAddresses   = 16
	MaxInterfaces  = 128
	MaxOutputBytes = 64 << 10
	MaxDuration    = 20 * time.Second
	MaxAge         = 30 * time.Second
)

var identifier = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$`)

type Underlay struct {
	ID         string `json:"id" yaml:"id"`
	Interface  string `json:"interface" yaml:"interface"`
	Kind       string `json:"kind" yaml:"kind"`
	SourceIPv4 string `json:"source_ipv4,omitempty" yaml:"source_ipv4,omitempty"`
}

// Reject misspelled source constraints instead of silently falling back to
// automatic selection. Restrict this strict decoding to the new mapping type.
func (u *Underlay) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.MappingNode {
		return fmt.Errorf("relay underlay must be a mapping")
	}
	for i := 0; i < len(node.Content); i += 2 {
		switch node.Content[i].Value {
		case "id", "interface", "kind", "source_ipv4":
		default:
			return fmt.Errorf("unknown relay underlay field %q", node.Content[i].Value)
		}
	}
	type plain Underlay
	var value plain
	if e := node.Decode(&value); e != nil {
		return e
	}
	*u = Underlay(value)
	return nil
}

func usableIPv4(s string) bool {
	a, e := netip.ParseAddr(s)
	return e == nil && a.Is4() && a.String() == s && a.IsGlobalUnicast() && !a.IsLoopback() && !a.IsLinkLocalUnicast() && a.As4()[0] != 0 && a.As4()[0] < 224
}
func ValidateUnderlays(v []Underlay) error {
	if len(v) > MaxUnderlays {
		return fmt.Errorf("relay_underlays permits at most four devices")
	}
	ids, devices := map[string]bool{}, map[string]bool{}
	for _, u := range v {
		if !identifier.MatchString(u.ID) || !identifier.MatchString(u.Interface) || len(u.Interface) > 15 || ids[u.ID] || devices[u.Interface] {
			return fmt.Errorf("invalid or duplicate relay underlay ID/interface")
		}
		if u.Kind != "ethernet" && u.Kind != "wifi" && u.Kind != "lte" {
			return fmt.Errorf("relay underlay kind must be ethernet, wifi or lte")
		}
		if u.SourceIPv4 != "" && !usableIPv4(u.SourceIPv4) {
			return fmt.Errorf("relay underlay source_ipv4 must be a canonical unicast IPv4 address")
		}
		ids[u.ID], devices[u.Interface] = true, true
	}
	return nil
}

type Check struct {
	State  string `json:"state"`
	Reason string `json:"reason,omitempty"`
}

func unknown(reason string) Check { return Check{"unknown", reason} }
func down(reason string) Check    { return Check{"down", reason} }

type Route struct {
	Check
	Endpoint string `json:"endpoint"`
	Source   string `json:"source,omitempty"`
	Gateway  string `json:"gateway,omitempty"`
}
type Inventory struct {
	Underlay
	Check
	ObservedAt time.Time `json:"observed_at"`
	IfIndex    int       `json:"ifindex,omitempty"`
	Present    *bool     `json:"present"`
	AdminUp    *bool     `json:"admin_up"`
	Carrier    *bool     `json:"carrier"`
	Addresses  []string  `json:"ipv4_addresses"`
	DNS        Check     `json:"dns"`
	Modem      Check     `json:"modem"`
	Routes     []Route   `json:"routes"`
}

type Collector interface {
	Collect(context.Context, Underlay, []string) Inventory
}

// PinInput is a proposal for a later backend. Numeric resources are not reserved
// or checked against the kernel here. Apply MUST revalidate inventory, approval,
// all existing marks/masks/rules/tables/devices and its durable ownership journal.
type PinInput struct {
	Owner                  string `json:"owner"`
	WGInterface            string `json:"wg_interface"`
	FWMark                 uint32 `json:"fwmark"`
	Table                  uint32 `json:"table"`
	RulePriority           uint32 `json:"rule_priority"`
	EndpointPrefix         string `json:"endpoint_prefix"`
	Interface              string `json:"interface"`
	IfIndex                int    `json:"ifindex"`
	Source                 string `json:"source"`
	Gateway                string `json:"gateway,omitempty"`
	TerminalUnreachable    bool   `json:"terminal_unreachable"`
	RequiresOwnershipCheck bool   `json:"requires_ownership_check"`
}
type Candidate struct {
	PathID             string                `json:"path_id"`
	RelayID            string                `json:"relay_id"`
	UnderlayID         string                `json:"underlay_id"`
	Endpoint           string                `json:"endpoint"`
	RelayPublicKey     string                `json:"relay_public_key"`
	RelayKeyGeneration uint64                `json:"relay_key_generation"`
	PublicKey          string                `json:"public_key,omitempty"`
	InnerAddress       string                `json:"inner_address,omitempty"`
	Targets            []relaycatalog.Target `json:"targets"`
	Priority           int                   `json:"priority"`
	Cost               int                   `json:"cost"`
	State              string                `json:"state"`
	Reason             string                `json:"reason,omitempty"`
	Pin                *PinInput             `json:"pin,omitempty"`
}
type Plan struct {
	SchemaVersion int         `json:"schema_version"`
	ControllerID  string      `json:"controller_id,omitempty"`
	NodeID        string      `json:"node_id"`
	Generation    uint64      `json:"generation"`
	ObservedAt    time.Time   `json:"observed_at"`
	ValidUntil    time.Time   `json:"valid_until"`
	CacheValidity string      `json:"cache_validity"`
	State         string      `json:"state"`
	Reason        string      `json:"reason,omitempty"`
	Applied       bool        `json:"applied"`
	UplinkHealth  string      `json:"uplink_health"`
	Inventory     []Inventory `json:"inventory"`
	Paths         []Candidate `json:"paths"`
}

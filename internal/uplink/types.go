// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

// Package uplink observes network state without changing links, routes or modems.
// Collector and Prober are independent of the controller and deployment layout.
package uplink

import (
	"fmt"
	"math"
	"net"
	"regexp"
	"strconv"
	"time"
)

const (
	MaxLinks         = 8
	MaxTargets       = 4
	MaxSnapshotBytes = 32768
)

var identifier = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$`)

func ValidID(s string) bool { return identifier.MatchString(s) }

type Config struct {
	IntervalSec int            `yaml:"interval_sec"`
	TimeoutMS   int            `yaml:"timeout_ms"`
	Links       []LinkConfig   `yaml:"links"`
	Controller  *Endpoint      `yaml:"controller_probe,omitempty"`
	Targets     []TargetConfig `yaml:"targets"`
}
type LinkConfig struct {
	ID        string `yaml:"id"`
	Interface string `yaml:"interface"`
	Kind      string `yaml:"kind"`            // ethernet, wifi, lte
	Modem     string `yaml:"modem,omitempty"` // numeric ModemManager index, optional
}
type Endpoint struct {
	CAFile   string `yaml:"ca_file,omitempty"`
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	Protocol string `yaml:"protocol"` // tcp, tls, udp-echo
}

func (e Endpoint) Address() string { return net.JoinHostPort(e.Host, strconv.Itoa(e.Port)) }

type TargetConfig struct {
	ID         string `yaml:"id"`
	Endpoint   `yaml:",inline"`
	Interface  string    `yaml:"interface,omitempty"` // expected egress; empty permits kernel choice
	RelayID    string    `yaml:"relay_id,omitempty"`  // configured expectation, not routing proof
	RelayProbe *Endpoint `yaml:"relay_probe,omitempty"`
}

func (c *Config) Defaults() {
	if c.IntervalSec == 0 {
		c.IntervalSec = 60
	}
	if c.TimeoutMS == 0 {
		c.TimeoutMS = 1000
	}
}
func validInterface(s string) bool { return ValidID(s) && len(s) <= 15 }
func validateEndpoint(e Endpoint) error {
	if e.CAFile != "" && e.Protocol != "tls" {
		return fmt.Errorf("ca_file requires tls protocol")
	}
	if e.Host == "" || len(e.Host) > 253 || e.Port < 1 || e.Port > 65535 {
		return fmt.Errorf("invalid probe host/port")
	}
	for _, r := range e.Host {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '-' || r == ':') {
			return fmt.Errorf("probe host must be DNS name or unscoped IP")
		}
	}
	if e.Protocol != "tcp" && e.Protocol != "tls" && e.Protocol != "udp-echo" {
		return fmt.Errorf("probe protocol must be tcp, tls or udp-echo")
	}
	return nil
}
func (c Config) Validate() error {
	if c.IntervalSec < 30 || c.IntervalSec > 3600 || c.TimeoutMS < 100 || c.TimeoutMS > 5000 {
		return fmt.Errorf("uplink interval must be 30..3600s and timeout 100..5000ms")
	}
	if len(c.Links) < 1 || len(c.Links) > MaxLinks || len(c.Targets) < 1 || len(c.Targets) > MaxTargets {
		return fmt.Errorf("uplink requires 1..8 links and 1..4 targets")
	}
	ids, interfaces := map[string]bool{}, map[string]bool{}
	for _, l := range c.Links {
		if !ValidID(l.ID) || !validInterface(l.Interface) || ids[l.ID] || interfaces[l.Interface] {
			return fmt.Errorf("invalid or duplicate uplink identity/interface")
		}
		ids[l.ID], interfaces[l.Interface] = true, true
		if l.Kind != "ethernet" && l.Kind != "wifi" && l.Kind != "lte" {
			return fmt.Errorf("unsupported uplink kind")
		}
		if l.Modem != "" {
			if _, e := strconv.ParseUint(l.Modem, 10, 32); e != nil || l.Kind != "lte" {
				return fmt.Errorf("modem must be an LTE numeric ModemManager index")
			}
		}
	}
	ids = map[string]bool{}
	for _, t := range c.Targets {
		if !ValidID(t.ID) || ids[t.ID] || t.Interface != "" && !validInterface(t.Interface) || t.RelayID != "" && !ValidID(t.RelayID) {
			return fmt.Errorf("invalid or duplicate target identity/interface")
		}
		ids[t.ID] = true
		if e := validateEndpoint(t.Endpoint); e != nil {
			return e
		}
		if t.RelayProbe != nil {
			if t.Interface == "" || t.RelayID == "" {
				return fmt.Errorf("relay probe requires interface and relay_id")
			}
			if e := validateEndpoint(*t.RelayProbe); e != nil {
				return e
			}
		}
	}
	if c.Controller != nil {
		return validateEndpoint(*c.Controller)
	}
	return nil
}

// State is unknown, up or down. Unknown is never counted as a failed attempt.
type Check struct {
	State  string   `json:"state"`
	Reason string   `json:"reason,omitempty"`
	RTTMs  *float64 `json:"rtt_ms,omitempty"`
}

func Unknown(reason string) Check { return Check{State: "unknown", Reason: reason} }
func Down(reason string) Check    { return Check{State: "down", Reason: reason} }
func Up() Check                   { return Check{State: "up"} }

type Link struct {
	ID        string `json:"id"`
	Interface string `json:"interface"`
	Kind      string `json:"kind"`
	Check
	Present         *bool    `json:"present"`
	Modem           Check    `json:"modem"`
	Addresses       []string `json:"addresses,omitempty"`
	Gateways        []string `json:"gateways,omitempty"`
	GatewayState    Check    `json:"gateway_state"`
	DNS             Check    `json:"dns"` // resolver configuration presence, not DNS availability
	Controller      Check    `json:"controller"`
	ControllerRoute Route    `json:"controller_route"`
}
type Route struct {
	Check
	Interface   string `json:"interface,omitempty"`
	Source      string `json:"source,omitempty"`
	Gateway     string `json:"gateway,omitempty"`
	Destination string `json:"destination,omitempty"`
}
type Target struct {
	TransportRoute       Route  `json:"transport_route"`
	RelayPeerFingerprint string `json:"relay_peer_fingerprint,omitempty"`
	ID                   string `json:"id"`
	Protocol             string `json:"protocol"`
	ExpectedRelayID      string `json:"expected_relay_id,omitempty"`
	Route                Route  `json:"route"`
	Relay                Check  `json:"relay"`
	Service              Check  `json:"service"`
	FailureStage         string `json:"failure_stage"` // earliest evidenced failure; not necessarily root cause
}
type Snapshot struct {
	ID          string    `json:"id"`
	At          time.Time `json:"at"` // cycle completion
	IntervalSec int       `json:"interval_sec"`
	Underlay    Check     `json:"underlay"`
	Links       []Link    `json:"links"`
	Targets     []Target  `json:"targets"`
	Dropped     uint64    `json:"dropped"` // cumulative unsubmitted snapshots discarded in this process
	Stale       bool      `json:"stale"`
}

func (s Snapshot) Fresh(now time.Time) Snapshot {
	s.Stale = now.Before(s.At) || now.Sub(s.At) >= time.Duration(s.IntervalSec*3)*time.Second
	return s
}
func (s Snapshot) Validate(now time.Time) error {
	if !ValidID(s.ID) || s.At.IsZero() || s.At.After(now) || !s.At.After(now.Add(-7*24*time.Hour)) || s.IntervalSec < 30 || s.IntervalSec > 3600 || len(s.Links) < 1 || len(s.Links) > MaxLinks || len(s.Targets) < 1 || len(s.Targets) > MaxTargets || s.Stale {
		return fmt.Errorf("invalid uplink snapshot")
	}
	check := func(c Check) bool {
		return (c.State == "unknown" || c.State == "up" || c.State == "down") && (c.Reason == "" || ValidID(c.Reason)) && (c.RTTMs == nil || c.State == "up" && *c.RTTMs >= 0 && *c.RTTMs <= 60000 && !math.IsNaN(*c.RTTMs) && !math.IsInf(*c.RTTMs, 0))
	}
	route := func(r Route) bool {
		return check(r.Check) && (r.Interface == "" || validInterface(r.Interface)) && (r.Source == "" || net.ParseIP(r.Source) != nil) && (r.Gateway == "" || net.ParseIP(r.Gateway) != nil) && (r.Destination == "" || net.ParseIP(r.Destination) != nil)
	}
	if !check(s.Underlay) {
		return fmt.Errorf("invalid underlay")
	}
	ids := map[string]bool{}
	for _, l := range s.Links {
		if !ValidID(l.ID) || ids[l.ID] || !validInterface(l.Interface) || !check(l.Check) || !check(l.Modem) || !check(l.DNS) || !check(l.GatewayState) || !check(l.Controller) || !route(l.ControllerRoute) || (l.Kind != "ethernet" && l.Kind != "wifi" && l.Kind != "lte") || len(l.Addresses) > 16 || len(l.Gateways) > 16 {
			return fmt.Errorf("invalid link")
		}
		ids[l.ID] = true
		for _, a := range l.Addresses {
			if _, _, e := net.ParseCIDR(a); e != nil {
				return fmt.Errorf("invalid link IP")
			}
		}
		for _, a := range l.Gateways {
			if net.ParseIP(a) == nil {
				return fmt.Errorf("invalid gateway")
			}
		}
	}
	ids = map[string]bool{}
	for _, t := range s.Targets {
		if !ValidID(t.ID) || ids[t.ID] || t.ExpectedRelayID != "" && !ValidID(t.ExpectedRelayID) || !route(t.Route) || !route(t.TransportRoute) || t.RelayPeerFingerprint != "" && !ValidID(t.RelayPeerFingerprint) || !check(t.Relay) || !check(t.Service) || t.Service.State == "up" && t.Service.RTTMs == nil || (t.Protocol != "tcp" && t.Protocol != "tls" && t.Protocol != "udp-echo") {
			return fmt.Errorf("invalid target")
		}
		ids[t.ID] = true
		switch t.FailureStage {
		case "none", "underlay", "controller", "relay_tunnel", "overlay_route", "server_endpoint", "unknown":
		default:
			return fmt.Errorf("invalid failure stage")
		}
	}
	return nil
}

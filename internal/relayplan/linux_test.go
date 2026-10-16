// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayplan

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func linkJSON(l linkRecord) []byte { b, _ := json.Marshal([]linkRecord{l}); return b }
func validLink() linkRecord {
	return linkRecord{Index: 7, Name: "wan0", Flags: []string{"UP", "LOWER_UP"}, OperState: "UP", Addresses: []addressRecord{{Family: "inet", Local: "192.0.2.10", PrefixLen: 24, Scope: "global"}}}
}
func TestLinuxInventoryStatesAndChanges(t *testing.T) {
	for _, tc := range []struct {
		name, state, reason string
		link                func(*linkRecord)
		after               func(*linkRecord)
		raw                 string
		readErr             error
		source              string
		route               string
	}{
		{name: "connected-no-default", state: "up"},
		{name: "gateway", state: "up", route: `[{"dev":"wan0","dst":"192.0.2.1","from":"192.0.2.10","gateway":"192.0.2.254"}]`},
		{name: "absent", state: "down", reason: "interface_absent", raw: `[]`},
		{name: "incomplete-list", state: "unknown", reason: "collector_unavailable", raw: `[{}]`},
		{name: "null", state: "unknown", reason: "collector_unavailable", raw: `null`},
		{name: "permission", state: "unknown", reason: "collector_unavailable", readErr: errors.New("denied")},
		{name: "malformed", state: "unknown", reason: "collector_unavailable", raw: `not json`},
		{name: "oversized", state: "unknown", reason: "collector_unavailable", raw: strings.Repeat(" ", MaxOutputBytes+1)},
		{name: "down", state: "down", reason: "link_down", link: func(l *linkRecord) { l.Flags = []string{"UP"} }},
		{name: "IPv6-only", state: "down", reason: "no_ipv4", link: func(l *linkRecord) {
			l.Addresses = []addressRecord{{Family: "inet6", Local: "2001:db8::1", PrefixLen: 64, Scope: "global"}}
		}},
		{name: "malformed-address", state: "unknown", reason: "address_inventory_invalid", link: func(l *linkRecord) { l.Addresses[0].Local = "broken" }},
		{name: "too-many-addresses", state: "unknown", reason: "collector_unavailable", link: func(l *linkRecord) { l.Addresses = make([]addressRecord, 17) }},
		{name: "ambiguous", state: "unknown", reason: "source_ambiguous", link: func(l *linkRecord) { a := l.Addresses[0]; a.Local = "192.0.2.20"; l.Addresses = append(l.Addresses, a) }},
		{name: "selected", state: "up", source: "192.0.2.10", link: func(l *linkRecord) { a := l.Addresses[0]; a.Local = "192.0.2.20"; l.Addresses = append(l.Addresses, a) }},
		{name: "missing-source", state: "down", reason: "source_absent", source: "192.0.2.50"},
		{name: "prefix-change", state: "unknown", reason: "inventory_changed", after: func(l *linkRecord) { l.Addresses[0].PrefixLen = 16 }},
		{name: "recreated", state: "unknown", reason: "inventory_changed", after: func(l *linkRecord) { l.Index++ }},
		{name: "renamed", state: "unknown", reason: "inventory_changed", after: func(l *linkRecord) { l.Name = "new0" }},
		{name: "address-change", state: "unknown", reason: "inventory_changed", after: func(l *linkRecord) { l.Addresses[0].Local = "192.0.2.20" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reads := 0
			l := validLink()
			if tc.link != nil {
				tc.link(&l)
			}
			c := LinuxCollector{ReadIP: func(ctx context.Context, args ...string) ([]byte, error) {
				if slices.Equal(args, []string{"-j", "link", "show"}) {
					if tc.readErr != nil {
						return nil, tc.readErr
					}
					return linkJSON(l), nil
				}
				if slices.Contains(args, "address") {
					reads++
					if tc.readErr != nil {
						return nil, tc.readErr
					}
					if tc.raw != "" {
						return []byte(tc.raw), nil
					}
					if reads > 1 && tc.after != nil {
						tc.after(&l)
					}
					return linkJSON(l), nil
				}
				if !slices.Equal(args, []string{"-j", "-4", "route", "get", "192.0.2.1", "from", "192.0.2.10", "oif", "wan0"}) {
					t.Fatal("lookup not constrained", args)
				}
				raw := tc.route
				if raw == "" {
					raw = `[{"dev":"wan0","dst":"192.0.2.1","from":"192.0.2.10"}]`
				}
				return []byte(raw), nil
			}}
			v := c.Collect(context.Background(), Underlay{ID: "lan", Interface: "wan0", Kind: "ethernet", SourceIPv4: tc.source}, []string{"192.0.2.1:51820"})
			if v.State != tc.state || v.Reason != tc.reason {
				t.Fatalf("%+v", v)
			}
			if tc.state == "up" && (len(v.Routes) != 1 || v.Routes[0].State != "up") {
				t.Fatal(v.Routes)
			}
		})
	}
}
func TestLinuxInventoryRejectsUntrustedRoutes(t *testing.T) {
	for _, tc := range []struct {
		raw   string
		err   error
		state string
	}{
		{raw: `[{"dev":"other","dst":"192.0.2.1","from":"192.0.2.10"}]`, state: "unknown"},
		{raw: `[{"dev":"wan0","dst":"192.0.2.1","from":"192.0.2.99"}]`, state: "unknown"},
		{raw: `[{"dev":"wan0","dst":"192.0.2.1","from":"192.0.2.10","type":"blackhole"}]`, state: "unknown"},
		{raw: `null`, state: "unknown"}, {raw: `[]`, state: "unknown"}, {raw: `[{},{}]`, state: "unknown"},
		{raw: strings.Repeat("x", MaxOutputBytes+1), state: "unknown"}, {err: errNoRoute, state: "down"}, {err: context.DeadlineExceeded, state: "unknown"},
	} {
		c := LinuxCollector{ReadIP: func(_ context.Context, args ...string) ([]byte, error) {
			if slices.Contains(args, "address") {
				return linkJSON(validLink()), nil
			}
			return []byte(tc.raw), tc.err
		}}
		v := c.Collect(context.Background(), Underlay{ID: "lan", Interface: "wan0", Kind: "ethernet"}, []string{"192.0.2.1:51820"})
		if len(v.Routes) != 1 || v.Routes[0].State != tc.state {
			t.Fatal(v)
		}
	}
	b := &cappedBuffer{limit: 3}
	if _, e := b.Write([]byte("abcd")); !errors.Is(e, errOutputLimit) || b.Len() != 0 {
		t.Fatal("output limit not enforced")
	}
}

// Test the production subprocess boundary, not just an already bounded mock.
func TestInventoryProcessLimits(t *testing.T) {
	for _, script := range []string{
		"#!/bin/sh\nhead -c 70000 /dev/zero\n",
		"#!/bin/sh\nhead -c 5000 /dev/zero >&2\nexit 1\n",
		"#!/bin/sh\nsleep 10\n",
	} {
		dir := t.TempDir()
		if e := os.WriteFile(filepath.Join(dir, "ip"), []byte(script), 0700); e != nil {
			t.Fatal(e)
		}
		t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		began := time.Now()
		b, e := readIP(ctx, "-j", "address", "show")
		cancel()
		if e == nil || len(b) != 0 || time.Since(began) > time.Second {
			t.Fatal("unbounded command", len(b), e, time.Since(began))
		}
	}
}

// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package wireguard

import (
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

// sameSetConf proves that a rendered configuration already matches the live
// device. Read the device each time rather than caching successful writes: a
// removed interface, operator change or failed apply must still be repaired.
// Unspecified peer endpoints are learned by WireGuard and must be preserved.
func sameSetConf(desired, current string) bool {
	want, ok := parseSetConf(desired)
	if !ok {
		return false
	}
	have, ok := parseSetConf(current)
	if !ok || len(want) != len(have) {
		return false
	}
	for section, fields := range want {
		existing, ok := have[section]
		if !ok {
			return false
		}
		if section == "interface" && fields["ListenPort"] == "" && existing["ListenPort"] != "" {
			// An omitted listen port asks the kernel to retain/allocate its own port.
			// Reapplying unchanged AllowedIPs on every retry can drop in-flight packets.
			port, err := strconv.Atoi(existing["ListenPort"])
			if err != nil || port < 1 || port > 65535 {
				return false
			}
			delete(existing, "ListenPort")
		}
		if section != "interface" && fields["Endpoint"] == "" {
			delete(existing, "Endpoint")
		}
		if len(fields) != len(existing) {
			return false
		}
		for key, value := range fields {
			if existing[key] != value {
				return false
			}
		}
	}
	return true
}

func parseSetConf(text string) (map[string]map[string]string, bool) {
	sections := make(map[string]map[string]string)
	var fields map[string]string
	peer := false
	finish := func() bool {
		if fields == nil {
			return true
		}
		name := "interface"
		if peer {
			name = fields["PublicKey"]
			if name == "" || name == "interface" {
				return false
			}
		}
		if _, duplicate := sections[name]; duplicate {
			return false
		}
		sections[name] = fields
		return true
	}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if line == "[Interface]" || line == "[Peer]" {
			if !finish() {
				return nil, false
			}
			fields = make(map[string]string)
			peer = line == "[Peer]"
			continue
		}
		if fields == nil {
			return nil, false
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return nil, false
		}
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		if key == "" || value == "" {
			return nil, false
		}
		if _, duplicate := fields[key]; duplicate {
			return nil, false
		}
		if key == "AllowedIPs" {
			var prefixes []string
			for _, part := range strings.Split(value, ",") {
				prefix, err := netip.ParsePrefix(strings.TrimSpace(part))
				if err != nil {
					return nil, false
				}
				prefixes = append(prefixes, prefix.Masked().String())
			}
			slices.Sort(prefixes)
			value = strings.Join(prefixes, ",")
		}
		fields[key] = value
	}
	if !finish() {
		return nil, false
	}
	if _, ok := sections["interface"]; !ok {
		return nil, false
	}
	return sections, true
}

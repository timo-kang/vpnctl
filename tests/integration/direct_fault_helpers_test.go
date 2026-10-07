//go:build integration

// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package integration

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

func directFaultMode(raw string) (string, error) {
	switch raw {
	case "", "outer-wg":
		return "outer-wg", nil
	case "inner-nonce":
		return raw, nil
	default:
		return "", errors.New("direct fault must be outer-wg or inner-nonce")
	}
}

func directFaultRules(mode, peer string) (string, error) {
	address, err := netip.ParseAddr(peer)
	if err != nil || !address.Is4() {
		return "", errors.New("direct fault requires an IPv4 peer address")
	}
	if mode == "outer-wg" {
		return fmt.Sprintf("table inet direct_fault {\n chain output {\n type filter hook output priority 0; policy accept;\n ip daddr %s udp dport 51820 drop\n }\n}\n", peer), nil
	}
	if mode != "inner-nonce" {
		return "", errors.New("unsupported direct fault")
	}
	// WireGuard type 4 has a 16-byte header and a 16-byte AEAD tag. An
	// authenticated empty keepalive therefore has UDP length 8+16+16=40.
	// Drop only nonempty encrypted transport between these two endpoints:
	// handshake/cookie/empty messages and the hub's relay traffic still pass.
	// A plaintext wg0 filter would also drop fallback through that same device.
	// Format: https://www.wireguard.com/protocol/#subsequent-messages-exchange-of-data-packets
	return fmt.Sprintf(`table inet direct_fault {
 counter payload_drop { }
 counter keepalive_tx { }
 counter keepalive_rx { }
 counter handshake_rx { }
 chain output {
  type filter hook output priority 0; policy accept;
  ip daddr %[1]s udp dport 51820 @th,64,32 0x04000000 udp length > 40 counter name payload_drop drop
  ip daddr %[1]s udp dport 51820 @th,64,32 0x04000000 udp length 40 counter name keepalive_tx
 }
 chain input {
  type filter hook input priority 0; policy accept;
  ip saddr %[1]s udp sport 51820 udp dport 51820 @th,64,32 0x04000000 udp length 40 counter name keepalive_rx
  ip saddr %[1]s udp sport 51820 udp dport 51820 @th,64,8 { 1, 2 } counter name handshake_rx
 }
}
`, peer), nil
}

type directTransportEvidence struct {
	Handshake int64  `json:"handshake_unix"`
	RX        uint64 `json:"rx_bytes"`
	TX        uint64 `json:"tx_bytes"`
}

// Parse only public wg subcommands; no private-key dump is captured or exported.
func directTransportSummary(key, handshakes, transfers string) (directTransportEvidence, error) {
	var out directTransportEvidence
	seen := 0
	for _, line := range strings.Split(handshakes, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != key {
			continue
		}
		if len(fields) != 2 || seen != 0 {
			return out, errors.New("ambiguous direct handshake evidence")
		}
		var err error
		out.Handshake, err = strconv.ParseInt(fields[1], 10, 64)
		if err != nil || out.Handshake <= 0 {
			return out, errors.New("direct handshake not observed")
		}
		seen++
	}
	for _, line := range strings.Split(transfers, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != key {
			continue
		}
		if len(fields) != 3 || seen != 1 {
			return out, errors.New("ambiguous direct transfer evidence")
		}
		var e1, e2 error
		out.RX, e1 = strconv.ParseUint(fields[1], 10, 64)
		out.TX, e2 = strconv.ParseUint(fields[2], 10, 64)
		if e1 != nil || e2 != nil || out.RX == 0 || out.TX == 0 {
			return out, errors.New("authenticated direct transport not observed")
		}
		seen++
	}
	if seen != 2 {
		return out, errors.New("current direct peer evidence missing")
	}
	return out, nil
}

func directFaultCounters(raw []byte) (map[string]uint64, error) {
	var wire struct {
		Rows []struct {
			Counter *struct {
				Family  string  `json:"family"`
				Table   string  `json:"table"`
				Name    string  `json:"name"`
				Packets *uint64 `json:"packets"`
			} `json:"counter"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(raw, &wire); err != nil {
		return nil, errors.New("invalid direct fault counter inventory")
	}
	out := map[string]uint64{}
	for _, row := range wire.Rows {
		counter := row.Counter
		if counter == nil || counter.Family != "inet" || counter.Table != "direct_fault" {
			continue
		}
		switch counter.Name {
		case "payload_drop", "keepalive_tx", "keepalive_rx", "handshake_rx":
		default:
			return nil, errors.New("unexpected direct fault counter")
		}
		if _, exists := out[counter.Name]; exists || counter.Packets == nil || *counter.Packets == 0 {
			return nil, errors.New("direct payload/keepalive/handshake counter missing or ambiguous")
		}
		out[counter.Name] = *counter.Packets
	}
	if len(out) != 4 {
		return nil, errors.New("incomplete direct fault counter evidence")
	}
	return out, nil
}

func directSocketDiagnostic(read func(string) ([]byte, error)) map[string]any {
	// This limit is global on kernels that do not expose it inside netns.
	// It is optional diagnostic evidence, not a dataplane success condition.
	value, err := read("/proc/sys/net/core/wmem_max")
	out := map[string]any{"scope": "kernel_global", "available": err == nil}
	if err != nil {
		out["error"] = err.Error()
	} else {
		out["value"] = strings.TrimSpace(string(value))
	}
	return out
}

// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayapply

import (
	"errors"
	"math"
	"net/netip"
	"strings"
)

// kernelPrefix decodes the IPv4 public inventory used for foreign conflict
// checks. iproute2 can emit CIDR strings or a bare address with a separate
// srclen/dstlen. Ambiguous selectors must remain possible conflicts; this
// parser grants no ownership of the containing rule or route.
func kernelPrefix(o object, key string) (netip.Prefix, error) {
	invalid := errors.New("ambiguous IPv4 kernel prefix")
	raw := ""
	if value, exists := o[key]; exists {
		var ok bool
		raw, ok = value.(string)
		if !ok {
			return netip.Prefix{}, invalid
		}
	}
	bits := -1
	if value, exists := o[key+"len"]; exists {
		// kernel.list uses encoding/json's default numeric representation.
		// Reject strings and fractional/out-of-range values instead of
		// coercing a malformed inventory into a narrower, nonmatching host.
		n, ok := value.(float64)
		if !ok || math.IsNaN(n) || n < 0 || n > 32 || math.Trunc(n) != n {
			return netip.Prefix{}, invalid
		}
		bits = int(n)
	}
	if raw == "" || raw == "all" || raw == "default" {
		if bits > 0 {
			return netip.Prefix{}, invalid
		}
		return netip.PrefixFrom(netip.IPv4Unspecified(), 0), nil
	}
	if strings.Contains(raw, "/") {
		p, err := netip.ParsePrefix(raw)
		if err != nil || !p.Addr().Is4() || bits >= 0 && p.Bits() != bits {
			return netip.Prefix{}, invalid
		}
		return p.Masked(), nil
	}
	addr, err := netip.ParseAddr(raw)
	if err != nil || !addr.Is4() {
		return netip.Prefix{}, invalid
	}
	if bits < 0 {
		bits = 32
	}
	return netip.PrefixFrom(addr, bits).Masked(), nil
}

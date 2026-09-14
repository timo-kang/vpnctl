// Copyright 2025 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"fmt"
	"net/netip"
	"strings"

	"vpnctl/internal/store"
)

const maxIPAMPoolSize = 1_048_576

type ipReservation struct {
	prefix netip.Prefix
	reason string
}

type ipam struct {
	prefix       netip.Prefix
	reservations []ipReservation
}

func newIPAM(cidr, controllerAddress string, configuredReservations []string) (*ipam, error) {
	if cidr == "" {
		if controllerAddress != "" || len(configuredReservations) != 0 {
			return nil, fmt.Errorf("vpn_cidr is required when wg_address or reserved_vpn_ips is configured")
		}
		return nil, nil
	}
	prefix, err := parseIPv4Prefix(cidr, "vpn_cidr")
	if err != nil {
		return nil, err
	}
	if prefix != prefix.Masked() {
		return nil, fmt.Errorf("vpn_cidr %q must be a network prefix", cidr)
	}

	allocator := &ipam{prefix: prefix}
	if controllerAddress != "" {
		addr, err := parseHostAddress(controllerAddress)
		if err != nil {
			return nil, fmt.Errorf("wg_address %q: %w", controllerAddress, err)
		}
		if !prefix.Contains(addr) {
			return nil, fmt.Errorf("wg_address %s is outside vpn_cidr %s", addr, prefix)
		}
		if allocator.isNetworkOrBroadcast(addr) {
			return nil, fmt.Errorf("wg_address %s is not a usable host address in %s", addr, prefix)
		}
		allocator.reservations = append(allocator.reservations, ipReservation{
			prefix: netip.PrefixFrom(addr, 32),
			reason: "controller wg_address",
		})
	}

	for index, value := range configuredReservations {
		reservation, err := parseReservation(value)
		if err != nil {
			return nil, fmt.Errorf("reserved_vpn_ips[%d] %q: %w", index, value, err)
		}
		if !prefixContainsPrefix(prefix, reservation) {
			return nil, fmt.Errorf("reserved_vpn_ips[%d] %s is outside vpn_cidr %s", index, reservation, prefix)
		}
		allocator.reservations = append(allocator.reservations, ipReservation{
			prefix: reservation,
			reason: fmt.Sprintf("reserved_vpn_ips[%d]", index),
		})
	}
	return allocator, nil
}

func parseIPv4Prefix(value, field string) (netip.Prefix, error) {
	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("%s must be a valid CIDR: %w", field, err)
	}
	if !prefix.Addr().Is4() {
		return netip.Prefix{}, fmt.Errorf("%s must be IPv4", field)
	}
	return prefix, nil
}

func parseHostAddress(value string) (netip.Addr, error) {
	if strings.Contains(value, "/") {
		prefix, err := parseIPv4Prefix(value, "address")
		if err != nil {
			return netip.Addr{}, err
		}
		return prefix.Addr(), nil
	}
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("must be a valid IPv4 address: %w", err)
	}
	if !addr.Is4() {
		return netip.Addr{}, fmt.Errorf("must be IPv4")
	}
	return addr, nil
}

func parseReservation(value string) (netip.Prefix, error) {
	if strings.Contains(value, "/") {
		prefix, err := parseIPv4Prefix(value, "reservation")
		if err != nil {
			return netip.Prefix{}, err
		}
		if prefix != prefix.Masked() {
			return netip.Prefix{}, fmt.Errorf("CIDR must be a network prefix")
		}
		return prefix, nil
	}
	addr, err := parseHostAddress(value)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(addr, 32), nil
}

func parseLease(value string) (netip.Addr, error) {
	if strings.Contains(value, "/") {
		prefix, err := parseIPv4Prefix(value, "vpn_ip")
		if err != nil {
			return netip.Addr{}, err
		}
		if prefix.Bits() != 32 {
			return netip.Addr{}, fmt.Errorf("vpn_ip must be an IPv4 host address with a /32 prefix")
		}
		return prefix.Addr(), nil
	}
	return parseHostAddress(value)
}

func prefixContainsPrefix(outer, inner netip.Prefix) bool {
	if !outer.Contains(inner.Addr()) {
		return false
	}
	return outer.Contains(lastIPv4(inner))
}

func lastIPv4(prefix netip.Prefix) netip.Addr {
	hostBits := uint(32 - prefix.Bits())
	size := uint64(1) << hostBits
	return addIPv4(prefix.Masked().Addr(), uint32(size-1))
}

func (i *ipam) isNetworkOrBroadcast(addr netip.Addr) bool {
	return addr == i.prefix.Masked().Addr() || addr == lastIPv4(i.prefix)
}

func (i *ipam) reservationReason(addr netip.Addr) string {
	for _, reservation := range i.reservations {
		if reservation.prefix.Contains(addr) {
			return reservation.reason
		}
	}
	return ""
}

func (i *ipam) validateAddress(addr netip.Addr, nodeID string, reg *store.Registry) error {
	if !i.prefix.Contains(addr) {
		return fmt.Errorf("vpn_ip %s is outside vpn_cidr %s", addr, i.prefix)
	}
	if i.isNetworkOrBroadcast(addr) {
		return fmt.Errorf("vpn_ip %s is a network or broadcast address in %s", addr, i.prefix)
	}
	if reason := i.reservationReason(addr); reason != "" {
		return fmt.Errorf("vpn_ip %s is reserved by %s", addr, reason)
	}
	for _, node := range reg.Nodes {
		if node.VPNIP == "" || node.ID == nodeID {
			continue
		}
		used, err := parseLease(node.VPNIP)
		if err != nil {
			return fmt.Errorf("registry node %q has invalid vpn_ip %q: %w", node.ID, node.VPNIP, err)
		}
		if used == addr {
			return fmt.Errorf("vpn_ip %s is already leased to node %q", addr, node.ID)
		}
	}
	return nil
}

func (i *ipam) lease(nodeID, requested string, reg *store.Registry) (string, error) {
	if i == nil {
		return "", fmt.Errorf("vpn_cidr is required for address allocation")
	}

	for _, node := range reg.Nodes {
		if node.ID != nodeID || node.VPNIP == "" {
			continue
		}
		current, err := parseLease(node.VPNIP)
		if err != nil {
			return "", fmt.Errorf("existing lease for node %q is invalid: %w", nodeID, err)
		}
		if requested != "" {
			candidate, err := parseLease(requested)
			if err != nil {
				return "", err
			}
			if candidate != current {
				return "", fmt.Errorf("node %q already owns vpn_ip %s; remove the lease before changing it", nodeID, current)
			}
		}
		if err := i.validateAddress(current, nodeID, reg); err != nil {
			return "", err
		}
		return current.String() + "/32", nil
	}

	if requested != "" {
		addr, err := parseLease(requested)
		if err != nil {
			return "", err
		}
		if err := i.validateAddress(addr, nodeID, reg); err != nil {
			return "", err
		}
		return addr.String() + "/32", nil
	}

	hostBits := uint(32 - i.prefix.Bits())
	size := uint64(1) << hostBits
	if size > maxIPAMPoolSize {
		return "", fmt.Errorf("vpn_cidr %s is too large (size=%d)", i.prefix, size)
	}
	used := make(map[netip.Addr]struct{}, len(reg.Nodes))
	for _, node := range reg.Nodes {
		if node.VPNIP == "" {
			continue
		}
		addr, err := parseLease(node.VPNIP)
		if err != nil {
			return "", fmt.Errorf("registry node %q has invalid vpn_ip %q: %w", node.ID, node.VPNIP, err)
		}
		used[addr] = struct{}{}
	}
	for offset := uint64(1); offset+1 < size; offset++ {
		addr := addIPv4(i.prefix.Masked().Addr(), uint32(offset))
		if _, occupied := used[addr]; occupied {
			continue
		}
		if i.reservationReason(addr) != "" {
			continue
		}
		return addr.String() + "/32", nil
	}
	return "", fmt.Errorf("no available vpn_ip in %s", i.prefix)
}

func (i *ipam) validateAndNormalizeRegistry(reg *store.Registry) (bool, error) {
	if reg == nil {
		return false, nil
	}
	if i == nil {
		for _, node := range reg.Nodes {
			if node.VPNIP != "" {
				return false, fmt.Errorf("vpn_cidr is required to validate existing node %q", node.ID)
			}
		}
		return false, nil
	}

	owners := make(map[netip.Addr]string, len(reg.Nodes))
	identities := make(map[string]int, len(reg.Nodes))
	changed := false
	for index := range reg.Nodes {
		node := &reg.Nodes[index]
		if node.ID == "" {
			if node.VPNIP != "" {
				return false, fmt.Errorf("registry node at index %d has vpn_ip %q but no node ID", index, node.VPNIP)
			}
		} else if previousIndex, duplicate := identities[node.ID]; duplicate {
			return false, fmt.Errorf("node ID %q appears more than once (indexes %d and %d)", node.ID, previousIndex, index)
		} else {
			identities[node.ID] = index
		}
		if node.VPNIP == "" {
			continue
		}
		addr, err := parseLease(node.VPNIP)
		if err != nil {
			return false, fmt.Errorf("node %q has invalid vpn_ip %q: %w", node.ID, node.VPNIP, err)
		}
		if !i.prefix.Contains(addr) {
			return false, fmt.Errorf("node %q vpn_ip %s is outside vpn_cidr %s", node.ID, addr, i.prefix)
		}
		if i.isNetworkOrBroadcast(addr) {
			return false, fmt.Errorf("node %q vpn_ip %s is a network or broadcast address", node.ID, addr)
		}
		if reason := i.reservationReason(addr); reason != "" {
			return false, fmt.Errorf("node %q vpn_ip %s conflicts with %s", node.ID, addr, reason)
		}
		if owner, duplicate := owners[addr]; duplicate {
			return false, fmt.Errorf("vpn_ip %s is assigned to both node %q and node %q", addr, owner, node.ID)
		}
		owners[addr] = node.ID
		canonical := addr.String() + "/32"
		if node.VPNIP != canonical {
			node.VPNIP = canonical
			changed = true
		}
	}
	return changed, nil
}

func addIPv4(base netip.Addr, offset uint32) netip.Addr {
	value := base.As4()
	number := uint32(value[0])<<24 | uint32(value[1])<<16 | uint32(value[2])<<8 | uint32(value[3])
	number += offset
	return netip.AddrFrom4([4]byte{byte(number >> 24), byte(number >> 16), byte(number >> 8), byte(number)})
}

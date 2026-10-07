//go:build integration

// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package integration

import (
	"os"
	"testing"
)

// The guarded guest agent selects one existing dataplane profile per VM. Keep
// the original integration entry point and its deadlines unchanged.
func TestVMDirectDataplane(t *testing.T) {
	if os.Getenv("VPNCTL_VM_DIRECT") != "1" {
		t.Skip("requires disposable direct VM runner")
	}
	requireIsolatedGuest(t) // No network or filesystem mutation before this gate.
	if os.Getenv("VPNCTL_VM_WORKER") != "1" {
		t.Fatal("explicit disposable VM worker required")
	}
	switch os.Getenv("VPNCTL_DIRECT_SIZES") {
	case "2", "3", "8", "32":
	default:
		t.Fatal("one explicit direct node count (2, 3, 8, 32) required")
	}
	if _, err := directFaultMode(os.Getenv("VPNCTL_DIRECT_FAULT")); err != nil {
		t.Fatal(err)
	}
	TestNetns_DirectDataplane(t)
}

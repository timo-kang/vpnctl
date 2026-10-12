// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package relayplan

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The fake records only that a child was started. It never reads arguments,
// configuration, addresses, or routes, and cannot execute the real ip command.
func forbidNativeInventoryIP(t *testing.T) func() {
	t.Helper()
	dir := t.TempDir()
	marker := filepath.Join(dir, "ip-invoked")
	script := "#!/bin/sh\n: > \"$VPNCTL_NATIVE_TEST_IP_MARKER\"\nexit 99\n"
	if err := os.WriteFile(filepath.Join(dir, "ip"), []byte(script), 0700); err != nil {
		t.Fatal("could not create isolated ip detector")
	}
	t.Setenv("VPNCTL_NATIVE_TEST_IP_MARKER", marker)
	t.Setenv("PATH", dir)
	return func() {
		t.Helper()
		if _, err := os.Stat(marker); err == nil {
			t.Error("link/address collection started an external ip process")
		} else if !errors.Is(err, os.ErrNotExist) {
			t.Error("could not verify ip detector")
		}
	}
}

func TestNativeInventoryLoopbackWithoutIPProcess(t *testing.T) {
	// This is an independent, read-only oracle for identity and administrative
	// state; the test never creates an interface or changes its flags/addresses.
	loopback, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatal("read-only loopback precondition unavailable")
	}
	checkNoIP := forbidNativeInventoryIP(t)
	defer checkNoIP()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	started := time.Now()
	v := (LinuxCollector{}).Collect(ctx, Underlay{ID: "loopback-test", Interface: "lo", Kind: "ethernet"}, nil)
	finished := time.Now()
	if v.Present == nil || !*v.Present || v.IfIndex != loopback.Index {
		t.Error("default collector did not establish current loopback presence and identity")
	}
	if v.AdminUp == nil || *v.AdminUp != (loopback.Flags&net.FlagUp != 0) {
		t.Error("default collector did not establish loopback administrative state")
	}
	if v.Carrier == nil {
		t.Error("default collector left loopback carrier state unknown")
	}
	if v.ObservedAt.Before(started) || v.ObservedAt.After(finished) {
		t.Error("loopback observation timestamp is outside collection interval")
	}
}

func TestNativeInventoryAbsentInterfaceWithoutIPProcess(t *testing.T) {
	const absent = "vx7a6f9b2c3d4e5"
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal("read-only interface precondition unavailable")
	}
	for _, iface := range interfaces {
		if iface.Name == absent {
			t.Fatal("absent-interface test name already exists; no network changes attempted")
		}
	}
	checkNoIP := forbidNativeInventoryIP(t)
	defer checkNoIP()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	v := (LinuxCollector{}).Collect(ctx, Underlay{ID: "absent-test", Interface: absent, Kind: "ethernet"}, nil)
	if v.Present == nil || *v.Present {
		t.Error("absent interface was not positively established as absent")
	}
	if v.State != "down" || v.Reason != "interface_absent" {
		t.Error("absent interface did not produce down/interface_absent")
	}
	if v.IfIndex != 0 || v.AdminUp != nil || v.Carrier != nil || len(v.Addresses) != 0 || len(v.Routes) != 0 {
		t.Error("absent interface carried unsupported link, address, or route evidence")
	}
}

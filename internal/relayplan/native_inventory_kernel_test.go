//go:build linux

// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayplan

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"reflect"
	"testing"
	"time"
)

func inventoryKernelFixture(t *testing.T) (Underlay, func(...string)) {
	t.Helper()
	if os.Getenv("VPNCTL_INVENTORY_QUERY_TEST") != "1" {
		t.Skip("requires dedicated loopback-only container")
	}
	if _, err := os.Stat("/.dockerenv"); err != nil {
		t.Fatal("disposable container required")
	}
	interfaces, err := net.Interfaces()
	if err != nil || len(interfaces) != 1 || interfaces[0].Name != "lo" {
		t.Fatal("fresh loopback-only namespace required")
	}
	run := func(args ...string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if exec.CommandContext(ctx, "ip", args...).Run() != nil {
			t.Fatal("isolated fixture mutation failed")
		}
	}
	run("link", "add", "test-uplink", "type", "dummy")
	t.Cleanup(func() { _ = exec.Command("ip", "link", "del", "test-uplink").Run() })
	run("link", "set", "test-uplink", "up")
	run("address", "add", "192.0.2.2/24", "dev", "test-uplink")
	run("route", "add", "default", "via", "192.0.2.1", "dev", "test-uplink")
	return Underlay{ID: "test-uplink", Interface: "test-uplink", Kind: "ethernet"}, run
}
func TestLiveNativeInventoryStateChanges(t *testing.T) {
	u, run := inventoryKernelFixture(t)
	collect := func() Inventory {
		return (LinuxCollector{}).Collect(context.Background(), u, []string{"203.0.113.8:51820"})
	}
	check := func(state, reason string) {
		t.Helper()
		got := collect()
		if got.State != state || got.Reason != reason {
			t.Fatalf("wrong state: %s/%s", got.State, got.Reason)
		}
	}
	check("up", "")
	native := collect()
	legacy := (LinuxCollector{ReadIP: readIP}).Collect(context.Background(), u, []string{"203.0.113.8:51820"})
	native.ObservedAt = legacy.ObservedAt
	if !reflect.DeepEqual(native, legacy) {
		t.Fatal("native collector differs from iproute2 reference")
	}
	initialIndex := native.IfIndex
	run("link", "set", "test-uplink", "down")
	check("down", "link_down")
	run("link", "set", "test-uplink", "up")
	check("up", "")
	run("address", "change", "192.0.2.2/24", "dev", "test-uplink", "preferred_lft", "0")
	check("down", "no_ipv4")
	run("address", "change", "192.0.2.2/24", "dev", "test-uplink", "preferred_lft", "forever")
	run("address", "add", "192.0.2.3/24", "dev", "test-uplink")
	check("unknown", "source_ambiguous")
	u.SourceIPv4 = "192.0.2.2"
	check("up", "")
	run("address", "del", "192.0.2.2/24", "dev", "test-uplink")
	// Linux may delete the secondary address with its primary; either known
	// absence reason is correct, but no former source may remain usable.
	got := collect()
	if got.State != "down" || (got.Reason != "source_absent" && got.Reason != "no_ipv4") {
		t.Fatal("removed source stayed usable")
	}
	run("link", "set", "test-uplink", "name", "test-renamed")
	check("down", "interface_absent")
	run("link", "del", "test-renamed")
	run("link", "add", "test-uplink", "type", "dummy")
	run("link", "set", "test-uplink", "up")
	run("address", "add", "192.0.2.2/24", "dev", "test-uplink")
	got = collect()
	if got.IfIndex == initialIndex || got.State != "up" {
		t.Fatal("recreated interface identity was cached")
	}
}
func TestLiveNativeInventoryUnrelatedPopulation(t *testing.T) {
	u, run := inventoryKernelFixture(t)
	// A busy robot namespace must not make a single requested link's address
	// inventory exceed the old global JSON budget.
	for i := 0; i < 80; i++ {
		name := fmt.Sprintf("extra%d", i)
		run("link", "add", name, "type", "dummy")
		t.Cleanup(func() { _ = exec.Command("ip", "link", "del", name).Run() })
		run("address", "add", "198.51.100.1/24", "dev", name)
	}
	got := (LinuxCollector{}).Collect(context.Background(), u, nil)
	if got.State != "up" || len(got.Addresses) != 1 {
		t.Fatal("unrelated interfaces invalidated selected inventory")
	}
}
func TestLiveNativeInventoryBoundsAndDescriptors(t *testing.T) {
	u, run := inventoryKernelFixture(t)
	before, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 32; i++ {
		got := (LinuxCollector{}).Collect(context.Background(), u, nil)
		if got.State != "up" {
			t.Fatal("fresh query failed")
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		got = (LinuxCollector{}).Collect(ctx, u, nil)
		if got.State != "unknown" || got.Present != nil {
			t.Fatal("cancelled query produced evidence")
		}
	}
	after, err := os.ReadDir("/proc/self/fd")
	if err != nil || len(after) != len(before) {
		t.Fatal("descriptor leak")
	}
	for i := 3; i < 20; i++ {
		run("address", "add", fmt.Sprintf("192.0.2.%d/24", i), "dev", "test-uplink")
	}
	got := (LinuxCollector{}).Collect(context.Background(), u, nil)
	if got.State != "unknown" || got.Present != nil {
		t.Fatal("oversized address inventory admitted")
	}
}

func TestLiveNativeInventoryBlockedReceiveCancellation(t *testing.T) {
	_, _ = inventoryKernelFixture(t)
	before, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	for _, timeout := range []bool{false, true} {
		for i := 0; i < 16; i++ {
			ctx, cancel := context.WithCancel(context.Background())
			if timeout {
				cancel()
				ctx, cancel = context.WithTimeout(context.Background(), 20*time.Millisecond)
			}
			socket, _, closeSocket, err := nativeInventorySocket(ctx)
			if err != nil {
				cancel()
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { _, _, err := socket.Receive(); done <- err }()
			if !timeout {
				cancel()
			}
			select {
			case err := <-done:
				if err == nil {
					t.Error("cancelled receive succeeded")
				}
			case <-time.After(time.Second):
				cancel()
				closeSocket()
				<-done
				t.Fatal("blocked receive survived cancellation")
			}
			cancel()
			closeSocket()
		}
	}
	after, err := os.ReadDir("/proc/self/fd")
	if err != nil || len(after) != len(before) {
		t.Fatal("cancelled socket descriptor leak")
	}
}

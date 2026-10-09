//go:build linux

// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayapply

import (
	"context"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"vpnctl/internal/relaycatalog"
	"vpnctl/internal/relayplan"
)

// Run only in a disposable --network none container with --cap-drop ALL
// --cap-add NET_ADMIN and explicit CPU, memory and PID bounds. The extra checks
// reject accidental invocation on the shared host before any mutation.
func routeQueryKernelFixture(t testing.TB) (Entry, relaycatalog.Target, func(...string)) {
	t.Helper()
	if os.Getenv("VPNCTL_ROUTE_QUERY_TEST") != "1" {
		t.Skip("requires the disposable route-query test container")
	}
	if os.Geteuid() != 0 {
		t.Fatal("route-query fixture requires container root")
	}
	if _, err := os.Stat("/.dockerenv"); err != nil {
		t.Fatal("route-query fixture requires a disposable Docker container")
	}
	devices, err := net.Interfaces()
	if err != nil || len(devices) != 1 || devices[0].Name != "lo" {
		t.Fatal("route-query fixture requires an initially loopback-only namespace")
	}
	status, err := os.ReadFile("/proc/self/status")
	if err != nil || !strings.Contains(string(status), "CapEff:\t0000000000001000\n") {
		t.Fatal("route-query fixture requires only CAP_NET_ADMIN")
	}
	ip := func(args ...string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if output, err := exec.CommandContext(ctx, "ip", args...).CombinedOutput(); err != nil {
			t.Fatalf("synthetic ip fixture %v: %v: %s", args, err, output)
		}
	}
	const device = "vrquerytest0"
	ip("link", "add", device, "type", "dummy")
	t.Cleanup(func() { ip("link", "del", device) })
	ip("link", "set", device, "up")
	ip("address", "add", "192.0.2.2/32", "dev", device)
	// Mirror the application's source/device-bound policy table and terminal
	// route. Linux can still synthesize an on-link response for a pinned-oif
	// lookup after route removal; independent route inventory remains required.
	t.Cleanup(func() { ip("route", "flush", "table", "100901") })
	ip("route", "add", "unreachable", "default", "table", "100901", "proto", "186", "metric", "100001")
	ip("route", "add", "198.51.100.2/32", "dev", device, "src", "192.0.2.2", "table", "100901", "proto", "186", "metric", "100001")
	ip("rule", "add", "priority", "28000", "from", "192.0.2.2/32", "oif", device, "table", "100901", "protocol", "186")
	t.Cleanup(func() { ip("rule", "del", "priority", "28000") })
	link, err := net.InterfaceByName(device)
	if err != nil {
		t.Fatal(err)
	}
	entry := Entry{LinkIndex: uint32(link.Index), Candidate: relayplan.Candidate{
		InnerAddress: "192.0.2.2/32", Pin: &relayplan.PinInput{WGInterface: device},
	}}
	return entry, relaycatalog.Target{ProbeAddress: "198.51.100.2"}, ip
}

func TestLiveTargetRouteKernelContract(t *testing.T) {
	for _, scenario := range []string{"direct", "lookup-only-removed-route", "gateway", "local", "lookup-only-blackhole-route", "wrong-source", "wrong-name", "wrong-index", "cancelled"} {
		t.Run(scenario, func(t *testing.T) {
			entry, target, ip := routeQueryKernelFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if err := liveTargetRoute(ctx, entry, target); err != nil {
				t.Fatalf("initial approved route: %v", err)
			}
			switch scenario {
			case "lookup-only-removed-route":
				ip("route", "del", target.ProbeAddress+"/32", "table", "100901")
			case "gateway":
				ip("route", "replace", target.ProbeAddress+"/32", "via", "192.0.2.1", "dev", entry.Candidate.Pin.WGInterface, "onlink", "table", "100901", "metric", "100001")
			case "local":
				ip("route", "add", "local", target.ProbeAddress+"/32", "dev", entry.Candidate.Pin.WGInterface, "table", "local")
			case "lookup-only-blackhole-route":
				ip("route", "replace", "blackhole", target.ProbeAddress+"/32", "table", "100901", "metric", "100001")
			case "wrong-source":
				entry.Candidate.InnerAddress = "192.0.2.99/32"
			case "wrong-name":
				entry.Candidate.Pin.WGInterface = "vrmissingtest0"
			case "wrong-index":
				entry.LinkIndex = 1 // loopback must never stand in for the approved link
			case "cancelled":
				cancel()
			}
			// Linux synthesizes an on-link unicast result for these pinned-oif
			// lookups, including the real iproute2 reference. This test preserves
			// lookup equivalence; it does not certify route-table membership.
			wantSuccess := scenario == "direct" || strings.HasPrefix(scenario, "lookup-only-")
			if err := liveTargetRoute(ctx, entry, target); (err == nil) != wantSuccess {
				t.Errorf("live lookup success=%t, want %t: %v", err == nil, wantSuccess, err)
			}
			// Legacy code pins by name, so the new index check is intentionally
			// stronger. All other cases must agree with the real iproute2 result.
			if scenario != "wrong-index" {
				if err := (kernel{run: command}).targetRoute(ctx, entry, target); (err == nil) != wantSuccess {
					t.Fatalf("reference lookup success=%t, want %t: %v", err == nil, wantSuccess, err)
				}
			}
			if scenario == "lookup-only-removed-route" || scenario == "gateway" {
				ip("route", "replace", target.ProbeAddress+"/32", "dev", entry.Candidate.Pin.WGInterface, "src", "192.0.2.2", "table", "100901", "proto", "186", "metric", "100001")
				if err := liveTargetRoute(ctx, entry, target); err != nil {
					t.Fatalf("recovered route not reread: %v", err)
				}
			}
		})
	}
}

func TestLiveTargetRouteRejectsRecreatedDevice(t *testing.T) {
	entry, target, ip := routeQueryKernelFixture(t)
	ctx := context.Background()
	if err := liveTargetRoute(ctx, entry, target); err != nil {
		t.Fatal(err)
	}
	name := entry.Candidate.Pin.WGInterface
	ip("link", "del", name)
	ip("link", "add", name, "type", "dummy")
	ip("link", "set", name, "up")
	ip("address", "add", "192.0.2.2/32", "dev", name)
	ip("route", "add", target.ProbeAddress+"/32", "dev", name, "src", "192.0.2.2", "table", "100901", "proto", "186", "metric", "100001")
	link, err := net.InterfaceByName(name)
	if err != nil || uint32(link.Index) == entry.LinkIndex {
		t.Fatal("fixture did not replace the original index")
	}
	if err := (kernel{run: command}).targetRoute(ctx, entry, target); err != nil {
		t.Fatalf("reference must demonstrate its name-only acceptance: %v", err)
	}
	if err := liveTargetRoute(ctx, entry, target); err == nil {
		t.Fatal("accepted a replacement with the same name and a new index")
	}
	entry.LinkIndex = uint32(link.Index)
	if err := liveTargetRoute(ctx, entry, target); err != nil {
		t.Fatalf("fresh approval for the replacement index: %v", err)
	}
}

func BenchmarkLiveTargetRouteKernel(b *testing.B) {
	entry, target, _ := routeQueryKernelFixture(b)
	ctx := context.Background()
	for _, implementation := range []struct {
		name string
		read func(context.Context, Entry, relaycatalog.Target) error
	}{
		{"iproute2", (kernel{run: command}).targetRoute},
		{"netlink", liveTargetRoute},
	} {
		b.Run(implementation.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if err := implementation.read(ctx, entry, target); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

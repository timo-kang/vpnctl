//go:build integration

// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"vpnctl/internal/api"
	"vpnctl/internal/relayapply"
	"vpnctl/internal/relaycache"
	"vpnctl/internal/relaycatalog"
	"vpnctl/internal/relayplan"
)

type failedDeploymentIssuer struct{ err error }

func (f failedDeploymentIssuer) RelayDeployment(context.Context, string, string) (relaycatalog.DeploymentView, error) {
	return relaycatalog.DeploymentView{}, f.err
}

func checkM3RelayApply(t *testing.T, relays []string, private, configPath string, keys []string, plan relayplan.Plan, issuer *planIssuer, phases *[]string) ([][]string, func(), *m3LeaseFixture) {
	t.Helper()
	if err := os.Chmod(private, 0700); err != nil {
		t.Fatal(err)
	}
	bin := integrationBinary(t)
	lease := newM3LeaseFixture(t, relays, private, issuer)
	interfaces := make([][]string, len(relays))
	args := func(r int, action string, endpoint int) []string {
		a := []string{bin, "relay", action, "--config", configPath, "--relay-id", fmt.Sprintf("r%d", r), "--cache-dir", filepath.Join(private, fmt.Sprintf("deploy-cache-%d", r))}
		if endpoint >= 0 {
			a = append(a, "--endpoint-id", fmt.Sprintf("ep%d", endpoint))
		}
		if action == "apply" {
			a = append(a, "--key-file", filepath.Join(private, fmt.Sprintf("deploy-%d.key", r)), "--key-generation", "1", "--listen-port", strconv.Itoa(51820+endpoint))
		}
		return a
	}
	call := func(r int, action string, endpoint int, success bool) relayapply.DeploymentResult {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 70*time.Second)
		defer cancel()
		b, err := netCommand(ctx, relays[r], args(r, action, endpoint)...).CombinedOutput()
		for _, key := range keys {
			if strings.Contains(string(b), strings.TrimSpace(key)) {
				t.Fatal("relay key disclosed")
			}
		}
		if (err == nil) != success {
			for _, a := range [][]string{{"ip", "-j", "-N", "-d", "link", "show"}, {"ip", "-j", "-N", "-6", "route", "show", "table", "all"}, {"ip", "-j", "-N", "-4", "route", "show", "table", "all"}} {
				t.Log(netOutput(t, relays[r], a...))
			}
			t.Fatalf("relay %d %s: %v %s", r, action, err, b)
		}
		var out relayapply.DeploymentResult
		if err := json.Unmarshal([]byte(strings.SplitN(string(b), "\n", 2)[0]), &out); err != nil {
			t.Fatalf("relay output: %v %s", err, b)
		}
		if out.UplinkHealth != "unknown" || out.ExpiryEnforcement != "kernel_lease" {
			t.Fatal("unsupported readiness claim", out)
		}
		return out
	}
	refresh := func(r int, fault error) {
		t.Helper()
		c, err := relaycache.OpenDeployment(filepath.Join(private, fmt.Sprintf("deploy-cache-%d", r)), relaycache.DeploymentOptions{PrincipalID: "robot", RelayID: fmt.Sprintf("r%d", r), Create: true})
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		if fault == nil {
			_, err = c.Refresh(context.Background(), issuer)
		} else {
			_, err = c.Refresh(context.Background(), failedDeploymentIssuer{fault})
		}
		if (err == nil) != (fault == nil) {
			t.Fatal("refresh", err)
		}
	}
	for r, ns := range relays {
		refresh(r, nil)
		mustWrite(t, filepath.Join(private, fmt.Sprintf("deploy-%d.key", r)), keys[r])
		// A separate interface owning the requested UDP port must survive.
		netOutput(t, ns, "ip", "link", "add", "relay-sentinel", "type", "wireguard")
		netOutput(t, ns, "wg", "set", "relay-sentinel", "listen-port", "51820")
		call(r, "apply", 0, false)
		if strings.TrimSpace(netOutput(t, ns, "wg", "show", "relay-sentinel", "listen-port")) != "51820" {
			t.Fatal("foreign listener changed")
		}
		netOutput(t, ns, "wg", "set", "relay-sentinel", "listen-port", "51999")
		peer := plan.Paths[r*2]
		netOutput(t, ns, "ip", "route", "add", "unreachable", peer.InnerAddress, "table", "123")
		call(r, "apply", 0, false)
		if !strings.Contains(netOutput(t, ns, "ip", "route", "show", "table", "123"), strings.TrimSuffix(peer.InnerAddress, "/32")) {
			t.Fatal("foreign route changed")
		}
		netOutput(t, ns, "ip", "route", "del", "unreachable", peer.InnerAddress, "table", "123")
		for u := 0; u < 2; u++ {
			out := call(r, "apply", u, true)
			if !out.KernelReady {
				t.Fatal("relay not ready", out)
			}
			call(r, "apply", u, true)
			iface := out.Endpoints[u].Interface
			interfaces[r] = append(interfaces[r], iface)
			// Forwarding authorization/NAT are explicitly still fixture-owned.
			netOutput(t, ns, "nft", "add", "rule", "ip", "m3", "forward", "iifname", iface, "oifname", "uplink0", "ip", "daddr", m3Target, "tcp", "dport", "9192", "accept")
			netOutput(t, ns, "nft", "add", "rule", "ip", "m3", "forward", "iifname", "uplink0", "oifname", iface, "ct", "state", "established,related", "accept")
		}
		// External cryptographic changes block readiness and destructive cleanup.
		foreign, foreignPublic := wgKeyPair(t)
		mustWrite(t, filepath.Join(private, "relay-external.psk"), foreign)
		iface := interfaces[r][0]
		netOutput(t, ns, "wg", "set", iface, "peer", foreignPublic, "allowed-ips", "203.0.113.1/32")
		call(r, "inspect", -1, false)
		call(r, "release", 0, false)
		if !strings.Contains(netOutput(t, ns, "wg", "show", iface, "peers"), foreignPublic) {
			t.Fatal("foreign peer removed")
		}
		netOutput(t, ns, "wg", "set", iface, "peer", foreignPublic, "remove")
		netOutput(t, ns, "wg", "set", iface, "peer", peer.PublicKey, "preshared-key", filepath.Join(private, "relay-external.psk"))
		call(r, "inspect", -1, false)
		call(r, "release", 0, false)
		netOutput(t, ns, "wg", "set", iface, "peer", peer.PublicKey, "preshared-key", "/dev/null")
		// A conflict blocks the lease even when ownership prevents deleting
		// foreign configuration. Explicitly recreate after resolving it.
		call(r, "release", 0, true)
		call(r, "apply", 0, true)
		if out := call(r, "inspect", -1, true); !out.KernelReady {
			t.Fatal("relay did not recover after external conflict", out)
		}
		*phases = append(*phases, fmt.Sprintf("relay_%d_product_peers_idempotence_foreign_listener_route_peer_psk", r))
		lease.start(r)
		lease.ready(r)
	}
	return interfaces, func() {
		lease.stop()
		for r, ns := range relays {
			refresh(r, &api.HTTPError{StatusCode: 403})
			out := call(r, "inspect", -1, false)
			if len(out.Endpoints) != 0 || out.KernelReady {
				t.Fatal("denial retained relay endpoints", out)
			}
			refresh(r, io.EOF)
			call(r, "apply", 0, false)
			if got := strings.Fields(netOutput(t, ns, "wg", "show", "interfaces")); len(got) != 1 || got[0] != "relay-sentinel" {
				t.Fatal("revoked relay resources survived", got)
			}
			refresh(r, nil)
			for u := 0; u < 2; u++ {
				call(r, "apply", u, true)
				call(r, "release", u, true)
			}
			*phases = append(*phases, fmt.Sprintf("relay_%d_revocation_blocks_all_outage_stays_blocked_fresh_approval_restores", r))
			// Kill a separate CLI after each successful kernel mutation. Its
			// replacement must recover the durable intent, including an up link.
			faultDir := filepath.Join(private, fmt.Sprintf("relay-fault-%d", r))
			if err := os.Mkdir(faultDir, 0700); err != nil {
				t.Fatal(err)
			}
			for _, tool := range []string{"ip", "wg", "nft"} {
				real, err := exec.LookPath(tool)
				if err != nil {
					t.Fatal(err)
				}
				script := "#!/bin/sh\n" + real + " \"$@\"\nstatus=$?\nif [ \"$status\" = 0 ]; then\ncase \"$*\" in\n$VPNCTL_TEST_KILL_PATTERN) printf fired > \"$VPNCTL_TEST_KILL_MARKER\"; kill -KILL \"$PPID\";;\nesac\nfi\nexit \"$status\"\n"
				if err = os.WriteFile(filepath.Join(faultDir, tool), []byte(script), 0700); err != nil {
					t.Fatal(err)
				}
			}
			for i, pattern := range []string{"-f /dev/stdin", "link add *", "link set dev * alias *", "setconf * /dev/stdin", "-4 -batch /dev/stdin", "link set dev * up"} {
				marker := filepath.Join(private, fmt.Sprintf("relay-killed-%d-%d", r, i))
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				cmd := netCommand(ctx, ns, args(r, "apply", 0)...)
				cmd.Env = append(os.Environ(), "PATH="+faultDir+":"+os.Getenv("PATH"), "VPNCTL_TEST_KILL_PATTERN="+pattern, "VPNCTL_TEST_KILL_MARKER="+marker)
				b, err := cmd.CombinedOutput()
				cancel()
				if err == nil {
					t.Fatal("relay CLI not killed", pattern)
				}
				if data, e := os.ReadFile(marker); e != nil || string(data) != "fired" {
					t.Fatal("relay kill point not exercised", pattern, e, string(b))
				}
				if status, ok := cmd.ProcessState.Sys().(syscall.WaitStatus); !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
					t.Fatal("relay not killed by signal", err)
				}
				if out := call(r, "recover", -1, true); out.State != "empty" {
					t.Fatal("relay crash resources survived", out)
				}
				call(r, "apply", 0, true)
				call(r, "release", 0, true)
				*phases = append(*phases, fmt.Sprintf("relay_%d_sigkill_recovery_%d", r, i))
			}
			if strings.TrimSpace(netOutput(t, ns, "wg", "show", "relay-sentinel", "listen-port")) != "51999" {
				t.Fatal("relay sentinel changed")
			}
			netOutput(t, ns, "ip", "link", "del", "relay-sentinel")
		}
	}, lease
}

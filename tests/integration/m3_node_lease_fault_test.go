//go:build integration

// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package integration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"vpnctl/internal/api"
	"vpnctl/internal/config"
	"vpnctl/internal/pki"
	"vpnctl/internal/relayapply"
	"vpnctl/internal/relaycache"
)

func nodeLeaseFaultFixture(t *testing.T) (*m3AuthorityFixture, string) {
	t.Helper()
	f := newM3AuthorityFixtureWithOptions(t, m3AuthorityOptions{separateController: true, independentRecipients: true})
	f.releaseNodeCandidates()
	for _, p := range f.plan.Paths {
		netOutput(t, f.robot, integrationBinary(t), "node", "relay", "prepare", "--config", f.node, "--path-id", p.PathID, "--probe-routes", "--lease")
	}
	cfg, err := config.Load(f.node)
	if err != nil {
		t.Fatal(err)
	}
	cache := cfg.Node.RelayCacheDir
	if cache == "" {
		cache = filepath.Join(cfg.Node.PKIDir, "relay-cache")
	}
	return f, cache
}
func startNodeLeaseWatch(t *testing.T, f *m3AuthorityFixture, label string, env ...string) *networkProcess {
	t.Helper()
	return startNetworkProcess(t, f.robot, filepath.Join(f.results, label+".jsonl"), env, integrationBinary(t), "node", "relay", "supervise", "--config", f.node, "--refresh-interval", "1s")
}
func awaitNodeLease(t *testing.T, f *m3AuthorityFixture) {
	t.Helper()
	eventually(t, 20*time.Second, "node lease recovery", func() error {
		for _, p := range f.plan.Paths {
			if !f.probe(p).OK {
				return fmt.Errorf("%s blocked", p.PathID)
			}
		}
		return nil
	})
}
func startNodeLeaseStream(t *testing.T, f *m3AuthorityFixture, label string) *networkProcess {
	t.Helper()
	p := startNetworkProcess(t, f.robot, filepath.Join(f.results, label+"-stream.jsonl"), []string{"VPNCTL_WORKER=lease-stream", "VPNCTL_PROBE_SOURCE=" + strings.TrimSuffix(f.plan.Paths[0].InnerAddress, "/32")}, f.worker, "-test.run=^TestNetworkWorker$")
	eventually(t, 3*time.Second, "stream baseline", func() error {
		b, _ := os.ReadFile(p.log)
		if !strings.Contains(string(b), `"ok":true`) {
			return errors.New("no echo")
		}
		return nil
	})
	return p
}
func requireNodeBlocked(t *testing.T, f *m3AuthorityFixture, stream *networkProcess, deadline time.Time) {
	t.Helper()
	for _, p := range f.plan.Paths {
		if f.probe(p).OK {
			t.Fatal("new TCP escaped node expiry", p.PathID)
		}
	}
	b, err := os.ReadFile(stream.log)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, line := range strings.Split(string(b), "\n") {
		var e leaseStreamEvent
		if json.Unmarshal([]byte(line), &e) == nil && e.At.After(deadline) {
			count++
			if e.OK {
				t.Fatal("existing TCP escaped node expiry")
			}
		}
	}
	if count == 0 {
		t.Fatal("missing post-deadline TCP evidence")
	}
}
func nodeControllerOutage(t *testing.T, f *m3AuthorityFixture) {
	t.Helper()
	(relayUplink{relay: f.robot}).nft(t, `table inet node_outage {
 chain output { type filter hook output priority -310; policy accept;
 ip daddr 192.0.2.254 tcp dport 9443 counter drop
 }
}`)
}

func TestNetns_M3NodeLeasePressure(t *testing.T) {
	requireNetwork(t)
	for _, fault := range []string{"cache-lock", "namespace-lock", "enospc", "stdout-backpressure", "slow-kernel"} {
		t.Run(fault, func(t *testing.T) {
			f, cache := nodeLeaseFaultFixture(t)
			watch := startNodeLeaseWatch(t, f, "baseline")
			awaitNodeLease(t, f)
			stream := startNodeLeaseStream(t, f, "pressure")
			watch.terminate(t)
			var release func()
			switch fault {
			case "cache-lock":
				c, err := relaycache.Open(cache, relaycache.Options{NodeID: "robot"})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { c.Close() })
				release = func() { c.Close() }
				watch = startNodeLeaseWatch(t, f, fault)
			case "namespace-lock":
				ready := filepath.Join(f.private, "node-locked")
				holder := startNetworkProcess(t, f.robot, filepath.Join(f.results, "lock.log"), []string{"VPNCTL_WORKER=lease-lock", "VPNCTL_LOCK_READY=" + ready}, f.worker, "-test.run=^TestNetworkWorker$")
				eventually(t, 3*time.Second, "lock holder", func() error { _, err := os.Stat(ready); return err })
				release = holder.stop
				watch = startNodeLeaseWatch(t, f, fault)
			case "enospc":
				entries, err := os.ReadDir(cache)
				if err != nil {
					t.Fatal(err)
				}
				backup := map[string][]byte{}
				for _, e := range entries {
					b, err := os.ReadFile(filepath.Join(cache, e.Name()))
					if err != nil {
						t.Fatal(err)
					}
					backup[e.Name()] = b
				}
				if b, err := exec.Command("mount", "-t", "tmpfs", "-o", "size=1m,mode=0700", "tmpfs", cache).CombinedOutput(); err != nil {
					t.Fatal(err, string(b))
				}
				t.Cleanup(func() {
					if b, err := exec.Command("umount", "-l", cache).CombinedOutput(); err != nil {
						t.Error(err, string(b))
					}
				})
				for name, b := range backup {
					if err := os.WriteFile(filepath.Join(cache, name), b, 0600); err != nil {
						t.Fatal(err)
					}
				}
				file, err := os.Create(filepath.Join(cache, "fill"))
				if err != nil {
					t.Fatal(err)
				}
				for i := 0; i < 512 && err == nil; i++ {
					_, err = file.Write(make([]byte, 4096))
				}
				file.Close()
				if !errors.Is(err, syscall.ENOSPC) {
					t.Fatal("ENOSPC not exercised", err)
				}
				release = func() {
					if err := os.Remove(filepath.Join(cache, "fill")); err != nil {
						t.Fatal(err)
					}
				}
				watch = startNodeLeaseWatch(t, f, fault)
			case "stdout-backpressure":
				r, w, err := os.Pipe()
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { r.Close(); w.Close() })
				n, err := unix.FcntlInt(w.Fd(), unix.F_SETPIPE_SZ, 4096)
				if err != nil {
					t.Fatal(err)
				}
				if written, err := w.Write(make([]byte, n)); err != nil || written != n {
					t.Fatal("pipe not full")
				}
				cmd := netCommand(context.Background(), f.robot, integrationBinary(t), "node", "relay", "supervise", "--config", f.node, "--refresh-interval", "1s")
				cmd.Stdout = w
				if err := cmd.Start(); err != nil {
					t.Fatal(err)
				}
				watch = &networkProcess{cmd: cmd}
				t.Cleanup(watch.stop)
				release = func() { r.Close(); w.Close() }
			case "slow-kernel":
				dir := filepath.Join(f.private, "slow")
				if err := os.Mkdir(dir, 0700); err != nil {
					t.Fatal(err)
				}
				script := "#!/bin/sh\nprintf invoked > '" + filepath.Join(dir, "invoked") + "'\nsleep 30\nexec /usr/sbin/nft \"$@\"\n"
				if err := os.WriteFile(filepath.Join(dir, "nft"), []byte(script), 0700); err != nil {
					t.Fatal(err)
				}
				watch = startNodeLeaseWatch(t, f, fault, "PATH="+dir+":"+os.Getenv("PATH"))
				release = func() {}
				eventually(t, 5*time.Second, "slow command", func() error { _, err := os.Stat(filepath.Join(dir, "invoked")); return err })
			}
			at := time.Now()
			time.Sleep(12 * time.Second)
			requireNodeBlocked(t, f, stream, at.Add(12*time.Second))
			watch.stop()
			nodeControllerOutage(t, f)
			release()
			watch = startNodeLeaseWatch(t, f, "cached")
			time.Sleep(3 * time.Second)
			for _, p := range f.plan.Paths {
				if f.probe(p).OK {
					t.Fatal("cached authority reopened expired lease")
				}
			}
			if strings.Contains(netOutput(t, f.robot, "nft", "list", "table", "inet", "node_outage"), "counter packets 0 bytes 0") {
				t.Fatal("outage not exercised")
			}
			netOutput(t, f.robot, "nft", "delete", "table", "inet", "node_outage")
			awaitNodeLease(t, f)
			watch.terminate(t)
			writeM3Report(t, filepath.Join(f.results, "node-pressure.json"), map[string]any{"completed": !t.Failed(), "fault": fault, "old_and_new_tcp_blocked": true, "cached_rearm_rejected": true, "fresh_recovery": true})
		})
	}
}

func TestNetns_M3NodeApprovalExpiry(t *testing.T) {
	requireNetwork(t)
	f, _ := nodeLeaseFaultFixture(t)
	grant := f.controller.apply(f.spec, 60)
	watch := startNodeLeaseWatch(t, f, "expiry")
	awaitNodeLease(t, f)
	stream := startNodeLeaseStream(t, f, "expiry")
	nodeControllerOutage(t, f)
	// Relays receive a new long approval; the isolated node only has the old
	// short grant. Its packet cutoff cannot be attributed to relay expiration.
	f.controller.apply(f.spec, 3600)
	time.Sleep(12 * time.Second)
	awaitNodeLease(t, f)
	if time.Until(grant.ExpiresAt) <= 0 {
		t.Fatal("no offline continuation interval")
	}
	time.Sleep(time.Until(grant.ExpiresAt.Add(time.Second)))
	requireNodeBlocked(t, f, stream, grant.ExpiresAt.Add(500*time.Millisecond))
	for _, r := range f.recipients {
		if out := r.require("inspect", -1, 0); !out.KernelReady {
			t.Fatal("relay also blocked", out)
		}
	}
	netOutput(t, f.robot, "nft", "delete", "table", "inet", "node_outage")
	awaitNodeLease(t, f)
	watch.terminate(t)
	writeM3Report(t, filepath.Join(f.results, "node-approval-expiry.json"), map[string]any{"completed": !t.Failed(), "expires_at": grant.ExpiresAt, "offline_continuation": true, "node_only_expiration": true, "fresh_generation_recovers": true})
}

func TestNetns_M3NodeApprovalRevoked(t *testing.T) {
	requireNetwork(t)
	f, _ := nodeLeaseFaultFixture(t)
	watch := startNodeLeaseWatch(t, f, "revoked")
	awaitNodeLease(t, f)
	stream := startNodeLeaseStream(t, f, "revoked")
	cfg, err := config.Load(f.node)
	if err != nil {
		t.Fatal(err)
	}
	creds, err := pki.LoadCredentials(cfg.Node.PKIDir)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := pki.ParseCertificate(creds.ClientCert)
	if err != nil {
		t.Fatal(err)
	}
	f.controller.admin(api.AdminRequest{Operation: "pki.revoke", Fingerprint: pki.Fingerprint(cert)})
	at := time.Now()
	time.Sleep(11 * time.Second)
	requireNodeBlocked(t, f, stream, at.Add(11*time.Second))
	for _, r := range f.recipients {
		if out := r.require("inspect", -1, 0); !out.KernelReady {
			t.Fatal("independent relay approval lost", out)
		}
	}
	// A later transport outage cannot erase a previously observed denial.
	nodeControllerOutage(t, f)
	time.Sleep(3 * time.Second)
	for _, p := range f.plan.Paths {
		if f.probe(p).OK {
			t.Fatal("outage undid node revocation")
		}
	}
	watch.terminate(t)
	writeM3Report(t, filepath.Join(f.results, "node-revoked.json"), map[string]any{"completed": !t.Failed(), "node_identity_revoked": true, "relay_approvals_live": true, "outage_does_not_undo_denial": true})
}

func TestNetns_M3NodeLeaseForeignState(t *testing.T) {
	requireNetwork(t)
	parentTest := t
	f, cache := nodeLeaseFaultFixture(t)
	watch := startNodeLeaseWatch(t, f, "foreign")
	awaitNodeLease(t, f)
	raw, err := os.ReadFile(filepath.Join(cache, "apply.json"))
	if err != nil {
		t.Fatal(err)
	}
	var journal struct {
		Journal relayapply.Journal `json:"journal"`
	}
	if err := json.Unmarshal(raw, &journal); err != nil {
		t.Fatal(err)
	}
	e := journal.Journal.Entries[0]
	iface := e.Candidate.Pin.WGInterface
	table := "vl" + iface[2:]
	phases := []string{}
	for _, kind := range []string{"peer", "route", "tc", "nft"} {
		t.Run(kind, func(t *testing.T) {
			watch.terminate(t)
			var undo func()
			var snapshot func() string
			switch kind {
			case "peer":
				_, key := wgKeyPair(t)
				netOutput(t, f.robot, "wg", "set", iface, "peer", key, "allowed-ips", "203.0.114.1/32")
				snapshot = func() string { return netOutput(t, f.robot, "wg", "show", iface, "allowed-ips") }
				undo = func() { netOutput(t, f.robot, "wg", "set", iface, "peer", key, "remove") }
			case "route":
				netOutput(t, f.robot, "ip", "route", "add", "unreachable", "203.0.114.0/24", "table", fmt.Sprint(e.Candidate.Pin.Table), "proto", "99")
				snapshot = func() string {
					return netOutput(t, f.robot, "ip", "-j", "route", "show", "table", fmt.Sprint(e.Candidate.Pin.Table))
				}
				undo = func() {
					netOutput(t, f.robot, "ip", "route", "del", "unreachable", "203.0.114.0/24", "table", fmt.Sprint(e.Candidate.Pin.Table), "proto", "99")
				}
			case "tc":
				netOutput(t, f.robot, "tc", "filter", "add", "dev", iface, "ingress", "pref", "22", "matchall", "action", "pass")
				snapshot = func() string {
					return netOutput(t, f.robot, "tc", "filter", "show", "dev", iface, "ingress", "pref", "22")
				}
				undo = func() { netOutput(t, f.robot, "tc", "filter", "del", "dev", iface, "ingress", "pref", "22") }
			case "nft":
				netOutput(t, f.robot, "nft", "add", "chain", "inet", table, "foreign")
				snapshot = func() string { return netOutput(t, f.robot, "nft", "list", "chain", "inet", table, "foreign") }
				undo = func() { netOutput(t, f.robot, "nft", "delete", "chain", "inet", table, "foreign") }
			}
			before := snapshot()
			watch = startNodeLeaseWatch(parentTest, f, "foreign-"+kind)
			eventually(t, 8*time.Second, "foreign candidate blocked", func() error {
				if f.probe(f.plan.Paths[0]).OK {
					return errors.New("still open")
				}
				return nil
			})
			if snapshot() != before {
				t.Fatal("foreign object changed")
			}
			if !f.probe(f.plan.Paths[1]).OK {
				t.Fatal("independent owned candidate starved")
			}
			watch.terminate(t)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			_, err := netCommand(ctx, f.robot, integrationBinary(t), "node", "relay", "release", "--config", f.node, "--path-id", e.Candidate.PathID).CombinedOutput()
			cancel()
			if err == nil || snapshot() != before {
				t.Fatal("release adopted or removed foreign object")
			}
			undo()
			f.nodeCall("recover", "")
			netOutput(t, f.robot, integrationBinary(t), "node", "relay", "prepare", "--config", f.node, "--path-id", e.Candidate.PathID, "--lease", "--probe-routes")
			watch = startNodeLeaseWatch(parentTest, f, "recovered-"+kind)
			awaitNodeLease(t, f)
			raw, err = os.ReadFile(filepath.Join(cache, "apply.json"))
			if err != nil {
				t.Fatal(err)
			}
			if err = json.Unmarshal(raw, &journal); err != nil {
				t.Fatal(err)
			}
			for _, entry := range journal.Journal.Entries {
				if entry.Candidate.PathID == e.Candidate.PathID {
					e = entry
					iface = e.Candidate.Pin.WGInterface
					table = "vl" + iface[2:]
				}
			}
			phases = append(phases, kind)
		})
	}
	watch.terminate(t)
	writeM3Report(t, filepath.Join(f.results, "node-foreign.json"), map[string]any{"completed": !t.Failed(), "preserved": phases})
}

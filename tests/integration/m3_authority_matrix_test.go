//go:build integration

// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"vpnctl/internal/api"
	"vpnctl/internal/config"
	"vpnctl/internal/pki"
	"vpnctl/internal/relaycatalog"
	"vpnctl/internal/relayplan"
)

type m3AuthorityFixture struct {
	t                                             *testing.T
	controller                                    *m3Controller
	robot, target, private, results, node, worker string
	recipients                                    []*m3Recipient
	nodeSupervisor                                *networkProcess
	plan                                          relayplan.Plan
	spec                                          relaycatalog.Spec
}

func copyM3Spec(spec relaycatalog.Spec) relaycatalog.Spec {
	b, _ := json.Marshal(spec)
	var out relaycatalog.Spec
	if err := json.Unmarshal(b, &out); err != nil {
		panic(err)
	}
	return out
}

// Safe public inventory, including on failure. Never use `wg show ... dump`.
func (f *m3AuthorityFixture) snapshot() map[string]any {
	out := map[string]any{"at": time.Now().UTC()}
	for _, r := range f.recipients {
		state := map[string]any{}
		for _, args := range [][]string{{"wg", "show", "all", "allowed-ips"}, {"wg", "show", "all", "endpoints"}, {"ip", "-j", "link", "show"}, {"ip", "-j", "-4", "route", "show", "table", "all"}, {"nft", "-j", "-n", "-T", "list", "ruleset"}} {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			b, err := netCommand(ctx, r.ns, args...).CombinedOutput()
			cancel()
			key := strings.Join(args, " ")
			state[key] = string(b)
			if err != nil {
				state[key+" error"] = err.Error()
			}
		}

		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		cmd := netCommand(ctx, r.ns, f.worker, "-test.run=^TestNetworkWorker$")
		cmd.Env = append(os.Environ(), "VPNCTL_WORKER=boot-guard-snapshot")
		b, err := cmd.CombinedOutput()
		cancel()
		if err != nil {
			state["bpf_error"] = err.Error()
		}
		for _, line := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(line, "BOOTTIME_GUARDS=") {
				var guards map[string]any
				if json.Unmarshal([]byte(strings.TrimPrefix(line, "BOOTTIME_GUARDS=")), &guards) == nil {
					state["bpf_guards"] = guards
				}
			}
		}
		out[r.relay] = state
	}
	return out
}

type m3AuthorityOptions struct {
	separateController    bool
	independentRecipients bool
	underlays             int
	extraTarget           bool
	robotInGuestRoot      bool
}

func newM3AuthorityFixture(t *testing.T) *m3AuthorityFixture {
	t.Helper()
	return newM3AuthorityFixtureWithOptions(t, m3AuthorityOptions{})
}

func newM3AuthorityFixtureWithOptions(t *testing.T, opts m3AuthorityOptions) *m3AuthorityFixture {
	t.Helper()
	if opts.underlays == 0 {
		opts.underlays = 2
	}
	layout := newM3TopologyLayoutWithGuestRobot(t, opts.separateController, opts.underlays, opts.robotInGuestRoot)
	robot, relays, target := layout.robot, layout.relays, layout.target
	private := t.TempDir()
	if err := os.Chmod(private, 0700); err != nil {
		t.Fatal(err)
	}
	results, err := os.MkdirTemp(os.Getenv("VPNCTL_ARTIFACT_DIR"), "m3-authority-")
	if err != nil {
		t.Fatal(err)
	}
	worker, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	f := &m3AuthorityFixture{t: t, robot: robot, target: target, private: private, results: results, worker: worker}
	t.Cleanup(func() {
		writeM3Report(t, filepath.Join(results, "outcome.json"), map[string]any{"test": t.Name(), "completed": !t.Failed(), "final_kernel": f.snapshot()})
	})
	f.controller = newM3Controller(t, layout.controller, layout.controllerAddress, private, results)
	f.node = f.controller.enroll(robot, "robot")
	agent := ""
	if !opts.independentRecipients {
		agent = f.controller.enroll(relays[0], "agent")
	}
	principals := make(map[string]string)
	cfg, err := config.Load(f.node)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Node.RelayUnderlays = []relayplan.Underlay{{ID: "lan0", Interface: "wan0", Kind: "ethernet"}, {ID: "lan1", Interface: "wan1", Kind: "wifi"}}
	for u := 2; u < opts.underlays; u++ {
		cfg.Node.RelayUnderlays = append(cfg.Node.RelayUnderlays, relayplan.Underlay{ID: fmt.Sprint("lan", u), Interface: fmt.Sprint("wan", u), Kind: "ethernet"})
	}
	if err = config.Save(f.node, cfg); err != nil {
		t.Fatal(err)
	}
	f.spec = relaycatalog.Spec{SchemaVersion: 1, PoolCIDR: "10.78.0.0/16", Targets: []relaycatalog.Target{{ID: "app", Prefixes: []string{m3Target + "/32"}, ProbeAddress: m3Target, Port: 9192, Protocol: "tcp"}}}
	if opts.extraTarget {
		f.spec.Targets = append(f.spec.Targets, relaycatalog.Target{ID: "app2", Prefixes: []string{"198.18.0.3/32"}, ProbeAddress: "198.18.0.3", Port: 9192, Protocol: "tcp"})
		netOutput(t, target, "ip", "addr", "add", "198.18.0.3/32", "dev", "eth0")
		startNetworkProcess(t, target, filepath.Join(private, "echo2.log"), []string{"VPNCTL_WORKER=m3-echo", "VPNCTL_PROBE_TARGET=198.18.0.3"}, worker, "-test.run=^TestNetworkWorker$")
	}
	for r, ns := range relays {
		key, pub := wgKeyPair(t)
		id := fmt.Sprintf("r%d", r)
		principal := "agent"
		if opts.independentRecipients {
			principal = "agent-" + id
			agent = f.controller.enroll(ns, principal)
		}
		principals[id] = principal
		keyfile := filepath.Join(private, id+".key")
		mustWrite(t, keyfile, key)
		relay := relaycatalog.Relay{ID: id, PublicKey: pub, KeyGeneration: 1}
		for u, prefix := range []string{"192.0.2", "198.51.100", "203.0.113", "198.19.0"}[:opts.underlays] {
			ep := fmt.Sprintf("ep%d", u)
			relay.Endpoints = append(relay.Endpoints, relaycatalog.Endpoint{ID: ep, Address: fmt.Sprintf("%s.%d:%d", prefix, 11+r, 51820+u)})
			f.spec.Paths = append(f.spec.Paths, relaycatalog.Path{ID: fmt.Sprintf("p%d%d", r, u), NodeID: "robot", RelayID: id, EndpointID: ep, UnderlayID: fmt.Sprintf("lan%d", u), TargetIDs: []string{"app"}})
		}
		if opts.extraTarget {
			for i := range f.spec.Paths {
				f.spec.Paths[i].TargetIDs = []string{"app", "app2"}
			}
		}
		f.spec.Relays = append(f.spec.Relays, relay)
		f.recipients = append(f.recipients, &m3Recipient{t: t, ns: ns, config: agent, relay: id, cache: filepath.Join(private, id+"-cache"), key: keyfile, results: results, generation: 1})
	}
	f.controller.apply(f.spec, 3600)
	for _, r := range f.recipients {
		f.controller.grant(r.relay, principals[r.relay])
	}
	startNetworkProcess(t, target, filepath.Join(private, "echo.log"), []string{"VPNCTL_WORKER=m3-echo"}, worker, "-test.run=^TestNetworkWorker$")
	f.install()
	return f
}

func (f *m3AuthorityFixture) nodeCall(action, path string) []byte {
	f.t.Helper()
	a := []string{integrationBinary(f.t), "node", "relay", action, "--config", f.node}
	if path != "" {
		a = append(a, "--path-id", path)
	}
	return []byte(nodeAdmissionOutput(f.t, f, a...))
}

// Retry only an explicit failure before ownership admission. Operation errors
// (including uncertain mutations and foreign conflicts) are never replayed.
func nodeAdmissionOutput(t *testing.T, f *m3AuthorityFixture, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 65*time.Second)
	defer cancel()
	log, err := os.CreateTemp(f.results, "node-admission-*.log")
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	for {
		b, err := netCommand(ctx, f.robot, args...).CombinedOutput()
		if _, writeErr := log.Write(b); writeErr != nil {
			t.Fatal(writeErr)
		}
		if err == nil {
			return strings.TrimSpace(string(b))
		}
		var out struct {
			SchemaVersion int             `json:"schema_version"`
			State         string          `json:"state"`
			Reason        string          `json:"reason"`
			KernelReady   bool            `json:"kernel_ready"`
			Activated     bool            `json:"activated"`
			Guarded       bool            `json:"guarded"`
			Reservation   json.RawMessage `json:"reservation"`
		}
		first, _, _ := strings.Cut(string(b), "\n")
		if ctx.Err() != nil || json.Unmarshal([]byte(first), &out) != nil || out.SchemaVersion != 1 || out.State != "blocked" || out.Reason != "ownership_unavailable" || out.KernelReady || out.Activated || out.Guarded || len(out.Reservation) != 0 {
			t.Fatalf("node operation failed: %v %s (attempts: %s)", err, b, log.Name())
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func (f *m3AuthorityFixture) releaseNodeCandidates() {
	for i, p := range f.plan.Paths {
		netOutput(f.t, f.robot, "ip", "rule", "del", "priority", fmt.Sprint(28000+i))
		netOutput(f.t, f.robot, "ip", "route", "del", m3Target+"/32", "table", fmt.Sprint(28000+i))
		f.nodeCall("release", p.PathID)
	}
}
func (f *m3AuthorityFixture) install() {
	f.nodeCall("refresh", "")
	if err := json.Unmarshal(f.nodeCall("plan", ""), &f.plan); err != nil {
		f.t.Fatal(err)
	}
	for _, p := range f.plan.Paths {
		f.nodeCall("prepare", p.PathID)
	}
	for _, r := range f.recipients {
		r.require("refresh", -1, 0)
		for ep := 0; ep < len(f.spec.Relays[0].Endpoints); ep++ {
			r.require("apply", ep, 51820+ep)
		}
		r.start()
		r.ready()
	}
	for r, recipient := range f.recipients {
		out := recipient.require("inspect", -1, 0)
		if len(out.Endpoints) != len(f.spec.Relays[0].Endpoints) {
			f.t.Fatal("missing endpoint", out)
		}
		ifaces := []string{}
		for _, ep := range out.Endpoints {
			ifaces = append(ifaces, fmt.Sprintf("%q", ep.Interface))
		}
		// Deployment fixture forwarding/NAT remains separate from the product
		// source/target ACL and lease guards, which run before this chain.
		netOutput(f.t, recipient.ns, "nft", "delete", "table", "ip", "m3")
		targets := []string{}
		for _, target := range f.spec.Targets {
			targets = append(targets, target.ProbeAddress)
		}
		(relayUplink{relay: recipient.ns}).nft(f.t, fmt.Sprintf(`table ip m3 {
 chain forward { type filter hook forward priority filter; policy drop;
 iifname { %s } oifname "uplink0" ip daddr { %s } tcp dport 9192 accept
 iifname "uplink0" oifname { %s } ct state established,related accept
 }
 chain postrouting { type nat hook postrouting priority srcnat; policy accept;
 oifname "uplink0" ip saddr 10.78.0.0/16 ip daddr { %s } tcp dport 9192 snat to 198.18.0.%d
 }
}`, strings.Join(ifaces, ", "), strings.Join(targets, ", "), strings.Join(ifaces, ", "), strings.Join(targets, ", "), 11+r))
	}
	for i, p := range f.plan.Paths {
		source := strings.TrimSuffix(p.InnerAddress, "/32")
		table := fmt.Sprint(28000 + i)
		netOutput(f.t, f.robot, "ip", "route", "replace", m3Target+"/32", "dev", p.Pin.WGInterface, "src", source, "table", table)
		netOutput(f.t, f.robot, "ip", "rule", "add", "priority", table, "from", source+"/32", "lookup", table)
	}
}
func (f *m3AuthorityFixture) probe(p relayplan.Candidate) m3Probe {
	f.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := netCommand(ctx, f.robot, f.worker, "-test.run=^TestNetworkWorker$")
	cmd.Env = append(os.Environ(), "VPNCTL_WORKER=m3-probe", "VPNCTL_PROBE_SOURCE="+strings.TrimSuffix(p.InnerAddress, "/32"))
	b, err := cmd.Output()
	var result m3Probe
	if err != nil || json.Unmarshal(b, &result) != nil {
		f.t.Fatalf("probe %s: %v %s", p.PathID, err, b)
	}
	if result.OK {
		for i, r := range f.recipients {
			if r.relay == p.RelayID && result.Source != fmt.Sprintf("198.18.0.%d", 11+i) {
				f.t.Fatal("TCP used wrong relay", p.PathID, result.Source)
			}
		}
	}
	return result
}

func TestNetns_M3AuthorityMatrix(t *testing.T) {
	requireNetwork(t)
	for _, fault := range []string{"withdraw", "path-disabled", "peer-removed", "endpoint-removed", "key-generation", "identity-revoked", "identity-removed", "expired"} {
		t.Run(fault, func(t *testing.T) {
			f := newM3AuthorityFixture(t)
			report := map[string]any{"schema_version": 1, "fault": fault, "completed": false, "scope": "real controller mTLS + product prepare/apply/supervise; fixture source routes and forwarding/NAT; four simultaneous paths, not fleet SLO"}
			defer func() {
				b, err := json.MarshalIndent(report, "", "  ")
				if err != nil {
					t.Error(err)
					return
				}
				if err = os.WriteFile(filepath.Join(f.results, "report.json"), b, 0600); err != nil {
					t.Error(err)
				}
			}()
			streams := []*networkProcess{}
			before := map[string]m3Probe{}
			for _, p := range f.plan.Paths {
				p := p
				eventually(t, 10*time.Second, "initial TCP "+p.PathID, func() error {
					v := f.probe(p)
					before[p.PathID] = v
					if !v.OK {
						return fmt.Errorf("unreachable: %+v", v)
					}
					return nil
				})
				stream := startNetworkProcess(t, f.robot, filepath.Join(f.results, p.PathID+"-stream.jsonl"), []string{"VPNCTL_WORKER=lease-stream", "VPNCTL_PROBE_SOURCE=" + strings.TrimSuffix(p.InnerAddress, "/32")}, f.worker, "-test.run=^TestNetworkWorker$")
				streams = append(streams, stream)
				eventually(t, 3*time.Second, "existing TCP "+p.PathID, func() error {
					b, _ := os.ReadFile(stream.log)
					if !strings.Contains(string(b), `"ok":true`) {
						return fmt.Errorf("no successful echo")
					}
					return nil
				})
			}
			report["before"] = before
			report["kernel_before"] = f.snapshot()
			report["approval_before"] = f.controller.status()
			at := time.Now().UTC()
			report["fault_at"] = at
			lastAllowedObservation := at.Add(11 * time.Second)
			spec := copyM3Spec(f.spec)
			switch fault {
			case "withdraw":
				for _, r := range f.recipients {
					f.controller.grant(r.relay, "")
				}
			case "identity-revoked":
				cfg, err := config.Load(f.recipients[0].config)
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
			case "identity-removed":
				f.controller.admin(api.AdminRequest{Operation: "node.remove", NodeID: "agent"})
			case "expired":
				s := f.controller.apply(spec, 60)
				report["approval_deadline"] = s.ExpiresAt
				lastAllowedObservation = s.ExpiresAt.Add(500 * time.Millisecond)
				for _, r := range f.recipients {
					r.ready()
				}
				// Real elapsed TTL, no wall-clock mutation and no controller stop.
				time.Sleep(time.Until(s.ExpiresAt.Add(200 * time.Millisecond)))
			default:
				for i := range spec.Paths {
					spec.Paths[i].Disabled = true
				}
				f.controller.apply(spec, 3600)
				if fault != "path-disabled" {
					spec.Paths = nil
					if fault == "endpoint-removed" {
						for i := range spec.Relays {
							spec.Relays[i].Endpoints = []relaycatalog.Endpoint{{ID: "empty", Address: fmt.Sprintf("192.0.2.%d:51999", 11+i)}}
						}
					}
					if fault == "key-generation" {
						for i := range spec.Relays {
							key, pub := wgKeyPair(t)
							mustWrite(t, f.recipients[i].key, key)
							spec.Relays[i].PublicKey = pub
							spec.Relays[i].KeyGeneration++
							f.recipients[i].generation++
						}
					}
					f.controller.apply(spec, 3600)
				}
			}
			report["approval_after"] = f.controller.status()
			blocked := map[string]m3Probe{}
			for _, p := range f.plan.Paths {
				p := p
				eventually(t, 12*time.Second, "blocked "+p.PathID, func() error {
					v := f.probe(p)
					blocked[p.PathID] = v
					if v.OK {
						return fmt.Errorf("still open")
					}
					return nil
				})
			}
			report["fault_probes"] = blocked
			kernel := map[string]string{}
			for _, r := range f.recipients {
				kernel[r.relay] = netOutput(t, r.ns, "wg", "show", "all", "allowed-ips")
				if kernel[r.relay] != "" {
					t.Fatal("revoked managed peers remain", kernel[r.relay])
				}
			}
			report["kernel_after"] = kernel
			report["kernel_blocked"] = f.snapshot()
			// Observe a denied approval, then a transport outage. Restarted
			// supervision must not revive the cached pre-denial permissions.
			for _, r := range f.recipients {
				r.watch.terminate(t)
				(relayUplink{relay: r.ns}).nft(t, `table inet authority_outage {
 chain output { type filter hook output priority -310; policy accept;
 ip daddr 192.0.2.11 tcp dport 9443 counter drop
 }
}`)
				r.start()
			}
			time.Sleep(2 * time.Second)
			for _, p := range f.plan.Paths {
				if f.probe(p).OK {
					t.Fatal("outage resurrected denied approval")
				}
			}
			for _, r := range f.recipients {
				r.watch.terminate(t)
				outage := netOutput(t, r.ns, "nft", "list", "table", "inet", "authority_outage")
				if strings.Contains(outage, "counter packets 0 bytes 0") {
					t.Fatal("controller outage was not exercised")
				}
				netOutput(t, r.ns, "nft", "delete", "table", "inet", "authority_outage")
			}
			// Remove fixture source rules and product node candidates before a
			// new path definition. Retired IDs/keys are deliberately not reused.
			f.releaseNodeCandidates()
			if fault == "identity-revoked" || fault == "identity-removed" {
				newConfig := f.controller.enroll(f.recipients[0].ns, "replacement")
				for _, r := range f.recipients {
					r.config = newConfig
					r.cache = filepath.Join(f.private, r.relay+"-replacement")
				}
			}
			recovery := copyM3Spec(f.spec)
			if fault == "peer-removed" || fault == "endpoint-removed" || fault == "key-generation" {
				for i := range recovery.Paths {
					recovery.Paths[i].ID += "-new"
				}
			}
			for i := range recovery.Paths {
				recovery.Paths[i].Disabled = false
			}
			if fault == "key-generation" {
				for i := range recovery.Relays {
					recovery.Relays[i].PublicKey = spec.Relays[i].PublicKey
					recovery.Relays[i].KeyGeneration = spec.Relays[i].KeyGeneration
				}
			}
			f.controller.apply(recovery, 3600)
			principal := "agent"
			if fault == "identity-revoked" || fault == "identity-removed" {
				principal = "replacement"
			}
			for _, r := range f.recipients {
				f.controller.grant(r.relay, principal)
			}
			f.install()
			restored := map[string]m3Probe{}
			for _, p := range f.plan.Paths {
				p := p
				eventually(t, 10*time.Second, "recovered "+p.PathID, func() error {
					v := f.probe(p)
					restored[p.PathID] = v
					if !v.OK {
						return fmt.Errorf("not restored")
					}
					return nil
				})
			}
			report["recovery_probes"] = restored
			report["kernel_recovery"] = f.snapshot()
			report["approval_recovery"] = f.controller.status()
			timing := map[string]any{}
			for _, stream := range streams {
				stream.stop()
				b, err := os.ReadFile(stream.log)
				if err != nil {
					t.Fatal(err)
				}
				var last, first time.Time
				for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
					var e leaseStreamEvent
					if json.Unmarshal([]byte(line), &e) != nil {
						t.Fatal("invalid stream event")
					}
					if e.OK {
						last = e.At
					} else if first.IsZero() {
						first = e.At
					}
				}
				if last.IsZero() || first.IsZero() {
					t.Fatal("fault did not interrupt existing TCP")
				}
				if last.After(lastAllowedObservation) {
					t.Fatal("existing TCP passed beyond enforcement/probe observation bound", last, lastAllowedObservation)
				}
				timing[filepath.Base(stream.log)] = map[string]any{"last_success_at": last, "first_failure_at": first, "probe_timeout_ms": 500, "probe_cadence_ms": 100}
			}
			report["existing_tcp"] = timing
			report["completed"] = true
		})
	}
}

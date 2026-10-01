//go:build integration

// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package integration

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

const m3Target = "198.18.0.2"

type m3Probe struct {
	OK      bool    `json:"ok"`
	Source  string  `json:"server_observed_source,omitempty"`
	Failure string  `json:"failure,omitempty"`
	MS      float64 `json:"duration_ms"`
}

func serveM3Echo() error {
	l, e := net.Listen("tcp4", m3Target+":9192")
	if e != nil {
		return e
	}
	defer l.Close()
	for {
		c, e := l.Accept()
		if e != nil {
			return e
		}
		go func() {
			defer c.Close()
			for {
				idle := 2 * time.Second
				if os.Getenv("VPNCTL_VM_WORKER") == "1" {
					// A VM pause must test the kernel gate, not the fixture's
					// application idle timeout after the VM resumes.
					idle = 30 * time.Minute
				}
				c.SetDeadline(time.Now().Add(idle))
				b := make([]byte, 16)
				if _, e := io.ReadFull(c, b); e != nil {
					return
				}
				fmt.Fprintln(c, c.RemoteAddr().String())
				c.Write(b)
			}
		}()
	}
}
func runM3Probe() error {
	began := time.Now()
	r := m3Probe{}
	probe := func() error {
		c, e := m3Dial(time.Second)
		if e != nil {
			return e
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(time.Second))
		b := make([]byte, 16)
		if _, e = rand.Read(b); e != nil {
			return e
		}
		if _, e = c.Write(b); e != nil {
			return e
		}
		reader := bufio.NewReader(io.LimitReader(c, 256))
		line, e := reader.ReadString('\n')
		if e != nil {
			return e
		}
		source, _, e := net.SplitHostPort(strings.TrimSpace(line))
		if e != nil {
			return e
		}
		got := make([]byte, 16)
		if _, e = io.ReadFull(reader, got); e != nil {
			return e
		}
		if !bytes.Equal(got, b) {
			return fmt.Errorf("nonce mismatch")
		}
		r.OK = true
		r.Source = source
		return nil
	}
	if e := probe(); e != nil {
		var n net.Error
		switch {
		case errors.As(e, &n) && n.Timeout():
			r.Failure = "timeout"
		case errors.Is(e, syscall.ENETUNREACH) || errors.Is(e, syscall.EHOSTUNREACH):
			r.Failure = "unreachable"
		case errors.Is(e, syscall.ECONNREFUSED):
			r.Failure = "refused"
		default:
			return e
		}
	}
	r.MS = float64(time.Since(began).Microseconds()) / 1000
	return json.NewEncoder(os.Stdout).Encode(r)
}

// Source routing is installed explicitly by the four-path test fixture.
func m3Dial(timeout time.Duration) (net.Conn, error) {
	d := net.Dialer{Timeout: timeout}
	if source := os.Getenv("VPNCTL_PROBE_SOURCE"); source != "" {
		d.LocalAddr = &net.TCPAddr{IP: net.ParseIP(source)}
	}
	return d.Dial("tcp4", m3Target+":9192")
}

type m3Path struct {
	relay, underlay                            int
	iface, endpoint, source, inner, relayInner string
	mark                                       int
}

// Prepared candidate paths, explicit test-owned route changes. This does not
// run the product's automatic selection, relay catalog or failover controller.
func TestNetns_M3PathTopology(t *testing.T) {
	requireNetwork(t)
	worker, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	robot, relays, target := newM3Topology(t)
	checkM3Topology(t, worker, robot, relays, target)
}

// Only test-owned links, forwarding and NAT; callers supply production tunnels.
func newM3Topology(t *testing.T) (string, []string, string) {
	t.Helper()
	suffix := fmt.Sprintf("%x", time.Now().UnixNano()&0xfffffff)
	ns := make([]string, 4)
	for i := range ns {
		ns[i] = fmt.Sprintf("m3%s-%d", suffix, i)
		run(t, ".", "ip", "netns", "add", ns[i])
		name := ns[i]
		t.Cleanup(func() { _ = exec.Command("ip", "netns", "del", name).Run() })
		netOutput(t, name, "ip", "link", "set", "lo", "up")
	}
	robot, relays, target := ns[0], ns[1:3], ns[3]
	bridges := make([]string, 3)
	for i := range bridges {
		bridges[i] = fmt.Sprintf("m3b%s%d", suffix, i)
		br := bridges[i]
		run(t, ".", "ip", "link", "add", br, "type", "bridge")
		t.Cleanup(func() { _ = exec.Command("ip", "link", "del", br).Run() })
		run(t, ".", "ip", "link", "set", br, "up")
	}
	linkIndex := 0
	link := func(namespace, iface, addr, bridge string) {
		t.Helper()
		host := fmt.Sprintf("m3v%s%x", suffix, linkIndex)
		linkIndex++
		run(t, ".", "ip", "link", "add", host, "type", "veth", "peer", "name", iface, "netns", namespace)
		run(t, ".", "ip", "link", "set", host, "master", bridge)
		run(t, ".", "ip", "link", "set", host, "up")
		netOutput(t, namespace, "ip", "addr", "add", addr, "dev", iface)
		netOutput(t, namespace, "ip", "link", "set", iface, "up")
	}
	for u, prefix := range []string{"192.0.2", "198.51.100"} {
		iface := fmt.Sprintf("wan%d", u)
		link(robot, iface, prefix+".10/24", bridges[u])
		for r, relay := range relays {
			link(relay, iface, fmt.Sprintf("%s.%d/24", prefix, 11+r), bridges[u])
		}
	}
	link(target, "eth0", m3Target+"/24", bridges[2])
	for r, relay := range relays {
		addr := fmt.Sprintf("198.18.0.%d", 11+r)
		link(relay, "uplink0", addr+"/24", bridges[2])
		(relayUplink{relay: relay}).forwarding(t, true)
		(relayUplink{relay: relay}).nft(t, fmt.Sprintf(`table ip m3 {
   chain forward { type filter hook forward priority filter; policy drop;
    iifname { "wg0", "wg1" } oifname "uplink0" ip daddr 198.18.0.2 tcp dport 9192 accept
    iifname "uplink0" oifname { "wg0", "wg1" } ct state established,related accept
   }
   chain postrouting { type nat hook postrouting priority srcnat; policy accept;
    oifname "uplink0" ip saddr 10.78.0.0/16 ip daddr 198.18.0.2 tcp dport 9192 snat to %s
   }
  }`, addr))
	}
	return robot, relays, target
}

func checkM3Topology(t *testing.T, worker, robot string, relays []string, target string) {
	private := t.TempDir()
	results, e := os.MkdirTemp(os.Getenv("VPNCTL_ARTIFACT_DIR"), "m3-topology-")
	if e != nil {
		t.Fatal(e)
	}
	report := struct {
		SchemaVersion int              `json:"schema_version"`
		Completed     bool             `json:"completed"`
		Scope         string           `json:"scope"`
		Phases        []map[string]any `json:"phases"`
	}{SchemaVersion: 1, Scope: "static four-path kernel topology; explicit selection; no automatic failover, session migration or SLO qualification"}
	defer func() {
		report.Completed = report.Completed && !t.Failed()
		b, e := json.MarshalIndent(report, "", "  ")
		if e != nil {
			t.Error(e)
			return
		}
		if e = os.WriteFile(filepath.Join(results, "report.json"), b, 0600); e != nil {
			t.Error(e)
		}
	}()
	relayKeys, relayPubs := make([]string, 2), make([]string, 2)
	for r := range relays {
		relayKeys[r], relayPubs[r] = wgKeyPair(t)
	}
	checkM3LocalPlans(t, robot, relays, target, private, relayKeys, relayPubs)
	var paths []m3Path
	for r, relay := range relays {
		for u, prefix := range []string{"192.0.2", "198.51.100"} {
			i := r*2 + u
			p := m3Path{r, u, fmt.Sprintf("wg%d", i), fmt.Sprintf("%s.%d", prefix, 11+r), prefix + ".10", fmt.Sprintf("10.78.%d.2", i), fmt.Sprintf("10.78.%d.1", i), 101 + i}
			robotKey, robotPub := wgKeyPair(t)
			relayKey, relayPub := relayKeys[r], relayPubs[r]
			robotKeyFile := filepath.Join(private, fmt.Sprintf("robot-%d.key", i))
			relayKeyFile := filepath.Join(private, fmt.Sprintf("relay-%d.key", i))
			mustWrite(t, robotKeyFile, robotKey)
			mustWrite(t, relayKeyFile, relayKey)
			rif := fmt.Sprintf("wg%d", u)
			port := strconv.Itoa(51820 + u)
			for _, end := range []struct{ ns, iface, addr string }{{robot, p.iface, p.inner}, {relay, rif, p.relayInner}} {
				netOutput(t, end.ns, "ip", "link", "add", end.iface, "type", "wireguard")
				netOutput(t, end.ns, "ip", "addr", "add", end.addr+"/32", "dev", end.iface)
				netOutput(t, end.ns, "ip", "link", "set", end.iface, "mtu", "1280", "up")
			}
			netOutput(t, robot, "wg", "set", p.iface, "private-key", robotKeyFile, "fwmark", strconv.Itoa(p.mark), "peer", relayPub, "endpoint", p.endpoint+":"+port, "allowed-ips", m3Target+"/32")
			netOutput(t, relay, "wg", "set", rif, "private-key", relayKeyFile, "listen-port", port, "peer", robotPub, "allowed-ips", p.inner+"/32")
			netOutput(t, relay, "ip", "route", "add", p.inner+"/32", "dev", rif)
			table := strconv.Itoa(p.mark)
			netOutput(t, robot, "ip", "rule", "add", "priority", strconv.Itoa(20000+p.mark), "fwmark", table, "lookup", table)
			netOutput(t, robot, "ip", "route", "add", "unreachable", "default", "table", table, "metric", "32760")
			netOutput(t, robot, "ip", "route", "add", p.endpoint+"/32", "dev", fmt.Sprintf("wan%d", u), "src", p.source, "table", table)
			paths = append(paths, p)
		}
	}
	echo := startNetworkProcess(t, target, filepath.Join(private, "echo.log"), []string{"VPNCTL_WORKER=m3-echo"}, worker, "-test.run=^TestNetworkWorker$")
	defer echo.stop()
	probe := func() m3Probe {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		cmd := netCommand(ctx, robot, worker, "-test.run=^TestNetworkWorker$")
		cmd.Env = append(os.Environ(), "VPNCTL_WORKER=m3-probe")
		b, e := cmd.CombinedOutput()
		if e != nil {
			t.Fatalf("probe worker: %v: %s", e, b)
		}
		var v m3Probe
		if e = json.Unmarshal(b, &v); e != nil {
			t.Fatal(e)
		}
		return v
	}
	selectPath := func(p m3Path) {
		netOutput(t, robot, "ip", "route", "replace", m3Target+"/32", "dev", p.iface, "src", p.inner)
	}
	observe := func(phase string, p m3Path, want bool) {
		t.Helper()
		started := time.Now()
		v := probe()
		if want {
			deadline := started.Add(10 * time.Second)
			for !v.OK && time.Now().Before(deadline) {
				time.Sleep(100 * time.Millisecond)
				v = probe()
			}
		}
		r := map[string]any{"phase": phase, "at": time.Now().UTC(), "relay": p.relay, "underlay": p.underlay, "expected_reachable": want, "probe": v, "ready_after_ms": float64(time.Since(started).Microseconds()) / 1000, "application_route": netOutput(t, robot, "ip", "route", "get", m3Target)}
		report.Phases = append(report.Phases, r)
		if v.OK != want {
			t.Log("robot routes", netOutput(t, robot, "ip", "-4", "route", "show", "table", "all"))
			t.Log("robot rules", netOutput(t, robot, "ip", "rule", "show"))
			t.Log("robot endpoints", netOutput(t, robot, "wg", "show", "all", "endpoints"))
			t.Log("robot handshakes", netOutput(t, robot, "wg", "show", "all", "latest-handshakes"))
			for _, ns := range relays {
				t.Log("relay routes", netOutput(t, ns, "ip", "-4", "route", "show", "table", "all"))
				t.Log("relay endpoints", netOutput(t, ns, "wg", "show", "all", "endpoints"))
			}
			t.Fatalf("%s path %s: %+v expected=%t", phase, p.iface, v, want)
		}
		if want && v.Source != fmt.Sprintf("198.18.0.%d", 11+p.relay) {
			t.Fatalf("wrong relay source: %+v", v)
		}
		if want {
			appRoute := r["application_route"].(string)
			if !strings.Contains(appRoute, "dev "+p.iface+" ") || !strings.Contains(appRoute, "src "+p.inner+" ") {
				t.Fatal("wrong application route", appRoute)
			}
			route := netOutput(t, robot, "ip", "route", "get", p.endpoint, "mark", strconv.Itoa(p.mark))
			if !strings.Contains(route, "dev "+fmt.Sprintf("wan%d", p.underlay)) || !strings.Contains(route, "src "+p.source) {
				t.Fatal("wrong outer route", route)
			}
			r["transport_route"] = route
		}
	}
	// No direct target route/default route exists before selecting a tunnel.
	initial := probe()
	report.Phases = append(report.Phases, map[string]any{"phase": "no-vpn-route", "at": time.Now().UTC(), "expected_reachable": false, "probe": initial})
	if initial.OK {
		t.Fatal("target is reachable without a VPN route")
	}
	for _, p := range paths {
		selectPath(p)
		observe("candidate", p, true)
	}
	a, b, c := paths[0], paths[2], paths[1]
	for cycle := 0; cycle < 3; cycle++ {
		prefix := fmt.Sprintf("cycle-%d-", cycle)
		selectPath(a)
		netOutput(t, relays[0], "ip", "link", "set", "uplink0", "down")
		observe(prefix+"relay-a-down", a, false)
		selectPath(b)
		observe(prefix+"explicit-relay-b", b, true)
		netOutput(t, relays[0], "ip", "link", "set", "uplink0", "up")
		selectPath(a)
		netOutput(t, robot, "ip", "link", "set", "wan0", "down")
		observe(prefix+"underlay-0-down", a, false)
		selectPath(c)
		observe(prefix+"explicit-underlay-1", c, true)
		netOutput(t, robot, "ip", "link", "set", "wan0", "up")
		selectPath(a)
		// Linux removes device-bound policy routes on link-down. Link-up alone
		// must not silently fall back to main: reconcile the owned tables first.
		observe(prefix+"link-up-before-reconcile", a, false)
		for _, p := range paths {
			if p.underlay == 0 {
				netOutput(t, robot, "ip", "route", "replace", p.endpoint+"/32", "dev", "wan0", "src", p.source, "table", strconv.Itoa(p.mark))
			}
		}
		observe(prefix+"restored-after-reconcile", a, true)
		selectPath(b)
		observe(prefix+"relay-b-after-reconcile", b, true)
	}
	// A tempting main-table route must not defeat the chosen transport policy.
	selectPath(a)
	table := strconv.Itoa(a.mark)
	netOutput(t, robot, "ip", "route", "add", a.endpoint+"/32", "via", "198.51.100.11", "dev", "wan1")
	netOutput(t, robot, "ip", "route", "del", a.endpoint+"/32", "table", table)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	out, e := netCommand(ctx, robot, "ip", "route", "get", a.endpoint, "mark", table).CombinedOutput()
	cancel()
	if e == nil || !(strings.Contains(string(out), "unreachable") || strings.Contains(string(out), "No route to host")) {
		t.Fatal("transport pin silently fell through", string(out), e)
	}
	observe("pin-missing-no-fallback", a, false)
	selectPath(c)
	observe("explicit-alternative-still-works", c, true)
	netOutput(t, robot, "ip", "route", "del", a.endpoint+"/32")
	netOutput(t, robot, "ip", "route", "add", a.endpoint+"/32", "dev", "wan0", "src", a.source, "table", table)
	selectPath(a)
	observe("pin-restored", a, true)
	if got := netOutput(t, target, "wg", "show", "interfaces"); got != "" {
		t.Fatal("server unexpectedly has WG")
	}
	report.Completed = true
	t.Logf("M3 prepared topology: %d phases, four candidates, manual switches; results=%s", len(report.Phases), results)
}

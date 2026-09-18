// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package uplink

import (
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

type fakeCollector map[string]Link

func (f fakeCollector) Collect(_ context.Context, c LinkConfig) Link { return f[c.ID] }

type probeResult struct {
	route Route
	check Check
}
type fakeProber map[string]probeResult

func (f fakeProber) Probe(_ context.Context, e Endpoint, _ string) (Route, Check) {
	r := f[e.Host]
	return r.route, r.check
}
func fixtureConfig() Config {
	return Config{IntervalSec: 60, TimeoutMS: 100, Links: []LinkConfig{{ID: "lan", Interface: "eth0", Kind: "ethernet"}}, Targets: []TargetConfig{{ID: "server", Endpoint: Endpoint{Host: "target", Port: 80, Protocol: "tcp"}, Interface: "wg0", RelayID: "hub", RelayProbe: &Endpoint{Host: "relay", Port: 51900, Protocol: "udp-echo"}}}, Controller: &Endpoint{Host: "control", Port: 443, Protocol: "tcp"}}
}
func TestFailureStagesDoNotInventRootCause(t *testing.T) {
	cases := []struct {
		name                        string
		link, relay, route, service Check
		stage, underlay             string
	}{
		{"healthy", Up(), Up(), Up(), Check{State: "up", RTTMs: ptr(2.)}, "none", "up"},
		{"no-modem-and-no-link", Down("no_modem"), Down("reachability_timeout"), Down("no_route"), Down("route_blocked"), "underlay", "down"},
		{"tunnel-failed", Up(), Down("reachability_timeout"), Up(), Down("reachability_timeout"), "relay_tunnel", "up"},
		{"route-missing", Up(), Up(), Down("no_route"), Down("route_blocked"), "overlay_route", "up"},
		{"server-or-forwarding", Up(), Up(), Up(), Down("reachability_timeout"), "server_endpoint", "up"},
		{"collector-permission", Unknown("denied"), Unknown("denied"), Unknown("denied"), Unknown("denied"), "unknown", "unknown"},
		{"unlisted-working-link", Down("interface_absent"), Up(), Up(), Check{State: "up", RTTMs: ptr(1.)}, "none", "unknown"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := fixtureConfig()
			collector := fakeCollector{"lan": {ID: "lan", Interface: "eth0", Kind: "ethernet", Check: tc.link, Modem: Unknown("not_configured"), GatewayState: Unknown("not_configured"), DNS: Unknown("not_configured")}}
			prober := fakeProber{"relay": {Route{Check: Up(), Interface: "wg0"}, tc.relay}, "target": {Route{Check: tc.route, Interface: "wg0"}, tc.service}, "control": {Route{Check: Up(), Interface: "eth0"}, Down("service_refused")}}
			s := (Observer{cfg, collector, prober}).Collect(context.Background())
			if s.Targets[0].FailureStage != tc.stage || s.Underlay.State != tc.underlay || s.Links[0].Controller.State != "down" {
				t.Fatalf("%+v", s)
			}
			if e := s.Validate(time.Now()); e != nil {
				t.Fatal(e, s)
			}
		})
	}
}
func ptr[T any](v T) *T { return &v }

type commandFake struct {
	values map[string]string
	err    error
}

func (f commandFake) RunContext(context.Context, string, ...string) error { return f.err }
func (f commandFake) OutputContext(_ context.Context, name string, args ...string) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	v, ok := f.values[name+" "+strings.Join(args, " ")]
	if !ok {
		return "", fmt.Errorf("unsupported")
	}
	return v, nil
}
func TestModemCollectionNeverLeaksDeviceMetadata(t *testing.T) {
	list := "modem-list.length : 1\nmodem-list.value[1] : /org/freedesktop/ModemManager1/Modem/0"
	for _, tc := range []struct {
		list, state, want string
		err               error
	}{
		{"modem-list.length : 0", "", "no_modem", nil}, {list, "searching", "modem_no_service", nil}, {list, "registered", "modem_no_data", nil}, {list, "connected", "", nil}, {list, "invented", "modem_state_unknown", nil}, {list, "", "modem_collector_unavailable", errors.New("permission denied")}, {"bad", "", "modem_output_invalid", nil},
	} {
		r := commandFake{values: map[string]string{"mmcli --list-modems --output-keyvalue": tc.list, "mmcli --modem 0 --output-keyvalue": "modem.generic.state : " + tc.state + "\nmodem.3gpp.imei : PRIVATE"}, err: tc.err}
		got := collectModem(context.Background(), r, "0")
		if got.Reason != tc.want {
			t.Fatalf("%+v: %+v", tc, got)
		}
	}
}
func TestRootlessCollectorMissingInterfaceAndOptionalTools(t *testing.T) {
	l := (LinuxCollector{Runner: commandFake{err: errors.New("missing command")}}).Collect(context.Background(), LinkConfig{ID: "lte", Interface: "missing0123", Kind: "lte", Modem: "0"})
	if l.Present == nil || *l.Present || l.State != "down" || l.Modem.State != "unknown" || l.DNS.State != "unknown" {
		t.Fatal(l)
	}
}
func TestNetworkProbeRealServiceAndCancellation(t *testing.T) {
	listener, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, e := listener.Accept()
		if e == nil {
			defer c.Close()
			<-time.After(10 * time.Millisecond)
		}
	}()
	port := listener.Addr().(*net.TCPAddr).Port
	runner := commandFake{values: map[string]string{fmt.Sprintf("ip -j route get 127.0.0.1 ipproto 6 dport %d", port): `[{"dev":"lo","prefsrc":"127.0.0.1"}]`}}
	p := NetworkProber{Runner: runner}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	route, result := p.Probe(ctx, Endpoint{Host: "127.0.0.1", Port: port, Protocol: "tcp"}, "")
	if result.State != "up" || result.RTTMs == nil || route.Interface != "lo" {
		t.Fatal(route, result)
	}
	<-done
	listener.Close()
	_, result = p.Probe(ctx, Endpoint{Host: "127.0.0.1", Port: port, Protocol: "tcp"}, "")
	if result.Reason != "service_refused" {
		t.Fatal(result)
	}
	ctx, cancel = context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	_, _ = p.Probe(ctx, Endpoint{Host: "127.0.0.1", Port: port, Protocol: "tcp"}, "")
	if time.Since(start) > time.Second {
		t.Fatal("cancellation blocked")
	}
}
func TestConfigAndSnapshotBounds(t *testing.T) {
	cfg := fixtureConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []func(*Config){func(c *Config) { c.IntervalSec = 1 }, func(c *Config) { c.Links = append(c.Links, c.Links[0]) }, func(c *Config) { c.Targets[0].Host = "host;command" }, func(c *Config) { c.Targets[0].Protocol = "http" }, func(c *Config) { c.Links[0].Modem = "--enable" }} {
		c := fixtureConfig()
		bad(&c)
		if c.Validate() == nil {
			t.Fatal("invalid config accepted")
		}
	}
}

func TestWireGuardTransportUsesLongestPrefixAndMark(t *testing.T) {
	runner := commandFake{values: map[string]string{
		"wg show wg0 allowed-ips": "broad 10.77.0.0/24,198.18.0.0/16\nspecific 198.18.0.2/32",
		"wg show wg0 endpoints":   "broad 192.0.2.1:51820\nspecific 192.0.2.3:51821",
		"wg show wg0 fwmark":      "0x2a",
		"ip -j route get 192.0.2.3 ipproto 17 dport 51821 mark 42": `[{"dev":"wlan0","prefsrc":"192.0.2.2","gateway":"192.0.2.254"}]`,
	}}
	p := NetworkProber{Runner: runner}
	route, peer := p.Transport(context.Background(), Route{Check: Up(), Interface: "wg0", Destination: "198.18.0.2"})
	if route.State != "up" || route.Interface != "wlan0" || route.Destination != "192.0.2.3" || len(peer) != 64 {
		t.Fatal(route, peer)
	}
	route, _ = (NetworkProber{Runner: commandFake{err: errors.New("not authorized")}}).Transport(context.Background(), Route{Check: Up(), Interface: "wg0", Destination: "198.18.0.2"})
	if route.State != "unknown" {
		t.Fatal(route)
	}
}

func TestTLSProbeValidatesPrivateTrustAndReloadsCA(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	addr := server.Listener.Addr().(*net.TCPAddr)
	runner := commandFake{values: map[string]string{fmt.Sprintf("ip -j route get 127.0.0.1 ipproto 6 dport %d", addr.Port): `[{"dev":"lo","prefsrc":"127.0.0.1"}]`}}
	p := NetworkProber{Runner: runner}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	e := Endpoint{Host: "127.0.0.1", Port: addr.Port, Protocol: "tls"}
	_, result := p.Probe(ctx, e, "")
	if result.State != "down" || result.Reason != "tls_handshake_failed" {
		t.Fatal("untrusted certificate accepted", result)
	}
	e.CAFile = filepath.Join(t.TempDir(), "root.pem")
	if err := os.WriteFile(e.CAFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	_, result = p.Probe(ctx, e, "")
	if result.State != "up" || result.RTTMs == nil {
		t.Fatal(result)
	}
	if err := os.WriteFile(e.CAFile, []byte("invalid rotated trust"), 0600); err != nil {
		t.Fatal(err)
	}
	_, result = p.Probe(ctx, e, "")
	if result.State != "unknown" || result.Reason != "trust_unavailable" {
		t.Fatal("stale trust retained", result)
	}
	fifo := filepath.Join(t.TempDir(), "fifo")
	if err := syscall.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readRoots(fifo); err == nil {
		t.Fatal("FIFO accepted")
	}
}
func TestUDPEchoRejectsUnrelatedReply(t *testing.T) {
	conn, e := net.ListenPacket("udp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 100)
		_, addr, e := conn.ReadFrom(buf)
		if e == nil {
			_, _ = conn.WriteTo([]byte("wrong-reply"), addr)
		}
	}()
	port := conn.LocalAddr().(*net.UDPAddr).Port
	p := NetworkProber{Runner: commandFake{values: map[string]string{fmt.Sprintf("ip -j route get 127.0.0.1 ipproto 17 dport %d", port): `[{"dev":"lo"}]`}}}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, result := p.Probe(ctx, Endpoint{Host: "127.0.0.1", Port: port, Protocol: "udp-echo"}, "")
	<-done
	if result.State != "down" || result.Reason != "echo_mismatch" || result.RTTMs != nil {
		t.Fatal(result)
	}
}

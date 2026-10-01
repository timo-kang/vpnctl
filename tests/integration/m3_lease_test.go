//go:build integration

// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package integration

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"vpnctl/internal/config"
	"vpnctl/internal/pki"
	"vpnctl/internal/relayapply"
	"vpnctl/internal/relaycatalog"
)

// This issuer is a fault-injection fixture; mTLS, the recipient CLI, cache,
// supervisor, WireGuard and nftables are production code and real kernels.
type leaseResponse struct {
	Status int                                    `json:"status"`
	Views  map[string]relaycatalog.DeploymentView `json:"views"`
}

func serveLeaseIssuer() error {
	dir := os.Getenv("VPNCTL_LEASE_DIR")
	ca, err := os.ReadFile(filepath.Join(dir, "ca.crt"))
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return fmt.Errorf("invalid fixture CA")
	}
	cert, err := tls.LoadX509KeyPair(filepath.Join(dir, "server.crt"), filepath.Join(dir, "server.key"))
	if err != nil {
		return err
	}
	l, err := tls.Listen("tcp4", "192.0.2.11:9443", &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots})
	if err != nil {
		return err
	}
	defer l.Close()
	if err = os.WriteFile(filepath.Join(dir, "ready"), []byte("1"), 0600); err != nil {
		return err
	}
	s := &http.Server{ReadHeaderTimeout: time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.URL.Path != "/relay-deployment" || r.TLS.PeerCertificates[0].Subject.CommonName != "robot" {
			http.Error(w, "denied", 403)
			return
		}
		b, e := os.ReadFile(filepath.Join(dir, "response.json"))
		var response leaseResponse
		if e != nil || json.Unmarshal(b, &response) != nil {
			http.Error(w, "fixture unavailable", 503)
			return
		}
		if response.Status != 200 {
			http.Error(w, "injected failure", response.Status)
			return
		}
		v, ok := response.Views[r.URL.Query().Get("relay_id")]
		if !ok {
			http.Error(w, "denied", 403)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(v)
	})}
	return s.Serve(l)
}

type leaseStreamEvent struct {
	At time.Time `json:"at"`
	OK bool      `json:"ok"`
}

// Never reconnect: failure must concern the TCP socket opened before the fault.
func runLeaseStream() error {
	c, err := net.DialTimeout("tcp4", m3Target+":9192", time.Second)
	if err != nil {
		return err
	}
	defer c.Close()
	reader := bufio.NewReader(c)
	for n := 0; ; n++ {
		if err == nil {
			c.SetDeadline(time.Now().Add(500 * time.Millisecond))
			payload := []byte(fmt.Sprintf("%016d", n))
			_, err = c.Write(payload)
			if err == nil {
				_, err = reader.ReadString('\n')
			}
			got := make([]byte, 16)
			if err == nil {
				_, err = io.ReadFull(reader, got)
			}
			if err == nil && !bytes.Equal(got, payload) {
				err = fmt.Errorf("echo mismatch")
			}
		}
		if e := json.NewEncoder(os.Stdout).Encode(leaseStreamEvent{time.Now().UTC(), err == nil}); e != nil {
			return e
		}
		time.Sleep(100 * time.Millisecond)
	}
}

type m3LeaseFixture struct {
	t                   *testing.T
	dir, config, worker string
	results             string
	relays              []string
	watch               []*networkProcess
	response            leaseResponse
	issuer              *planIssuer
	sequence            int
}

func newM3LeaseFixture(t *testing.T, relays []string, private string, issuer *planIssuer) *m3LeaseFixture {
	t.Helper()
	f := &m3LeaseFixture{t: t, dir: filepath.Join(private, "lease-pki"), relays: relays, watch: make([]*networkProcess, len(relays)), response: leaseResponse{Status: 200, Views: map[string]relaycatalog.DeploymentView{}}}
	f.issuer = issuer
	var resultErr error
	f.results, resultErr = os.MkdirTemp(os.Getenv("VPNCTL_ARTIFACT_DIR"), "m3-lease-")
	if resultErr != nil {
		t.Fatal(resultErr)
	}
	if err := os.Mkdir(f.dir, 0700); err != nil {
		t.Fatal(err)
	}
	caKey, caCert := filepath.Join(f.dir, "ca.key"), filepath.Join(f.dir, "ca.crt")
	if err := pki.GenerateCA(caKey, caCert, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := pki.GenerateServerCert(caCert, caKey, filepath.Join(f.dir, "server.key"), filepath.Join(f.dir, "server.crt"), []string{"192.0.2.11"}, time.Hour); err != nil {
		t.Fatal(err)
	}
	f.renewCredential()
	f.config = filepath.Join(f.dir, "relay.yaml")
	if err := config.Save(f.config, config.Config{Node: &config.NodeConfig{Name: "robot", PKIDir: f.dir, Controller: "https://192.0.2.11:9443"}}); err != nil {
		t.Fatal(err)
	}
	for r := range relays {
		id := fmt.Sprintf("r%d", r)
		v, err := issuer.RelayDeployment(context.Background(), "robot", id)
		if err != nil {
			t.Fatal(err)
		}
		f.response.Views[id] = v
	}
	f.publish(200)
	var err error
	f.worker, err = os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	startNetworkProcess(t, relays[0], filepath.Join(f.dir, "issuer.log"), []string{"VPNCTL_WORKER=lease-issuer", "VPNCTL_LEASE_DIR=" + f.dir}, f.worker, "-test.run=^TestNetworkWorker$")
	eventually(t, 5*time.Second, "mTLS fixture listener", func() error { _, err := os.Stat(filepath.Join(f.dir, "ready")); return err })
	return f
}

func (f *m3LeaseFixture) renewCredential() {
	t := f.t
	ca, key, err := pki.LoadCA(filepath.Join(f.dir, "ca.key"), filepath.Join(f.dir, "ca.crt"))
	if err != nil {
		t.Fatal(err)
	}
	csr, clientKey, err := pki.GenerateCSR("robot")
	if err != nil {
		t.Fatal(err)
	}
	cert, err := pki.SignNodeCSR(ca, key, csr, "robot", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	caPEM, err := os.ReadFile(filepath.Join(f.dir, "ca.crt"))
	if err != nil {
		t.Fatal(err)
	}
	f.sequence++
	if err = pki.SaveCredentials(f.dir, pki.Credentials{Version: 1, Generation: uint64(f.sequence), CACert: string(caPEM), ClientCert: string(cert), ClientKey: string(clientKey)}, ""); err != nil {
		t.Fatal(err)
	}
}
func (f *m3LeaseFixture) publish(status int) {
	f.response.Status = status
	b, err := json.Marshal(f.response)
	if err != nil {
		f.t.Fatal(err)
	}
	if err = pki.WriteAtomic(filepath.Join(f.dir, "response.json"), b, 0600); err != nil {
		f.t.Fatal(err)
	}
}
func (f *m3LeaseFixture) start(r int) {
	f.sequence++
	cache := filepath.Join(filepath.Dir(f.dir), fmt.Sprintf("deploy-cache-%d", r))
	f.watch[r] = startNetworkProcess(f.t, f.relays[r], filepath.Join(f.results, fmt.Sprintf("supervise-%d-%d.jsonl", r, f.sequence)), nil, integrationBinary(f.t), "relay", "supervise", "--config", f.config, "--relay-id", fmt.Sprintf("r%d", r), "--cache-dir", cache, "--refresh-interval", "1s")
}
func (f *m3LeaseFixture) stop() {
	for _, p := range f.watch {
		p.stop()
	}
}
func (f *m3LeaseFixture) ready(r int) {
	after := time.Now()
	eventually(f.t, 8*time.Second, "fresh authenticated supervision", func() error {
		b, err := os.ReadFile(f.watch[r].log)
		if err != nil {
			return err
		}
		lines := strings.Split(strings.TrimSpace(string(b)), "\n")
		var v struct {
			State      string
			Refresh    string
			Kernel     *relayapply.DeploymentResult
			ObservedAt time.Time `json:"observed_at"`
		}
		if json.Unmarshal([]byte(lines[len(lines)-1]), &v) != nil || !v.ObservedAt.After(after) || v.State != "watching" || v.Refresh != "success" || v.Kernel == nil || !v.Kernel.KernelReady {
			return fmt.Errorf("supervisor not ready: %s", lines[len(lines)-1])
		}
		return nil
	})
}

func (f *m3LeaseFixture) checkPause(robot string, r int, iface, mode string, phases *[]string) {
	t := f.t
	f.ready(r)
	log := filepath.Join(f.results, "stream-"+mode+".jsonl")
	stream := startNetworkProcess(t, robot, log, []string{"VPNCTL_WORKER=lease-stream"}, f.worker, "-test.run=^TestNetworkWorker$")
	defer stream.stop()
	eventually(t, 5*time.Second, "established TCP echo", func() error {
		b, e := os.ReadFile(log)
		if e == nil && strings.Contains(string(b), `"ok":true`) {
			return nil
		}
		return fmt.Errorf("stream unavailable")
	})
	f.publish(503)
	cache := filepath.Join(filepath.Dir(f.dir), fmt.Sprintf("deploy-cache-%d", r))
	if mode == "enospc" {
		f.watch[r].stop()
		backup := map[string][]byte{}
		entries, err := os.ReadDir(cache)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			b, err := os.ReadFile(filepath.Join(cache, entry.Name()))
			if err != nil {
				t.Fatal(err)
			}
			backup[entry.Name()] = b
		}
		// ip netns exec creates a temporary mount namespace: mount in this
		// isolated test container's namespace so subsequent workers inherit it.
		if b, err := exec.Command("mount", "-t", "tmpfs", "-o", "size=1m,mode=0700", "tmpfs", cache).CombinedOutput(); err != nil {
			t.Fatalf("mount test tmpfs: %v %s", err, b)
		}
		t.Cleanup(func() {
			if b, err := exec.Command("umount", "-l", cache).CombinedOutput(); err != nil {
				t.Errorf("unmount test tmpfs: %v %s", err, b)
			}
		})
		for name, b := range backup {
			if err := os.WriteFile(filepath.Join(cache, name), b, 0600); err != nil {
				t.Fatal(err)
			}
		}
		file, err := os.Create(filepath.Join(cache, "test-fill"))
		if err != nil {
			t.Fatal(err)
		}
		block := make([]byte, 4096)
		for n := 0; n < 512 && err == nil; n++ {
			_, err = file.Write(block)
		}
		file.Close()
		if !errors.Is(err, syscall.ENOSPC) {
			t.Fatal("ENOSPC not exercised", err)
		}
		f.start(r)
	} else if mode == "stop" {
		if err := f.watch[r].cmd.Process.Signal(syscall.SIGSTOP); err != nil {
			t.Fatal(err)
		}
	} else {
		f.watch[r].stop()
	}
	paused := time.Now()
	// No inspect/recover command runs until autonomous blocking is established.
	time.Sleep(relayapply.DeploymentLeaseDuration + time.Second)
	if !strings.Contains(netOutput(t, f.relays[r], "wg", "show", "interfaces"), iface) {
		t.Fatal("test did not retain installed peers")
	}
	probe := func(want bool) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		cmd := netCommand(ctx, robot, f.worker, "-test.run=^TestNetworkWorker$")
		cmd.Env = append(os.Environ(), "VPNCTL_WORKER=m3-probe")
		b, err := cmd.Output()
		var p m3Probe
		if err != nil || json.Unmarshal(b, &p) != nil || p.OK != want {
			t.Fatalf("lease new TCP want %t: %v %s", want, err, b)
		}
	}
	probe(false)
	b, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	blocked := false
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		var e leaseStreamEvent
		if json.Unmarshal([]byte(line), &e) != nil {
			t.Fatal("invalid stream record")
		}
		if e.At.After(paused.Add(relayapply.DeploymentLeaseDuration)) {
			if e.OK {
				t.Fatal("established TCP survived lease deadline")
			}
			blocked = true
		}
	}
	if !blocked {
		t.Fatal("missing expired lease samples")
	}
	if mode == "enospc" {
		if err := os.Remove(filepath.Join(cache, "test-fill")); err != nil {
			t.Fatal(err)
		}
	} else if mode == "stop" {
		if err := f.watch[r].cmd.Process.Signal(syscall.SIGCONT); err != nil {
			t.Fatal(err)
		}
	} else {
		f.start(r)
	}
	time.Sleep(3 * time.Second)
	probe(false)
	f.renewCredential()
	f.publish(200)
	f.ready(r)
	probe(true)
	summary := map[string]any{"mode": mode, "relay": r, "fault_at": paused, "deadline": paused.Add(relayapply.DeploymentLeaseDuration), "old_tcp_blocked": true, "new_tcp_blocked": true, "cached_rearm_rejected": true, "fresh_approval_restored": true}
	data, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(f.results, "fault-"+mode+".json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	*phases = append(*phases, fmt.Sprintf("relay_%d_%s_existing_and_new_TCP_blocked_within_10s_outage_cannot_rearm_fresh_mTLS_after_cert_reload_restores", r, mode))
}

func (f *m3LeaseFixture) probe(robot string, want bool) {
	f.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := netCommand(ctx, robot, f.worker, "-test.run=^TestNetworkWorker$")
	cmd.Env = append(os.Environ(), "VPNCTL_WORKER=m3-probe")
	b, err := cmd.Output()
	var p m3Probe
	if err != nil || json.Unmarshal(b, &p) != nil || p.OK != want {
		f.t.Fatalf("lease TCP want %t: %v %s", want, err, b)
	}
}

func (f *m3LeaseFixture) setExpiry(expiry time.Time) {
	f.issuer.state.Generation++
	f.issuer.state.IssuedAt = expiry.Add(-time.Hour)
	f.issuer.state.ExpiresAt = expiry
	for r := range f.relays {
		id := fmt.Sprintf("r%d", r)
		v, err := f.issuer.RelayDeployment(context.Background(), "robot", id)
		if err != nil {
			f.t.Fatal(err)
		}
		f.response.Views[id] = v
	}
	f.publish(200)
}

func (f *m3LeaseFixture) checkExpiry(robot string, interfaces [][]string, phases *[]string) {
	t := f.t
	expiry := time.Now().Add(20 * time.Second).UTC()
	f.setExpiry(expiry)
	for r := range f.relays {
		f.ready(r)
	}
	f.publish(503)
	// Keep refreshing the kernel lease while transport is down. This must
	// survive a full 10s lease period, but never the approval's own deadline.
	time.Sleep(time.Until(expiry.Add(-3 * time.Second)))
	f.probe(robot, true)
	f.stop()
	log := filepath.Join(f.results, "stream-expiry.jsonl")
	stream := startNetworkProcess(t, robot, log, []string{"VPNCTL_WORKER=lease-stream"}, f.worker, "-test.run=^TestNetworkWorker$")
	defer stream.stop()
	eventually(t, time.Second, "TCP before approval expiry", func() error {
		b, _ := os.ReadFile(log)
		if strings.Contains(string(b), `"ok":true`) {
			return nil
		}
		return fmt.Errorf("no successful sample")
	})
	time.Sleep(time.Until(expiry.Add(time.Second)))
	f.probe(robot, false)
	for r, ns := range f.relays {
		for _, iface := range interfaces[r] {
			if !strings.Contains(netOutput(t, ns, "wg", "show", "interfaces"), iface) {
				t.Fatal("expiry test required peers to remain installed")
			}
			var doc struct {
				NFTables []map[string]any `json:"nftables"`
			}
			if err := json.Unmarshal([]byte(netOutput(t, ns, "nft", "-j", "list", "table", "inet", "vl"+iface[2:])), &doc); err != nil {
				t.Fatal(err)
			}
		}
	}
	b, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		var e leaseStreamEvent
		if json.Unmarshal([]byte(line), &e) != nil {
			t.Fatal("invalid expiry sample")
		}
		if e.At.After(expiry) {
			if e.OK {
				t.Fatal("existing TCP passed after approval expiry")
			}
			count++
		}
	}
	if count == 0 {
		t.Fatal("no samples after expiry")
	}
	// A fresh, newer approval is necessary for rearming retained peers.
	f.setExpiry(time.Now().Add(time.Hour).UTC())
	for r := range f.relays {
		f.start(r)
		f.ready(r)
	}
	f.probe(robot, true)
	*phases = append(*phases, "controller_outage_keeps_valid_lease_approval_expiry_blocks_without_process_fresh_revision_restores")
	data, _ := json.MarshalIndent(map[string]any{"approval_expires_at": expiry, "after_expiry_failed_existing_tcp_samples": count, "new_tcp_blocked": true, "relay_count": len(f.relays), "interfaces": interfaces}, "", "  ")
	if err = os.WriteFile(filepath.Join(f.results, "expiry.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
}

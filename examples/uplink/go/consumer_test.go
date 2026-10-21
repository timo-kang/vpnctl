// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"vpnctl/internal/relayapply"
	"vpnctl/internal/uplinkapi"
	"vpnctl/internal/uplinkclient"
)

type appReport struct {
	API        uplinkclient.View `json:"api"`
	APIRecords uint64            `json:"api_records"`
	Payload    probeSnapshot     `json:"payload"`
	UserCPU    uint64            `json:"cpu_user_ns"`
	SystemCPU  uint64            `json:"cpu_system_ns"`
	PeakRSS    uint64            `json:"process_peak_rss_kib"`
}

func fixtureCA(t *testing.T, cfg probeConfig) string {
	t.Helper()
	c, err := tls.Dial("tcp", cfg.Address, &tls.Config{RootCAs: cfg.Roots, ServerName: cfg.ServerName, MinVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.ConnectionState().PeerCertificates[0].Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	return ca
}

func TestPythonAuthenticatedPayloadBoundaries(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal(err)
	}
	module, _ := filepath.Abs("../python/main.py")
	for _, mode := range []string{"wrong_nonce", "wrong_identity"} {
		t.Run(mode, func(t *testing.T) {
			var wrong atomic.Bool
			wrong.Store(mode == "wrong_nonce")
			cfg, _ := echoFixture(t, &wrong)
			ca := fixtureCA(t, cfg)
			identity := cfg.ServerName
			if mode == "wrong_identity" {
				identity = "untrusted.invalid"
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, python, "-B", module, "--address", cfg.Address, "--server-name", identity, "--ca", ca, "--runtime", "/nonexistent/vpnctl-test", "--duration", "3", "--io-timeout", ".15", "--interval", ".05")
			var output bytes.Buffer
			cmd.Stdout = &output
			if err := cmd.Run(); err != nil {
				t.Fatal("Python probe did not finish", err)
			}
			var r appReport
			if json.Unmarshal(output.Bytes(), &r) != nil {
				t.Fatal("invalid Python report")
			}
			if r.Payload.Correct != 0 || r.Payload.Attempts < 4 {
				t.Fatal("incorrect TLS/payload response accepted or retries missing")
			}
			if mode == "wrong_identity" && (r.Payload.Connections != 0 || r.Payload.Ambiguous != 0) {
				t.Fatal("untrusted server reached payload")
			}
			if mode == "wrong_nonce" && r.Payload.InvalidResponses < 4 {
				t.Fatal("nonce mismatch not classified")
			}
			for i, e := range r.Payload.Events[:4] {
				upper := uint64(250*time.Millisecond) * uint64(1<<i)
				if e.NextDelayNS < upper/2 || e.NextDelayNS > upper {
					t.Fatal("Python reset retry without exact authenticated payload")
				}
			}
		})
	}
}

func TestPythonReferenceEchoServer(t *testing.T) {
	seed := httptest.NewTLSServer(nil)
	key, err := x509.MarshalPKCS8PrivateKey(seed.TLS.Certificates[0].PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	der := seed.Certificate().Raw
	seed.Close()
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), 0600); err != nil {
		t.Fatal(err)
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal(err)
	}
	module, _ := filepath.Abs("../python")
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, python, "-B", "-c", `import sys,threading,queue,ssl,socket,time
sys.path.insert(0,sys.argv[1])
from echo_server import serve
from probe import Probe
ready=queue.Queue(maxsize=1)
stop=threading.Event()
worker=threading.Thread(target=serve,args=(('127.0.0.1',0),sys.argv[2],sys.argv[3],stop),kwargs={'ready':ready.put,'session_seconds':60,'max_requests':512})
worker.start()
try:
    address=ready.get(timeout=2)
    tls=ssl.create_default_context(cafile=sys.argv[2])
    with tls.wrap_socket(socket.create_connection(address,timeout=1),server_hostname='example.com') as conn:
        for i in range(300):
            line=('VPNCTL-ECHO/1 %d %032x\n' % (i+1,i)).encode()
            conn.sendall(line)
            result=b''
            while len(result) < len(line):
                part=conn.recv(len(line)-len(result))
                assert part
                result+=part
            assert result==line
    with socket.create_connection(address,timeout=1) as raw:
        with tls.wrap_socket(raw,server_hostname='example.com') as conn:
            conn.sendall(b'unsupported operation\n')
            assert conn.recv(1)==b''
    p=Probe(address,'example.com',sys.argv[2],interval=.05)
    client_stop=threading.Event()
    timer=threading.Timer(.35,client_stop.set);timer.start()
    p.run(client_stop);timer.join()
    assert p.snapshot()['correct'] >= 3
    # Server shutdown must also finish with peers in partial handshake/read.
    handshake=socket.create_connection(address,timeout=1)
    partial=tls.wrap_socket(socket.create_connection(address,timeout=1),server_hostname='example.com')
    try:
        handshake.sendall(b'\x16\x03')
        partial.sendall(b'VPNCTL-ECHO/1 999 partial')
        started=time.monotonic()
        stop.set();worker.join(3)
        assert not worker.is_alive() and time.monotonic()-started < 2.8
    finally:
        handshake.close();partial.close()
finally:
    stop.set();worker.join(3)
assert not worker.is_alive()
`, module, certPath, keyPath)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatal("Python echo server contract failed", err, string(output))
	}
}

func TestTwoConsumersKeepPayloadDuringAPIOutageAndRestart(t *testing.T) {
	cfg, _ := echoFixture(t, nil)
	c, err := tls.Dial("tcp", cfg.Address, &tls.Config{RootCAs: cfg.Roots, ServerName: cfg.ServerName, MinVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatal(err)
	}
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.ConnectionState().PeerCertificates[0].Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	c.Close()
	var dirs, progress [2]string
	var api [2]*uplinkapi.Server
	var producers [2]string
	start := func(i int) {
		p, err := relayapply.NewUplinkPublisher([]string{"app", "app2"}[i])
		if err != nil {
			t.Fatal(err)
		}
		api[i], err = uplinkapi.Start(context.Background(), uplinkapi.Options{Directory: dirs[i], AllowedUIDs: []uint32{uint32(os.Geteuid())}}, p)
		if err != nil {
			t.Fatal(err)
		}
		producers[i] = p.Snapshot().ProducerID
	}
	for i := range dirs {
		dirs[i] = t.TempDir()
		if err := os.Chmod(dirs[i], 0700); err != nil {
			t.Fatal(err)
		}
		progress[i] = filepath.Join(t.TempDir(), "progress.json")
		start(i)
	}
	t.Cleanup(func() {
		for _, server := range api {
			server.Close()
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	var goOutput, pythonOutput bytes.Buffer
	done := make(chan error, 1)
	go func() {
		done <- runExample(ctx, []string{"--address", cfg.Address, "--server-name", cfg.ServerName, "--ca", ca, "--runtime", dirs[0], "--server-uid", strconv.Itoa(os.Geteuid()), "--duration", "10s", "--interval", "50ms", "--io-timeout", "150ms", "--progress", progress[0]}, &goOutput)
	}()
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal(err)
	}
	module, _ := filepath.Abs("../python/main.py")
	cmd := exec.CommandContext(ctx, python, "-B", module, "--address", cfg.Address, "--server-name", cfg.ServerName, "--ca", ca, "--runtime", dirs[1], "--server-uid", strconv.Itoa(os.Geteuid()), "--target", "app2", "--duration", "10", "--interval", ".05", "--io-timeout", ".15", "--progress", progress[1])
	cmd.Stdout = &pythonOutput
	var pythonErr bytes.Buffer
	cmd.Stderr = &pythonErr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	pythonDone := make(chan error, 1)
	go func() { pythonDone <- cmd.Wait() }()
	t.Cleanup(func() { cancel(); cmd.Process.Kill() })
	await := func(label string, check func([2]appReport) bool) [2]appReport {
		t.Helper()
		deadline := time.Now().Add(4 * time.Second)
		for time.Now().Before(deadline) && ctx.Err() == nil {
			var reports [2]appReport
			valid := true
			for i, p := range progress {
				b, e := os.ReadFile(p)
				if e != nil || json.Unmarshal(b, &reports[i]) != nil {
					valid = false
				}
			}
			if valid && check(reports) {
				return reports
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatal("two-consumer phase not observed:", label)
		return [2]appReport{}
	}
	baseline := await("baseline", func(r [2]appReport) bool {
		return r[0].APIRecords > 0 && r[1].APIRecords > 0 && r[0].Payload.Correct >= 3 && r[1].Payload.Correct >= 3
	})
	for _, server := range api {
		server.Close()
	}
	outage := await("API outage detected", func(r [2]appReport) bool {
		for i := range r {
			if r[i].API.APIAvailable || r[i].Payload.Correct < baseline[i].Payload.Correct+3 || r[i].Payload.Connections != 1 {
				return false
			}
		}
		return true
	})
	await("payload after API outage detection", func(r [2]appReport) bool {
		for i := range r {
			if r[i].API.APIAvailable || r[i].Payload.Correct < outage[i].Payload.Correct+3 || r[i].Payload.Connections != 1 {
				return false
			}
		}
		return true
	})
	for i := range dirs {
		start(i)
	}
	restarted := await("producer replacement", func(r [2]appReport) bool {
		return r[0].API.ProducerID == producers[0] && r[1].API.ProducerID == producers[1] && r[0].Payload.Connections == 1 && r[1].Payload.Connections == 1
	})
	await("payload after producer replacement", func(r [2]appReport) bool {
		for i := range r {
			if r[i].API.ProducerID != producers[i] || r[i].Payload.Correct < restarted[i].Payload.Correct+3 || r[i].Payload.Connections != 1 {
				return false
			}
		}
		return true
	})
	// Graceful termination lets both reference CLIs finish bounded reports.
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-pythonDone:
		if err != nil {
			t.Fatal("Python CLI failed", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Python CLI stop timeout")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Go CLI stop timeout")
	}
	for _, raw := range [][]byte{goOutput.Bytes(), pythonOutput.Bytes()} {
		var report appReport
		if err := json.Unmarshal(raw, &report); err != nil {
			t.Fatal("missing final report")
		}
		if report.Payload.Connections != 1 || report.Payload.ExistingSocketCorrect < 3 || report.Payload.FirstCorrectNS == 0 || report.PeakRSS == 0 || report.UserCPU+report.SystemCPU == 0 {
			t.Fatal("missing independent app evidence")
		}
	}
}

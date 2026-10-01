//go:build integration

// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package integration

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// Called only by the disposable VM's guarded agent. All privileged commands
// below act on the guest kernel; ordinary container/network CI skips this test.
func TestVMWorker(t *testing.T) {
	cmdline, _ := os.ReadFile("/proc/cmdline")
	if os.Getenv("VPNCTL_VM_WORKER") != "1" || !strings.Contains(string(cmdline), "vpnctl_vm_test ") {
		t.Skip("requires disposable VM runner")
	}
	requireNetwork(t)
	f := newM3AuthorityFixture(t)
	clients := map[string]*http.Client{}
	for _, p := range f.plan.Paths {
		path := filepath.Join(f.private, p.PathID+".sock")
		startNetworkProcess(t, f.robot, filepath.Join(f.private, p.PathID+"-probe.log"),
			[]string{"VPNCTL_WORKER=vm-probe", "VPNCTL_VM_PROBE_SOCKET=" + path, "VPNCTL_PROBE_SOURCE=" + strings.TrimSuffix(p.InnerAddress, "/32")},
			f.worker, "-test.run=^TestNetworkWorker$")
		eventually(t, 5*time.Second, "VM probe socket", func() error { _, err := os.Stat(path); return err })
		clients[p.PathID] = &http.Client{Timeout: time.Second, Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", path)
		}}}
	}
	var mu sync.Mutex
	delays := map[string]string{}
	stop := func() {
		for _, r := range f.recipients {
			if r.watch != nil && !r.watch.stopped {
				_ = r.watch.cmd.Process.Signal(syscall.SIGCONT)
				r.watch.terminate(t)
			}
		}
	}
	snapshot := func() map[string]any {
		x := map[string]any{"kernel": f.snapshot()}
		for _, r := range f.recipients {
			b, _ := os.ReadFile(r.watch.log)
			if len(b) > 64<<10 {
				b = b[len(b)-(64<<10):]
			}
			x[r.relay+"_supervision"] = string(b)
		}
		return x
	}
	// A power cycle intentionally leaves these files. They are private and are
	// used to prove that the next boot rejects an old journal without deleting it.
	writeMetadata := func() {
		boot, _ := os.ReadFile("/proc/sys/kernel/random/boot_id")
		meta := map[string]any{"boot_id": strings.TrimSpace(string(boot)), "private": f.private, "recipients": []map[string]any{}}
		for _, r := range f.recipients {
			out := r.require("inspect", -1, 0)
			meta["recipients"] = append(meta["recipients"].([]map[string]any), map[string]any{
				"namespace": r.ns, "config": r.config, "relay": r.relay, "cache": r.cache, "endpoints": out.Endpoints})
		}
		writeM3Report(t, "/var/lib/vpnctl-vm/fixture.json", meta)
		for _, name := range []string{"/var/lib/vpnctl-vm/fixture.json", "/var/lib/vpnctl-vm"} {
			file, err := os.Open(name)
			if err != nil {
				t.Fatal(err)
			}
			err = file.Sync()
			file.Close()
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	writeMetadata()
	mux := http.NewServeMux()
	mux.HandleFunc("/probe", func(w http.ResponseWriter, req *http.Request) {
		var input struct {
			Path, Kind, Nonce string
		}
		if json.NewDecoder(io.LimitReader(req.Body, 16384)).Decode(&input) != nil || clients[input.Path] == nil {
			http.Error(w, "invalid probe", 400)
			return
		}
		b, _ := json.Marshal(input)
		r, err := clients[input.Path].Post("http://unix/probe", "application/json", bytes.NewReader(b))
		if err != nil {
			json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": err.Error()})
			return
		}
		defer r.Body.Close()
		w.WriteHeader(r.StatusCode)
		io.Copy(w, io.LimitReader(r.Body, 4096))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		var result any
		switch req.URL.Path {
		case "/ready":
			paths := []string{}
			for _, p := range f.plan.Paths {
				paths = append(paths, p.PathID)
			}
			result = map[string]any{"ready": !t.Failed(), "paths": paths, "approval": f.controller.status()}
		case "/snapshot":
			result = snapshot()
		case "/stop":
			stop()
			result = snapshot()
		case "/fence":
			stop()
			for _, r := range f.recipients {
				for ep := 0; ep < 2; ep++ {
					r.require("release", ep, 0)
				}
				out := r.require("inspect", -1, 0)
				if len(out.Endpoints) != 0 || netOutput(t, r.ns, "wg", "show", "interfaces") != "" {
					t.Fatal("managed relay resources remain; refusing pause")
				}
			}
			result = snapshot()
		case "/freeze":
			for _, r := range f.recipients {
				r.ready()
				if err := r.watch.cmd.Process.Signal(syscall.SIGSTOP); err != nil {
					t.Fatal(err)
				}
				vmRequireStopped(t, r.watch.cmd.Process.Pid)
			}
			result = snapshot()
		case "/delay-start":
			stop()
			rows := []map[string]any{}
			for _, r := range f.recipients {
				dir := filepath.Join(f.private, "delay-"+r.relay)
				if err := os.Mkdir(dir, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("/opt/vpnctl-vm/nft_delay.py", filepath.Join(dir, "nft")); err != nil {
					t.Fatal(err)
				}
				delays[r.relay] = dir
				r.start("PATH="+dir+":"+os.Getenv("PATH"), "VPNCTL_VM_NFT_DELAY="+dir)
				var ready map[string]any
				eventually(t, 8*time.Second, "renewal prepared before nft commit", func() error {
					b, err := os.ReadFile(filepath.Join(dir, "ready.json"))
					if err != nil {
						return err
					}
					return json.Unmarshal(b, &ready)
				})
				vmRequireStopped(t, r.watch.cmd.Process.Pid)
				rows = append(rows, ready)
			}
			result = rows
		case "/delay-release":
			if len(delays) != len(f.recipients) {
				t.Fatal("missing delay injection")
			}
			for _, dir := range delays {
				mustWrite(t, filepath.Join(dir, "release"), "release")
			}
			rows := []map[string]any{}
			for _, r := range f.recipients {
				var done map[string]any
				eventually(t, 5*time.Second, "delayed nft completed", func() error {
					b, err := os.ReadFile(filepath.Join(delays[r.relay], "done.json"))
					if err != nil {
						return err
					}
					return json.Unmarshal(b, &done)
				})
				if done["exit"] != float64(0) {
					t.Fatal("delayed nft failed", done)
				}
				vmRequireStopped(t, r.watch.cmd.Process.Pid)
				rows = append(rows, done)
			}
			result = rows
		case "/outage":
			for _, r := range f.recipients {
				(relayUplink{relay: r.ns}).nft(t, `table inet vm_outage {
 chain output { type filter hook output priority -310; policy accept;
 ip daddr 192.0.2.11 tcp dport 9443 counter drop
 }
}`)
			}
			result = map[string]any{"outage": true}
		case "/supervise":
			for _, r := range f.recipients {
				if r.watch.stopped {
					r.start()
				} else {
					_ = r.watch.cmd.Process.Signal(syscall.SIGCONT)
				}
			}
			result = map[string]any{"started": true}
		case "/expiry":
			result = f.controller.apply(f.spec, 60)
			for _, r := range f.recipients {
				r.ready()
			}
		case "/deny":
			for _, r := range f.recipients {
				f.controller.grant(r.relay, "")
			}
			result = map[string]any{"withdrawn": true}
		case "/downgrade":
			stop()
			rows := []map[string]any{}
			for _, r := range f.recipients {
				before, err := os.ReadFile(filepath.Join(r.cache, "peers.json"))
				if err != nil {
					t.Fatal(err)
				}
				links := netOutput(t, r.ns, "ip", "-j", "link", "show")
				a := r.args("inspect", "")
				a[0] = "/opt/vpnctl-vm/vpnctl-legacy"
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				out, err := netCommand(ctx, r.ns, a...).CombinedOutput()
				cancel()
				after, readErr := os.ReadFile(filepath.Join(r.cache, "peers.json"))
				if err == nil || readErr != nil || !bytes.Equal(before, after) || links != netOutput(t, r.ns, "ip", "-j", "link", "show") {
					t.Fatal("old binary accepted/mutated new journal", err, string(out))
				}
				rows = append(rows, map[string]any{"relay": r.relay, "rejected": true, "journal_sha256": fmt.Sprintf("%x", sha256.Sum256(before)), "reason": string(out)})
			}
			result = rows
		case "/legacy-upgrade":
			stop()
			rows := []map[string]any{}
			for _, r := range f.recipients {
				for ep := 0; ep < 2; ep++ {
					r.require("release", ep, 0)
				}
				// Build a genuinely old installation in a new directory. Never
				// erase a new journal/marker to make an old binary accept it.
				r.cache = filepath.Join(f.private, "legacy-"+r.relay)
				r.require("refresh", -1, 0)
				for ep := 0; ep < 2; ep++ {
					a := r.args("apply", fmt.Sprintf("ep%d", ep))
					a[0] = "/opt/vpnctl-vm/vpnctl-legacy"
					a = append(a, "--key-file", r.key, "--key-generation", "1", "--listen-port", fmt.Sprint(51820+ep))
					ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
					out, err := netCommand(ctx, r.ns, a...).CombinedOutput()
					cancel()
					if err != nil {
						t.Fatal("legacy fixture apply", err, string(out))
					}
				}
				old, err := os.ReadFile(filepath.Join(r.cache, "peers.json"))
				if err != nil || bytes.Contains(old, []byte("lease_version")) || len(strings.Fields(netOutput(t, r.ns, "wg", "show", "interfaces"))) != 2 {
					t.Fatal("legacy peer fixture not installed", err)
				}
				r.start()
				eventually(t, 10*time.Second, "legacy peers removed by new supervisor", func() error {
					if netOutput(t, r.ns, "wg", "show", "interfaces") != "" {
						return fmt.Errorf("legacy peers remain")
					}
					return nil
				})
				rows = append(rows, map[string]any{"relay": r.relay, "legacy_journal_sha256": fmt.Sprintf("%x", sha256.Sum256(old)), "legacy_peers_removed": true})
			}
			result = rows
		case "/recover":
			stop()
			for _, r := range f.recipients {
				// This table is created only by this fixture. Absence is normal.
				_ = netCommand(context.Background(), r.ns, "nft", "delete", "table", "inet", "vm_outage").Run()
				f.controller.grant(r.relay, "agent")
			}
			f.controller.apply(f.spec, 3600)
			f.releaseNodeCandidates()
			for _, r := range f.recipients {
				// A healthy but expired applied entry is not an incomplete
				// transaction for recover(). Explicitly drain/reinstall it.
				r.require("refresh", -1, 0)
				for ep := 0; ep < 2; ep++ {
					r.require("release", ep, 0)
				}
			}
			f.install()
			writeMetadata()
			result = snapshot()
		default:
			http.Error(w, "unknown fixture operation", 404)
			return
		}
		if t.Failed() {
			w.WriteHeader(500)
		}
		json.NewEncoder(w).Encode(result)
	})
	server := &http.Server{Addr: "127.0.0.1:18081", Handler: mux, ReadHeaderTimeout: 2 * time.Second}
	t.Fatal(server.ListenAndServe())
}

func vmRequireStopped(t *testing.T, pid int) {
	t.Helper()
	eventually(t, time.Second, "supervisor actually SIGSTOPed", func() error {
		b, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
		if err != nil {
			return err
		}
		if !strings.Contains(string(b), "State:\tT") {
			return fmt.Errorf("process not stopped")
		}
		return nil
	})
}

// One socket is retained for the existing-TCP probe. A failed stream is never
// reconnected. Fresh probes always dial anew. The external observer supplies
// a new nonce, so queued responses cannot masquerade as post-resume traffic.
func serveVMProbe() error {
	l, err := net.Listen("unix", os.Getenv("VPNCTL_VM_PROBE_SOCKET"))
	if err != nil {
		return err
	}
	defer l.Close()
	var mu sync.Mutex
	var stream net.Conn
	var streamErr error
	var opened bool
	return http.Serve(l, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		var input struct{ Kind, Nonce string }
		if json.NewDecoder(io.LimitReader(req.Body, 16384)).Decode(&input) != nil || len(input.Nonce) != 16 || (input.Kind != "new" && input.Kind != "existing") {
			http.Error(w, "invalid probe", 400)
			return
		}
		var c net.Conn
		var err error
		if input.Kind == "existing" {
			if !opened {
				stream, streamErr = m3Dial(350 * time.Millisecond)
				opened = true
			}
			c, err = stream, streamErr
		} else {
			c, err = m3Dial(350 * time.Millisecond)
			if c != nil {
				defer c.Close()
			}
		}
		source := ""
		protocolError := false
		if err == nil {
			c.SetDeadline(time.Now().Add(350 * time.Millisecond))
			_, err = io.WriteString(c, input.Nonce)
			reader := bufio.NewReader(c)
			if err == nil {
				var line string
				line, err = reader.ReadString('\n')
				if err == nil {
					source, _, err = net.SplitHostPort(strings.TrimSpace(line))
					protocolError = err != nil
				}
			}
			if err == nil {
				got := make([]byte, 16)
				_, err = io.ReadFull(reader, got)
				if err == nil && string(got) != input.Nonce {
					err = fmt.Errorf("nonce mismatch")
					protocolError = true
				}
			}
		}
		if input.Kind == "existing" {
			streamErr = err
		}
		result := map[string]any{"ok": err == nil, "kind": input.Kind, "nonce": input.Nonce, "source": source, "protocol_error": protocolError, "guest_at": time.Now().UTC()}
		if err != nil {
			result["error"] = err.Error()
		}
		json.NewEncoder(w).Encode(result)
	}))
}

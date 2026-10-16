//go:build integration

// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package integration

import (
	"bufio"
	"encoding/json"
	"errors"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// Child runs in the robot network namespace, but on the measurement CPU. Its
// only output is bounded timing/enum evidence, never socket addresses or keys.
func TestUplinkTrafficWorker(t *testing.T) {
	path := os.Getenv("VPNCTL_UPLINK_TRACE")
	if path == "" {
		t.Skip("comparison worker only")
	}
	requireUplinkTrafficGuest(t)
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	var mu sync.Mutex
	var wg sync.WaitGroup
	count := 0
	deadline := time.Now().Add(8 * time.Minute)
	for _, kind := range []string{"app", "app2", "existing"} {
		wg.Add(1)
		go func(kind string) {
			defer wg.Done()
			target := m3Target
			if kind == "app2" {
				target = "198.18.0.3"
			}
			var stream *managerStream
			defer func() {
				if stream != nil {
					stream.c.Close()
				}
			}()
			for time.Now().Before(deadline) {
				if _, err := os.Stat(path + ".stop"); err == nil {
					return
				}
				r := uplinkSample{Kind: kind, Begin: managerMono()}
				r.Attempt = r.Begin
				var source string
				var err error
				if kind == "existing" {
					if stream == nil {
						var c net.Conn
						c, err = net.DialTimeout("tcp4", target+":9192", 400*time.Millisecond)
						if err == nil {
							stream = &managerStream{c: c, reader: bufio.NewReader(c)}
						}
					}
					if stream != nil {
						source, err = stream.exchange()
						r.Begin = stream.sentAt
					}
				} else {
					source, err = managerAutoTCP(target)
				}
				// exchange creates a fresh nonce after the sampling attempt begins. On a
				// retry it retains the earlier send time instead of relabelling old data.
				if r.Begin > r.Attempt {
					r.Attempt = r.Begin
				}
				r.End = managerMono()
				if err == nil {
					switch source {
					case "198.18.0.11":
						r.Relay = "r0"
					case "198.18.0.12":
						r.Relay = "r1"
					default:
						r.Failure = "unexpected_source"
					}
					r.OK = r.Relay != ""
				} else {
					var ne net.Error
					switch {
					case errors.As(err, &ne) && ne.Timeout():
						r.Failure = "timeout"
					case errors.Is(err, errManagerProtocol):
						r.Failure = "protocol"
					default:
						r.Failure = "socket"
					}
				}
				mu.Lock()
				count++
				if count > 8192 {
					t.Error("trace capacity exceeded")
					mu.Unlock()
					return
				}
				err = json.NewEncoder(file).Encode(r)
				mu.Unlock()
				if err != nil {
					t.Error("trace write failed")
					return
				}
				time.Sleep(200 * time.Millisecond)
			}
			t.Error("traffic worker exceeded deadline")
		}(kind)
	}
	wg.Wait()
}

func readUplinkTrace(t *testing.T, path string) []uplinkSample {
	t.Helper()
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil || len(b) > 2*1024*1024 {
		t.Fatal("missing or oversized trace", err)
	}
	lines := strings.Split(string(b), "\n")
	rows := make([]uplinkSample, 0, len(lines))
	for _, line := range lines[:len(lines)-1] { // A concurrently written partial tail is not a row.
		var r uplinkSample
		if json.Unmarshal([]byte(line), &r) != nil {
			t.Fatal("invalid traffic evidence")
		}
		rows = append(rows, r)
	}
	return rows
}

// This read-only worker must be inside a disposable guest AND a child network
// namespace. requireIsolatedGuest deliberately permits only guest-root mutations.
func requireUplinkTrafficGuest(t *testing.T) {
	t.Helper()
	if os.Getenv("VPNCTL_VM_WORKER") != "1" {
		t.Fatal("traffic requires VM worker")
	}
	b, e := os.ReadFile("/proc/cmdline")
	if e != nil {
		t.Fatal(e)
	}
	args := map[string]string{}
	for _, s := range strings.Fields(string(b)) {
		k, v, _ := strings.Cut(s, "=")
		args[k] = v
	}
	boot, e1 := os.ReadFile("/proc/sys/kernel/random/boot_id")
	uuid, e2 := os.ReadFile("/sys/class/dmi/id/product_uuid")
	own, e3 := os.Readlink("/proc/self/ns/net")
	root, e4 := os.Readlink("/proc/1/ns/net")
	_, marker := args["vpnctl_vm_test"]
	if !marker || len(args["vpnctl_vm_token"]) != 32 || args["vpnctl_host_boot"] == "" || args["vpnctl_host_boot"] == strings.TrimSpace(string(boot)) || args["vpnctl_vm_uuid"] != strings.ToLower(strings.TrimSpace(string(uuid))) || e1 != nil || e2 != nil || e3 != nil || e4 != nil || own == root {
		t.Fatal("traffic worker outside owned guest namespace")
	}
}

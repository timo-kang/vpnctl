//go:build integration

// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package integration

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestNetns_M3NodeLeaseCrash(t *testing.T) {
	requireNetwork(t)
	f := newM3AuthorityFixture(t)
	f.releaseNodeCandidates()
	f.plan.Paths = f.plan.Paths[:1]
	p := f.plan.Paths[0]
	dir := filepath.Join(f.private, "fault-bin")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	ip, err := exec.LookPath("ip")
	if err != nil {
		t.Fatal(err)
	}
	nft, err := exec.LookPath("nft")
	if err != nil {
		t.Fatal(err)
	}
	// The wrappers execute real mutations, then kill only their own vpnctl
	// parent. Never alter a host process, clock, network or mount namespace.
	ipScript := "#!/bin/sh\n" + ip + " \"$@\"\nstatus=$?\nif [ \"$status\" = 0 ] && [ \"$VPNCTL_NODE_FAULT\" = up ] && [ \"$1 $2 $3\" = 'link set dev' ] && [ \"$5\" = up ]; then printf fired > \"$VPNCTL_NODE_MARKER\"; kill -KILL \"$PPID\"; fi\nexit \"$status\"\n"
	nftScript := "#!/bin/sh\nif [ \"$1\" != '-f' ]; then exec " + nft + " \"$@\"; fi\nscript=$(cat)\nprintf '%s\\n' \"$script\" | " + nft + " -f /dev/stdin\nstatus=$?\nfire=0\ncase \"$VPNCTL_NODE_FAULT:$script\" in\ncreate:create\\ table*) fire=1;;\nprepare:create\\ set*) fire=1;;\nselect:*flush\\ chain*) fire=1;;\nesac\nif [ \"$status\" = 0 ] && [ \"$fire\" = 1 ]; then printf fired > \"$VPNCTL_NODE_MARKER\"; kill -KILL \"$PPID\"; fi\nexit \"$status\"\n"
	for name, script := range map[string]string{"ip": ipScript, "nft": nftScript} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0700); err != nil {
			t.Fatal(err)
		}
	}
	phases := []string{}
	for _, point := range []string{"create", "up", "prepare", "select"} {
		prepare := []string{integrationBinary(t), "node", "relay", "prepare", "--config", f.node, "--path-id", p.PathID, "--lease", "--probe-routes"}
		args := prepare
		if point == "prepare" || point == "select" {
			netOutput(t, f.robot, prepare...)
			args = []string{integrationBinary(t), "node", "relay", "supervise", "--config", f.node, "--once"}
		}
		marker := filepath.Join(f.private, "crash-"+point)
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		cmd := netCommand(ctx, f.robot, args...)
		cmd.Env = append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"), "VPNCTL_NODE_FAULT="+point, "VPNCTL_NODE_MARKER="+marker)
		b, err := cmd.CombinedOutput()
		cancel()
		if err == nil || cmd.ProcessState == nil {
			t.Fatal("fault not exercised", point, string(b))
		}
		if state, ok := cmd.ProcessState.Sys().(syscall.WaitStatus); !ok || !state.Signaled() || state.Signal() != syscall.SIGKILL {
			t.Fatal("unexpected exit", point, err, string(b))
		}
		if b, err := os.ReadFile(marker); err != nil || string(b) != "fired" {
			t.Fatal("missing crash evidence", point, err)
		}
		if point == "create" || point == "up" {
			f.nodeCall("recover", "")
		} else {
			time.Sleep(11 * time.Second)
			if f.probe(p).OK {
				t.Fatal("crashed activation kept path open", point)
			}
			f.nodeCall("release", p.PathID)
		}
		if strings.Contains(netOutput(t, f.robot, "ip", "-j", "link", "show"), p.Pin.WGInterface) {
			t.Fatal("candidate not reclaimed", point)
		}
		phases = append(phases, fmt.Sprint(point, "_sigkill_recovered"))
	}
	writeM3Report(t, filepath.Join(f.results, "node-crash.json"), map[string]any{"completed": !t.Failed(), "phases": phases})
}

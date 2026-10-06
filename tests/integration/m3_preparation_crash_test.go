//go:build integration

// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"vpnctl/internal/relayapply"
)

func TestNetns_M3PreparationCrash(t *testing.T) {
	requireNetwork(t)
	f := newM3AuthorityFixtureWithOptions(t, m3AuthorityOptions{separateController: true, independentRecipients: true})
	f.releaseNodeCandidates()
	f.plan.Paths = f.plan.Paths[:1]
	p := f.plan.Paths[0]
	netOutput(t, f.robot, "sh", "-c", "mount -t proc proc /proc && printf 0 > /proc/sys/net/ipv4/conf/all/rp_filter && printf 0 > /proc/sys/net/ipv4/conf/default/rp_filter")
	dir := filepath.Join(f.private, "rebuild-fault-bin")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	ip, err := exec.LookPath("ip")
	if err != nil {
		t.Fatal(err)
	}
	wg, err := exec.LookPath("wg")
	if err != nil {
		t.Fatal(err)
	}
	nft, err := exec.LookPath("nft")
	if err != nil {
		t.Fatal(err)
	}
	// Run the real mutation, then SIGKILL only the wrapper's own vpnctl parent.
	// WireGuard stdin is passed directly to wg and is never recorded.
	ipScript := `#!/bin/sh
` + ip + ` "$@"
status=$?
fire=0
case "$VPNCTL_REBUILD_FAULT:$1 $2 $3" in
link:link\ add*) fire=1;;
tag:link\ set\ dev) [ "$5" = alias ] && fire=1;;
up:link\ set\ dev) [ "$5" = up ] && fire=1;;
guard:-4\ route\ add) [ "$4" = unreachable ] && fire=1;;
endpoint:-4\ route\ add) [ "$4" = "$VPNCTL_REBUILD_ENDPOINT" ] && fire=1;;
rule:-4\ rule\ add) [ "$6" = fwmark ] && fire=1;;
address:-4\ address\ add) fire=1;;
probe-targets:-4\ route\ add) [ "$4" = "198.18.0.2/32" ] && fire=1;;
probe-source:-4\ rule\ add) [ "$6" = from ] && fire=1;;
remove-link:link\ del\ dev) fire=1;;
remove-probe-source:-4\ rule\ del) [ "$6" = from ] && fire=1;;
remove-rule:-4\ rule\ del) [ "$6" = fwmark ] && fire=1;;
remove-endpoint:-4\ route\ del) [ "$4" = "$VPNCTL_REBUILD_ENDPOINT" ] && fire=1;;
remove-guard:-4\ route\ del) [ "$4" = unreachable ] && fire=1;;
esac
if [ "$status" = 0 ] && [ "$fire" = 1 ]; then printf fired > "$VPNCTL_REBUILD_MARKER"; kill -KILL "$PPID"; fi
exit "$status"
`
	wgScript := "#!/bin/sh\n" + wg + " \"$@\"\nstatus=$?\nif [ \"$status\" = 0 ] && [ \"$VPNCTL_REBUILD_FAULT\" = wg ] && [ \"$1\" = setconf ]; then printf fired > \"$VPNCTL_REBUILD_MARKER\"; kill -KILL \"$PPID\"; fi\nexit \"$status\"\n"
	nftScript := "#!/bin/sh\nif [ \"$1\" != -f ]; then exec " + nft + " \"$@\"; fi\nscript=$(cat)\nprintf '%s\\n' \"$script\" | " + nft + " -f /dev/stdin\nstatus=$?\ncase \"$VPNCTL_REBUILD_FAULT:$script\" in\nremove-lease:delete\\ table*) if [ \"$status\" = 0 ]; then printf fired > \"$VPNCTL_REBUILD_MARKER\"; kill -KILL \"$PPID\"; fi;;\nesac\nexit \"$status\"\n"
	for name, script := range map[string]string{"ip": ipScript, "wg": wgScript, "nft": nftScript} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0700); err != nil {
			t.Fatal(err)
		}
	}
	results := map[string]any{}
	t.Cleanup(func() {
		results["completed"] = !t.Failed()
		writeM3Report(t, filepath.Join(f.results, "preparation-crash.json"), results)
	})
	for _, step := range []string{"link", "tag", "guard", "endpoint", "rule", "address", "wg", "up", "probe-targets", "probe-source", "remove-probe-source", "remove-link", "remove-rule", "remove-endpoint", "remove-guard", "remove-lease"} {
		enablePreparation(t, f, p.PathID)
		if strings.HasPrefix(step, "remove-") {
			// Start from a complete candidate, then change the physical source so
			// cleanup still has an owned endpoint route to remove at that boundary.
			for turn := 0; turn < 12; turn++ {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				b, _ := netCommand(ctx, f.robot, integrationBinary(t), "node", "relay", "supervise", "--config", f.node, "--once").CombinedOutput()
				cancel()
				if !strings.Contains(string(b), `"preparation"`) {
					t.Fatal("initial preparation unavailable", string(b))
				}
			}
			// A fixture-only endpoint route lookup change triggers rebuilding while
			// leaving the owned candidate endpoint route present for deletion.
			netOutput(t, f.robot, "ip", "route", "add", p.Pin.EndpointPrefix, "via", "192.0.2.11", "dev", "wan0", "src", "192.0.2.10", "onlink")
		}
		marker := filepath.Join(f.private, "rebuild-crash-"+step)
		log, err := os.Create(filepath.Join(f.results, "rebuild-crash-"+step+".jsonl"))
		if err != nil {
			t.Fatal(err)
		}
		crashed := false
		for turn := 0; turn < 16; turn++ {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			cmd := netCommand(ctx, f.robot, integrationBinary(t), "node", "relay", "supervise", "--config", f.node, "--once")
			cmd.Env = append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"), "VPNCTL_REBUILD_FAULT="+step, "VPNCTL_REBUILD_MARKER="+marker, "VPNCTL_REBUILD_ENDPOINT="+p.Pin.EndpointPrefix)
			b, runErr := cmd.CombinedOutput()
			cancel()
			if _, err := log.Write(b); err != nil {
				t.Fatal(err)
			}
			if cmd.ProcessState != nil {
				if state, ok := cmd.ProcessState.Sys().(syscall.WaitStatus); ok && state.Signaled() && state.Signal() == syscall.SIGKILL {
					crashed = true
					break
				}
			}
			if runErr != nil && !strings.Contains(string(b), `"preparation"`) {
				t.Fatal("unexpected supervise failure", step, runErr, string(b))
			}
		}
		log.Close()
		if b, err := os.ReadFile(marker); !crashed || err != nil || string(b) != "fired" {
			t.Fatal("SIGKILL boundary not reached", step, err)
		}
		ready := false
		for turn := 0; turn < 32; turn++ {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			b, _ := netCommand(ctx, f.robot, integrationBinary(t), "node", "relay", "supervise", "--config", f.node, "--once").CombinedOutput()
			cancel()
			var report struct {
				Kernel      *relayapply.Result `json:"kernel"`
				Preparation *relayapply.Result `json:"preparation"`
			}
			// A blocked aggregate still emits structured evidence on stdout.
			for _, line := range strings.Split(string(b), "\n") {
				if strings.HasPrefix(line, "{") {
					if err := json.Unmarshal([]byte(line), &report); err != nil {
						t.Fatal(err)
					}
				}
			}
			if report.Preparation == nil {
				t.Fatal("missing resumed intent", step, string(b))
			}
			for _, intent := range report.Preparation.Preparations {
				if intent.PathID == p.PathID && intent.Phase == "ready" {
					ready = true
				}
			}
			if ready {
				break
			}
			if report.Kernel != nil && report.Kernel.KernelReady {
				t.Fatal("partially rebuilt candidate granted", step, report)
			}
		}
		if !ready {
			t.Fatal("crash did not converge", step)
		}
		nodeAdmissionOutput(t, f, integrationBinary(t), "node", "relay", "supervise", "--config", f.node, "--once")
		if payload := applicationCandidate(t, f, p); !payload.OK {
			t.Fatal("recovered payload unavailable", step, payload)
		}
		nodeAdmissionOutput(t, f, integrationBinary(t), "node", "relay", "release", "--config", f.node, "--path-id", p.PathID)
		if strings.HasPrefix(step, "remove-") {
			netOutput(t, f.robot, "ip", "route", "del", p.Pin.EndpointPrefix, "table", "main")
		}
		results[step] = fmt.Sprint("SIGKILL, owned cleanup, fresh approval and payload verified")
	}
}

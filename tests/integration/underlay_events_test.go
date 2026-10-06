//go:build integration

// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package integration

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
	"vpnctl/internal/relayplan"
	"vpnctl/internal/underlayevent"
)

type underlayEventReply struct {
	ID          string            `json:"request_id"`
	Generations map[string]string `json:"generations"`
	Errors      map[string]string `json:"errors"`
}

func runUnderlayEventWorker() error {
	m, err := underlayevent.New([]relayplan.Underlay{{ID: "wifi", Interface: "wan0", Kind: "wifi"}, {ID: "lan", Interface: "wan1", Kind: "ethernet"}, {ID: "lte", Interface: "wwan0", Kind: "lte"}})
	if err != nil {
		return err
	}
	defer m.Close()
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 1024), 1024)
	for scanner.Scan() {
		r := underlayEventReply{ID: scanner.Text(), Generations: map[string]string{}, Errors: map[string]string{}}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		for _, id := range []string{"wifi", "lan", "lte"} {
			g, err := m.Generation(ctx, id)
			r.Generations[id] = g
			if err != nil {
				r.Errors[id] = err.Error()
			}
		}
		cancel()
		if err := json.NewEncoder(os.Stdout).Encode(r); err != nil {
			return err
		}
	}
	return scanner.Err()
}
func eventReply(t *testing.T, stdin io.Writer, log, id string) underlayEventReply {
	t.Helper()
	if _, err := fmt.Fprintln(stdin, id); err != nil {
		t.Fatal(err)
	}
	var result underlayEventReply
	eventually(t, 5*time.Second, "kernel event reply "+id, func() error {
		b, err := os.ReadFile(log)
		if err != nil {
			return err
		}
		for _, line := range strings.Split(string(b), "\n") {
			var r underlayEventReply
			if json.Unmarshal([]byte(line), &r) == nil && r.ID == id {
				result = r
				return nil
			}
		}
		return fmt.Errorf("reply pending")
	})
	return result
}
func TestNetns_UnderlayEvents(t *testing.T) {
	requireNetwork(t)
	ns := newNamespaces(t, 0)[0]
	results, err := os.MkdirTemp(os.Getenv("VPNCTL_ARTIFACT_DIR"), "underlay-events-")
	if err != nil {
		t.Fatal(err)
	}
	evidence := map[string]any{}
	t.Cleanup(func() {
		evidence["completed"] = !t.Failed()
		writeM3Report(t, filepath.Join(results, "underlay-events.json"), evidence)
	})
	for i, name := range []string{"wan0", "wan1", "ethercat"} {
		netOutput(t, ns, "ip", "link", "add", name, "type", "dummy")
		netOutput(t, ns, "ip", "link", "set", name, "up")
		netOutput(t, ns, "ip", "address", "add", fmt.Sprintf("198.19.%d.1/24", i), "dev", name)
	}
	netOutput(t, ns, "ip", "route", "add", "203.0.113.1/32", "dev", "ethercat", "table", "999")
	netOutput(t, ns, "ip", "rule", "add", "pref", "30000", "to", "203.0.113.1/32", "lookup", "999")
	foreign := netOutput(t, ns, "ip", "-j", "-4", "route", "show", "table", "999")
	rules := netOutput(t, ns, "ip", "-j", "-4", "rule", "show")
	worker, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	log := filepath.Join(results, "events.jsonl")
	file, err := os.Create(log)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	cmd := netCommand(context.Background(), ns, worker, "-test.run=^TestNetworkWorker$")
	cmd.Env = append(os.Environ(), "VPNCTL_WORKER=underlay-events")
	cmd.Stdout, cmd.Stderr = file, file
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	proc := &networkProcess{cmd: cmd, log: log}
	t.Cleanup(func() { stdin.Close(); proc.stop() })
	before := eventReply(t, stdin, log, "baseline")
	if len(before.Errors) != 0 || len(before.Generations["wifi"]) != 64 {
		t.Fatal(before)
	}
	// All mutations remain inside this fixture-owned namespace. The reader never
	// installs routes, changes links or adopts an unconfigured control device.
	steps := []struct {
		name     string
		commands [][]string
	}{
		{"link-flap", [][]string{{"link", "set", "wan0", "down"}, {"link", "set", "wan0", "up"}}},
		{"address-ABA", [][]string{{"address", "del", "198.19.0.1/24", "dev", "wan0"}, {"address", "add", "198.19.0.1/24", "dev", "wan0"}}},
		{"route-ABA", [][]string{{"route", "add", "203.0.113.8/32", "dev", "wan0"}, {"route", "del", "203.0.113.8/32", "dev", "wan0"}}},
		{"rename-return", [][]string{{"link", "set", "wan0", "name", "renamed"}, {"link", "set", "renamed", "name", "wan0"}}},
	}
	for _, step := range steps {
		for _, args := range step.commands {
			netOutput(t, ns, append([]string{"ip"}, args...)...)
		}
		after := eventReply(t, stdin, log, step.name)
		if len(after.Errors) != 0 || after.Generations["wifi"] == before.Generations["wifi"] || after.Generations["lan"] != before.Generations["lan"] {
			t.Fatal("missed change or invalidated independent underlay", step.name, before, after)
		}
		evidence[step.name] = after
		before = after
	}
	var links []struct {
		Index int `json:"ifindex"`
	}
	if err := json.Unmarshal([]byte(netOutput(t, ns, "ip", "-j", "link", "show", "wan0")), &links); err != nil || len(links) != 1 {
		t.Fatal(links, err)
	}
	oldIndex := strconv.Itoa(links[0].Index)
	netOutput(t, ns, "ip", "link", "del", "wan0")
	netOutput(t, ns, "ip", "link", "add", "wan0", "index", oldIndex, "type", "dummy")
	netOutput(t, ns, "ip", "link", "set", "wan0", "up")
	netOutput(t, ns, "ip", "address", "add", "198.19.0.1/24", "dev", "wan0")
	after := eventReply(t, stdin, log, "same-index-reuse")
	if len(after.Errors) != 0 || after.Generations["wifi"] == before.Generations["wifi"] || after.Generations["lan"] != before.Generations["lan"] {
		t.Fatal(after)
	}
	evidence["same-index-reuse"] = after
	before = after
	netOutput(t, ns, "ip", "link", "set", "ethercat", "alias", "foreign-control")
	netOutput(t, ns, "ip", "address", "add", "198.19.2.2/24", "dev", "ethercat")
	after = eventReply(t, stdin, log, "foreign-change")
	if len(after.Errors) != 0 || after.Generations["wifi"] != before.Generations["wifi"] || after.Generations["lan"] != before.Generations["lan"] {
		t.Fatal("adopted foreign interface", after)
	}
	// A foreign terminal route in a custom table has no OIF. Never infer that
	// it is an owned app guard from its table range or routing protocol.
	netOutput(t, ns, "ip", "route", "add", "unreachable", "default", "table", "700001", "proto", "186", "metric", "100001")
	after = eventReply(t, stdin, log, "custom-terminal")
	if len(after.Errors) != 0 || after.Generations["wifi"] == before.Generations["wifi"] || after.Generations["lan"] == before.Generations["lan"] {
		t.Fatal("foreign custom terminal route ignored", after)
	}
	evidence["custom-terminal"] = after
	netOutput(t, ns, "ip", "route", "del", "unreachable", "default", "table", "700001", "proto", "186", "metric", "100001")
	before = eventReply(t, stdin, log, "custom-terminal-removed")
	if len(before.Errors) != 0 {
		t.Fatal(before)
	}
	// A shared nexthop update can bypass the normal route notification group.
	netOutput(t, ns, "ip", "nexthop", "add", "id", "17", "via", "198.19.0.2", "dev", "wan0")
	after = eventReply(t, stdin, log, "nexthop-object")
	if len(after.Errors) != 0 || after.Generations["wifi"] == before.Generations["wifi"] || after.Generations["lan"] == before.Generations["lan"] {
		t.Fatal("shared nexthop change missed", after)
	}
	evidence["nexthop-object"] = after
	netOutput(t, ns, "ip", "nexthop", "del", "id", "17")
	before = eventReply(t, stdin, log, "nexthop-deleted")
	if len(before.Errors) != 0 {
		t.Fatal(before)
	}
	// Stop consumption (not the host/process) and fill the actual netlink receive
	// buffer with 2048 real link notifications. ENOBUFS or bounded-drain exhaustion
	// must reject the batch; the next subscribed snapshot gets a new epoch.
	var batch strings.Builder
	for i := 0; i < 2048; i++ {
		fmt.Fprintf(&batch, "link set dev wan0 alias event-%d\n", i)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	burst := netCommand(ctx, ns, "ip", "-batch", "-")
	burst.Stdin = strings.NewReader(batch.String())
	if b, err := burst.CombinedOutput(); err != nil {
		t.Fatal(err, string(b))
	}
	lost := eventReply(t, stdin, log, "overflow")
	if len(lost.Errors) != 3 {
		t.Fatal("event loss not reported unknown", lost)
	}
	evidence["overflow"] = lost
	time.Sleep(1100 * time.Millisecond)
	restored := eventReply(t, stdin, log, "resnapshot")
	if len(restored.Errors) != 0 || restored.Generations["wifi"] == before.Generations["wifi"] || restored.Generations["lan"] == before.Generations["lan"] {
		t.Fatal("lost epoch reused", restored)
	}
	evidence["resnapshot"] = restored
	if got := netOutput(t, ns, "ip", "-j", "-4", "route", "show", "table", "999"); got != foreign {
		t.Fatal("foreign route changed", got)
	}
	if got := netOutput(t, ns, "ip", "-j", "-4", "rule", "show"); got != rules {
		t.Fatal("foreign rules changed", got)
	}
	evidence["foreign_route_preserved"], evidence["foreign_rules_preserved"] = true, true
	stdin.Close()
	proc.finish(t)
}

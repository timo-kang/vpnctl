//go:build integration

// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package integration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/vishvananda/netlink"
	"vpnctl/internal/relayguard"
)

func TestNetns_BootGuard(t *testing.T) {
	requireNetwork(t)
	ns := newNamespaces(t, 1)
	worker, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := netCommand(ctx, ns[1], "setpriv", "--bounding-set=-all,+net_admin,+bpf", worker, "-test.run=^TestBootGuardWorker$", "-test.v")
	cmd.Env = append(os.Environ(), "VPNCTL_BOOT_GUARD_WORKER=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%v\n%s", err, out)
	} else {
		t.Log(string(out))
		for _, line := range strings.Split(string(out), "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "FREED_MAP=") {
				id, err := strconv.ParseUint(strings.TrimPrefix(strings.TrimSpace(line), "FREED_MAP="), 10, 32)
				if err != nil {
					t.Fatal(err)
				}
				eventually(t, 3*time.Second, "map freed after link and pin removal", func() error {
					m, err := ebpf.NewMapFromID(ebpf.MapID(id))
					if errors.Is(err, syscall.ENOENT) {
						return nil
					}
					if m != nil {
						m.Close()
					}
					return fmt.Errorf("map retained: %v", err)
				})
			}
		}
	}
	cmd = netCommand(ctx, ns[1], "setpriv", "--bounding-set=-all,+net_admin", worker, "-test.run=^TestBootGuardWorker$", "-test.v")
	cmd.Env = append(os.Environ(), "VPNCTL_BOOT_GUARD_WORKER=1", "VPNCTL_BOOT_GUARD_DENIED=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("capability denial: %v\n%s", err, out)
	} else {
		t.Log(string(out))
	}
	// The build mount is owned by the outer host UID. The nested user
	// namespace cannot traverse it after losing outer DAC_OVERRIDE.
	clockWorker := filepath.Join(t.TempDir(), "clock-worker")
	src, err := os.Open(worker)
	if err != nil {
		t.Fatal(err)
	}
	dst, err := os.OpenFile(clockWorker, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0700)
	if err != nil {
		src.Close()
		t.Fatal(err)
	}
	_, copyErr := io.Copy(dst, src)
	src.Close()
	closeErr := dst.Close()
	if copyErr != nil || closeErr != nil {
		t.Fatal(copyErr, closeErr)
	}
	cmd = netCommand(ctx, ns[1], "unshare", "--user", "--map-root-user", "--time", "--boottime", "1", "--monotonic", "1", "--fork", clockWorker, "-test.run=^TestBootClockWorker$", "-test.v")
	cmd.Env = append(os.Environ(), "VPNCTL_BOOT_CLOCK_WORKER=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("time namespace rejection: %v\n%s", err, out)
	} else {
		t.Log(string(out))
	}
}

func TestBootClockWorker(t *testing.T) {
	if os.Getenv("VPNCTL_BOOT_CLOCK_WORKER") != "1" {
		t.Skip("isolated time namespace worker")
	}
	if _, err := relayguard.Now(); err == nil || !strings.Contains(err.Error(), "zero time namespace offsets") {
		t.Fatal("time namespace offset accepted", err)
	}
}

func TestBootGuardWorker(t *testing.T) {
	if os.Getenv("VPNCTL_BOOT_GUARD_WORKER") != "1" {
		t.Skip("isolated kernel worker only")
	}
	requireNetwork(t)
	ctx := context.Background()
	owner := relayguard.Owner{Interface: "bootguard", Index: 424242, Group: 424242, Alias: "vpnctl:0102030405060708090a0b0c0d0e0f10"}
	l := &netlink.Wireguard{LinkAttrs: netlink.LinkAttrs{Name: owner.Interface, Index: owner.Index, Group: owner.Group, Alias: owner.Alias}}
	if err := netlink.LinkAdd(l); err != nil {
		t.Fatal(err)
	}
	defer netlink.LinkDel(l)
	pending := owner
	pending.Pending = true
	if err := relayguard.Block(ctx, pending); err != nil {
		t.Fatal("untagged pending cleanup", err)
	}
	if err := relayguard.InspectPartial(ctx, owner); !errors.Is(err, relayguard.ErrConflict) {
		t.Fatal("untagged applied owner accepted", err)
	}
	if err := netlink.LinkSetAlias(l, owner.Alias); err != nil {
		t.Fatal(err)
	}
	if os.Getenv("VPNCTL_BOOT_GUARD_DENIED") == "1" {
		if err := relayguard.Install(ctx, owner); err == nil {
			t.Fatal("installed without BPF capability")
		}
		if _, err := relayguard.Read(ctx, owner); err == nil {
			t.Fatal("missing guard ready")
		}
		qs, err := netlink.QdiscList(l)
		if err != nil || len(qs) != 0 {
			t.Fatal("capability failure left attachments", qs, err)
		}
		return
	}
	if err := relayguard.Install(ctx, owner); err != nil {
		actual, _ := netlink.LinkByIndex(owner.Index)
		qs, _ := netlink.QdiscList(actual)
		t.Logf("link %+v qdiscs %+v", actual.Attrs(), qs)
		for _, parent := range []uint32{netlink.HANDLE_MIN_INGRESS, netlink.HANDLE_MIN_EGRESS} {
			fs, _ := netlink.FilterList(actual, parent)
			for _, f := range fs {
				b, _ := json.Marshal(f)
				t.Logf("filter %s", b)
			}
		}
		t.Fatalf("install: %+v", err)
	}
	s, err := relayguard.Read(ctx, owner)
	if err != nil || s.Active || s.Generation != 0 {
		t.Fatal(s, err)
	}
	gate, err := ebpf.LoadPinnedProgram(filepath.Join("/run/vpnctl-bpf", "lease_"+owner.Alias[7:]+"_program"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer gate.Close()
	packet := make([]byte, 64)
	packet[12], packet[13] = 8, 0
	packet[14] = 0x45
	checkGate := func(want uint32) {
		t.Helper()
		got, _, err := gate.Test(packet)
		if err != nil || got != want {
			t.Fatal("packet decision", got, want, err)
		}
	}
	checkGate(2)
	now, err := relayguard.Now()
	if err != nil {
		t.Fatal(err)
	}
	s, err = relayguard.Update(ctx, owner, 0, now+uint64(2*time.Second), now+uint64(3*time.Second))
	if err != nil || !s.Active || s.Generation != 1 {
		t.Fatalf("fresh grant: %+v %+v", s, err)
	}
	checkGate(0)
	if _, err := relayguard.Update(ctx, owner, 0, now+uint64(2*time.Second), now+uint64(3*time.Second)); !errors.Is(err, relayguard.ErrExpired) {
		t.Fatal("replay accepted", err)
	}
	if err := relayguard.Block(ctx, owner); err != nil {
		t.Fatal(err)
	}
	checkGate(2)
	s, err = relayguard.Read(ctx, owner)
	if err != nil || s.Generation != 2 || s.Active {
		t.Fatal(s, err)
	}
	if _, err := relayguard.Update(ctx, owner, s.Generation, now+uint64(2*time.Second), 0); !errors.Is(err, relayguard.ErrExpired) {
		t.Fatal("cache reopened", err)
	}
	now, err = relayguard.Now()
	if err != nil {
		t.Fatal(err)
	}
	s, err = relayguard.Update(ctx, owner, s.Generation, now+uint64(time.Second), now+uint64(2*time.Second))
	if err != nil || !s.Active {
		t.Fatal(s, err)
	}
	checkGate(0)
	time.Sleep(1200 * time.Millisecond)
	checkGate(2)
	// All three supplied times/generation are fixed before delay. The kernel,
	// rather than a userspace age check, must reject this stale renewal.
	if _, err := relayguard.Update(ctx, owner, s.Generation, now+uint64(time.Second), now+uint64(time.Second)); !errors.Is(err, relayguard.ErrExpired) {
		t.Fatal("stale queued proposal accepted", err)
	}
	checkGate(2)
	final, err := relayguard.Read(ctx, owner)
	if err != nil || final.Generation != s.Generation || final.Active {
		t.Fatal(final, err)
	}

	// Attack the expired state repeatedly with future deadlines but no fresh
	// response, with overly long windows, and with already consumed generations.
	now, err = relayguard.Now()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 32; i++ {
		for _, proposal := range [][3]uint64{
			{s.Generation, now + uint64(time.Second), 0},
			{s.Generation, now + uint64(11*time.Second), now + uint64(2*time.Second)},
			{s.Generation, now + uint64(time.Second), now + uint64(8*time.Second)},
			{s.Generation - 1, now + uint64(time.Second), now + uint64(2*time.Second)},
		} {
			if _, err := relayguard.Update(ctx, owner, proposal[0], proposal[1], proposal[2]); !errors.Is(err, relayguard.ErrExpired) {
				t.Fatal("invalid renewal accepted", proposal, err)
			}
		}
	}
	checkGate(2)
	final, err = relayguard.Read(ctx, owner)
	if err != nil || final.Generation != s.Generation {
		t.Fatal("rejected renewal mutated state", final, err)
	}
	// A missing half attachment is never ready, but the owned partial map can
	// still be blocked and recovered after interruption between attachments.
	filters, err := netlink.FilterList(l, netlink.HANDLE_MIN_EGRESS)
	if err != nil || len(filters) != 1 {
		t.Fatal(filters, err)
	}
	saved := filters[0].(*netlink.BpfFilter)
	if err := netlink.FilterDel(saved); err != nil {
		t.Fatal(err)
	}
	if _, err := relayguard.Read(ctx, owner); !errors.Is(err, relayguard.ErrConflict) {
		t.Fatal("partial attachment ready", err)
	}
	if err := relayguard.Block(ctx, owner); err != nil {
		t.Fatal("partial block", err)
	}
	saved.Fd = gate.FD()
	if err := netlink.FilterAdd(saved); err != nil {
		t.Fatal(err)
	}
	// Same link/name/attributes with foreign always-pass code must be rejected.
	foreign, err := ebpf.NewProgram(&ebpf.ProgramSpec{Name: "foreign", Type: ebpf.SchedCLS, License: "MIT", Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, 0), asm.Return()}})
	if err != nil {
		t.Fatal(err)
	}
	defer foreign.Close()
	saved.Fd = foreign.FD()
	if err := netlink.FilterReplace(saved); err != nil {
		t.Fatal(err)
	}
	if err := relayguard.InspectPartial(ctx, owner); !errors.Is(err, relayguard.ErrConflict) {
		t.Fatal("foreign filter accepted", err)
	}
	if err := relayguard.Block(ctx, owner); !errors.Is(err, relayguard.ErrConflict) {
		t.Fatal("foreign filter modified", err)
	}
	saved.Fd = gate.FD()
	if err := netlink.FilterReplace(saved); err != nil {
		t.Fatal(err)
	}
	if _, err := relayguard.Read(ctx, owner); err != nil {
		t.Fatal("restored owned filter", err)
	}
	if err := gate.Close(); err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkDel(l); err != nil {
		t.Fatal(err)
	}
	if err := relayguard.InspectPartial(ctx, owner); err != nil {
		t.Fatal("absent owned link", err)
	}
	if err := relayguard.RemovePins(ctx, owner); err != nil {
		t.Fatal("pin cleanup", err)
	}
	entries, err := os.ReadDir("/run/vpnctl-bpf")
	if err != nil || len(entries) != 0 {
		t.Fatal("pins retained", entries, err)
	}
	fmt.Printf("FREED_MAP=%d\n", final.MapID)

	b, _ := json.Marshal(final)
	t.Log("kernel-enforced final state", string(b))
}

// Public read-only kernel evidence; no approval cache or relay mutations.
func snapshotBootGuards() error {
	links, err := netlink.LinkList()
	if err != nil {
		return err
	}
	out := map[string]any{}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	for _, l := range links {
		a := l.Attrs()
		if l.Type() != "wireguard" || !strings.HasPrefix(a.Name, "vd") {
			continue
		}
		state, err := relayguard.Read(ctx, relayguard.Owner{Interface: a.Name, Alias: a.Alias, Index: a.Index, Group: a.Group})
		entry := map[string]any{"state": state}
		if err != nil {
			entry["error"] = err.Error()
		}
		out[a.Name] = entry
	}
	b, err := json.Marshal(out)
	if err != nil {
		return err
	}
	fmt.Printf("BOOTTIME_GUARDS=%s\n", b)
	return nil
}

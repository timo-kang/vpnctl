// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayguard

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func (o Owner) valid() bool {
	if o.Interface == "" || o.Index <= 0 || len(o.Alias) != 39 || !strings.HasPrefix(o.Alias, "vpnctl:") {
		return false
	}
	b, err := hex.DecodeString(o.Alias[7:])
	return err == nil && len(b) == 16 && hex.EncodeToString(b) == o.Alias[7:]
}
func (o Owner) name() string { return "vl" + o.Alias[7:20] }
func (o Owner) words() (uint64, uint64) {
	b, _ := hex.DecodeString(o.Alias[7:])
	return binary.NativeEndian.Uint64(b[:8]), binary.NativeEndian.Uint64(b[8:])
}

// The BPF helper uses the host kernel's clock, not time-namespace offsets.
// Refuse an offset namespace rather than compare incompatible time domains.
func Now() (uint64, error) {
	b, err := os.ReadFile("/proc/self/timens_offsets")
	if err != nil {
		return 0, fmt.Errorf("read time namespace offsets: %w", err)
	}
	seen := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		f := strings.Fields(line)
		if len(f) != 3 || (f[0] != "monotonic" && f[0] != "boottime") || seen[f[0]] || f[1] != "0" || f[2] != "0" {
			return 0, errors.New("relay boottime guard requires zero time namespace offsets")
		}
		seen[f[0]] = true
	}
	if len(seen) != 2 {
		return 0, errors.New("incomplete time namespace offsets")
	}
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts); err != nil {
		return 0, err
	}
	return uint64(ts.Nano()), nil
}

func handle(ctx context.Context) (*netlink.Handle, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	h, err := netlink.NewHandle(unix.NETLINK_ROUTE)
	if err != nil {
		return nil, err
	}
	budget := time.Second
	if end, ok := ctx.Deadline(); ok {
		budget = min(budget, time.Until(end))
	}
	if budget <= 0 {
		h.Close()
		return nil, context.DeadlineExceeded
	}
	if err := h.SetSocketTimeout(budget); err != nil {
		h.Close()
		return nil, err
	}
	return h, nil
}

func link(h *netlink.Handle, o Owner) (netlink.Link, error) {
	if !o.valid() {
		return nil, ErrConflict
	}
	l, err := h.LinkByIndex(o.Index)
	if err != nil {
		return nil, err
	}
	a := l.Attrs()
	if l.Type() != "wireguard" || a.Index != o.Index || a.Name != o.Interface || a.Alias != o.Alias || a.Group != o.Group {
		return nil, fmt.Errorf("%w: link", ErrConflict)
	}
	return l, nil
}

func qdiscs(h *netlink.Handle, l netlink.Link) (bool, error) {
	list, err := h.QdiscList(l)
	if err != nil {
		return false, err
	}
	seen := false
	for _, q := range list {
		a := q.Attrs()
		if q.Type() == "noqueue" && a.Handle == 0 && a.Parent == netlink.HANDLE_ROOT {
			continue
		}
		if q.Type() != "clsact" || seen || a.Handle != netlink.MakeHandle(0xffff, 0) || a.Parent != netlink.HANDLE_CLSACT {
			return false, fmt.Errorf("%w: qdisc", ErrConflict)
		}
		seen = true
	}
	return seen, nil
}

func filterAttrs(o Owner, parent uint32) netlink.FilterAttrs {
	return netlink.FilterAttrs{LinkIndex: o.Index, Parent: parent, Handle: 1, Priority: 1, Protocol: unix.ETH_P_ALL}
}

func openMap(ctx context.Context, o Owner, partial bool) (*ebpf.Map, State, error) {
	state := State{}
	h, err := handle(ctx)
	if err != nil {
		return nil, state, err
	}
	defer h.Close()
	l, err := link(h, o)
	if err != nil {
		var missing netlink.LinkNotFoundError
		if partial && o.valid() && errors.As(err, &missing) {
			// Do not mistake index reuse or a foreign same-name link for absence.
			_, nameErr := h.LinkByName(o.Interface)
			if errors.As(nameErr, &missing) {
				l = nil
				err = nil
			}
		}
		if partial && o.Pending && o.valid() {
			candidate, lookupErr := h.LinkByIndex(o.Index)
			if lookupErr == nil {
				a := candidate.Attrs()
				if candidate.Type() == "wireguard" && a.Name == o.Interface && a.Group == o.Group && a.Alias == "" && a.Flags&net.FlagUp == 0 {
					present, checkErr := qdiscs(h, candidate)
					if checkErr == nil && !present {
						l = candidate
						err = nil
					}
				}
			}
		}
		if err != nil {
			return nil, state, err
		}
	}
	present := false
	if l != nil {
		present, err = qdiscs(h, l)
	}
	if err != nil {
		return nil, state, err
	}
	if !present && !partial {
		return nil, state, ErrConflict
	}

	m, p, err := loadPins(o, partial)
	if err != nil || m == nil {
		if err == nil && present {
			err = ErrConflict
		}
		return nil, state, err
	}
	failed := true
	defer func() {
		if failed {
			m.Close()
		}
	}()
	if p != nil {
		defer p.Close()
	}
	info, err := m.Info()
	if err != nil {
		return nil, state, err
	}
	selected, ok := info.ID()
	if !ok || info.Type != ebpf.Array || info.KeySize != 4 || info.ValueSize != 40 || info.MaxEntries != 1 || info.Flags != 0 || info.Name != o.name() {
		return nil, state, fmt.Errorf("%w: map layout", ErrConflict)
	}
	count := 0
	var programID ebpf.ProgramID
	tag := ""
	if p != nil {
		pi, err := p.Info()
		if err != nil {
			return nil, state, err
		}
		want := gateSpec(o, 0)
		if err := want.Instructions.Marshal(io.Discard, instructionOrder()); err != nil {
			return nil, state, err
		}
		ids, ok := pi.MapIDs()
		programID, _ = pi.ID()
		if pi.Type != ebpf.SchedCLS || pi.Name != o.name() || want.Compatible(pi) != nil || programID == 0 || !ok || len(ids) != 1 || ids[0] != selected {
			return nil, state, fmt.Errorf("%w: program identity", ErrConflict)
		}
		tag = pi.Tag
	}
	if present {
		for _, parent := range []uint32{netlink.HANDLE_MIN_INGRESS, netlink.HANDLE_MIN_EGRESS} {
			filters, err := h.FilterList(l, parent)
			if err != nil {
				return nil, state, err
			}
			if len(filters) == 0 && partial {
				continue
			}
			if len(filters) != 1 {
				return nil, state, ErrConflict
			}
			f, ok := filters[0].(*netlink.BpfFilter)
			if !ok || f.Handle != 1 || f.Priority != 1 || f.Protocol != unix.ETH_P_ALL || f.Parent != parent || f.LinkIndex != o.Index || (f.Chain != nil && *f.Chain != 0) || !f.DirectAction || f.ClassId != 0 || f.Name != o.name() || f.Tag != tag || f.Id <= 0 || uint32(f.Id) != uint32(programID) {
				return nil, state, fmt.Errorf("%w: filter attributes", ErrConflict)
			}
			count++
		}
	}
	if !partial && (count != 2 || p == nil) {
		return nil, state, ErrConflict
	}
	state.ProgramID = uint32(programID)
	var v value
	if err = m.LookupWithFlags(uint32(0), &v, ebpf.LookupLock); err != nil {
		return nil, state, err
	}
	lo, hi := o.words()
	if v.OwnerLo != lo || v.OwnerHi != hi || v.Pad != 0 {
		return nil, state, ErrConflict
	}
	now, err := Now()
	if err != nil {
		return nil, state, err
	}
	if v.Deadline > now+uint64(MaxLease) {
		return nil, state, ErrConflict
	}
	if p == nil && v.Deadline != 0 {
		return nil, state, ErrConflict
	}
	failed = false
	state.DeadlineNS, state.Generation, state.ObservedNS, state.MapID = v.Deadline, v.Generation, now, uint32(selected)
	state.Active = now < v.Deadline && count == 2
	return m, state, nil
}

func Read(ctx context.Context, o Owner) (State, error) {
	m, state, err := openMap(ctx, o, false)
	if m != nil {
		m.Close()
	}
	return state, err
}

// InspectPartial is only for quiescing/removing a journaled installation that
// may have crashed between its two attachments. It never grants readiness.
func InspectPartial(ctx context.Context, o Owner) error {
	m, _, err := openMap(ctx, o, true)
	if m != nil {
		m.Close()
	}
	return err
}

func Install(ctx context.Context, o Owner) error {
	if err := Preflight(o); err != nil {
		return err
	}
	if _, err := Now(); err != nil {
		return err
	}
	h, err := handle(ctx)
	if err != nil {
		return err
	}
	defer h.Close()
	l, err := link(h, o)
	if err != nil {
		return err
	}
	if l.Attrs().Flags&net.FlagUp != 0 {
		return errors.New("boottime guard must be installed before link up")
	}
	if exists, err := qdiscs(h, l); err != nil {
		return err
	} else if exists {
		return ErrConflict
	}
	m, err := ebpf.NewMap(mapSpec(o))
	if err != nil {
		return fmt.Errorf("load lease map (CAP_BPF and kernel support required): %w", err)
	}
	defer m.Close()
	lo, hi := o.words()
	if err = m.Update(uint32(0), value{OwnerLo: lo, OwnerHi: hi}, ebpf.UpdateAny); err != nil {
		return err
	}
	p, err := ebpf.NewProgram(gateSpec(o, m.FD()))
	if err != nil {
		return fmt.Errorf("load lease packet guard: %w", err)
	}
	defer p.Close()
	dir, err := pinDirectory()
	if err != nil {
		return err
	}
	defer dir.Close()
	if err = m.Pin(pinPath(dir, o, "map")); err != nil {
		return err
	}
	if err = p.Pin(pinPath(dir, o, "program")); err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	if err = h.QdiscAdd(&netlink.Clsact{QdiscAttrs: netlink.QdiscAttrs{LinkIndex: o.Index, Handle: netlink.MakeHandle(0xffff, 0), Parent: netlink.HANDLE_CLSACT}}); err != nil {
		return err
	}
	for _, parent := range []uint32{netlink.HANDLE_MIN_INGRESS, netlink.HANDLE_MIN_EGRESS} {
		if err = ctx.Err(); err != nil {
			return err
		}
		if err = h.FilterAdd(&netlink.BpfFilter{FilterAttrs: filterAttrs(o, parent), Fd: p.FD(), Name: o.name(), DirectAction: true}); err != nil {
			return err
		}
	}
	_, err = Read(ctx, o)
	return err
}

// Update is a kernel compare-and-update, not a userspace map overwrite. A
// stopped process cannot extend an expired lease by replaying a queued syscall.
func Update(ctx context.Context, o Owner, expectedGeneration, deadline, freshUntil uint64) (State, error) {
	m, state, err := openMap(ctx, o, false)
	if err != nil {
		return state, err
	}
	defer m.Close()
	if state.Generation != expectedGeneration {
		return state, ErrExpired
	}
	p, err := ebpf.NewProgram(controlSpec(o, m.FD()))
	if err != nil {
		return state, fmt.Errorf("load lease update guard: %w", err)
	}
	defer p.Close()
	if err = ctx.Err(); err != nil {
		return state, err
	}
	ret, _, err := p.Test(proposal(deadline, freshUntil, expectedGeneration))
	if err != nil {
		return state, err
	}
	if ret != 0 {
		return state, ErrExpired
	}
	return Read(ctx, o)
}

func Block(ctx context.Context, o Owner) error {
	m, state, err := openMap(ctx, o, true)
	if err != nil || m == nil {
		return err
	}
	defer m.Close()
	p, err := ebpf.NewProgram(controlSpec(o, m.FD()))
	if err != nil {
		return err
	}
	defer p.Close()
	if err = ctx.Err(); err != nil {
		return err
	}
	ret, _, err := p.Test(proposal(0, 0, state.Generation))
	if err == nil && ret != 0 {
		err = ErrExpired
	}
	return err
}

// asm requires one of the concrete byte orders, not binary.NativeEndian.
func instructionOrder() binary.ByteOrder {
	if binary.NativeEndian.Uint16([]byte{1, 0}) == 1 {
		return binary.LittleEndian
	}
	return binary.BigEndian
}

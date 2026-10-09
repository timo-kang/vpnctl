// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayapply

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"syscall"
	"time"

	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
	"vpnctl/internal/relaycatalog"
)

type targetRouteLookup func(context.Context, Entry, relaycatalog.Target) error

// Keep a single reply strictly smaller than nl.Receive's 64 KiB buffer. A
// buffer-sized prefix cannot prove that a larger datagram was not truncated.
const maxTargetRouteReply = 16 << 10

// Each call opens a new socket in the caller's namespace. This replaces only
// the two route-get processes around a TCP proof, not ownership checks or any
// route mutation. Source and the already verified resource index pin the lookup;
// the enclosing proof still rechecks interface identity and authority afterwards.
func liveTargetRoute(parent context.Context, entry Entry, target relaycatalog.Target) error {
	ctx, cancel := context.WithTimeout(parent, 3*time.Second)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return err
	}
	source, err := netip.ParsePrefix(entry.Candidate.InnerAddress)
	destination, dstErr := netip.ParseAddr(target.ProbeAddress)
	if err != nil || dstErr != nil || !source.Addr().Is4() || source.Bits() != 32 || !destination.Is4() || entry.LinkIndex == 0 || entry.LinkIndex > 0x7fffffff || entry.Candidate.Pin == nil {
		return errors.New("invalid candidate route request")
	}
	req := nl.NewNetlinkRequest(unix.RTM_GETROUTE, unix.NLM_F_REQUEST)
	req.AddData(&nl.RtMsg{RtMsg: unix.RtMsg{Family: unix.AF_INET, Dst_len: 32, Src_len: 32, Flags: unix.RTM_F_LOOKUP_TABLE}})
	req.AddData(nl.NewRtAttr(unix.RTA_DST, destination.AsSlice()))
	req.AddData(nl.NewRtAttr(unix.RTA_SRC, source.Addr().AsSlice()))
	index := make([]byte, 4)
	binary.NativeEndian.PutUint32(index, entry.LinkIndex)
	req.AddData(nl.NewRtAttr(unix.RTA_OIF, index))
	s, closeSocket, err := targetRouteSocket(ctx)
	if err != nil {
		return routeQueryError(ctx)
	}
	defer closeSocket()
	pid, err := s.GetPid()
	if err != nil {
		return routeQueryError(ctx)
	}
	exchange := func(request *nl.NetlinkRequest, kind uint16) ([]byte, error) {
		if err := s.Send(request); err != nil {
			return nil, routeQueryError(ctx)
		}
		messages, from, err := s.Receive()
		if err != nil || ctx.Err() != nil {
			return nil, routeQueryError(ctx)
		}
		return targetKernelReply(messages, from, pid, request.Seq, kind)
	}
	// Resolve the current name as iproute2 does, also rejecting reuse of that
	// name for a different installed resource. Do not cache the name/index pair.
	linkReq := nl.NewNetlinkRequest(unix.RTM_GETLINK, unix.NLM_F_REQUEST)
	linkReq.AddData(&nl.IfInfomsg{IfInfomsg: unix.IfInfomsg{Index: int32(entry.LinkIndex)}})
	data, err := exchange(linkReq, unix.RTM_NEWLINK)
	if err != nil {
		return err
	}
	if err = validateTargetRouteLink(data, entry.LinkIndex, entry.Candidate.Pin.WGInterface); err != nil {
		return err
	}
	data, err = exchange(req, unix.RTM_NEWROUTE)
	if err != nil {
		return err
	}
	if err = validateTargetRouteData(data, entry.LinkIndex, source.Addr(), destination); err != nil {
		return err
	}
	return ctx.Err()
}

func targetRouteSocket(ctx context.Context) (*nl.NetlinkSocket, func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	s, err := nl.Subscribe(unix.NETLINK_ROUTE)
	if err != nil {
		return nil, nil, err
	}
	// Close interrupts the library's pollable, nonblocking file, including a
	// blocked send/receive. Join cancellation before returning; no worker survives
	// namespace/cache ownership and no descriptor is reused by a callback.
	closed := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { s.Close(); close(closed) })
	return s, func() {
		if !stop() {
			<-closed
		}
		s.Close()
	}, nil
}

func routeQueryError(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return errors.New("candidate route query failed")
}

// Route-get is a single unicast reply, never a multipart inventory. Refuse
// unsolicited, interrupted, ambiguous and error/ACK-only responses.
func targetKernelReply(messages []syscall.NetlinkMessage, from *unix.SockaddrNetlink, pid, seq uint32, kind uint16) ([]byte, error) {
	if from == nil || from.Pid != 0 || from.Groups != 0 || len(messages) != 1 {
		return nil, errors.New("invalid candidate route reply")
	}
	m := messages[0]
	if m.Header.Seq != seq || m.Header.Pid != pid || m.Header.Type != kind || m.Header.Flags&(unix.NLM_F_MULTI|unix.NLM_F_DUMP_INTR) != 0 {
		return nil, errors.New("candidate route unavailable")
	}
	if len(m.Data) > maxTargetRouteReply {
		return nil, errors.New("candidate route reply exceeds limit")
	}
	return m.Data, nil
}

func validateTargetRouteLink(data []byte, index uint32, name string) error {
	invalid := errors.New("candidate route interface changed")
	if len(data) < unix.SizeofIfInfomsg || len(data) > maxTargetRouteReply || binary.NativeEndian.Uint32(data[4:]) != index || len(name) == 0 || len(name) > 15 {
		return invalid
	}
	found := false
	for attrs := data[unix.SizeofIfInfomsg:]; len(attrs) > 0; {
		if len(attrs) < 4 {
			return invalid
		}
		size, kind := int(binary.NativeEndian.Uint16(attrs)), binary.NativeEndian.Uint16(attrs[2:])
		aligned := (size + 3) &^ 3
		if size < 4 || aligned > len(attrs) {
			return invalid
		}
		if kind == unix.IFLA_IFNAME {
			if found || !bytes.Equal(attrs[4:size], append([]byte(name), 0)) {
				return invalid
			}
			found = true
		}
		attrs = attrs[aligned:]
	}
	if !found {
		return invalid
	}
	return nil
}

func validateTargetRouteData(data []byte, index uint32, source, destination netip.Addr) error {
	invalid := errors.New("target route does not use approved candidate")
	if len(data) < unix.SizeofRtMsg || len(data) > maxTargetRouteReply || data[0] != unix.AF_INET || data[1] != 32 || data[2] != 32 || data[7] != unix.RTN_UNICAST {
		return invalid
	}
	seen := map[uint16]bool{}
	for attrs := data[unix.SizeofRtMsg:]; len(attrs) > 0; {
		if len(attrs) < 4 {
			return invalid
		}
		size, kind := int(binary.NativeEndian.Uint16(attrs)), binary.NativeEndian.Uint16(attrs[2:])
		aligned := (size + 3) &^ 3
		if size < 4 || aligned > len(attrs) || seen[kind] {
			return invalid
		}
		seen[kind] = true
		value := attrs[4:size]
		switch kind {
		case unix.RTA_DST:
			if !bytes.Equal(value, destination.AsSlice()) {
				return invalid
			}
		case unix.RTA_SRC:
			if !bytes.Equal(value, source.AsSlice()) {
				return invalid
			}
		case unix.RTA_OIF:
			if len(value) != 4 || binary.NativeEndian.Uint32(value) != index {
				return invalid
			}
		case unix.RTA_GATEWAY, unix.RTA_VIA, unix.RTA_MULTIPATH:
			return invalid
		}
		attrs = attrs[aligned:]
	}
	if !seen[unix.RTA_DST] || !seen[unix.RTA_SRC] || !seen[unix.RTA_OIF] {
		return invalid
	}
	return nil
}

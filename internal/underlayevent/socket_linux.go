// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package underlayevent

import (
	"context"
	"encoding/binary"
	"errors"
	"time"

	"golang.org/x/sys/unix"
	"vpnctl/internal/relayplan"
)

// RTA_NH_ID is Linux UAPI attribute 30 (linux/rtnetlink.h); x/sys does not export it.
const rtaNextHopID = 30

const (
	newLink    = unix.RTM_NEWLINK
	delLink    = unix.RTM_DELLINK
	newAddress = unix.RTM_NEWADDR
	delAddress = unix.RTM_DELADDR
	newRoute   = unix.RTM_NEWROUTE
	delRoute   = unix.RTM_DELROUTE
)

type socket struct {
	fd     int
	buffer [64 << 10]byte
}
type message struct {
	kind, flags uint16
	seq         uint32
	data        []byte
}

func align(n int) int { return (n + 3) &^ 3 }
func messages(data []byte) ([]message, error) {
	var out []message
	for len(data) != 0 {
		if len(data) < unix.NLMSG_HDRLEN {
			return nil, ErrUnavailable
		}
		n := int(binary.NativeEndian.Uint32(data))
		if n < unix.NLMSG_HDRLEN || n > len(data) || align(n) > len(data) {
			return nil, ErrUnavailable
		}
		out = append(out, message{binary.NativeEndian.Uint16(data[4:]), binary.NativeEndian.Uint16(data[6:]), binary.NativeEndian.Uint32(data[8:]), data[16:n]})
		data = data[align(n):]
	}
	if len(out) == 0 {
		return nil, ErrUnavailable
	}
	return out, nil
}
func attributes(data []byte) (map[uint16][]byte, error) {
	out := map[uint16][]byte{}
	for len(data) != 0 {
		if len(data) < 4 {
			return nil, ErrUnavailable
		}
		n := int(binary.NativeEndian.Uint16(data))
		kind := binary.NativeEndian.Uint16(data[2:]) & 0x3fff
		if n < 4 || n > len(data) || align(n) > len(data) {
			return nil, ErrUnavailable
		}
		if _, exists := out[kind]; exists {
			return nil, ErrUnavailable
		}
		out[kind] = data[4:n]
		data = data[align(n):]
	}
	return out, nil
}
func indexAttribute(b []byte) (int, error) {
	if len(b) != 4 {
		return 0, ErrUnavailable
	}
	i := int(int32(binary.NativeEndian.Uint32(b)))
	if i <= 0 {
		return 0, ErrUnavailable
	}
	return i, nil
}
func decode(m message) (event, error) {
	e := event{kind: m.kind}
	var header int
	switch m.kind {
	case newLink, delLink:
		header = unix.SizeofIfInfomsg
	case newAddress, delAddress:
		header = unix.SizeofIfAddrmsg
	case newRoute, delRoute:
		header = unix.SizeofRtMsg
	case unix.RTM_NEWNEXTHOP, unix.RTM_DELNEXTHOP, unix.RTM_NEWNEXTHOPBUCKET, unix.RTM_DELNEXTHOPBUCKET:
		header = unix.SizeofNhmsg
	case unix.NLMSG_NOOP:
		return e, nil
	default:
		return e, ErrUnavailable
	}
	if len(m.data) < header {
		return e, ErrUnavailable
	}
	attrs, err := attributes(m.data[header:])
	if err != nil {
		return e, err
	}
	switch m.kind {
	case unix.RTM_NEWNEXTHOP, unix.RTM_DELNEXTHOP, unix.RTM_NEWNEXTHOPBUCKET, unix.RTM_DELNEXTHOPBUCKET:
		// Shared nexthop objects can change routing without RTM_NEWROUTE.
		// Without a full reference graph, invalidate every configured uplink.
		e.global = true
	case newLink, delLink:
		e.index, err = indexAttribute(m.data[4:8])
		if err != nil {
			return e, err
		}
		name := attrs[unix.IFLA_IFNAME]
		if len(name) < 2 || len(name) > 16 || name[len(name)-1] != 0 {
			return e, ErrUnavailable
		}
		for _, c := range name[:len(name)-1] {
			if c == 0 {
				return e, ErrUnavailable
			}
		}
		e.name = string(name[:len(name)-1])
	case newAddress, delAddress:
		if m.data[0] != unix.AF_INET {
			return event{}, nil
		}
		e.index, err = indexAttribute(m.data[4:8])
		if err != nil {
			return e, err
		}
	case newRoute, delRoute:
		if m.data[0] != unix.AF_INET {
			return event{}, nil
		}
		e.table = uint32(m.data[4])
		if b, ok := attrs[unix.RTA_TABLE]; ok {
			if len(b) != 4 {
				return e, ErrUnavailable
			}
			e.table = binary.NativeEndian.Uint32(b)
		}
		if b, ok := attrs[unix.RTA_PRIORITY]; ok {
			if len(b) != 4 {
				return e, ErrUnavailable
			}
			e.metric = binary.NativeEndian.Uint32(b)
		}
		if b, ok := attrs[unix.RTA_OIF]; ok {
			i, err := indexAttribute(b)
			if err != nil {
				return e, err
			}
			e.indexes = append(e.indexes, i)
		}
		if b, ok := attrs[unix.RTA_MULTIPATH]; ok {
			if len(b) == 0 {
				return e, ErrUnavailable
			}
			for len(b) != 0 {
				if len(b) < 8 {
					return e, ErrUnavailable
				}
				n := int(binary.NativeEndian.Uint16(b))
				if n < 8 || n > len(b) || align(n) > len(b) {
					return e, ErrUnavailable
				}
				i, err := indexAttribute(b[4:8])
				if err != nil {
					return e, err
				}
				if _, err := attributes(b[8:n]); err != nil {
					return e, err
				}
				e.indexes = append(e.indexes, i)
				b = b[align(n):]
			}
		}
		if b, ok := attrs[rtaNextHopID]; ok {
			if len(b) != 4 {
				return e, ErrUnavailable
			}
			e.global = true
		}
		// OIF identifies a pinned underlay even in a non-main transport table.
		// An OIF-less route may be an external blackhole/throw/unreachable policy
		// route. Table number or protocol alone never proves application ownership.
		// Conservatively invalidate all, including app terminal guard creation.
		if len(e.indexes) == 0 {
			e.global = true
		}
		// Scope only the exact terminal route form used by candidate preparation.
		// Unknown attributes, selectors, nexthops, main tables and foreign metrics
		// retain global invalidation; protocol/table range alone is insufficient.
		e.terminal = len(e.indexes) == 0 && m.data[1] == 0 && m.data[2] == 0 && m.data[3] == 0 && m.data[5] == 186 && m.data[6] == unix.RT_SCOPE_UNIVERSE && m.data[7] == unix.RTN_UNREACHABLE && binary.NativeEndian.Uint32(m.data[8:12]) == 0
		for kind := range attrs {
			if kind != unix.RTA_TABLE && kind != unix.RTA_PRIORITY {
				e.terminal = false
			}
		}
	}
	return e, nil
}
func (s *socket) receive() ([]message, bool, error) {
	n, _, flags, from, err := unix.Recvmsg(s.fd, s.buffer[:], nil, unix.MSG_DONTWAIT)
	if errors.Is(err, unix.EAGAIN) {
		return nil, false, errEmpty
	}
	if err != nil {
		return nil, false, err
	}
	peer, ok := from.(*unix.SockaddrNetlink)
	if !ok || peer.Pid != 0 || flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 {
		return nil, false, ErrUnavailable
	}
	ms, err := messages(s.buffer[:n])
	return ms, peer.Groups != 0, err
}
func (s *socket) read() ([]event, error) {
	ms, multicast, err := s.receive()
	if err != nil {
		return nil, err
	}
	if !multicast {
		return nil, ErrUnavailable
	}
	out := make([]event, 0, len(ms))
	for _, m := range ms {
		if m.flags&unix.NLM_F_DUMP_INTR != 0 {
			return nil, ErrUnavailable
		}
		e, err := decode(m)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, nil
}
func (s *socket) wait(d time.Duration) error {
	if d <= 0 {
		return nil
	}
	fds := []unix.PollFd{{Fd: int32(s.fd), Events: unix.POLLIN}}
	_, err := unix.Poll(fds, int((d+time.Millisecond-1)/time.Millisecond))
	if errors.Is(err, unix.EINTR) {
		return nil
	}
	if err != nil || fds[0].Revents&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 {
		return ErrUnavailable
	}
	return nil
}
func (s *socket) close() error { return unix.Close(s.fd) }

func openSource(parent context.Context) (source, []link, error) {
	ctx, cancel := context.WithTimeout(parent, 2*time.Second)
	defer cancel()
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, unix.NETLINK_ROUTE)
	if err != nil {
		return nil, nil, err
	}
	s := &socket{fd: fd}
	success := false
	defer func() {
		if !success {
			_ = s.close()
		}
	}()
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Groups: unix.RTMGRP_LINK | unix.RTMGRP_IPV4_IFADDR | unix.RTMGRP_IPV4_ROUTE}); err != nil {
		return nil, nil, err
	}
	if err := unix.SetsockoptInt(fd, unix.SOL_NETLINK, unix.NETLINK_ADD_MEMBERSHIP, unix.RTNLGRP_NEXTHOP); err != nil {
		return nil, nil, err
	}
	// Do not enable NETLINK_NO_ENOBUFS: loss must invalidate all prior evidence.
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, 256<<10); err != nil {
		return nil, nil, err
	}
	request := make([]byte, unix.NLMSG_HDRLEN+unix.SizeofIfInfomsg)
	binary.NativeEndian.PutUint32(request, uint32(len(request)))
	binary.NativeEndian.PutUint16(request[4:], unix.RTM_GETLINK)
	binary.NativeEndian.PutUint16(request[6:], unix.NLM_F_REQUEST|unix.NLM_F_DUMP)
	binary.NativeEndian.PutUint32(request[8:], 1)
	if err := unix.Sendto(fd, request, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, nil, err
	}
	links, err := initialSnapshot(ctx, s.receive, s.wait)
	if err != nil {
		return nil, nil, err
	}
	success = true
	return s, links, nil
}

func initialSnapshot(ctx context.Context, receive func() ([]message, bool, error), wait func(time.Duration) error) ([]link, error) {
	var links []link
	indexes, names := map[int]bool{}, map[string]bool{}
	for packets := 0; packets < 512; {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		ms, multicast, err := receive()
		if errors.Is(err, errEmpty) {
			if err := wait(25 * time.Millisecond); err != nil {
				return nil, err
			}
			continue
		}
		if err != nil {
			return nil, err
		}
		packets++
		for _, m := range ms {
			if m.flags&unix.NLM_F_DUMP_INTR != 0 {
				return nil, ErrUnavailable
			}
			if multicast {
				// A link change interleaved with a non-atomic initial dump could
				// overwrite newer identity with an older record. Start over unknown.
				e, err := decode(m)
				if err != nil || e.kind == newLink || e.kind == delLink {
					return nil, ErrUnavailable
				}
				continue // Address/route state will be read live before every proof.
			}
			if m.seq != 1 {
				return nil, ErrUnavailable
			}
			if m.kind == unix.NLMSG_DONE {
				if len(m.data) != 0 && (len(m.data) < 4 || binary.NativeEndian.Uint32(m.data) != 0) {
					return nil, ErrUnavailable
				}
				return links, nil
			}
			if m.kind != newLink {
				return nil, ErrUnavailable
			}
			e, err := decode(m)
			if err != nil || len(links) >= relayplan.MaxInterfaces || indexes[e.index] || names[e.name] {
				return nil, ErrUnavailable
			}
			indexes[e.index], names[e.name] = true, true
			links = append(links, link{e.index, e.name})
		}
	}
	return nil, ErrUnavailable
}

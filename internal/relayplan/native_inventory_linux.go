// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package relayplan

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"syscall"
	"time"

	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

var errNativeInventory = errors.New("invalid live underlay inventory")

// Open a fresh socket in the caller's namespace for every read. Strict dump
// checking makes ifa_index a kernel filter. No historical inventory, installed
// ownership, approval or route evidence is reused here.
func readNativeLink(parent context.Context, name string) (linkRecord, bool, error) {
	ctx, cancel := context.WithTimeout(parent, 2*time.Second)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return linkRecord{}, false, err
	}
	s, pid, closeSocket, err := nativeInventorySocket(ctx)
	if err != nil {
		return linkRecord{}, false, err
	}
	defer closeSocket()
	exchange := func(req *nl.NetlinkRequest, kind uint16, dump bool) ([][]byte, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if err := s.Send(req); err != nil {
			return nil, err
		}
		return nativeReplies(ctx, s.Receive, pid, req.Seq, kind, dump)
	}
	req := nl.NewNetlinkRequest(unix.RTM_GETLINK, unix.NLM_F_REQUEST)
	req.AddData(nl.NewIfInfomsg(unix.AF_UNSPEC))
	req.AddData(nl.NewRtAttr(unix.IFLA_IFNAME, append([]byte(name), 0)))
	rows, err := exchange(req, unix.RTM_NEWLINK, false)
	if errors.Is(err, unix.ENODEV) {
		return linkRecord{}, false, nil
	}
	if err != nil {
		return linkRecord{}, false, err
	}
	l, err := parseNativeLink(rows[0], name)
	if err != nil {
		return linkRecord{}, false, err
	}
	req = nl.NewNetlinkRequest(unix.RTM_GETADDR, unix.NLM_F_REQUEST|unix.NLM_F_DUMP)
	// Keep the existing address count bound, including IPv6. Only IPv4 records
	// participate in source selection and stable-address comparison.
	req.AddData(&nl.IfAddrmsg{IfAddrmsg: unix.IfAddrmsg{Family: unix.AF_UNSPEC, Index: uint32(l.Index)}})
	rows, err = exchange(req, unix.RTM_NEWADDR, true)
	if err != nil {
		return linkRecord{}, false, err
	}
	l.Addresses = make([]addressRecord, 0, len(rows))
	for _, row := range rows {
		a, err := parseNativeAddress(row, uint32(l.Index))
		if err != nil {
			return linkRecord{}, false, err
		}
		l.Addresses = append(l.Addresses, a)
	}
	return l, true, ctx.Err()
}

func nativeInventorySocket(ctx context.Context) (*nl.NetlinkSocket, uint32, func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, 0, nil, err
	}
	s, err := nl.Subscribe(unix.NETLINK_ROUTE)
	if err != nil {
		return nil, 0, nil, err
	}
	// Set the option before installing cancellation, avoiding fd reuse in a
	// setsockopt call racing Close. Send/Receive use the library's pollable file.
	if err = unix.SetsockoptInt(s.GetFd(), unix.SOL_NETLINK, unix.NETLINK_GET_STRICT_CHK, 1); err != nil {
		s.Close()
		return nil, 0, nil, err
	}
	pid, err := s.GetPid()
	if err != nil {
		s.Close()
		return nil, 0, nil, err
	}
	closed := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { s.Close(); close(closed) })
	closeSocket := func() {
		if !stop() {
			<-closed
		}
		s.Close()
	}

	return s, pid, closeSocket, nil
}

type nativeReceive func() ([]syscall.NetlinkMessage, *unix.SockaddrNetlink, error)

// Reject partial or interrupted dumps, unsolicited messages, ambiguous replies
// and ACK-only success. nl.Receive uses a 64KiB buffer: a datagram at least
// 32KiB is rejected even if its prefix parses, so truncation cannot look complete.
func nativeReplies(ctx context.Context, receive nativeReceive, pid, seq uint32, kind uint16, dump bool) ([][]byte, error) {
	var rows [][]byte
	total := 0
	for packets := 0; packets <= MaxAddresses+1; packets++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		messages, from, err := receive()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if err != nil {
			return nil, err
		}
		if from == nil || from.Pid != 0 || from.Groups != 0 || len(messages) == 0 {
			return nil, errNativeInventory
		}
		size := 0
		for _, m := range messages {
			size += unix.NLMSG_HDRLEN + (len(m.Data)+3)&^3
		}
		total += size
		if size >= 32<<10 || total > MaxOutputBytes {
			return nil, errOutputLimit
		}
		for i, m := range messages {
			if m.Header.Pid != pid || m.Header.Seq != seq || m.Header.Flags&unix.NLM_F_DUMP_INTR != 0 {
				return nil, errNativeInventory
			}
			switch m.Header.Type {
			case unix.NLMSG_ERROR:
				if len(messages) != 1 || len(rows) != 0 || len(m.Data) < 4+unix.NLMSG_HDRLEN {
					return nil, errNativeInventory
				}
				code := int32(binary.NativeEndian.Uint32(m.Data))
				if code >= 0 || code < -4095 {
					return nil, errNativeInventory
				}
				return nil, syscall.Errno(-code)
			case unix.NLMSG_DONE:
				if !dump || m.Header.Flags&unix.NLM_F_MULTI == 0 || i != len(messages)-1 || len(m.Data) != 4 || binary.NativeEndian.Uint32(m.Data) != 0 {
					return nil, errNativeInventory
				}
				return rows, nil
			default:
				if m.Header.Type != kind || dump != (m.Header.Flags&unix.NLM_F_MULTI != 0) {
					return nil, errNativeInventory
				}
				if !dump {
					if len(messages) != 1 {
						return nil, errNativeInventory
					}
					return [][]byte{m.Data}, nil
				}
				if len(rows) >= MaxAddresses {
					return nil, errOutputLimit
				}
				// Own the bytes independently of the receive implementation.
				rows = append(rows, bytes.Clone(m.Data))
			}
		}
	}
	return nil, errOutputLimit
}

func nativeAttributes(data []byte, wanted ...uint16) (map[uint16][]byte, error) {
	attrs := map[uint16][]byte{}
	for len(data) > 0 {
		if len(data) < 4 {
			return nil, errNativeInventory
		}
		length, kind := int(binary.NativeEndian.Uint16(data)), binary.NativeEndian.Uint16(data[2:])
		aligned := (length + 3) &^ 3
		if length < 4 || aligned > len(data) {
			return nil, errNativeInventory
		}
		for _, required := range wanted {
			if kind == required {
				if attrs[kind] != nil {
					return nil, errNativeInventory
				}
				attrs[kind] = data[4:length]
				break
			}
		}
		data = data[aligned:]
	}
	return attrs, nil
}
func parseNativeLink(data []byte, name string) (linkRecord, error) {
	if len(data) < unix.SizeofIfInfomsg {
		return linkRecord{}, errNativeInventory
	}
	index := int32(binary.NativeEndian.Uint32(data[4:]))
	flags := binary.NativeEndian.Uint32(data[8:])
	attrs, err := nativeAttributes(data[unix.SizeofIfInfomsg:], unix.IFLA_IFNAME, unix.IFLA_OPERSTATE)
	if err != nil || index <= 0 || !bytes.Equal(attrs[unix.IFLA_IFNAME], append([]byte(name), 0)) || len(attrs[unix.IFLA_OPERSTATE]) != 1 {
		return linkRecord{}, errNativeInventory
	}
	f := []string{fmt.Sprintf("0x%x", flags)}
	if flags&unix.IFF_UP != 0 {
		f = append(f, "UP")
	}
	if flags&unix.IFF_LOWER_UP != 0 {
		f = append(f, "LOWER_UP")
	}
	return linkRecord{Index: int(index), Name: name, Flags: f, OperState: strconv.Itoa(int(attrs[unix.IFLA_OPERSTATE][0]))}, nil
}
func parseNativeAddress(data []byte, index uint32) (addressRecord, error) {
	if len(data) < unix.SizeofIfAddrmsg || binary.NativeEndian.Uint32(data[4:]) != index {
		return addressRecord{}, errNativeInventory
	}
	attrs, err := nativeAttributes(data[unix.SizeofIfAddrmsg:], unix.IFA_LOCAL, unix.IFA_FLAGS, unix.IFA_CACHEINFO)
	if err != nil {
		return addressRecord{}, err
	}
	if data[0] == unix.AF_INET6 {
		return addressRecord{Family: "inet6"}, nil
	}
	if data[0] != unix.AF_INET || data[1] > 32 || len(attrs[unix.IFA_LOCAL]) != 4 || len(attrs[unix.IFA_CACHEINFO]) != 16 || len(attrs[unix.IFA_FLAGS]) != 4 {
		return addressRecord{}, errNativeInventory
	}
	flags := binary.NativeEndian.Uint32(attrs[unix.IFA_FLAGS])
	if byte(flags) != data[2] {
		return addressRecord{}, errNativeInventory
	}
	scope := strconv.Itoa(int(data[3]))
	if data[3] == unix.RT_SCOPE_UNIVERSE {
		scope = "global"
	}
	local := netip.AddrFrom4([4]byte(attrs[unix.IFA_LOCAL]))
	cache := attrs[unix.IFA_CACHEINFO]
	return addressRecord{Family: "inet", Local: local.String(), PrefixLen: int(data[1]), Scope: scope, Flags: []string{fmt.Sprintf("0x%x", flags)}, Deprecated: flags&unix.IFA_F_DEPRECATED != 0, Tentative: flags&unix.IFA_F_TENTATIVE != 0, DADFailed: flags&unix.IFA_F_DADFAILED != 0, PreferredLifetime: json.RawMessage(strconv.FormatUint(uint64(binary.NativeEndian.Uint32(cache)), 10)), ValidLifetime: json.RawMessage(strconv.FormatUint(uint64(binary.NativeEndian.Uint32(cache[4:])), 10))}, nil
}

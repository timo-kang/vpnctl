// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayapply

import (
	"context"
	"encoding/binary"
	"errors"
	"os"
	"time"

	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

var errFlowtableQuery = errors.New("global flowtable inventory is nonempty or unavailable")

// Read afresh in the caller's namespace at every lease boundary. A separate
// dump avoids nft's exact-table cache narrowing its global flowtable inventory.
func liveNoFlowtables(parent context.Context) error {
	ctx, cancel := context.WithTimeout(parent, 3*time.Second)
	defer cancel()
	f, closeSocket, err := flowtableSocket(ctx)
	if err != nil {
		return flowtableQueryError(ctx)
	}
	defer closeSocket()
	conn, err := f.SyscallConn()
	if err != nil {
		return flowtableQueryError(ctx)
	}
	var address unix.Sockaddr
	var callErr error
	err = conn.Control(func(fd uintptr) { address, callErr = unix.Getsockname(int(fd)) })
	local, ok := address.(*unix.SockaddrNetlink)
	if err != nil || callErr != nil || !ok || local.Pid == 0 {
		return flowtableQueryError(ctx)
	}
	// No ACK and no attributes: only an unfiltered AF_UNSPEC dump proves global
	// absence. Any data, error or ACK instead of DONE must deny the lease.
	req := nl.NewNetlinkRequest(unix.NFNL_SUBSYS_NFTABLES<<8|unix.NFT_MSG_GETFLOWTABLE, unix.NLM_F_DUMP)
	req.AddData(&nl.Nfgenmsg{NfgenFamily: unix.AF_UNSPEC})
	data := req.Serialize()
	err = conn.Write(func(fd uintptr) bool {
		callErr = unix.Sendto(int(fd), data, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK})
		return callErr != unix.EAGAIN
	})
	if err != nil || callErr != nil {
		return flowtableQueryError(ctx)
	}
	if err := receiveEmptyFlowtableDump(f, local.Pid, req.Seq); err != nil {
		return flowtableQueryError(ctx)
	}
	return ctx.Err()
}

func flowtableQueryError(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return errFlowtableQuery
}

func flowtableSocket(ctx context.Context) (*os.File, func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, unix.NETLINK_NETFILTER)
	if err != nil {
		return nil, nil, err
	}
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		unix.Close(fd)
		return nil, nil, err
	}
	// The pollable file owns the descriptor. Every syscall uses SyscallConn so
	// concurrent Close cannot recycle the descriptor during a send or receive.
	f := os.NewFile(uintptr(fd), "flowtable-query")
	closed := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { f.Close(); close(closed) })
	return f, func() {
		if !stop() {
			<-closed
		}
		f.Close()
	}, nil
}

func receiveEmptyFlowtableDump(f *os.File, pid, seq uint32) error {
	conn, err := f.SyscallConn()
	if err != nil {
		return errFlowtableQuery
	}
	// An empty dump is exactly 20 bytes. We need no object parser or unbounded
	// drain: any other data already denies the lease. Recvmsg exposes truncation
	// that the dependency's Receive method hides.
	var data [64]byte
	var n, flags int
	var from unix.Sockaddr
	var callErr error
	err = conn.Read(func(fd uintptr) bool {
		n, _, flags, from, callErr = unix.Recvmsg(int(fd), data[:], nil, 0)
		return callErr != unix.EAGAIN
	})
	if err != nil || callErr != nil || n < 0 || n > len(data) {
		return errFlowtableQuery
	}
	return validateEmptyFlowtableDump(data[:n], flags, from, pid, seq)
}

// A request without ACK/filters can only prove absence with a single complete
// zero-status multipart DONE. This also rejects interrupted/filtered dumps,
// overrun, successful ACKs, trailing messages, malformed lengths and truncation.
func validateEmptyFlowtableDump(data []byte, flags int, from unix.Sockaddr, pid, seq uint32) error {
	sender, ok := from.(*unix.SockaddrNetlink)
	if !ok || sender == nil || sender.Family != unix.AF_NETLINK || sender.Pid != 0 || sender.Groups != 0 || flags != 0 || len(data) != unix.NLMSG_HDRLEN+4 {
		return errFlowtableQuery
	}
	order := binary.NativeEndian
	if order.Uint32(data) != uint32(len(data)) || order.Uint16(data[4:]) != unix.NLMSG_DONE || order.Uint16(data[6:]) != unix.NLM_F_MULTI || order.Uint32(data[8:]) != seq || order.Uint32(data[12:]) != pid || order.Uint32(data[16:]) != 0 {
		return errFlowtableQuery
	}
	return nil
}

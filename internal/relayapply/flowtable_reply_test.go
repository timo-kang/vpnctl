// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayapply

import (
	"encoding/binary"
	"testing"

	"golang.org/x/sys/unix"
)

const (
	flowtableReplyTestPID = uint32(27001)
	flowtableReplyTestSeq = uint32(19073)
)

// An empty unfiltered dump has exactly one 16-byte netlink header followed
// by the signed 32-bit completion status. The request does not ask for ACKs.
func emptyFlowtableReplyFixture() []byte {
	b := make([]byte, 20)
	binary.NativeEndian.PutUint32(b[0:4], 20)
	binary.NativeEndian.PutUint16(b[4:6], unix.NLMSG_DONE)
	binary.NativeEndian.PutUint16(b[6:8], unix.NLM_F_MULTI)
	binary.NativeEndian.PutUint32(b[8:12], flowtableReplyTestSeq)
	binary.NativeEndian.PutUint32(b[12:16], flowtableReplyTestPID)
	return b
}

func TestEmptyFlowtableDumpAcceptsOnlyCompleteKernelCompletion(t *testing.T) {
	from := &unix.SockaddrNetlink{Family: unix.AF_NETLINK}
	if err := validateEmptyFlowtableDump(emptyFlowtableReplyFixture(), 0, from, flowtableReplyTestPID, flowtableReplyTestSeq); err != nil {
		t.Fatal("complete empty dump rejected", err)
	}
	// Correlation is to the current request, not fixture-specific or a previous
	// successful socket. Use unrelated values for a second complete reply.
	b := emptyFlowtableReplyFixture()
	binary.NativeEndian.PutUint32(b[8:12], 37011)
	binary.NativeEndian.PutUint32(b[12:16], 61057)
	if err := validateEmptyFlowtableDump(b, 0, from, 61057, 37011); err != nil {
		t.Fatal("complete empty dump for another socket rejected", err)
	}
}

func TestEmptyFlowtableDumpRejectsMalformedOrExtraBytes(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func([]byte) []byte
	}{
		{"nil", func([]byte) []byte { return nil }},
		{"empty", func([]byte) []byte { return []byte{} }},
		{"short-header", func(b []byte) []byte { return b[:15] }},
		{"header-without-status", func(b []byte) []byte { return b[:16] }},
		{"partial-status", func(b []byte) []byte { return b[:19] }},
		{"zero-length", func(b []byte) []byte { binary.NativeEndian.PutUint32(b, 0); return b }},
		{"length-below-header", func(b []byte) []byte { binary.NativeEndian.PutUint32(b, 15); return b }},
		{"length-excludes-status", func(b []byte) []byte { binary.NativeEndian.PutUint32(b, 16); return b }},
		{"unaligned-declared-length", func(b []byte) []byte { binary.NativeEndian.PutUint32(b, 19); return b }},
		{"declared-overrun", func(b []byte) []byte { binary.NativeEndian.PutUint32(b, 24); return b }},
		{"huge-declared-length", func(b []byte) []byte { binary.NativeEndian.PutUint32(b, ^uint32(0)); return b }},
		{"trailing-zero-byte", func(b []byte) []byte { return append(b, 0) }},
		{"trailing-nonzero-byte", func(b []byte) []byte { return append(b, 1) }},
		{"trailing-aligned-zeroes", func(b []byte) []byte { return append(b, 0, 0, 0, 0) }},
		{"extended-aligned-completion", func(b []byte) []byte {
			binary.NativeEndian.PutUint32(b, 24)
			return append(b, 0, 0, 0, 0)
		}},
		{"unaligned-completion", func(b []byte) []byte {
			binary.NativeEndian.PutUint32(b, 21)
			return append(b, 0)
		}},
		{"large-datagram", func(b []byte) []byte { return append(b, make([]byte, 65536)...) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateEmptyFlowtableDump(tc.change(emptyFlowtableReplyFixture()), 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}, flowtableReplyTestPID, flowtableReplyTestSeq); err == nil {
				t.Fatal("incomplete or extended completion accepted")
			}
		})
	}
}

func TestEmptyFlowtableDumpRejectsOtherMessagesAndStatuses(t *testing.T) {
	for _, tc := range []struct {
		name   string
		kind   uint16
		status int32
	}{
		{"noop", unix.NLMSG_NOOP, 0},
		{"ack-is-not-done", unix.NLMSG_ERROR, 0},
		{"negative-error", unix.NLMSG_ERROR, -1},
		{"positive-error", unix.NLMSG_ERROR, 1},
		{"overrun", unix.NLMSG_OVERRUN, 0},
		{"data", unix.NLMSG_MIN_TYPE, 0},
		{"nft-data", 0x0a16, 0},
		{"unknown-zero", 0, 0},
		{"unknown-high", 65535, 0},
		{"positive-done", unix.NLMSG_DONE, 1},
		{"negative-done", unix.NLMSG_DONE, -1},
		{"interrupted-done-status", unix.NLMSG_DONE, -int32(unix.EINTR)},
		{"minimum-done-status", unix.NLMSG_DONE, -1 << 31},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := emptyFlowtableReplyFixture()
			binary.NativeEndian.PutUint16(b[4:6], tc.kind)
			binary.NativeEndian.PutUint32(b[16:20], uint32(tc.status))
			if err := validateEmptyFlowtableDump(b, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}, flowtableReplyTestPID, flowtableReplyTestSeq); err == nil {
				t.Fatal("message without successful empty completion accepted")
			}
		})
	}
}

func TestEmptyFlowtableDumpRequiresExactFlags(t *testing.T) {
	for _, flags := range []uint16{0, unix.NLM_F_DUMP_INTR, unix.NLM_F_DUMP_FILTERED, unix.NLM_F_MULTI | unix.NLM_F_DUMP_INTR, unix.NLM_F_MULTI | unix.NLM_F_DUMP_FILTERED, unix.NLM_F_MULTI | unix.NLM_F_ACK, unix.NLM_F_MULTI | unix.NLM_F_REQUEST, 0xffff} {
		b := emptyFlowtableReplyFixture()
		binary.NativeEndian.PutUint16(b[6:8], flags)
		if err := validateEmptyFlowtableDump(b, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}, flowtableReplyTestPID, flowtableReplyTestSeq); err == nil {
			t.Fatalf("incomplete, filtered, or unexpected flags accepted: flags=%d", flags)
		}
	}
	for _, flags := range []int{unix.MSG_TRUNC, unix.MSG_CTRUNC, unix.MSG_TRUNC | unix.MSG_CTRUNC, unix.MSG_PEEK, 1 << 30} {
		if err := validateEmptyFlowtableDump(emptyFlowtableReplyFixture(), flags, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}, flowtableReplyTestPID, flowtableReplyTestSeq); err == nil {
			t.Fatalf("nonzero receive flags accepted: flags=%d", flags)
		}
	}
}

func TestEmptyFlowtableDumpRequiresKernelSenderAndRequestIdentity(t *testing.T) {
	for _, tc := range []struct {
		name string
		from unix.Sockaddr
	}{
		{"nil", nil},
		{"typed-nil", (*unix.SockaddrNetlink)(nil)},
		{"wrong-socket-type", &unix.SockaddrInet4{}},
		{"missing-family", &unix.SockaddrNetlink{}},
		{"wrong-family", &unix.SockaddrNetlink{Family: unix.AF_INET}},
		{"userspace-port", &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Pid: 91}},
		{"multicast", &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Groups: 1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateEmptyFlowtableDump(emptyFlowtableReplyFixture(), 0, tc.from, flowtableReplyTestPID, flowtableReplyTestSeq); err == nil {
				t.Fatal("unverified sender accepted")
			}
		})
	}
	for _, tc := range []struct {
		name string
		pid  uint32
		seq  uint32
	}{
		{"different-port", flowtableReplyTestPID + 1, flowtableReplyTestSeq},
		{"zero-port", 0, flowtableReplyTestSeq},
		{"different-sequence", flowtableReplyTestPID, flowtableReplyTestSeq + 1},
		{"zero-sequence", flowtableReplyTestPID, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateEmptyFlowtableDump(emptyFlowtableReplyFixture(), 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}, tc.pid, tc.seq); err == nil {
				t.Fatal("reply for a different request accepted")
			}
		})
	}
}

func TestEmptyFlowtableDumpRejectsMultipartDataEvenWithCompletion(t *testing.T) {
	for _, kind := range []uint16{unix.NLMSG_DONE, unix.NLMSG_ERROR, unix.NLMSG_OVERRUN, unix.NLMSG_MIN_TYPE, 0x0a16} {
		data := emptyFlowtableReplyFixture()
		binary.NativeEndian.PutUint16(data[4:6], kind)
		for _, packet := range [][]byte{
			append(append([]byte(nil), data...), emptyFlowtableReplyFixture()...),
			append(emptyFlowtableReplyFixture(), data...),
		} {
			if err := validateEmptyFlowtableDump(packet, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}, flowtableReplyTestPID, flowtableReplyTestSeq); err == nil {
				t.Fatalf("extra message accepted with completion: kind=%d", kind)
			}
		}
	}
}

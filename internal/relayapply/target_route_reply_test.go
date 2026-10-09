// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayapply

import (
	"encoding/binary"
	"net/netip"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func routeReplyFixture() []byte {
	b := make([]byte, unix.SizeofRtMsg)
	b[0], b[1], b[2], b[7] = unix.AF_INET, 32, 32, unix.RTN_UNICAST
	attr := func(kind uint16, data []byte) {
		a := make([]byte, 4+len(data))
		binary.NativeEndian.PutUint16(a, uint16(len(a)))
		binary.NativeEndian.PutUint16(a[2:], kind)
		copy(a[4:], data)
		b = append(b, a...)
	}
	attr(unix.RTA_DST, []byte{198, 51, 100, 9})
	attr(unix.RTA_SRC, []byte{192, 0, 2, 2})
	index := make([]byte, 4)
	binary.NativeEndian.PutUint32(index, 17)
	attr(unix.RTA_OIF, index)
	return b
}

func TestTargetRouteReplyRejectsIncompleteOrDifferentEvidence(t *testing.T) {
	src, dst := netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("198.51.100.9")
	for _, tc := range []struct {
		name   string
		change func([]byte) []byte
	}{
		{"short-header", func(b []byte) []byte { return b[:11] }},
		{"oversized", func(b []byte) []byte { return append(b, make([]byte, 16<<10)...) }},
		{"ipv6", func(b []byte) []byte { b[0] = unix.AF_INET6; return b }},
		{"destination-prefix", func(b []byte) []byte { b[1] = 24; return b }},
		{"source-prefix", func(b []byte) []byte { b[2] = 24; return b }},
		{"local-route", func(b []byte) []byte { b[7] = unix.RTN_LOCAL; return b }},
		{"different-destination", func(b []byte) []byte { b[19]++; return b }},
		{"different-source", func(b []byte) []byte { b[27]++; return b }},
		{"different-interface", func(b []byte) []byte { b[32]++; return b }},
		{"missing-interface", func(b []byte) []byte { return b[:28] }},
		{"duplicate-source", func(b []byte) []byte { return append(b, b[20:28]...) }},
		{"duplicate-interface", func(b []byte) []byte { return append(b, b[28:36]...) }},
		{"short-attribute", func(b []byte) []byte { b[12] = 3; return b }},
		{"truncated-attribute", func(b []byte) []byte { return b[:len(b)-1] }},
		{"trailing-byte", func(b []byte) []byte { return append(b, 1) }},
		{"gateway", func(b []byte) []byte {
			a := append([]byte(nil), b[12:20]...)
			binary.NativeEndian.PutUint16(a[2:], unix.RTA_GATEWAY)
			return append(b, a...)
		}},
		{"cross-family-gateway", func(b []byte) []byte {
			a := append([]byte(nil), b[12:20]...)
			binary.NativeEndian.PutUint16(a[2:], unix.RTA_VIA)
			return append(b, a...)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateTargetRouteData(tc.change(routeReplyFixture()), 17, src, dst); err == nil {
				t.Fatal("unverified route accepted")
			}
		})
	}
	if err := validateTargetRouteData(routeReplyFixture(), 17, src, dst); err != nil {
		t.Fatal("valid pinned route rejected", err)
	}
}

func TestTargetRouteEnvelopeRequiresSingleKernelReply(t *testing.T) {
	good := syscall.NetlinkMessage{Header: syscall.NlMsghdr{Type: unix.RTM_NEWROUTE, Seq: 9, Pid: 12}, Data: routeReplyFixture()}
	for _, tc := range []struct {
		name     string
		messages []syscall.NetlinkMessage
		from     unix.SockaddrNetlink
	}{
		{"missing", nil, unix.SockaddrNetlink{}},
		{"two", []syscall.NetlinkMessage{good, good}, unix.SockaddrNetlink{}},
		{"non-kernel", []syscall.NetlinkMessage{good}, unix.SockaddrNetlink{Pid: 33}},
		{"multicast", []syscall.NetlinkMessage{good}, unix.SockaddrNetlink{Groups: 1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := targetKernelReply(tc.messages, &tc.from, 12, 9, unix.RTM_NEWROUTE); err == nil {
				t.Fatal("invalid envelope accepted")
			}
		})
	}
	for _, field := range []string{"sequence", "recipient", "type", "multipart", "interrupted", "empty-error", "ack", "oversized"} {
		t.Run(field, func(t *testing.T) {
			bad := good
			switch field {
			case "oversized":
				bad.Data = make([]byte, 16<<10+1)
			case "sequence":
				bad.Header.Seq++
			case "recipient":
				bad.Header.Pid++
			case "type":
				bad.Header.Type = unix.RTM_NEWLINK
			case "multipart":
				bad.Header.Flags = unix.NLM_F_MULTI
			case "interrupted":
				bad.Header.Flags = unix.NLM_F_DUMP_INTR
			case "empty-error":
				bad.Header.Type = unix.NLMSG_ERROR
				bad.Data = nil
			case "ack":
				bad.Header.Type = unix.NLMSG_ERROR
				bad.Data = make([]byte, 4)
			}
			if _, err := targetKernelReply([]syscall.NetlinkMessage{bad}, &unix.SockaddrNetlink{}, 12, 9, unix.RTM_NEWROUTE); err == nil {
				t.Fatal("invalid envelope accepted")
			}
		})
	}
	if _, err := targetKernelReply([]syscall.NetlinkMessage{good}, &unix.SockaddrNetlink{}, 12, 9, unix.RTM_NEWROUTE); err != nil {
		t.Fatal(err)
	}
}

func TestTargetRouteLinkRequiresCurrentNameAndIndex(t *testing.T) {
	fixture := func() []byte {
		b := make([]byte, unix.SizeofIfInfomsg)
		binary.NativeEndian.PutUint32(b[4:], 17)
		a := make([]byte, 12)
		binary.NativeEndian.PutUint16(a, 8)
		binary.NativeEndian.PutUint16(a[2:], unix.IFLA_IFNAME)
		copy(a[4:], []byte("wg0\x00"))
		return append(b, a[:8]...)
	}
	for _, tc := range []struct {
		name   string
		change func([]byte) []byte
	}{
		{"short", func(b []byte) []byte { return b[:15] }},
		{"oversized", func(b []byte) []byte { return append(b, make([]byte, 16<<10)...) }},
		{"index", func(b []byte) []byte { b[4]++; return b }},
		{"name", func(b []byte) []byte { b[20] = 'x'; return b }},
		{"terminator", func(b []byte) []byte { b[23] = 'x'; return b }},
		{"missing", func(b []byte) []byte { return b[:16] }},
		{"duplicate", func(b []byte) []byte { return append(b, b[16:]...) }},
		{"truncated", func(b []byte) []byte { return b[:len(b)-1] }},
		{"trailing", func(b []byte) []byte { return append(b, 1) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateTargetRouteLink(tc.change(fixture()), 17, "wg0"); err == nil {
				t.Fatal("invalid interface accepted")
			}
		})
	}
	if err := validateTargetRouteLink(fixture(), 17, "wg0"); err != nil {
		t.Fatal(err)
	}
}

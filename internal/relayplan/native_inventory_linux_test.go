// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package relayplan

import (
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"syscall"
	"testing"

	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

func nativeLinkFixture() []byte {
	b := make([]byte, unix.SizeofIfInfomsg)
	binary.NativeEndian.PutUint32(b[4:], 7)
	binary.NativeEndian.PutUint32(b[8:], unix.IFF_UP|unix.IFF_LOWER_UP)
	b = append(b, nl.NewRtAttr(unix.IFLA_IFNAME, []byte("eth0\x00")).Serialize()...)
	return append(b, nl.NewRtAttr(unix.IFLA_OPERSTATE, []byte{6}).Serialize()...)
}
func nativeAddressFixture() []byte {
	b := make([]byte, unix.SizeofIfAddrmsg)
	b[0] = unix.AF_INET
	b[1] = 24
	b[2] = unix.IFA_F_PERMANENT
	binary.NativeEndian.PutUint32(b[4:], 7)
	b = append(b, nl.NewRtAttr(unix.IFA_LOCAL, netip.MustParseAddr("192.0.2.2").AsSlice()).Serialize()...)
	cache := make([]byte, 16)
	binary.NativeEndian.PutUint32(cache, 100)
	binary.NativeEndian.PutUint32(cache[4:], 200)
	b = append(b, nl.NewRtAttr(unix.IFA_CACHEINFO, cache).Serialize()...)
	flags := make([]byte, 4)
	binary.NativeEndian.PutUint32(flags, unix.IFA_F_PERMANENT)
	return append(b, nl.NewRtAttr(unix.IFA_FLAGS, flags).Serialize()...)
}
func TestNativeLinkEncoding(t *testing.T) {
	good := nativeLinkFixture()
	l, err := parseNativeLink(good, "eth0")
	if err != nil || l.Index != 7 || l.Name != "eth0" {
		t.Fatal("valid link rejected", err)
	}
	cases := map[string][]byte{"short": good[:15], "duplicate-name": append(append([]byte(nil), good...), nl.NewRtAttr(unix.IFLA_IFNAME, []byte("eth0\x00")).Serialize()...), "trailing": append(append([]byte(nil), good...), 1)}
	for name, b := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := parseNativeLink(b, "eth0"); err == nil {
				t.Fatal("invalid link accepted")
			}
		})
	}
	if _, err := parseNativeLink(good, "renamed"); err == nil {
		t.Fatal("rename accepted")
	}
}
func TestNativeAddressEncodingAndLifetime(t *testing.T) {
	good := nativeAddressFixture()
	a, err := parseNativeAddress(good, 7)
	if err != nil || a.Local != "192.0.2.2" || a.PrefixLen != 24 {
		t.Fatal("valid address rejected", err)
	}
	if v, err := ipv4Addresses(linkRecord{Addresses: []addressRecord{a}}); err != nil || len(v) != 1 {
		t.Fatal("usable address rejected")
	}
	cases := map[string][]byte{"short": good[:7], "duplicate-local": append(append([]byte(nil), good...), nl.NewRtAttr(unix.IFA_LOCAL, []byte{192, 0, 2, 3}).Serialize()...), "trailing": append(append([]byte(nil), good...), 1)}
	for name, b := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := parseNativeAddress(b, 7); err == nil {
				t.Fatal("invalid address accepted")
			}
		})
	}
	if _, err := parseNativeAddress(good, 8); err == nil {
		t.Fatal("wrong device address accepted")
	}
	for _, flags := range []uint32{unix.IFA_F_TENTATIVE, unix.IFA_F_DADFAILED, unix.IFA_F_DEPRECATED} {
		b := append([]byte(nil), good...)
		b[2] = byte(flags)
		binary.NativeEndian.PutUint32(b[len(b)-4:], flags)
		a, err := parseNativeAddress(b, 7)
		if err != nil {
			t.Fatal(err)
		}
		if v, err := ipv4Addresses(linkRecord{Addresses: []addressRecord{a}}); err != nil || len(v) != 0 {
			t.Fatal("unusable address admitted")
		}
	}
	for _, offset := range []int{20, 24} { // cacheinfo preferred and valid lifetimes
		b := append([]byte(nil), good...)
		binary.NativeEndian.PutUint32(b[offset:], 0)
		a, err := parseNativeAddress(b, 7)
		if err != nil {
			t.Fatal(err)
		}
		if v, err := ipv4Addresses(linkRecord{Addresses: []addressRecord{a}}); err != nil || len(v) != 0 {
			t.Fatal("zero lifetime admitted")
		}
	}
}
func TestNativeReplyBoundary(t *testing.T) {
	addr := syscall.NetlinkMessage{Header: syscall.NlMsghdr{Type: unix.RTM_NEWADDR, Flags: unix.NLM_F_MULTI, Pid: 9, Seq: 12}, Data: nativeAddressFixture()}
	done := syscall.NetlinkMessage{Header: syscall.NlMsghdr{Type: unix.NLMSG_DONE, Flags: unix.NLM_F_MULTI, Pid: 9, Seq: 12}, Data: make([]byte, 4)}
	cases := map[string]struct {
		rows []syscall.NetlinkMessage
		from *unix.SockaddrNetlink
		ok   bool
	}{"valid": {[]syscall.NetlinkMessage{addr, done}, &unix.SockaddrNetlink{}, true}, "foreign-sender": {[]syscall.NetlinkMessage{addr, done}, &unix.SockaddrNetlink{Pid: 1}, false}, "missing-sender": {[]syscall.NetlinkMessage{addr, done}, nil, false}, "after-done": {[]syscall.NetlinkMessage{done, addr}, &unix.SockaddrNetlink{}, false}}
	for _, kind := range []string{"wrong-sequence", "wrong-port", "interrupted", "non-multipart", "wrong-type", "oversize"} {
		a := addr
		switch kind {
		case "wrong-sequence":
			a.Header.Seq++
		case "wrong-port":
			a.Header.Pid++
		case "interrupted":
			a.Header.Flags |= unix.NLM_F_DUMP_INTR
		case "non-multipart":
			a.Header.Flags = 0
		case "wrong-type":
			a.Header.Type = unix.RTM_NEWLINK
		case "oversize":
			a.Data = make([]byte, 32<<10)
		}
		cases[kind] = struct {
			rows []syscall.NetlinkMessage
			from *unix.SockaddrNetlink
			ok   bool
		}{[]syscall.NetlinkMessage{a, done}, &unix.SockaddrNetlink{}, false}
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			calls := 0
			receive := func() ([]syscall.NetlinkMessage, *unix.SockaddrNetlink, error) {
				calls++
				if calls > 1 {
					return nil, nil, errors.New("missing completion")
				}
				return c.rows, c.from, nil
			}
			rows, err := nativeReplies(context.Background(), receive, 9, 12, unix.RTM_NEWADDR, true)
			if (err == nil) != c.ok {
				t.Fatal("incorrect boundary verdict", err)
			}
			if c.ok && len(rows) != 1 {
				t.Fatal("incorrect data population")
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := nativeReplies(ctx, func() ([]syscall.NetlinkMessage, *unix.SockaddrNetlink, error) {
		t.Fatal("read after cancellation")
		return nil, nil, nil
	}, 9, 12, unix.RTM_NEWADDR, true); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation lost")
	}
}

func TestNativeInventoryRepeatedPadding(t *testing.T) {
	link := nativeLinkFixture()
	for i := 0; i < 3; i++ {
		link = append(link, nl.NewRtAttr(unix.IFLA_PAD, nil).Serialize()...)
	}
	if _, err := parseNativeLink(link, "eth0"); err != nil {
		t.Fatal("valid repeated alignment padding rejected", err)
	}
	address := nativeAddressFixture()
	for i := 0; i < 3; i++ {
		address = append(address, nl.NewRtAttr(unix.IFA_UNSPEC, nil).Serialize()...)
	}
	if _, err := parseNativeAddress(address, 7); err != nil {
		t.Fatal("well-framed ignored address attributes rejected", err)
	}
}

func TestNativeDumpRequiresCompleteBoundedInventory(t *testing.T) {
	row := syscall.NetlinkMessage{Header: syscall.NlMsghdr{Type: unix.RTM_NEWADDR, Flags: unix.NLM_F_MULTI, Pid: 9, Seq: 12}, Data: nativeAddressFixture()}
	done := syscall.NetlinkMessage{Header: syscall.NlMsghdr{Type: unix.NLMSG_DONE, Flags: unix.NLM_F_MULTI, Pid: 9, Seq: 12}, Data: make([]byte, 4)}
	for _, name := range []string{"missing-done", "too-many", "done-error", "done-interrupted", "ack-only"} {
		t.Run(name, func(t *testing.T) {
			calls := 0
			recv := func() ([]syscall.NetlinkMessage, *unix.SockaddrNetlink, error) {
				calls++
				if calls > 1 {
					return nil, nil, errors.New("end without completion")
				}
				rows := []syscall.NetlinkMessage{row, done}
				switch name {
				case "missing-done":
					rows = rows[:1]
				case "too-many":
					rows = make([]syscall.NetlinkMessage, MaxAddresses+2)
					for i := 0; i <= MaxAddresses; i++ {
						rows[i] = row
					}
					rows[len(rows)-1] = done
				case "done-error":
					rows[1].Data = []byte{1, 0, 0, 0}
				case "done-interrupted":
					rows[1].Header.Flags |= unix.NLM_F_DUMP_INTR
				case "ack-only":
					rows = []syscall.NetlinkMessage{{Header: syscall.NlMsghdr{Type: unix.NLMSG_ERROR, Pid: 9, Seq: 12}, Data: make([]byte, 20)}}
				}
				return rows, &unix.SockaddrNetlink{}, nil
			}
			if _, err := nativeReplies(context.Background(), recv, 9, 12, unix.RTM_NEWADDR, true); err == nil {
				t.Fatal("incomplete or unbounded dump accepted")
			}
		})
	}
}

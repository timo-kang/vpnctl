// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package underlayevent

import (
	"context"
	"encoding/binary"
	"errors"
	"golang.org/x/sys/unix"
	"testing"
	"time"
	"vpnctl/internal/relayobserve"
)

func attr(kind uint16, b []byte) []byte {
	out := make([]byte, align(4+len(b)))
	binary.NativeEndian.PutUint16(out, uint16(4+len(b)))
	binary.NativeEndian.PutUint16(out[2:], kind)
	copy(out[4:], b)
	return out
}

func TestOwnedTerminalScopeRequiresExactJournalTuple(t *testing.T) {
	for _, mode := range []string{"owned", "metric", "table", "protocol", "prefix", "extra", "unregistered", "retired", "nexthop"} {
		t.Run(mode, func(t *testing.T) {
			m, s := fixture(t)
			scope := relayobserve.TerminalScope{UnderlayID: "wifi", Table: 123456, Metric: 987654}
			if mode != "unregistered" {
				if err := m.SetTerminalScopes(context.Background(), []relayobserve.TerminalScope{scope}); err != nil {
					t.Fatal(err)
				}
			}
			msg := routeMessage(scope.Table, unix.RTN_UNREACHABLE, attr(unix.RTA_PRIORITY, u32(scope.Metric)))
			msg.data[5] = 186
			switch mode {
			case "metric":
				msg = routeMessage(scope.Table, unix.RTN_UNREACHABLE, attr(unix.RTA_PRIORITY, u32(scope.Metric+1)))
				msg.data[5] = 186
			case "table":
				msg = routeMessage(scope.Table+1, unix.RTN_UNREACHABLE, attr(unix.RTA_PRIORITY, u32(scope.Metric)))
				msg.data[5] = 186
			case "protocol":
				msg.data[5] = 99
			case "prefix":
				msg.data[1] = 32
			case "extra":
				msg.data = append(msg.data, attr(unix.RTA_PREFSRC, []byte{192, 0, 2, 1})...)
			case "nexthop":
				msg.data = append(msg.data, attr(rtaNextHopID, u32(1))...)
			case "retired":
				if err := m.SetTerminalScopes(context.Background(), nil); err != nil {
					t.Fatal(err)
				}
			}
			ev, err := decode(msg)
			if err != nil {
				t.Fatal(err)
			}
			before, other := generation(t, m, "wifi"), generation(t, m, "lan")
			s.events = [][]event{{ev}}
			if generation(t, m, "wifi") == before {
				t.Fatal("owned change missed")
			}
			if (generation(t, m, "lan") == other) != (mode == "owned") {
				t.Fatal("foreign event scoped or owned event global", ev)
			}
		})
	}
}
func u32(n uint32) []byte { b := make([]byte, 4); binary.NativeEndian.PutUint32(b, n); return b }
func linkMessage(index int, name string) message {
	b := make([]byte, 16)
	copy(b[4:], u32(uint32(index)))
	b = append(b, attr(unix.IFLA_IFNAME, append([]byte(name), 0))...)
	return message{kind: newLink, seq: 1, data: b}
}
func routeMessage(table uint32, kind byte, extra ...[]byte) message {
	b := make([]byte, 12)
	b[0] = unix.AF_INET
	b[4] = byte(table)
	b[7] = kind
	b = append(b, attr(unix.RTA_TABLE, u32(table))...)
	for _, a := range extra {
		b = append(b, a...)
	}
	return message{kind: newRoute, data: b}
}
func TestDecodeScopeAndMultipath(t *testing.T) {
	hop := make([]byte, 8)
	binary.NativeEndian.PutUint16(hop, 8)
	copy(hop[4:], u32(7))
	for _, tc := range []struct {
		name    string
		m       message
		global  bool
		indexes int
		fail    bool
	}{
		{"nexthop-update", message{kind: unix.RTM_NEWNEXTHOP, data: make([]byte, unix.SizeofNhmsg)}, true, 0, false},
		{"explicit-underlay", routeMessage(999, unix.RTN_UNICAST, attr(unix.RTA_OIF, u32(7))), false, 1, false},
		{"multipath", routeMessage(254, unix.RTN_UNICAST, attr(unix.RTA_MULTIPATH, hop)), false, 1, false},
		{"main-unreachable", routeMessage(254, unix.RTN_UNREACHABLE), true, 0, false},
		{"private-terminal", routeMessage(700001, unix.RTN_UNREACHABLE), true, 0, false},
		{"custom-blackhole", routeMessage(999, unix.RTN_BLACKHOLE), true, 0, false},
		{"custom-throw", routeMessage(999, unix.RTN_THROW), true, 0, false},
		{"unresolved-unicast", routeMessage(999, unix.RTN_UNICAST), true, 0, false},
		{"nexthop-object", routeMessage(999, unix.RTN_UNICAST, attr(rtaNextHopID, u32(1))), true, 0, false},
		{"bad-oif", routeMessage(254, unix.RTN_UNICAST, attr(unix.RTA_OIF, []byte{1})), false, 0, true},
		{"bad-multipath", routeMessage(254, unix.RTN_UNICAST, attr(unix.RTA_MULTIPATH, []byte{0})), false, 0, true},
		{"duplicate", routeMessage(254, unix.RTN_UNICAST, attr(unix.RTA_OIF, u32(7)), attr(unix.RTA_OIF, u32(8))), false, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, err := decode(tc.m)
			if (err != nil) != tc.fail || err == nil && (e.global != tc.global || len(e.indexes) != tc.indexes) {
				t.Fatal(e, err)
			}
		})
	}
	for _, m := range []message{{kind: unix.NLMSG_OVERRUN}, {kind: unix.NLMSG_ERROR}, {kind: newAddress, data: []byte{2}}, {kind: newLink, data: make([]byte, 16)}} {
		if _, err := decode(m); err == nil {
			t.Fatal("malformed accepted", m)
		}
	}
}
func TestInitialSnapshotRejectsGapInterruptedDumpAndUnexpectedMessages(t *testing.T) {
	done := message{kind: unix.NLMSG_DONE, seq: 1, data: u32(0)}
	for _, mode := range []string{"clean", "link-interleaved", "overflow", "interrupted", "bad-sequence", "done-error", "duplicate", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			m := linkMessage(7, "wan0")
			end := done
			multicast := false
			var injected error
			switch mode {
			case "link-interleaved":
				multicast = true
			case "overflow":
				injected = unix.ENOBUFS
			case "interrupted":
				m.flags = unix.NLM_F_DUMP_INTR
			case "bad-sequence":
				m.seq = 2
			case "done-error":
				end.data = u32(1)
			case "cancel":
				cancel()
			}
			ms := []message{m, end}
			if mode == "duplicate" {
				ms = []message{m, m, end}
			}
			calls := 0
			links, err := initialSnapshot(ctx, func() ([]message, bool, error) {
				calls++
				if calls > 1 {
					t.Fatal("unexpected retry without resubscribe")
				}
				return ms, multicast, injected
			}, func(time.Duration) error { return nil })
			if mode == "clean" {
				if err != nil || len(links) != 1 || links[0].index != 7 {
					t.Fatal(links, err)
				}
			} else if err == nil {
				t.Fatal("incomplete dump accepted", mode, links)
			}
		})
	}
}
func TestFramingRejectsTruncatedTailAndOversizedLengths(t *testing.T) {
	for _, b := range [][]byte{nil, {1}, make([]byte, 16), append(u32(65536), make([]byte, 12)...), append(append(u32(16), make([]byte, 12)...), 1)} {
		if _, err := messages(b); err == nil {
			t.Fatal("bad message frame accepted")
		}
	}
	if _, err := attributes([]byte{2, 0, 1, 0}); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
}
func FuzzEventDecode(f *testing.F) {
	for _, m := range []message{{kind: unix.RTM_NEWNEXTHOP, data: make([]byte, unix.SizeofNhmsg)}, linkMessage(7, "wan0"), routeMessage(254, unix.RTN_UNICAST, attr(unix.RTA_OIF, u32(7))), {kind: newAddress, data: []byte{2, 24, 0, 0, 7, 0, 0, 0}}} {
		f.Add(m.kind, m.data)
	}
	f.Fuzz(func(t *testing.T, kind uint16, data []byte) {
		if len(data) > 64<<10 {
			return
		}
		_, _ = decode(message{kind: kind, data: data})
		_, _ = messages(data)
	})
}

func TestTerminalScopeDelayedConsumerAcrossRebuild(t *testing.T) {
	m, s := fixture(t)
	ctx := context.Background()
	scope := relayobserve.TerminalScope{UnderlayID: "wifi", Table: 123456, Metric: 987654}
	if err := m.SetTerminalScopes(ctx, []relayobserve.TerminalScope{scope}); err != nil {
		t.Fatal(err)
	}
	before, other := generation(t, m, "wifi"), generation(t, m, "lan")
	msg := routeMessage(scope.Table, unix.RTN_UNREACHABLE, attr(unix.RTA_PRIORITY, u32(scope.Metric)))
	msg.data[5] = 186
	add, err := decode(msg)
	if err != nil {
		t.Fatal(err)
	}
	remove := add
	remove.kind = delRoute
	// Both notifications arrive while this observer is between admissions. The
	// locked journal may show no installed entry, but retains the explicit intent.
	s.events = [][]event{{remove, add}}
	if err := m.SetTerminalScopes(ctx, []relayobserve.TerminalScope{scope}); err != nil {
		t.Fatal(err)
	}
	if generation(t, m, "wifi") == before || generation(t, m, "lan") != other {
		t.Fatal("delayed rebuild invalidated independent underlay")
	}
	// After explicit release, the identical retired tuple must be global again.
	if err := m.SetTerminalScopes(ctx, nil); err != nil {
		t.Fatal(err)
	}
	other = generation(t, m, "lan")
	s.events = [][]event{{add}}
	if generation(t, m, "lan") == other {
		t.Fatal("retired scope adopted foreign event")
	}
}

package peersource

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

const dumpHeader = "private\tpublic\t51820\toff\n"
const dumpKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

func observationDump(rx, tx string) string {
	return dumpHeader + dumpKey + "\tpsk\t(none)\t10.7.0.2/32\t0\t" + rx + "\t" + tx + "\toff\n"
}
func TestWireGuardStrictDump(t *testing.T) {
	at := time.Now().UTC()
	r, e := parseWgDumpStrict(observationDump("18446744073709551615", "0"), 51900, at)
	if e != nil || len(r) != 1 || r[0].WireGuard.Endpoint || uint64(*r[0].WireGuard.RX) != ^uint64(0) || r[0].WireGuard.Handshake != nil {
		t.Fatal(r, e)
	}
	for _, dump := range []string{"", observationDump("NaN", "0"), observationDump("-1", "0"), observationDump("18446744073709551616", "0"), strings.Replace(observationDump("0", "0"), "\t0\t0\t0\t", "\tbad\t0\t0\t", 1), observationDump("0", "0") + strings.TrimPrefix(observationDump("0", "0"), dumpHeader), strings.Replace(observationDump("0", "0"), "\toff\n", "\n", 1)} {
		if peers, e := parseWgDumpStrict(dump, 51900, at); e == nil || len(peers) != 0 {
			t.Fatal("partial/malformed dump accepted", e)
		}
	}
}
func TestWireGuardEpochDetectsObservedLifecycle(t *testing.T) {
	at := time.Now().UTC()
	index := 1
	s := NewWgSource("test", 0)
	s.now = func() time.Time { return at }
	s.interfaceLookup = func(string) (*net.Interface, error) { return &net.Interface{Index: index}, nil }
	read := func(n uint64) string {
		t.Helper()
		at = at.Add(time.Second)
		s.runner = checkRunner{wg: observationDump(fmt.Sprint(n), fmt.Sprint(n))}
		p, e := s.Discover()
		if e != nil {
			t.Fatal(e)
		}
		return p[0].WireGuard.Generation
	}
	first := read(100)
	if got := read(120); got != first {
		t.Fatal("ordinary increase reset epoch")
	}
	reset := read(1)
	if reset == first {
		t.Fatal("reset not propagated to minute sampling")
	}
	if read(130) != reset {
		t.Fatal("new epoch not stable")
	}
	index++
	recreated := read(150)
	if recreated == reset {
		t.Fatal("interface recreation retained epoch")
	}
	s.runner = checkRunner{wg: dumpHeader}
	at = at.Add(time.Second)
	if _, e := s.Discover(); e != nil {
		t.Fatal(e)
	}
	readded := read(160)
	if readded == recreated {
		t.Fatal("peer re-add retained epoch")
	}
	s.runner = checkRunner{wg: "malformed"}
	if _, e := s.DiscoverContext(context.Background()); e == nil {
		t.Fatal("accepted bad dump")
	}
	if read(170) == readded {
		t.Fatal("failed collection retained epoch")
	}
	old := read(180)
	at = at.Add(3 * time.Minute)
	if read(190) == old {
		t.Fatal("gap retained epoch")
	}
}

func TestWireGuardNoAddressAndIPv6Host(t *testing.T) {
	if got := extractVPNIP("(none)"); got != "" {
		t.Fatal(got)
	}
	if got := extractVPNIP("10.0.0.0/8,2001:db8::2/128"); got != "2001:db8::2" {
		t.Fatal(got)
	}
}

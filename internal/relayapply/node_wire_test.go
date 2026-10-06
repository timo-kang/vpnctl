// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayapply

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"vpnctl/internal/relaycatalog"
	"vpnctl/internal/relayplan"
)

func nodeWireFixture(e Entry) string {
	return fmt.Sprintf("private-must-not-leak\t%s\t43210\t%s\n%s\t(none)\t%s\t%s\t0\t0\t0\toff\n", e.Candidate.PublicKey, hexMark(e.Candidate.Pin.FWMark), e.Candidate.RelayPublicKey, e.Candidate.Endpoint, strings.Join(prefixes(e), ","))
}

func TestNodeWireOwnershipAndPartialRecovery(t *testing.T) {
	e, _ := kernelFixture(t)
	e.Candidate.Targets[0].Prefixes = append(e.Candidate.Targets[0].Prefixes, "198.51.101.0/24")
	full := nodeWireFixture(e)
	for _, tc := range []struct {
		name        string
		change      func([]string, []string) string
		partialOnly bool
		bad         bool
	}{
		{name: "complete"},
		{name: "arbitrary-private-column", change: func(h, p []string) string { h[0] = "other-secret"; return "" }},
		{name: "wrong-public", bad: true, change: func(h, p []string) string { h[1] = public("foreign"); return "" }},
		{name: "wrong-peer", bad: true, change: func(h, p []string) string { p[0] = public("foreign"); return "" }},
		{name: "duplicate-peer", bad: true, change: func(h, p []string) string { return full + strings.Join(p, "\t") + "\n" }},
		{name: "extra-header-field", bad: true, change: func(h, p []string) string { return strings.Join(h, "\t") + "\textra\n" + strings.Join(p, "\t") + "\n" }},
		{name: "missing-peer-column", bad: true, change: func(h, p []string) string { return strings.Join(h, "\t") + "\n" + strings.Join(p[:7], "\t") + "\n" }},
		{name: "foreign-psk", bad: true, change: func(h, p []string) string { p[1] = "psk-must-not-leak"; return "" }},
		{name: "wrong-endpoint", bad: true, change: func(h, p []string) string { p[2] = "192.0.2.99:1234"; return "" }},
		{name: "wrong-prefix", bad: true, change: func(h, p []string) string { p[3] = "0.0.0.0/0"; return "" }},
		{name: "duplicate-prefix", bad: true, change: func(h, p []string) string { p[3] += "," + prefixes(e)[0]; return "" }},
		{name: "empty-prefix", bad: true, change: func(h, p []string) string { p[3] += ","; return "" }},
		{name: "keepalive", bad: true, change: func(h, p []string) string { p[7] = "25"; return "" }},
		{name: "wrong-mark", bad: true, change: func(h, p []string) string { h[3] = "0x1234"; return "" }},
		{name: "bad-port", bad: true, change: func(h, p []string) string { h[2] = "65536"; return "" }},
		{name: "bad-mark", bad: true, change: func(h, p []string) string { h[3] = "oops"; return "" }},
		{name: "negative-counter", bad: true, change: func(h, p []string) string { p[5] = "-1"; return "" }},
		{name: "overflow-counter", bad: true, change: func(h, p []string) string { p[6] = "18446744073709551616"; return "" }},
		{name: "max-counter", change: func(h, p []string) string { p[6] = "18446744073709551615"; return "" }},
		{name: "missing-peer", partialOnly: true, change: func(h, p []string) string { return strings.Join(h, "\t") + "\n" }},
		{name: "empty-link", partialOnly: true, change: func(h, p []string) string { return "(none)\t(none)\t0\toff\n" }},
		{name: "missing-endpoint", partialOnly: true, change: func(h, p []string) string { p[2] = "(none)"; return "" }},
		{name: "missing-prefixes", partialOnly: true, change: func(h, p []string) string { p[3] = "(none)"; return "" }},
		{name: "subset-prefixes", partialOnly: true, change: func(h, p []string) string { p[3] = prefixes(e)[0]; return "" }},
		{name: "unordered-prefixes", change: func(h, p []string) string {
			a := strings.Split(p[3], ",")
			for i, j := 0, len(a)-1; i < j; i, j = i+1, j-1 {
				a[i], a[j] = a[j], a[i]
			}
			p[3] = strings.Join(a, ",")
			return ""
		}},
	} {
		for _, partial := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/partial=%v", tc.name, partial), func(t *testing.T) {
				lines := strings.Split(strings.TrimSpace(full), "\n")
				h, p := strings.Fields(lines[0]), strings.Fields(lines[1])
				raw := ""
				if tc.change != nil {
					raw = tc.change(h, p)
				}
				if raw == "" {
					raw = strings.Join(h, "\t") + "\n" + strings.Join(p, "\t") + "\n"
				}
				buf := []byte(raw)
				ready, err := validateNodeWire(buf, e, partial)
				want := !tc.bad && (!tc.partialOnly || partial)
				if ready != want || (err == nil) != want {
					t.Fatalf("ready=%v err=%v want=%v", ready, err, want)
				}
				if !bytes.Equal(buf, make([]byte, len(buf))) {
					t.Fatal("private buffer was not erased")
				}
				if err != nil && err.Error() != ErrConflict.Error() {
					t.Fatal("non-generic error")
				}
			})
		}
	}
}

func TestNodeWireBoundsAndLiveReread(t *testing.T) {
	e, _ := kernelFixture(t)
	for _, raw := range [][]byte{nil, []byte("\n"), bytes.Repeat([]byte("secret"), 100000)} {
		if ok, err := validateNodeWire(raw, e, false); ok || !errors.Is(err, ErrConflict) {
			t.Fatal("bad size accepted")
		}
		if !bytes.Equal(raw, make([]byte, len(raw))) {
			t.Fatal("invalid buffer not erased")
		}
	}
	reads := 0
	k := kernel{run: func(_ context.Context, _ string, name string, args ...string) ([]byte, error) {
		if name == "ip" {
			return json.Marshal([]object{{"addr_info": []object{{"family": "inet", "local": strings.TrimSuffix(e.Candidate.InnerAddress, "/32"), "prefixlen": 32}}}})
		}
		if name != "wg" || strings.Join(args, " ") != "show "+e.Candidate.Pin.WGInterface+" dump" {
			t.Fatal("unexpected query")
		}
		reads++
		raw := nodeWireFixture(e)
		if reads == 2 {
			raw = strings.Replace(raw, "\t(none)\t", "\tforeign-psk\t", 1)
		}
		return []byte(raw), nil
	}}
	if ok, err := k.wireState(context.Background(), e, false); err != nil || !ok {
		t.Fatal(ok, err)
	}
	if ok, err := k.wireState(context.Background(), e, false); ok || !errors.Is(err, ErrConflict) {
		t.Fatal("new PSK hidden", ok, err)
	}
	if reads != 2 {
		t.Fatal("dump must be fresh for each check", reads)
	}
}

func FuzzNodeWire(f *testing.F) {
	e := Entry{Candidate: relayplan.Candidate{PublicKey: "public", RelayPublicKey: "peer", Endpoint: "192.0.2.1:51820", Pin: &relayplan.PinInput{FWMark: 7}, Targets: []relaycatalog.Target{{Prefixes: []string{"198.18.0.2/32"}}}}}
	f.Add([]byte(nodeWireFixture(e)), false)
	f.Add([]byte("(none)\t(none)\t0\toff\n"), true)
	f.Add([]byte("secret\n"), false)
	f.Fuzz(func(t *testing.T, data []byte, partial bool) {
		raw := append([]byte(nil), data...)
		ok, err := validateNodeWire(raw, e, partial)
		if ok && err != nil || !ok && !errors.Is(err, ErrConflict) {
			t.Fatal("invalid result")
		}
		if !bytes.Equal(raw, make([]byte, len(raw))) {
			t.Fatal("raw buffer survived validation")
		}
	})
}

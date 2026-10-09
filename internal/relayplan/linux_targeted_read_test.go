// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayplan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

const targetedRouteJSON = `[{"dev":"wan0","dst":"192.0.2.1","from":"192.0.2.10"}]`

func targetedUnderlay() Underlay {
	return Underlay{ID: "lan", Interface: "wan0", Kind: "ethernet"}
}

// The foreign interfaces are valid but irrelevant to this approved underlay.
// At scale the old full address dump exceeds its output bound; a scoped read
// must remain bounded by the selected device's address inventory instead.
func TestLinuxTargetedAddressReadsIgnoreUnrelatedInterfaces(t *testing.T) {
	for _, unrelated := range []int{0, 72} {
		t.Run(fmt.Sprintf("unrelated_%d", unrelated), func(t *testing.T) {
			links := []linkRecord{validLink()}
			for i := 0; i < unrelated; i++ {
				l := linkRecord{Index: 100 + i, Name: fmt.Sprintf("foreign%d", i), Flags: []string{"UP", "LOWER_UP"}, OperState: "UP", Addresses: []addressRecord{}}
				for a := 0; a < MaxAddresses; a++ {
					l.Addresses = append(l.Addresses, addressRecord{Family: "inet", Local: fmt.Sprintf("198.19.%d.%d", i, a+1), PrefixLen: 24, Scope: "global"})
				}
				links = append(links, l)
			}
			full, err := json.Marshal(links)
			if err != nil {
				t.Fatal(err)
			}
			if unrelated > 0 && len(full) <= MaxOutputBytes {
				t.Fatal("fixture does not exercise the full-dump limit")
			}
			targeted, broad, fallback, routes := 0, 0, 0, 0
			c := LinuxCollector{ReadIP: func(_ context.Context, args ...string) ([]byte, error) {
				switch strings.Join(args, " ") {
				case "-j address show dev wan0":
					targeted++
					return linkJSON(validLink()), nil
				case "-j address show":
					broad++
					return full, nil
				case "-j link show":
					fallback++
					return nil, errors.New("unnecessary fallback")
				case "-j -4 route get 192.0.2.1 from 192.0.2.10 oif wan0":
					routes++
					return []byte(targetedRouteJSON), nil
				default:
					t.Fatal("unexpected inventory command")
					return nil, errors.New("unexpected command")
				}
			}}
			v := c.Collect(context.Background(), targetedUnderlay(), []string{"192.0.2.1:51820"})
			if v.State != "up" || v.IfIndex != 7 || len(v.Routes) != 1 || v.Routes[0].State != "up" {
				t.Fatalf("selected device lost to unrelated inventory: state=%s reason=%s routes=%d", v.State, v.Reason, len(v.Routes))
			}
			if targeted != 2 || broad != 0 || fallback != 0 || routes != 1 {
				t.Fatalf("expected two live device reads and one pinned lookup: targeted=%d broad=%d fallback=%d routes=%d", targeted, broad, fallback, routes)
			}
		})
	}
}

func TestLinuxTargetedAddressFailureRequiresVerifiedAbsence(t *testing.T) {
	for _, tc := range []struct {
		name, links, state string
		readErr            error
	}{
		{name: "empty-namespace", links: `[]`, state: "down"},
		{name: "other-device-only", links: `[{"ifindex":1,"ifname":"lo","flags":["UP"]}]`, state: "down"},
		{name: "device-unreadable", links: `[{"ifindex":7,"ifname":"wan0","flags":["UP","LOWER_UP"]}]`, state: "unknown"},
		{name: "namespace-unreadable", readErr: errors.New("denied"), state: "unknown"},
		{name: "namespace-null", links: `null`, state: "unknown"},
		{name: "namespace-malformed", links: `not-json`, state: "unknown"},
		{name: "namespace-incomplete", links: `[{}]`, state: "unknown"},
		{name: "namespace-missing-flags", links: `[{"ifindex":1,"ifname":"lo"}]`, state: "unknown"},
		{name: "namespace-duplicate-name", links: `[{"ifindex":1,"ifname":"lo","flags":[]},{"ifindex":2,"ifname":"lo","flags":[]}]`, state: "unknown"},
		{name: "namespace-duplicate-index", links: `[{"ifindex":1,"ifname":"lo","flags":[]},{"ifindex":1,"ifname":"other","flags":[]}]`, state: "unknown"},
		{name: "namespace-oversized", links: strings.Repeat(" ", MaxOutputBytes+1), state: "unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			targeted, fallback, other := 0, 0, 0
			c := LinuxCollector{ReadIP: func(_ context.Context, args ...string) ([]byte, error) {
				switch strings.Join(args, " ") {
				case "-j address show dev wan0":
					targeted++
					return nil, errors.New("generic device read error")
				case "-j link show":
					fallback++
					return []byte(tc.links), tc.readErr
				default:
					other++
					return nil, errors.New("unexpected command")
				}
			}}
			v := c.Collect(context.Background(), targetedUnderlay(), []string{"192.0.2.1:51820"})
			if v.State != tc.state || tc.state == "down" && (v.Reason != "interface_absent" || v.Present == nil || *v.Present) || tc.state == "unknown" && v.Present != nil {
				t.Fatalf("unverified error classified as absence: state=%s reason=%s presentKnown=%t", v.State, v.Reason, v.Present != nil)
			}
			if targeted != 1 || fallback != 1 || other != 0 || len(v.Routes) != 0 {
				t.Fatalf("absence confirmation query contract: targeted=%d fallback=%d other=%d routes=%d", targeted, fallback, other, len(v.Routes))
			}
		})
	}
}

func TestLinuxTargetedAddressAbsenceInventoryCountLimit(t *testing.T) {
	for _, count := range []int{MaxInterfaces, MaxInterfaces + 1} {
		t.Run(fmt.Sprintf("links_%d", count), func(t *testing.T) {
			links := make([]linkRecord, count)
			for i := range links {
				links[i] = linkRecord{Index: 100 + i, Name: fmt.Sprintf("foreign%d", i), Flags: []string{}}
			}
			raw, err := json.Marshal(links)
			if err != nil || len(raw) > MaxOutputBytes {
				t.Fatal("fixture must isolate count from byte limit")
			}
			reads := 0
			c := LinuxCollector{ReadIP: func(_ context.Context, args ...string) ([]byte, error) {
				reads++
				switch strings.Join(args, " ") {
				case "-j address show dev wan0":
					return nil, errors.New("device unavailable")
				case "-j link show":
					return raw, nil
				default:
					t.Error("unexpected absence query")
					return nil, errors.New("unexpected command")
				}
			}}
			v := c.Collect(context.Background(), targetedUnderlay(), []string{"192.0.2.1:51820"})
			if count == MaxInterfaces {
				if v.State != "down" || v.Reason != "interface_absent" || v.Present == nil || *v.Present {
					t.Fatalf("valid bounded absence rejected: state=%s reason=%s", v.State, v.Reason)
				}
			} else if v.State != "unknown" || v.Present != nil {
				t.Fatalf("over-limit namespace claimed absence: state=%s presentKnown=%t", v.State, v.Present != nil)
			}
			if reads != 2 || len(v.Routes) != 0 {
				t.Fatalf("unexpected work after absence check: reads=%d routes=%d", reads, len(v.Routes))
			}
		})
	}
}

func TestLinuxTargetedAddressExplicitAbsenceNeedsNoFallback(t *testing.T) {
	reads := 0
	c := LinuxCollector{ReadIP: func(_ context.Context, args ...string) ([]byte, error) {
		reads++
		if strings.Join(args, " ") != "-j address show dev wan0" {
			t.Error("explicit successful absence must not require a namespace dump")
		}
		return []byte(`[]`), nil
	}}
	v := c.Collect(context.Background(), targetedUnderlay(), []string{"192.0.2.1:51820"})
	if v.State != "down" || v.Reason != "interface_absent" || v.Present == nil || *v.Present || reads != 1 || len(v.Routes) != 0 {
		t.Fatalf("successful empty targeted result not recognized: state=%s reason=%s reads=%d", v.State, v.Reason, reads)
	}
}

func TestLinuxTargetedAddressCancellationCannotEstablishAbsence(t *testing.T) {
	for _, moment := range []string{"target-read-failed", "fallback-read-completed"} {
		t.Run(moment, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			targeted, fallback, other := 0, 0, 0
			c := LinuxCollector{ReadIP: func(_ context.Context, args ...string) ([]byte, error) {
				switch strings.Join(args, " ") {
				case "-j address show dev wan0":
					targeted++
					if moment == "target-read-failed" {
						cancel()
					}
					return nil, errors.New("device read failed")
				case "-j link show":
					fallback++
					cancel() // Cancellation races a successfully completed command.
					return []byte(`[]`), nil
				default:
					other++
					return nil, errors.New("unexpected command")
				}
			}}
			v := c.Collect(ctx, targetedUnderlay(), []string{"192.0.2.1:51820"})
			wantFallback := 0
			if moment == "fallback-read-completed" {
				wantFallback = 1
			}
			if ctx.Err() != context.Canceled || v.State != "unknown" || v.Present != nil || len(v.Routes) != 0 || targeted != 1 || fallback != wantFallback || other != 0 {
				t.Fatalf("canceled collection granted absence or continued work: state=%s presentKnown=%t targeted=%d fallback=%d other=%d", v.State, v.Present != nil, targeted, fallback, other)
			}
		})
	}
}

func TestLinuxTargetedAddressRejectsUnrelatedOrAmbiguousResult(t *testing.T) {
	for _, raw := range []string{
		`[{"ifindex":8,"ifname":"other","flags":[],"addr_info":[]}]`,
		`[{"ifindex":7,"ifname":"wan0","flags":[],"addr_info":[]},{"ifindex":8,"ifname":"other","flags":[],"addr_info":[]}]`,
		`[{"ifindex":7,"ifname":"wan0","flags":[],"addr_info":[]},{"ifindex":7,"ifname":"wan0","flags":[],"addr_info":[]}]`,
		`[{"ifindex":0,"ifname":"wan0","flags":[],"addr_info":[]}]`,
		`[{"ifindex":7,"ifname":"wan0","addr_info":[]}]`,
		`[{"ifindex":7,"ifname":"wan0","flags":[]}]`,
		`null`,
	} {
		c := LinuxCollector{ReadIP: func(_ context.Context, args ...string) ([]byte, error) {
			if strings.Join(args, " ") != "-j address show dev wan0" {
				t.Error("invalid targeted response must not be repaired with another inventory")
			}
			return []byte(raw), nil
		}}
		v := c.Collect(context.Background(), targetedUnderlay(), nil)
		if v.State != "unknown" || v.Present != nil {
			t.Fatalf("invalid targeted inventory acquired known device state: state=%s presentKnown=%t", v.State, v.Present != nil)
		}
	}
}

func TestLinuxTargetedAddressRechecksIdentityAfterLookup(t *testing.T) {
	for _, fault := range []string{"index", "rename", "address", "carrier", "deleted", "unreadable"} {
		t.Run(fault, func(t *testing.T) {
			reads, routeReads, fallback := 0, 0, 0
			c := LinuxCollector{ReadIP: func(_ context.Context, args ...string) ([]byte, error) {
				switch strings.Join(args, " ") {
				case "-j address show dev wan0":
					reads++
					l := validLink()
					if reads == 2 {
						if routeReads != 1 {
							t.Fatal("post-read happened before the endpoint lookup")
						}
						switch fault {
						case "index":
							l.Index++
						case "rename":
							l.Name = "other"
						case "address":
							l.Addresses[0].Local = "192.0.2.20"
						case "carrier":
							l.Flags = []string{"UP"}
						case "deleted", "unreadable":
							return nil, errors.New("device read failed")
						}
					}
					return linkJSON(l), nil
				case "-j -4 route get 192.0.2.1 from 192.0.2.10 oif wan0":
					routeReads++
					return []byte(targetedRouteJSON), nil
				case "-j link show":
					fallback++
					if fault == "deleted" {
						return []byte(`[]`), nil
					}
					return []byte(`[{"ifindex":7,"ifname":"wan0","flags":["UP","LOWER_UP"]}]`), nil
				default:
					return nil, errors.New("unexpected command")
				}
			}}
			v := c.Collect(context.Background(), targetedUnderlay(), []string{"192.0.2.1:51820"})
			wantFallback := 0
			if fault == "deleted" || fault == "unreadable" {
				wantFallback = 1
			}
			if v.State != "unknown" || v.Reason != "inventory_changed" || len(v.Routes) != 0 || reads != 2 || routeReads != 1 || fallback != wantFallback {
				t.Fatalf("in-read replacement escaped: state=%s reason=%s routes=%d reads=%d lookups=%d fallback=%d", v.State, v.Reason, len(v.Routes), reads, routeReads, fallback)
			}
		})
	}
}

// Public, synthetic address inventory only: four underlays and eight candidate
// WG devices. The same fake serves full and targeted queries so this benchmark
// can be run unchanged on both sides of the collector optimization.
func BenchmarkLinuxCollectorCandidateAddressInventory(b *testing.B) {
	links := []linkRecord{validLink()}
	for i := 1; i < 4; i++ {
		l := validLink()
		l.Index, l.Name, l.Addresses[0].Local = 7+i, fmt.Sprintf("wan%d", i), fmt.Sprintf("192.0.%d.10", 2+i)
		links = append(links, l)
	}
	for i := 0; i < 8; i++ {
		links = append(links, linkRecord{Index: 100000 + i, Name: fmt.Sprintf("vr%012x", i), Flags: []string{"UP", "LOWER_UP", "POINTOPOINT", "NOARP"}, OperState: "UNKNOWN", Addresses: []addressRecord{{Family: "inet", Local: fmt.Sprintf("198.18.0.%d", 11+i), PrefixLen: 32, Scope: "global"}}})
	}
	full, err := json.Marshal(links)
	if err != nil {
		b.Fatal(err)
	}
	target, route := linkJSON(validLink()), []byte(targetedRouteJSON)
	var readBytes, reads int64
	c := LinuxCollector{ReadIP: func(_ context.Context, args ...string) ([]byte, error) {
		var data []byte
		switch strings.Join(args, " ") {
		case "-j address show":
			data = full
		case "-j address show dev wan0":
			data = target
		case "-j -4 route get 192.0.2.1 from 192.0.2.10 oif wan0":
			data = route
		default:
			return nil, errors.New("unexpected benchmark query")
		}
		reads++
		readBytes += int64(len(data))
		return data, nil
	}}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		v := c.Collect(context.Background(), targetedUnderlay(), []string{"192.0.2.1:51820"})
		if v.State != "up" || len(v.Routes) != 1 || v.Routes[0].State != "up" {
			b.Fatal("benchmark fixture did not produce a usable underlay")
		}
	}
	b.StopTimer()
	b.ReportMetric(float64(readBytes)/float64(b.N), "json-bytes/op")
	b.ReportMetric(float64(reads)/float64(b.N), "reads/op")
}

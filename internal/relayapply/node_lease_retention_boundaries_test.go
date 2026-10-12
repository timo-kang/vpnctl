// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayapply

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"strings"
	"testing"
	"time"
	"vpnctl/internal/relayguard"
)

func TestNodeLeaseRetentionHeadroomAndClockBounds(t *testing.T) {
	wall := time.Unix(2000000000, 0)
	boot := 100 * time.Second
	original := DeploymentLease{Active: true, Deadline: wall.Add(9 * time.Second), nftRemaining: 9 * time.Second}
	guard := relayguard.State{Active: true, ObservedNS: uint64(boot), DeadlineNS: uint64(boot + 9*time.Second), Generation: 3, MapID: 4, ProgramID: 5}
	for _, tc := range []struct {
		name   string
		edit   func(*DeploymentLease, *relayguard.State, *time.Time, *uint64, *time.Duration)
		retain bool
		want   error
	}{
		{name: "live", retain: true},
		{name: "nft exactly five seconds", edit: func(s *DeploymentLease, b *relayguard.State, a *time.Time, u *uint64, n *time.Duration) {
			s.nftRemaining = 5 * time.Second
		}, retain: true},
		{name: "nft below by one ns", edit: func(s *DeploymentLease, b *relayguard.State, a *time.Time, u *uint64, n *time.Duration) {
			s.nftRemaining = 5 * time.Second
			*n++
		}},
		{name: "nft above by one ns", edit: func(s *DeploymentLease, b *relayguard.State, a *time.Time, u *uint64, n *time.Duration) {
			s.nftRemaining = 5*time.Second + 1
		}, retain: true},
		{name: "BPF below", edit: func(s *DeploymentLease, b *relayguard.State, a *time.Time, u *uint64, n *time.Duration) {
			b.DeadlineNS = uint64(boot + 5*time.Second - 1)
		}},
		{name: "BPF exactly", edit: func(s *DeploymentLease, b *relayguard.State, a *time.Time, u *uint64, n *time.Duration) {
			b.DeadlineNS = uint64(boot + 5*time.Second)
		}, retain: true},
		{name: "wall below", edit: func(s *DeploymentLease, b *relayguard.State, a *time.Time, u *uint64, n *time.Duration) {
			s.Deadline = wall.Add(5*time.Second - 1)
		}},
		{name: "wall exactly", edit: func(s *DeploymentLease, b *relayguard.State, a *time.Time, u *uint64, n *time.Duration) {
			s.Deadline = wall.Add(5 * time.Second)
		}, retain: true},
		{name: "wall approval shortened", edit: func(s *DeploymentLease, b *relayguard.State, a *time.Time, u *uint64, n *time.Duration) {
			*a = wall.Add(6 * time.Second)
		}},
		{name: "boot approval shortened", edit: func(s *DeploymentLease, b *relayguard.State, a *time.Time, u *uint64, n *time.Duration) {
			*u = uint64(boot + 6*time.Second)
		}},
		{name: "wall approval expired", edit: func(s *DeploymentLease, b *relayguard.State, a *time.Time, u *uint64, n *time.Duration) { *a = wall }, want: ErrLeaseExpired},
		{name: "boot approval expired", edit: func(s *DeploymentLease, b *relayguard.State, a *time.Time, u *uint64, n *time.Duration) {
			*u = uint64(boot)
		}, want: ErrLeaseExpired},
		{name: "staged", edit: func(s *DeploymentLease, b *relayguard.State, a *time.Time, u *uint64, n *time.Duration) {
			s.staged = []string{"pending"}
		}},
		{name: "nft inactive", edit: func(s *DeploymentLease, b *relayguard.State, a *time.Time, u *uint64, n *time.Duration) {
			s.Active = false
		}},
		{name: "BPF inactive", edit: func(s *DeploymentLease, b *relayguard.State, a *time.Time, u *uint64, n *time.Duration) {
			b.Active = false
		}},
		{name: "subsecond", edit: func(s *DeploymentLease, b *relayguard.State, a *time.Time, u *uint64, n *time.Duration) {
			s.nftRemaining = 0
		}},
		{name: "invalid remaining", edit: func(s *DeploymentLease, b *relayguard.State, a *time.Time, u *uint64, n *time.Duration) {
			s.nftRemaining = 11 * time.Second
		}},
		{name: "read delay", edit: func(s *DeploymentLease, b *relayguard.State, a *time.Time, u *uint64, n *time.Duration) {
			*n += 4*time.Second + 1
		}},
		{name: "read delay exhausted lower bound", edit: func(s *DeploymentLease, b *relayguard.State, a *time.Time, u *uint64, n *time.Duration) {
			s.nftRemaining = 5 * time.Second
			*n += 5 * time.Second
		}},
		{name: "suspend expires BPF", edit: func(s *DeploymentLease, b *relayguard.State, a *time.Time, u *uint64, n *time.Duration) {
			*n += 9 * time.Second
		}, want: ErrLeaseExpired},
		{name: "clock reverse", edit: func(s *DeploymentLease, b *relayguard.State, a *time.Time, u *uint64, n *time.Duration) { *n-- }, want: ErrConflict},
		{name: "negative clock", edit: func(s *DeploymentLease, b *relayguard.State, a *time.Time, u *uint64, n *time.Duration) { *n = -1 }, want: ErrConflict},
		{name: "zero observed", edit: func(s *DeploymentLease, b *relayguard.State, a *time.Time, u *uint64, n *time.Duration) {
			b.ObservedNS = 0
		}, want: ErrConflict},
		{name: "unrepresentable observed", edit: func(s *DeploymentLease, b *relayguard.State, a *time.Time, u *uint64, n *time.Duration) {
			b.ObservedNS = math.MaxUint64 - 1
		}, want: ErrConflict},
		{name: "missing generation", edit: func(s *DeploymentLease, b *relayguard.State, a *time.Time, u *uint64, n *time.Duration) {
			b.Generation = 0
		}, want: ErrConflict},
		{name: "missing map", edit: func(s *DeploymentLease, b *relayguard.State, a *time.Time, u *uint64, n *time.Duration) { b.MapID = 0 }, want: ErrConflict},
		{name: "missing program", edit: func(s *DeploymentLease, b *relayguard.State, a *time.Time, u *uint64, n *time.Duration) {
			b.ProgramID = 0
		}, want: ErrConflict},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, b, n := original, guard, boot
			a, u := wall.Add(time.Minute), uint64(boot+time.Minute)
			if tc.edit != nil {
				tc.edit(&s, &b, &a, &u, &n)
			}
			r, err := planNodeLeaseRetention(s, b, a, u, wall, n)
			if !errors.Is(err, tc.want) || (r != nil) != tc.retain {
				t.Fatalf("retain=%v err=%v", r != nil, err)
			}
			if r != nil && (r.guard != b || r.nftUntilNS != b.ObservedNS+uint64(s.nftRemaining)) {
				t.Fatal("retention changed grant or lost original countdown anchor")
			}
		})
	}
}

func TestNodeLeaseRetentionFinalReadback(t *testing.T) {
	wall := time.Unix(2000000000, 0)
	boot := 100 * time.Second
	b := relayguard.State{Active: true, ObservedNS: uint64(boot), DeadlineNS: uint64(boot + 9*time.Second), Generation: 3, MapID: 4, ProgramID: 5}
	s := DeploymentLease{Active: true, Deadline: wall.Add(9 * time.Second), nftRemaining: 8 * time.Second}
	var err error
	s.retained, err = planNodeLeaseRetention(s, b, wall.Add(time.Minute), uint64(boot+time.Minute), wall, boot)
	if err != nil || s.retained == nil {
		t.Fatal("fixture", err)
	}
	for _, tc := range []struct {
		name string
		edit func(*DeploymentLease, *relayguard.State, *time.Time, *uint64, *time.Duration)
		want error
	}{
		{name: "same grant"},
		{name: "last ns before conservative expiry", edit: func(s *DeploymentLease, b *relayguard.State, w *time.Time, a *uint64, n *time.Duration) {
			*n += 8*time.Second - 1
		}},
		{name: "nft lower bound elapsed", edit: func(s *DeploymentLease, b *relayguard.State, w *time.Time, a *uint64, n *time.Duration) {
			*n += 8 * time.Second
		}, want: ErrLeaseExpired},
		{name: "suspend during final BPF read", edit: func(s *DeploymentLease, b *relayguard.State, w *time.Time, a *uint64, n *time.Duration) {
			*n += 10 * time.Second
		}, want: ErrLeaseExpired},
		{name: "wall moved forward", edit: func(s *DeploymentLease, b *relayguard.State, w *time.Time, a *uint64, n *time.Duration) {
			*w = w.Add(10 * time.Second)
		}, want: ErrLeaseExpired},
		{name: "boot approval elapsed", edit: func(s *DeploymentLease, b *relayguard.State, w *time.Time, a *uint64, n *time.Duration) {
			*a = uint64(boot)
		}, want: ErrLeaseExpired},
		{name: "boot approval shortened", edit: func(s *DeploymentLease, b *relayguard.State, w *time.Time, a *uint64, n *time.Duration) {
			*a = uint64(boot + 8*time.Second)
		}, want: ErrLeaseExpired},
		{name: "generation replaced", edit: func(s *DeploymentLease, b *relayguard.State, w *time.Time, a *uint64, n *time.Duration) {
			b.Generation++
		}, want: ErrConflict},
		{name: "map replaced", edit: func(s *DeploymentLease, b *relayguard.State, w *time.Time, a *uint64, n *time.Duration) { b.MapID++ }, want: ErrConflict},
		{name: "program replaced", edit: func(s *DeploymentLease, b *relayguard.State, w *time.Time, a *uint64, n *time.Duration) {
			b.ProgramID++
		}, want: ErrConflict},
		{name: "deadline changed", edit: func(s *DeploymentLease, b *relayguard.State, w *time.Time, a *uint64, n *time.Duration) {
			b.DeadlineNS++
		}, want: ErrConflict},
		{name: "BPF blocked", edit: func(s *DeploymentLease, b *relayguard.State, w *time.Time, a *uint64, n *time.Duration) {
			b.Active = false
		}, want: ErrLeaseExpired},
		{name: "nft blocked", edit: func(s *DeploymentLease, b *relayguard.State, w *time.Time, a *uint64, n *time.Duration) {
			s.Active = false
		}, want: ErrLeaseExpired},
		{name: "observed regressed", edit: func(s *DeploymentLease, b *relayguard.State, w *time.Time, a *uint64, n *time.Duration) {
			b.ObservedNS--
		}, want: ErrConflict},
		{name: "observed beyond final clock", edit: func(s *DeploymentLease, b *relayguard.State, w *time.Time, a *uint64, n *time.Duration) {
			b.ObservedNS++
		}, want: ErrConflict},
		{name: "final clock regressed", edit: func(s *DeploymentLease, b *relayguard.State, w *time.Time, a *uint64, n *time.Duration) { *n-- }, want: ErrConflict},
	} {
		t.Run(tc.name, func(t *testing.T) {
			latest, guard, w, n := s, b, wall, boot
			a := uint64(boot + time.Minute)
			if tc.edit != nil {
				tc.edit(&latest, &guard, &w, &a, &n)
			}
			if err := validateNodeLeaseRetention(latest, guard, wall.Add(time.Minute), a, w, n); !errors.Is(err, tc.want) {
				t.Fatalf("readback err=%v want=%v", err, tc.want)
			}
		})
	}
}

func TestNodeLeaseSelectedCountdownIsConservative(t *testing.T) {
	e := DeploymentEntry{Interface: "wgretain001", Alias: "vpnctl:node:retention-test", LinkIndex: 123, LeaseVersion: 3}
	for _, v := range []float64{0, 0.9, 4.999, 5, 9.99, 10, -1, 11} {
		rows := stagedLeaseTestRows(e, time.Now().Add(9*time.Second).Truncate(time.Second), "lease_00000000000000000000000000000001", "lease_00000000000000000000000000000002")
		rows[1]["set"].(object)["elem"] = []any{object{"elem": object{"val": e.LinkIndex, "expires": v}}}
		rows[len(rows)-1]["set"].(object)["elem"] = []any{object{"elem": object{"val": e.LinkIndex, "expires": 10}}}
		data, _ := json.Marshal(rows)
		var decoded []object
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatal(err)
		}
		s, err := validateStagedLease(decoded, e)
		if v < 0 || v > 10 {
			if !errors.Is(err, ErrConflict) {
				t.Fatal("invalid countdown accepted")
			}
			continue
		}
		if err != nil || s.nftRemaining != time.Duration(v)*time.Second {
			t.Fatalf("countdown=%v selected floor=%v err=%v", v, s.nftRemaining, err)
		}
	}
}

func TestNodeLeaseRetentionReadbackNeverFallsBackToWrite(t *testing.T) {
	for _, scenario := range []string{"missing", "selected replaced", "deadline replaced", "staged appeared", "blocked", "foreign owner", "read error", "cancelled"} {
		t.Run(scenario, func(t *testing.T) {
			e := DeploymentEntry{Interface: "wgretain001", Alias: "vpnctl:node:retention-test", LinkIndex: 123, LeaseVersion: 3}
			observed, err := relayguard.Now()
			if err != nil {
				t.Fatal(err)
			}
			b := relayguard.State{Active: true, ObservedNS: observed, DeadlineNS: observed + uint64(9*time.Second), Generation: 3, MapID: 4, ProgramID: 5}
			d := time.Now().Add(9 * time.Second).Truncate(time.Second)
			selected := "lease_00000000000000000000000000000001"
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			reads, writes := 0, 0
			k := deploymentKernel{kernel: kernel{run: func(_ context.Context, _ string, name string, args ...string) ([]byte, error) {
				switch strings.Join(args, " ") {
				case "-j -n -T list flowtables":
					return json.Marshal(object{"nftables": []object{}})
				case "-j -n -T list tables":
					if scenario == "missing" {
						return json.Marshal(object{"nftables": []object{}})
					}
					return json.Marshal(object{"nftables": leaseExpected(e, d)[:1]})
				case "-j -n -T list table inet " + leaseTable(e):
					reads++
					set, pending, deadline, expires := selected, "", d, 9
					if reads == 2 {
						switch scenario {
						case "missing":
							return nil, errors.New("test missing table")
						case "selected replaced":
							set = "lease_00000000000000000000000000000002"
						case "deadline replaced":
							deadline = d.Add(time.Second)
						case "staged appeared":
							pending = "lease_00000000000000000000000000000002"
						case "blocked":
							expires = 0
						case "read error":
							return nil, errors.New("test read error")
						case "cancelled":
							cancel()
						}
					}
					rows := stagedLeaseTestRows(e, deadline, set, pending)
					rows[1]["set"].(object)["elem"] = []any{object{"elem": object{"val": e.LinkIndex, "expires": expires}}}
					if reads == 2 && scenario == "foreign owner" {
						rows[1]["set"].(object)["comment"] = "foreign"
					}
					return json.Marshal(object{"nftables": rows})
				case "-f /dev/stdin":
					writes++
					return nil, errors.New("test forbids mutation")
				default:
					t.Fatal("unexpected command")
					return nil, ErrConflict
				}
			}}}
			_, err = k.stagedLeaseBounded(ctx, e, time.Now().Add(time.Minute), FreshApproval{}, &b, observed+uint64(time.Minute))
			if err == nil || writes != 0 || reads != 2 {
				t.Fatalf("failure incorrectly accepted or retried: reads=%d writes=%d err=%v", reads, writes, err)
			}
		})
	}
}

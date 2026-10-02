// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayapply

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestNFTTableReadDoesNotTurnErrorsIntoAbsence(t *testing.T) {
	denied := errors.New("read denied")
	for _, mode := range []string{"present", "absent", "unreadable", "inventory-error", "invalid-inventory", "malformed-table", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls := 0
			k := deploymentKernel{kernel{run: func(_ context.Context, input, name string, args ...string) ([]byte, error) {
				calls++
				switch strings.Join(args, " ") {
				case "-j -n -T list table inet owned":
					if mode == "present" {
						return []byte(`{"nftables":[{"table":{"family":"inet","name":"owned"}}]}`), nil
					}
					if mode == "malformed-table" {
						return []byte(`invalid JSON`), nil
					}
					if mode == "cancelled" {
						cancel()
					}
					return nil, denied
				case "-j -n -T list tables":
					switch mode {
					case "absent":
						return []byte(`{"nftables":[]}`), nil
					case "inventory-error":
						return nil, errors.New("inventory failed")
					case "invalid-inventory":
						return []byte(`{"nftables":[{"table":{}}]}`), nil
					default:
						return []byte(`{"nftables":[{"table":{"family":"inet","name":"owned"}}]}`), nil
					}
				}
				t.Fatal("unexpected query", name, args)
				return nil, denied
			}}}
			_, exists, err := k.readNFTTable(ctx, "owned")
			switch mode {
			case "present":
				if !exists || err != nil || calls != 1 {
					t.Fatal(exists, err, calls)
				}
			case "absent":
				if exists || err != nil || calls != 2 {
					t.Fatal(exists, err, calls)
				}
			case "unreadable":
				if !exists || !errors.Is(err, denied) {
					t.Fatal("existing unreadable table accepted", exists, err)
				}
			default:
				if err == nil {
					t.Fatal("failed inventory treated as absence", exists)
				}
			}
			if mode == "cancelled" && calls != 1 {
				t.Fatal("continued after cancellation", calls)
			}
		})
	}
}

func TestMaintenanceInventoryScopeAndFreshness(t *testing.T) {
	calls := map[string]int{}
	raw := func(_ context.Context, input, name string, args ...string) ([]byte, error) {
		key := input + name + strings.Join(args, " ")
		calls[key]++
		return []byte(fmt.Sprint(calls[key])), nil
	}
	queries := []struct {
		name   string
		args   []string
		shared bool
	}{
		{"ip", []string{"-j", "-N", "-d", "link", "show"}, true},
		{"ip", []string{"-j", "-N", "-4", "route", "show", "table", "all"}, true},
		{"ip", []string{"-j", "-N", "-4", "rule", "show"}, true},
		{"ip", []string{"-j", "-N", "-6", "route", "show", "table", "all"}, true},
		{"wg", []string{"show", "all", "fwmark"}, true},
		{"wg", []string{"show", "all", "listen-port"}, true},
		{"wg", []string{"show", "vdtest", "dump"}, false},
		{"ip", []string{"-j", "address", "show", "dev", "vdtest"}, false},
		{"nft", []string{"-j", "-n", "-T", "list", "tables"}, false},
		{"nft", []string{"-j", "-n", "-T", "list", "table", "inet", "vltest"}, false},
		{"nft", []string{"-j", "-n", "-T", "list", "flowtables"}, false},
		{"ip", []string{"link", "set", "dev", "vdtest", "down"}, false},
	}
	run := maintenanceInventory(raw)
	for _, q := range queries {
		first, err := run(context.Background(), "", q.name, q.args...)
		if err != nil {
			t.Fatal(err)
		}
		clear(first) // A caller cannot mutate another endpoint's observation.
		second, err := run(context.Background(), "", q.name, q.args...)
		if err != nil {
			t.Fatal(err)
		}
		want := "2"
		if q.shared {
			want = "1"
		}
		if string(second) != want {
			t.Fatal("wrong inventory scope", q.name, q.args, string(second), want)
		}
		next, err := maintenanceInventory(raw)(context.Background(), "", q.name, q.args...)
		if err != nil || string(next) == want {
			t.Fatal("inventory survived its cycle", q, err)
		}
	}
	cancelled, stop := context.WithCancel(context.Background())
	stop()
	if _, err := run(cancelled, "", "wg", "show", "all", "fwmark"); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled cycle reused inventory", err)
	}
	// Mutation helpers use the original backend, not this read-only closure.
	b, _ := raw(context.Background(), "", "wg", "show", "all", "fwmark")
	if string(b) != "3" {
		t.Fatal("original backend was changed", string(b))
	}
}

func TestMaintenanceInventoryNeverCachesFailureOrOversizedOutput(t *testing.T) {
	for _, oversized := range []bool{false, true} {
		calls := 0
		run := maintenanceInventory(func(context.Context, string, string, ...string) ([]byte, error) {
			calls++
			if calls == 1 {
				if oversized {
					return make([]byte, (512<<10)+1), nil
				}
				return nil, errors.New("read failed")
			}
			return []byte("fresh"), nil
		})
		if _, err := run(context.Background(), "", "wg", "show", "all", "fwmark"); err == nil {
			t.Fatal("bad inventory accepted")
		}
		b, err := run(context.Background(), "", "wg", "show", "all", "fwmark")
		if err != nil || string(b) != "fresh" || calls != 2 {
			t.Fatal("failure cached", calls, err)
		}
	}
}

func TestDeploymentFailureDiagnosticDoesNotLeakRawError(t *testing.T) {
	secret := "private-key-must-not-disclose"
	failure := deploymentFailure("ep0", "lease_renewal", errors.New(secret), FreshApproval{})
	raw, err := json.Marshal(failure)
	if err != nil || strings.Contains(string(raw), secret) || failure.Reason != "kernel_operation_failed" {
		t.Fatal("unsafe failure diagnostic", string(raw), err)
	}
	for _, tc := range []struct {
		err    error
		reason string
	}{
		{context.DeadlineExceeded, "deadline"}, {context.Canceled, "cancelled"},
		{ErrConflict, "ownership_conflict"}, {ErrLeaseExpired, "lease_expired"}, {nil, "incomplete"},
	} {
		if got := deploymentFailure("ep0", "ownership_check", tc.err, FreshApproval{}); got.Reason != tc.reason {
			t.Fatal(got)
		}
	}
}

func TestMaintenanceInventorySuspendAndClockRegressionInvalidateSnapshot(t *testing.T) {
	now := 10 * time.Second
	failClock := false
	calls := 0
	run := maintenanceInventoryAt(func(context.Context, string, string, ...string) ([]byte, error) {
		calls++
		return []byte(fmt.Sprint(calls)), nil
	}, func() (time.Duration, error) {
		if failClock {
			return 0, errors.New("clock unavailable")
		}
		return now, nil
	})
	read := func(want string) {
		t.Helper()
		b, err := run(context.Background(), "", "wg", "show", "all", "fwmark")
		if err != nil || string(b) != want {
			t.Fatal(string(b), want, err)
		}
	}
	read("1")
	read("1")
	now += 5 * time.Second // BOOTTIME advances through suspend, even if Go's deadline has not.
	read("2")
	now -= time.Second
	read("3")
	failClock = true
	if _, err := run(context.Background(), "", "wg", "show", "all", "fwmark"); err == nil || calls != 3 {
		t.Fatal("clock failure reused snapshot", calls, err)
	}
}

// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package integration

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"vpnctl/internal/api"
	"vpnctl/internal/pki"
)

// Admitted controller mutations finish after an IPC disconnect. Observe the
// exact transition before retrying; a lost response is not a rejected command.
// Both status requests and mutation attempts share the original total budget.
func convergeCATransition(ctx context.Context, call func(context.Context, api.AdminRequest) (api.AdminResponse, error), operation string) (*pki.AuthorityStatus, error) {
	request := func(op string) (*pki.AuthorityStatus, error) {
		attempt, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		r, err := call(attempt, api.AdminRequest{Operation: op})
		if err == nil && r.PKI == nil {
			err = errors.New("missing CA status")
		}
		return r.PKI, err
	}
	before, err := request("pki.status")
	if err != nil {
		return nil, err
	}
	want := *before
	if want.Generation == ^uint64(0) {
		return nil, errors.New("CA generation exhausted")
	}
	want.Generation++
	switch operation {
	case "ca.activate":
		if before.Phase != "prepared" || before.Pending == "" || before.Previous != "" {
			return nil, errors.New("CA activation did not start from prepared state")
		}
		want.Phase, want.Active, want.Previous, want.Pending = "overlap", before.Pending, before.Active, ""
	case "ca.retire":
		if (before.Phase != "overlap" && before.Phase != "rollback") || before.Previous == "" || before.Pending != "" {
			return nil, errors.New("CA retirement did not start from overlap/rollback")
		}
		want.Phase, want.Previous = "stable", ""
	default:
		return nil, errors.New("unsupported CA convergence operation")
	}
	same := func(a, b *pki.AuthorityStatus) bool {
		return a.Generation == b.Generation && a.Phase == b.Phase && a.Active == b.Active && a.Previous == b.Previous && a.Pending == b.Pending
	}
	current := before
	var last error
	for ctx.Err() == nil {
		if current != nil {
			if same(current, &want) {
				return current, nil
			}
			if !same(current, before) {
				return nil, fmt.Errorf("unexpected CA transition: generation=%d phase=%s", current.Generation, current.Phase)
			}
			current, last = request(operation)
			if last == nil {
				if !same(current, &want) {
					return nil, errors.New("successful CA command returned an unexpected transition")
				}
				return current, nil
			}
		}
		select {
		case <-ctx.Done():
			return nil, errors.Join(ctx.Err(), last)
		case <-time.After(100 * time.Millisecond):
		}
		current, err = request("pki.status")
		if err != nil {
			current = nil // Never retry a mutation while its outcome is unknown.
			last = err
		}
	}
	return nil, errors.Join(ctx.Err(), last)
}

func TestCATransitionLostResponse(t *testing.T) {
	for _, operation := range []string{"ca.activate", "ca.retire"} {
		t.Run(operation, func(t *testing.T) {
			state := pki.AuthorityStatus{Generation: 5, Phase: "prepared", Active: "old", Pending: "new"}
			if operation == "ca.retire" {
				state.Phase, state.Active, state.Previous, state.Pending = "rollback", "old", "new", ""
			}
			mutations, reads := 0, 0
			call := func(_ context.Context, req api.AdminRequest) (api.AdminResponse, error) {
				if req.Operation == "pki.status" {
					reads++
					if reads == 2 {
						return api.AdminResponse{}, errors.New("status response also lost")
					}
					copy := state
					return api.AdminResponse{PKI: &copy}, nil
				}
				mutations++
				state.Generation++
				if operation == "ca.activate" {
					state.Phase, state.Active, state.Previous, state.Pending = "overlap", "new", "old", ""
				} else {
					state.Phase, state.Previous = "stable", ""
				}
				return api.AdminResponse{}, context.DeadlineExceeded
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			got, err := convergeCATransition(ctx, call, operation)
			if err != nil || got == nil || got.Generation != 6 || mutations != 1 || reads != 3 {
				t.Fatalf("got=%+v err=%v mutations=%d reads=%d", got, err, mutations, reads)
			}
		})
	}
}

func TestCATransitionRejectsUnrelatedState(t *testing.T) {
	for _, fault := range []string{"signer", "generation", "phase", "never_committed"} {
		t.Run(fault, func(t *testing.T) {
			state := pki.AuthorityStatus{Generation: 5, Phase: "prepared", Active: "old", Pending: "new"}
			call := func(_ context.Context, req api.AdminRequest) (api.AdminResponse, error) {
				if req.Operation != "pki.status" {
					if fault == "never_committed" {
						return api.AdminResponse{}, context.DeadlineExceeded
					}
					state.Generation, state.Phase, state.Active, state.Previous, state.Pending = 6, "overlap", "new", "old", ""
					switch fault {
					case "signer":
						state.Active = "unrelated"
					case "generation":
						state.Generation++
					case "phase":
						state.Phase = "stable"
					}
					return api.AdminResponse{}, context.DeadlineExceeded
				}
				copy := state
				return api.AdminResponse{PKI: &copy}, nil
			}
			ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
			defer cancel()
			if _, err := convergeCATransition(ctx, call, "ca.activate"); err == nil {
				t.Fatal("uncommitted or unrelated transition accepted")
			}
		})
	}
}

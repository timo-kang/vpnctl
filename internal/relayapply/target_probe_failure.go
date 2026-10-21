// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayapply

import (
	"context"
	"errors"
	"syscall"

	"vpnctl/internal/relayobserve"
)

var errInvalidTargetCounters = errors.New("invalid candidate counters")

// Keep the original error chain for classification, but never serialize it.
type targetProbeError struct {
	failure relayobserve.ProbeFailure
	err     error
}

func (e *targetProbeError) Error() string { return "target probe evidence unavailable" }
func (e *targetProbeError) Unwrap() error { return e.err }

func probeContextState(ctx context.Context) string {
	switch {
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		return "deadline_exceeded"
	case errors.Is(ctx.Err(), context.Canceled):
		return "canceled"
	default:
		return "active"
	}
}

// cause is either a fixed failed-predicate enum or derived from the error's
// identity. A canceled context alone must not relabel an unrelated error.
func probeFailure(ctx context.Context, stage, cause string, err error) error {
	if cause == "" {
		var connect *targetConnectError
		switch {
		case errors.As(err, &connect):
			cause = connect.reason
		case errors.Is(err, context.Canceled):
			cause = "canceled"
		case errors.Is(err, context.DeadlineExceeded):
			cause = "deadline_exceeded"
		case errors.Is(err, syscall.EPERM), errors.Is(err, syscall.EACCES):
			cause = "permission_denied"
		case errors.Is(err, errInvalidTargetCounters):
			cause = "invalid_counters"
		default:
			cause = "unavailable"
		}
	}
	return &targetProbeError{relayobserve.ProbeFailure{Stage: stage, Cause: cause, ContextState: probeContextState(ctx)}, err}
}

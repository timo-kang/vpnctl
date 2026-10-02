//go:build !linux

// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayguard

import (
	"context"
	"errors"
)

var errPlatform = errors.New("relay BOOTTIME guard requires Linux with CAP_BPF, TC BPF, spin locks and bpf_ktime_get_boot_ns")

func Now() (uint64, error)                        { return 0, errPlatform }
func Read(context.Context, Owner) (State, error)  { return State{}, errPlatform }
func Install(context.Context, Owner) error        { return errPlatform }
func InspectPartial(context.Context, Owner) error { return errPlatform }
func Block(context.Context, Owner) error          { return errPlatform }
func Update(context.Context, Owner, uint64, uint64, uint64) (State, error) {
	return State{}, errPlatform
}

func RemovePins(context.Context, Owner) error { return errPlatform }

func Preflight(Owner) error { return errPlatform }

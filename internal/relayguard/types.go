// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayguard

import (
	"errors"
	"time"
)

const MaxLease = 10 * time.Second
const RearmWindow = 5 * time.Second

var ErrConflict = errors.New("relay boottime guard ownership conflict")
var ErrExpired = errors.New("relay boottime guard expired or stale proposal; fresh approval required")

type Owner struct {
	Interface, Alias string
	Index            int
	Group            uint32
	// Pending permits an untagged DOWN link only during interrupted creation.
	Pending bool
}

type State struct {
	DeadlineNS uint64 `json:"deadline_ns"`
	Generation uint64 `json:"generation"`
	ObservedNS uint64 `json:"observed_ns"`
	MapID      uint32 `json:"map_id"`
	ProgramID  uint32 `json:"program_id"`
	Active     bool   `json:"active"`
}

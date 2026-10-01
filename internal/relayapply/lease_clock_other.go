// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
//go:build !linux

package relayapply

import (
	"errors"
	"time"
)

func leaseBootTime() (time.Duration, error) {
	return 0, errors.New("relay lease requires Linux CLOCK_BOOTTIME")
}

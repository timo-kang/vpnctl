// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayselect

import (
	"golang.org/x/sys/unix"
	"time"
)

func bootTime() (time.Duration, error) {
	var t unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &t); err != nil {
		return 0, err
	}
	return time.Duration(t.Nano()), nil
}

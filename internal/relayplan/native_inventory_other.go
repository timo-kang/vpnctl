//go:build !linux

// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayplan

import "context"

func readNativeLink(ctx context.Context, name string) (linkRecord, bool, error) {
	return (LinuxCollector{ReadIP: readIP}).link(ctx, name)
}

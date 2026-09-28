// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"strings"
	"testing"
	"time"
	"vpnctl/internal/history"
)

func TestStorageHealthTextDoesNotRenderUnavailableValues(t *testing.T) {
	now := time.Now()
	h := history.UnknownStorageHealth("collection_failed")
	h.ObservedAt = &now
	h.Values = &history.StorageHealthValues{DatabaseBytes: 12345}
	var out bytes.Buffer
	if e := printFleetStorage(&out, h, false); e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(out.String(), "unknown") || strings.Contains(out.String(), "12345") {
		t.Fatal(out.String())
	}
}

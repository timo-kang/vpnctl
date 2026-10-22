//go:build integration

// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package integration

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
)

func directSnapshotLog(states ...string) []byte {
	var log strings.Builder
	for peer, state := range states {
		if state == "" {
			continue
		}
		fmt.Fprintf(&log, "time=2026-10-21T07:22:00Z level=INFO msg=\"direct dataplane\" peer=node-%d state=%s reason=verified\n", peer, state)
	}
	return []byte(log.String())
}

func TestDirectSnapshotReadsEachAgentOnce(t *testing.T) {
	for _, size := range []int{2, 3, 8, 32} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			paths := make([]string, size)
			states := make([]string, size)
			for i := range paths {
				paths[i], states[i] = fmt.Sprint(i), "active"
			}
			data := directSnapshotLog(states...)
			reads := map[string]int{}
			err := allDirectPathsActive(paths, func(path string) ([]byte, error) {
				reads[path]++
				return data, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, path := range paths {
				if reads[path] != 1 {
					t.Fatalf("agent %s read %d times in one observation", path, reads[path])
				}
			}
		})
	}
}

func TestDirectSnapshotDoesNotCombineDifferentReads(t *testing.T) {
	reads := 0
	err := allDirectPathsActive([]string{"0", "1", "2"}, func(path string) ([]byte, error) {
		if path == "0" {
			reads++
			if reads == 1 {
				return directSnapshotLog("", "active", "cooldown"), nil
			}
			return directSnapshotLog("", "cooldown", "active"), nil
		}
		return directSnapshotLog("active", "active", "active"), nil
	})
	if err == nil {
		t.Fatal("combined states that were never all active in one agent snapshot")
	}
}

func TestDirectSnapshotRequiresCurrentCompleteEvidence(t *testing.T) {
	active := directSnapshotLog("active", "active")
	for name, data := range map[string][]byte{
		"empty":              nil,
		"withdrawal":         append(append([]byte{}, active...), directSnapshotLog("", "cooldown")...),
		"unknown":            directSnapshotLog("", "unknown"),
		"peer prefix":        []byte("msg=\"direct dataplane\" peer=node-10 state=active\n"),
		"unrelated message":  []byte("msg=other peer=node-1 state=active\n"),
		"partial active":     []byte("msg=\"direct dataplane\" peer=node-1 state=active"),
		"partial withdrawal": append(append([]byte{}, active...), []byte("msg=\"direct dataplane\" peer=node-1 state=")...),
		"malformed latest":   append(append([]byte{}, active...), []byte("msg=\"direct dataplane\" peer=node-1 state=\n")...),
	} {
		t.Run(name, func(t *testing.T) {
			if err := allDirectPathsActive([]string{"0", "1"}, func(path string) ([]byte, error) {
				if path == "0" {
					return data, nil
				}
				return active, nil
			}); err == nil {
				t.Fatal("missing, superseded or incomplete evidence accepted")
			}
		})
	}
	read := func(string) ([]byte, error) { return active, nil }
	if err := allDirectPathsActive([]string{"0", "1"}, read); err != nil {
		t.Fatal(err)
	}
	if err := allDirectPathsActive([]string{"0", "1"}, func(string) ([]byte, error) {
		return active, os.ErrNotExist
	}); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("read error lost or stale active state reused", err)
	}
	if err := allDirectPathsActive([]string{"0", "1"}, func(string) ([]byte, error) { return nil, nil }); err == nil {
		t.Fatal("prior poll cached across truncation")
	}
}

//go:build integration

// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package integration

import (
	"fmt"
	"strings"
)

func allDirectPathsActive(logs []string, readFile func(string) ([]byte, error)) error {
	for i, path := range logs {
		// One fresh read per agent per poll. Re-reading for each peer both
		// multiplies observer load and can combine incompatible agent states.
		// This is a per-agent snapshot, not an atomic view across all agents.
		data, err := readFile(path)
		if err != nil {
			return fmt.Errorf("agent %d log: %w", i, err)
		}
		text := string(data)
		if len(text) > 0 && !strings.HasSuffix(text, "\n") {
			return fmt.Errorf("agent %d log has an incomplete record", i)
		}
		states := make(map[string]string)
		for line := range strings.SplitSeq(text, "\n") {
			if !strings.Contains(line, "msg=\"direct dataplane\"") {
				continue
			}
			var peer, state string
			for _, field := range strings.Fields(line) {
				if value, ok := strings.CutPrefix(field, "peer="); ok {
					peer = value
				}
				if value, ok := strings.CutPrefix(field, "state="); ok {
					state = value
				}
			}
			if peer == "" || state == "" {
				return fmt.Errorf("agent %d log has a malformed direct record", i)
			}
			states[peer] = state
		}
		for j := range logs {
			if observed := states[fmt.Sprintf("node-%d", j)]; i != j && observed != "active" {
				return fmt.Errorf("%d -> %d: %s", i, j, observed)
			}
		}
	}
	return nil
}

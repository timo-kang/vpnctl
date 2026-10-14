//go:build integration

// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package integration

import "vpnctl/internal/relayapply"

// Long, multi-stage fixtures validate their entire active history before
// reclaiming it. Carry the last complete observation and any partial next row;
// never reset evidence age, sticky input errors, or a previously sampled failure.
// Capacity fixtures retain their original lifetime bounds and never call this.
func (s *publicationStream) beginContinuityWindow(role string, report map[string]any) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if failure, ok := report["continuity_failure"].(*continuityFailure); ok {
		return s.sampledWindow, failure
	}
	baseline := 1
	if s.sampledWindow == 0 {
		baseline = len(s.rows) // Only initial activation may omit warmup rows.
	}
	if _, _, err := s.checkContinuityLocked(baseline, role, report); err != nil {
		return s.sampledWindow, err
	}
	last := s.input.Records[len(s.input.Records)-1]
	last.Record.Index = 0
	s.input = publicationSnapshot{Records: []publicationSample{last},
		Bytes: int64(s.lastRecordBytes + len(s.pending))}
	s.rows = []relayapply.TargetReconcileResult{s.rows[len(s.rows)-1]}
	s.sampledWindow++
	return s.sampledWindow, nil
}

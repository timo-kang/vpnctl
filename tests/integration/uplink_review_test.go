//go:build integration

// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package integration

import "testing"

func TestUplinkReviewRecoveryUsesOnlyCompletedPostFaultRequests(t *testing.T) {
	rows := []uplinkSample{
		{Kind: "app", Begin: 10, End: 11, OK: true},
		{Kind: "app", Begin: 19, End: 23, OK: true}, // In flight before fault begins.
		{Kind: "app", Begin: 21, End: 24, OK: true}, // Starts while fault is being installed.
		{Kind: "app", Begin: 25, End: 26},
		{Kind: "app", Begin: 39, End: 41, OK: true}, // Completes outside the observation window.
	}
	got, err := measureUplink(rows, "app", 10, 20, 22, 40)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Censored || got.FirstSuccess != 0 || got.Failed != 1 || got.ObservedFor != 18 {
		t.Fatalf("inflight or late response established recovery: %+v", got)
	}
	rows = append(rows[:4], uplinkSample{Kind: "app", Begin: 30, End: 31, OK: true})
	got, err = measureUplink(rows, "app", 10, 20, 22, 40)
	if err != nil || got.Censored || got.FirstSuccess != 31 {
		t.Fatalf("fresh completed response did not establish recovery: %+v, %v", got, err)
	}
}

func TestUplinkReviewOtherApplicationCannotCertifyRecovery(t *testing.T) {
	rows := []uplinkSample{
		{Kind: "app", Begin: 10, End: 11, OK: true},
		{Kind: "app2", Begin: 10, End: 11, OK: true},
		{Kind: "app", Begin: 25, End: 26},
		{Kind: "app2", Begin: 25, End: 26, OK: true},
	}
	got, err := measureUplink(rows, "app", 10, 20, 22, 40)
	if err != nil || !got.Censored || got.FirstSuccess != 0 || got.Failed != 1 {
		t.Fatalf("healthy unrelated application hid the target outage: %+v, %v", got, err)
	}
}

func TestUplinkReviewStaleBaselineCannotQualifyExperiment(t *testing.T) {
	rows := []uplinkSample{
		{Kind: "app", Begin: 1, End: 2, OK: true},
		{Kind: "app", Begin: 25, End: 26, OK: true},
	}
	if _, err := measureUplink(rows, "app", 10, 20, 22, 40); err == nil {
		t.Fatal("old setup success certified a baseline with no samples")
	}
}

func TestUplinkReviewRetainsBaselineFailures(t *testing.T) {
	rows := []uplinkSample{
		{Kind: "app", Begin: 10, End: 11, OK: true},
		{Kind: "app", Begin: 15, End: 16},
		{Kind: "app", Begin: 25, End: 26, OK: true},
	}
	got, err := measureUplink(rows, "app", 10, 20, 22, 40)
	if err != nil {
		t.Fatal(err)
	}
	if got.BaselineSamples != 2 || got.BaselineFailures != 1 || got.Failed != 0 {
		t.Fatalf("baseline failure disappeared or was blamed on the fault: %+v", got)
	}
}

func TestUplinkReviewSilentTailRemainsVisibleAfterFirstSuccess(t *testing.T) {
	rows := []uplinkSample{
		{Kind: "app", Begin: 10, End: 11, OK: true},
		{Kind: "app", Begin: 25, End: 26, OK: true},
		{Kind: "app", Begin: 27, End: 28},
	}
	got, err := measureUplink(rows, "app", 10, 20, 22, 60)
	if err != nil {
		t.Fatal(err)
	}
	if got.FirstSuccess != 26 || got.Censored {
		t.Fatalf("lost the first observed success: %+v", got)
	}
	if got.MaxSuccessGap < 34 || got.MaxSchedulingGap < 33 {
		t.Fatalf("sampler stopping early made the remaining window look healthy: %+v", got)
	}
}

func TestUplinkReviewRejectsInvalidWindowChronology(t *testing.T) {
	rows := []uplinkSample{{Kind: "app", Begin: 10, End: 11, OK: true}, {Kind: "app", Begin: 25, End: 26}}
	for _, tc := range []struct {
		name                       string
		baseline, begin, end, stop int64
	}{
		{"negative baseline", -1, 20, 22, 40},
		{"baseline after fault", 21, 20, 22, 40},
		{"fault end before begin", 10, 22, 20, 40},
		{"observation end before fault", 10, 20, 22, 21},
		{"empty observation window", 10, 20, 22, 22},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := measureUplink(rows, "app", tc.baseline, tc.begin, tc.end, tc.stop); err == nil {
				t.Fatal("accepted invalid measurement chronology")
			}
		})
	}
}

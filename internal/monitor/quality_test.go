// Copyright 2025 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package monitor

import "testing"

func TestComputeQuality(t *testing.T) {
	th := DefaultThresholds

	tests := []struct {
		name    string
		rttMs   float64
		lossPct float64
		success bool
		want    LinkQuality
	}{
		{"good", 8, 0, true, QualityGood},
		{"degraded_rtt", 100, 1, true, QualityDegraded},
		{"degraded_loss", 30, 5, true, QualityDegraded},
		{"poor_rtt", 300, 0, true, QualityPoor},
		{"poor_loss", 10, 15, true, QualityPoor},
		{"offline", 0, 0, false, QualityOffline},
		{"edge_good", 50, 2, true, QualityGood},
		{"edge_degraded", 200, 10, true, QualityDegraded},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ComputeQuality(tt.rttMs, tt.lossPct, tt.success, th)
			if got != tt.want {
				t.Errorf("ComputeQuality(%v, %v, %v) = %v, want %v", tt.rttMs, tt.lossPct, tt.success, got, tt.want)
			}
		})
	}
}

func TestLinkQuality_String(t *testing.T) {
	if QualityGood.String() != "good" {
		t.Error("good")
	}
	if QualityDegraded.String() != "degraded" {
		t.Error("degraded")
	}
	if QualityPoor.String() != "poor" {
		t.Error("poor")
	}
	if QualityOffline.String() != "offline" {
		t.Error("offline")
	}
}

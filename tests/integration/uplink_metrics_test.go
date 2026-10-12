//go:build integration

package integration

import "testing"

func TestUplinkMetricsRejectInflightSuccess(t *testing.T) {
	rows := []uplinkSample{{Kind: "app", Begin: 10, End: 11, OK: true}, {Kind: "app", Begin: 19, End: 23, OK: true}, {Kind: "app", Begin: 25, End: 28, OK: false}, {Kind: "app", Begin: 30, End: 31, OK: true}}
	got, err := measureUplink(rows, "app", 5, 20, 22, 40)
	if err != nil || got.FirstSuccess != 31 || got.Failed != 1 || got.Censored {
		t.Fatalf("inflight counted as recovery: %+v %v", got, err)
	}
}
func TestUplinkMetricsPreserveUnrecoveredWindow(t *testing.T) {
	rows := []uplinkSample{{Kind: "app", Begin: 10, End: 11, OK: true}, {Kind: "app", Begin: 25, End: 28}, {Kind: "app", Begin: 30, End: 31}}
	got, err := measureUplink(rows, "app", 5, 20, 22, 40)
	if err != nil || !got.Censored || got.FirstSuccess != 0 || got.ObservedFor != 18 || got.Failed != 2 {
		t.Fatalf("censoring lost: %+v %v", got, err)
	}
}
func TestUplinkMetricsRequireValidEvidence(t *testing.T) {
	cases := [][]uplinkSample{nil, {{Kind: "app", Begin: 25, End: 26, OK: true}}, {{Kind: "app", Begin: 10, End: 11, OK: true}, {Kind: "app", Begin: 25, End: 24}}, {{Kind: "app", Begin: 10, End: 11, OK: true}, {Kind: "app", Begin: 25, End: 26, OK: true}, {Kind: "app", Begin: 23, End: 24, OK: true}}}
	for i, rows := range cases {
		if _, err := measureUplink(rows, "app", 5, 20, 22, 40); err == nil {
			t.Fatalf("accepted invalid evidence %d", i)
		}
	}
}

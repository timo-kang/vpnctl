package main

import (
	"bytes"
	"strings"
	"testing"
	"time"
	"vpnctl/internal/history"
	"vpnctl/internal/wgstats"
)

func TestFleetWireGuardTextShowsValidityAndLoss(t *testing.T) {
	at := time.Now().UTC()
	n := wgstats.Counter(9007199254740993)
	report := wgstats.Report{ObservedAt: at, Peers: []wgstats.Reading{{Peer: wgstats.Binding{NodeID: "peer"}, Sample: wgstats.Sample{ObservedAt: at, Validity: "observed", RX: &n, TX: &n}}}}
	out := history.WireGuardHistory{Start: at.Add(-time.Hour), End: at, Truncated: true, Storage: history.WireGuardStorage{Evicted: 3, LossStart: &at, LossEnd: &at}, Snapshots: []wgstats.Snapshot{wgstats.CompareReport(report, nil, at)}}
	var w bytes.Buffer
	if e := printFleetWireGuard(&w, out, false); e != nil {
		t.Fatal(e)
	}
	for _, want := range []string{"truncated=true", "evicted=3", "loss-envelope=", "9007199254740993/9007199254740993", "hs=never", "first_sample"} {
		if !strings.Contains(w.String(), want) {
			t.Fatal(want, w.String())
		}
	}
}

// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package monitor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"vpnctl/internal/peersource"
)

var qualityPeer = peersource.Peer{PublicKey: "quality-peer", VPNIP: "10.7.0.2", ProbePort: 51900}

func observeOne(m *Monitor, at time.Time, success bool, rtt int64) {
	reason := ""
	if !success {
		reason = "probe_timeout"
	}
	m.recordCycle(at, []peersource.Peer{qualityPeer}, []probeOutcome{{rtt: rtt, success: success, reason: reason}}, "", "")
}
func metricValues(t *testing.T, m *Monitor) map[string]float64 {
	t.Helper()
	registry := prometheus.NewPedanticRegistry()
	registry.MustRegister(m.Collector())
	families, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	values := map[string]float64{}
	for _, f := range families {
		if len(f.Metric) == 1 {
			values[f.GetName()] = f.Metric[0].Gauge.GetValue()
		}
	}
	return values
}
func httpQuality(t *testing.T, m *Monitor) QualityResponse {
	t.Helper()
	w := httptest.NewRecorder()
	m.QualityHandler(w, httptest.NewRequest(http.MethodGet, "/network/quality", nil))
	if w.Code != http.StatusOK || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal(w)
	}
	var response QualityResponse
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	return response
}

func TestWindowedQualitySharedByHTTPMetricsAndTerminal(t *testing.T) {
	m := newTestMonitor(t, Config{})
	start := time.Now().UTC().Add(-45 * time.Second)
	// Expired history cannot influence this measurement. Ten live attempts with
	// eight successes at 12.5ms, then two failures: exactly 20% loss.
	observeOne(m, start.Add(-time.Minute), true, 500000)
	for i := 0; i < 10; i++ {
		observeOne(m, start.Add(time.Duration(i)*5*time.Second), i < 8, 12500)
	}
	response := httpQuality(t, m)
	if response.SchemaVersion != 1 || response.Window != 60 || len(response.Peers) != 1 {
		t.Fatal(response)
	}
	q := response.Peers[0]
	if q.Quality != "poor" || q.SampleCount != 10 || q.Stale || *q.LossPct != 20 || *q.RTTMs != 12.5 || !q.LastSuccessAt.Equal(start.Add(35*time.Second)) {
		t.Fatalf("wrong window: %+v", q)
	}
	metrics := metricValues(t, m)
	if metrics["vpnctl_link_quality"] != 1 || metrics["vpnctl_probe_loss_ratio"] != .2 || metrics["vpnctl_quality_rtt_seconds"] != .0125 || metrics["vpnctl_quality_sample_count"] != 10 {
		t.Fatal(metrics)
	}
	var watch bytes.Buffer
	NewWatchWriter(&watch).Write(m.Latest())
	tui := NewTUIModel("wg0", m)
	tui.snap = m.Latest()
	for _, output := range []string{watch.String(), tui.View()} {
		for _, want := range []string{"20.0%", "12.50ms", "poor", "probe_timeout"} {
			if !strings.Contains(output, want) {
				t.Fatalf("missing %q: %s", want, output)
			}
		}
	}
	// Consumers own every pointer as well as their slice; mutation cannot alter
	// later HTTP responses, metrics or another subscriber's quality.
	subA, subB := m.Subscribe(), m.Subscribe()
	observeOne(m, time.Now().UTC(), true, 12500)
	a, b := <-subA, <-subB
	*a.Peers[0].Quality.LossPct = 99
	*a.Peers[0].Quality.ObservedAt = time.Time{}
	if *b.Peers[0].Quality.LossPct == 99 || m.Latest().Peers[0].Quality.ObservedAt.IsZero() {
		t.Fatal("aliased quality pointers")
	}
}

func TestQualityFreshnessDiscoveryAndRemovedPeers(t *testing.T) {
	m := newTestMonitor(t, Config{})
	if r := httpQuality(t, m); !r.Stale || r.ErrorReason != "not_started" || r.ObservedAt != nil || len(r.Peers) != 0 {
		t.Fatal(r)
	}
	now := time.Now().UTC()
	observeOne(m, now.Add(-10*time.Second), true, 1000)
	if q := m.Latest().Peers[0].Quality; q.Level != QualityUnknown || q.ErrorReason != "insufficient_samples" || q.SampleCount != 1 {
		t.Fatal(q)
	}
	observeOne(m, now.Add(-5*time.Second), true, 1000)
	observeOne(m, now, true, 1000)
	if m.Latest().Peers[0].Quality.Level != QualityGood {
		t.Fatal("did not become good")
	}
	boundary := now.Add(m.cfg.Quality.StaleAfter)
	if m.latestAt(boundary.Add(-time.Nanosecond)).Stale {
		t.Fatal("expired early")
	}
	aged := m.latestAt(boundary)
	if !aged.Stale || aged.Peers[0].Quality.Level != QualityUnknown || aged.Peers[0].Quality.ErrorReason != "stale" {
		t.Fatal(aged)
	}
	// Reads must not mutate the published measurement.
	if m.latestAt(now).Peers[0].Quality.Level != QualityGood {
		t.Fatal("read mutated state")
	}
	m.recordCycle(now, nil, nil, "discovery_failed", "")
	failed := httpQuality(t, m)
	if !failed.Stale || failed.ErrorReason != "discovery_failed" || failed.Peers[0].Quality != "unknown" || failed.Peers[0].SampleCount != 3 {
		t.Fatal(failed)
	}
	values := metricValues(t, m)
	if values["vpnctl_link_quality"] != -1 || values["vpnctl_quality_stale"] != 1 || values["vpnctl_monitor_collection_ok"] != 0 || !math.IsNaN(values["vpnctl_probe_success"]) {
		t.Fatal(values)
	}
	m.recordCycle(now, nil, nil, "", "")
	empty := httpQuality(t, m)
	if empty.Stale || empty.ErrorReason != "no_peers" || len(empty.Peers) != 0 {
		t.Fatal(empty)
	}
	if _, exists := metricValues(t, m)["vpnctl_link_quality"]; exists {
		t.Fatal("removed peer metric remains")
	}
	observeOne(m, now, true, 1000)
	if q := m.Latest().Peers[0].Quality; q.SampleCount != 1 || q.Level != QualityUnknown {
		t.Fatal("removed peer reused samples", q)
	}
}

func TestStalledMonitorExpiresOnHTTPAndScrapeWithoutNewPublication(t *testing.T) {
	m := newTestMonitor(t, Config{})
	now := time.Now().UTC()
	for i := 0; i < 3; i++ {
		observeOne(m, now.Add(-time.Minute+time.Duration(i)*time.Second), true, 1000)
	}
	response := httpQuality(t, m)
	if !response.Stale || response.Peers[0].Quality != "unknown" {
		t.Fatal(response)
	}
	values := metricValues(t, m)
	if values["vpnctl_link_quality"] != -1 || values["vpnctl_quality_stale"] != 1 {
		t.Fatal(values)
	}
	tui := NewTUIModel("wg0", m)
	updated, _ := tui.Update(freshnessMsg(now))
	if output := updated.(TUIModel).View(); !strings.Contains(output, "unknown") || !strings.Contains(output, "stale") {
		t.Fatal(output)
	}
}

func TestQualityWindowBoundaryAndRecoveryHysteresis(t *testing.T) {
	cfg, err := (QualityConfig{Window: time.Second, StaleAfter: time.Second, MinSamples: 1, RecoverySamples: 3}).Normalized(time.Second)
	if err != nil {
		t.Fatal(err)
	}
	w := qualityWindow{}
	now := time.Now()
	q := w.observe(now, probeOutcome{rtt: 1000, success: true}, cfg)
	if q.Level != QualityGood {
		t.Fatal(q)
	}
	q = w.observe(now.Add(time.Second), probeOutcome{reason: "probe_timeout"}, cfg)
	if q.Level != QualityOffline || q.SampleCount != 1 || *q.LossPct != 100 || q.RTTMs != nil {
		t.Fatal(q)
	}
	for i := 2; i < 5; i++ {
		q = w.observe(now.Add(time.Duration(i)*time.Second), probeOutcome{rtt: 1000, success: true}, cfg)
		want := QualityOffline
		if i == 4 {
			want = QualityGood
		}
		if q.Level != want {
			t.Fatalf("recovery sample %d: %v", i-1, q.Level)
		}
	}
	// Recovery must restart if the improving candidate changes or deteriorates.
	w.observe(now.Add(5*time.Second), probeOutcome{reason: "probe_timeout"}, cfg)
	w.observe(now.Add(6*time.Second), probeOutcome{rtt: 1000, success: true}, cfg)
	q = w.observe(now.Add(7*time.Second), probeOutcome{rtt: 100000, success: true}, cfg)
	if q.Level != QualityOffline || q.ErrorReason != "recovering" {
		t.Fatal(q)
	}
}

func TestScrapesDoNotAdvanceHysteresis(t *testing.T) {
	m := newTestMonitor(t, Config{Quality: QualityConfig{Window: time.Second, StaleAfter: time.Second, MinSamples: 1}})
	now := time.Now().UTC()
	observeOne(m, now.Add(-time.Second), false, 0)
	observeOne(m, now, true, 1000)
	for i := 0; i < 20; i++ {
		if q := httpQuality(t, m).Peers[0]; q.Quality != "offline" {
			t.Fatal(q)
		}
		if metricValues(t, m)["vpnctl_link_quality"] != 0 {
			t.Fatal("scrape advanced recovery")
		}
	}
}

func TestInvalidTargetIsUnknownNotNetworkLoss(t *testing.T) {
	m := newTestMonitor(t, Config{Source: &fakePeerSource{peers: []peersource.Peer{{PublicKey: "unset", VPNIP: "", ProbePort: 51900}}}})
	for i := 0; i < 4; i++ {
		m.probeAll(context.Background())
	}
	q := httpQuality(t, m).Peers[0]
	if q.Quality != "unknown" || q.ErrorReason != "invalid_probe_target" || q.SampleCount != 0 || q.RTTMs != nil || q.LossPct != nil {
		t.Fatal(q)
	}
	if !math.IsNaN(metricValues(t, m)["vpnctl_probe_loss_ratio"]) {
		t.Fatal("missing measurement emitted zero")
	}
}

func TestQualityConfigurationRejectsInvalidBounds(t *testing.T) {
	for _, q := range []QualityConfig{
		{Window: -time.Second}, {StaleAfter: -time.Second}, {Window: time.Second, StaleAfter: 2 * time.Second}, {MinSamples: -1}, {RecoverySamples: -1},
		{Thresholds: &QualityThresholds{GoodMaxRTTMs: 200, DegradedMaxRTTMs: 100}},
		{Thresholds: &QualityThresholds{DegradedMaxLossPct: 101}},
		{Thresholds: &QualityThresholds{GoodMaxRTTMs: math.NaN()}},
		{Thresholds: &QualityThresholds{GoodMaxRTTMs: math.Inf(1)}},
	} {
		if _, err := New(Config{Quality: q}); err == nil {
			t.Fatalf("accepted invalid config %+v", q)
		}
	}
	thresholds := QualityThresholds{}
	m := newTestMonitor(t, Config{Quality: QualityConfig{Thresholds: &thresholds}})
	thresholds.GoodMaxRTTMs = 900
	if m.cfg.Quality.Thresholds.GoodMaxRTTMs != 0 {
		t.Fatal("retained caller-owned threshold pointer")
	}
}

type failingSource struct{ fakePeerSource }

func (*failingSource) Discover() ([]peersource.Peer, error) {
	return nil, errors.New("discovery broken")
}

func TestDiscoveryFailurePublishesAndSupersedesUnreadGood(t *testing.T) {
	m := newTestMonitor(t, Config{Source: &failingSource{}})
	sub := m.Subscribe()
	for i := 0; i < 3; i++ {
		observeOne(m, time.Now().UTC(), true, 1000)
	}
	m.probeAll(context.Background())
	snap := <-sub
	if snap.ErrorReason != "discovery_failed" || snap.Peers[0].Quality.Level != QualityUnknown {
		t.Fatal(snap)
	}
}

func TestStoreFailureDoesNotChangeLiveMeasurement(t *testing.T) {
	s, err := OpenStore(filepath.Join(t.TempDir(), "closed.db"))
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	m := newTestMonitor(t, Config{Source: &fakePeerSource{peers: []peersource.Peer{{PublicKey: "echo", VPNIP: "127.0.0.1", ProbePort: negativeProbeResponder(t)}}}, Store: s})
	for i := 0; i < 3; i++ {
		m.probeAll(context.Background())
	}
	snap := m.Latest()
	if snap.StorageError != "store_write_failed" || snap.Peers[0].Quality.SampleCount != 3 || *snap.Peers[0].Quality.LossPct != 100 || snap.Peers[0].Quality.Level != QualityOffline {
		t.Fatal(snap)
	}
	if metricValues(t, m)["vpnctl_monitor_storage_ok"] != 0 {
		t.Fatal("storage error hidden")
	}
}

func TestProbeFailureReasonsAndIPv6Addressing(t *testing.T) {
	for err, want := range map[error]string{syscall.ECONNREFUSED: "responder_unavailable", syscall.ENETUNREACH: "route_unreachable", syscall.EHOSTUNREACH: "route_unreachable", os.ErrDeadlineExceeded: "probe_timeout", errors.New("unknown"): "probe_error"} {
		if got := probeError(&net.OpError{Op: "read", Err: err}); got != want {
			t.Fatalf("%v -> %s", err, got)
		}
	}
	p := peersource.Peer{VPNIP: "127.0.0.1", ProbePort: negativeProbeResponder(t)}
	if got := probePeer(context.Background(), p); got.reason != "invalid_response" {
		t.Fatal(got)
	}
	conn, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.ParseIP("::1")})
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 2048)
		n, addr, err := conn.ReadFromUDP(buf)
		if err == nil {
			conn.WriteToUDP(buf[:n], addr)
		}
	}()
	defer func() { conn.Close(); <-done }()
	p.VPNIP, p.ProbePort = "::1", conn.LocalAddr().(*net.UDPAddr).Port
	if got := probePeer(context.Background(), p); !got.success {
		t.Fatal(got)
	}
}

func TestConcurrentQualityPublicationHTTPAndScraping(t *testing.T) {
	m := newTestMonitor(t, Config{})
	registry := prometheus.NewPedanticRegistry()
	registry.MustRegister(m.Collector())
	var wg sync.WaitGroup
	for reader := 0; reader < 4; reader++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				response := httpQuality(t, m)
				if response.ErrorReason == "clock_regressed" {
					t.Error("normal concurrent publication reported a clock regression")
				}
				if len(response.Peers) > 0 && response.Peers[0].RTTMs != nil {
					*response.Peers[0].RTTMs = 999
				}
				if _, err := registry.Gather(); err != nil {
					t.Error(err)
				}
			}
		}()
	}
	for i := 0; i < 100; i++ {
		observeOne(m, time.Now().UTC(), i%5 != 0, 1000)
	}
	wg.Wait()
	if *m.Latest().Peers[0].Quality.RTTMs != 1 {
		t.Fatal("HTTP consumer altered state")
	}
}

func TestBackwardClockCannotRevalidateFutureSamples(t *testing.T) {
	m := newTestMonitor(t, Config{})
	now := time.Now().UTC()
	for i := 0; i < 3; i++ {
		observeOne(m, now.Add(time.Duration(i)*time.Second), true, 1000)
	}
	if snap := m.latestAt(now); !snap.Stale || snap.ErrorReason != "clock_regressed" || snap.Peers[0].Quality.Level != QualityUnknown {
		t.Fatal(snap)
	}
	observeOne(m, now.Add(-time.Second), true, 1000)
	q := m.latestAt(now).Peers[0].Quality
	if q.SampleCount != 1 || q.Level != QualityUnknown || !q.LastSuccessAt.Equal(now.Add(-time.Second)) {
		t.Fatal(q)
	}
}

func TestInvalidProbeConfigDoesNotPolluteHistory(t *testing.T) {
	s, err := OpenStore(filepath.Join(t.TempDir(), "invalid.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	m := newTestMonitor(t, Config{Store: s, Source: &fakePeerSource{peers: []peersource.Peer{{PublicKey: "invalid", VPNIP: "10.7.0.2", ProbePort: -1}}}})
	m.probeAll(context.Background())
	rows, err := s.QueryAll(time.Minute)
	if err != nil || len(rows) != 0 {
		t.Fatal("configuration failure stored as network loss", rows, err)
	}
	if !math.IsNaN(metricValues(t, m)["vpnctl_probe_success"]) {
		t.Fatal("unattempted probe reported as failed")
	}
}

func TestSilentResponderIsTimeoutAndCancellationIsNotLoss(t *testing.T) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	peer := peersource.Peer{PublicKey: "silent", VPNIP: "127.0.0.1", ProbePort: conn.LocalAddr().(*net.UDPAddr).Port}
	if result := probePeer(context.Background(), peer); result.reason != "probe_timeout" {
		t.Fatal("deadline/close race changed the error reason", result)
	}
	m := newTestMonitor(t, Config{Source: &fakePeerSource{peers: []peersource.Peer{peer}}})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); m.Run(ctx) }()
	// Receipt proves the monitor has started a probe. The first datagram belongs
	// to the completed timeout above, so consume both before cancelling the loop.
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 2048)
	for i := 0; i < 2; i++ {
		if _, _, err := conn.ReadFromUDP(buf); err != nil {
			cancel()
			<-done
			t.Fatal(err)
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("probe did not cancel")
	}
	if snap := m.Latest(); !snap.Time.IsZero() || len(snap.Peers) != 0 {
		t.Fatal("shutdown counted as network loss", snap)
	}
}

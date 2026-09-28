package controller

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
	"vpnctl/internal/history"
	"vpnctl/internal/monitor"
	"vpnctl/internal/peersource"

	"vpnctl/internal/api"
	"vpnctl/internal/pki"
	"vpnctl/internal/wgstats"
)

func wireGuardTestKey(n byte) string {
	var b [32]byte
	b[0] = n
	return base64.StdEncoding.EncodeToString(b[:])
}
func TestWireGuardMTLSBindingRemovalRevocation(t *testing.T) {
	s, h := lifecycleServer(t, "10m", "30m")
	reporter, dir := lifecycleNode(t, s, h, "robot")
	peer, _ := lifecycleNode(t, s, h, "peer")
	monitorRegister(t, reporter, "robot", wireGuardTestKey(1))
	monitorRegister(t, peer, "peer", wireGuardTestKey(2))
	ctx := context.Background()
	catalog, e := reporter.MonitorPeers(ctx, "robot")
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now().UTC().Add(-time.Minute)
	rx := wgstats.Counter(100)
	req := wgstats.Report{ID: wgstats.ID(), ObservedAt: now, Interface: "wg0", Reporter: catalog.Self, Peers: []wgstats.Reading{{Peer: catalog.Peers[0], Sample: wgstats.Sample{ObservedAt: now, Generation: wgstats.ID(), Validity: "observed", RX: &rx, TX: &rx}}}}
	for i := 0; i < 2; i++ {
		if e = reporter.SubmitWireGuard(ctx, req); e != nil {
			t.Fatal(e)
		}
	}
	wrong := req.Clone()
	wrong.Peers[0].Peer.VPNIP = "10.7.0.254"
	expectMonitorCode(t, reporter.SubmitWireGuard(ctx, wrong), 409)
	wrong = req.Clone()
	wrong.Peers[0].Peer.Epoch = wgstats.ID()
	expectMonitorCode(t, reporter.SubmitWireGuard(ctx, wrong), 409)

	result, e := reporter.FleetWireGuard(ctx, "robot", "1h", 10)
	if e != nil || result.Storage.Rows != 1 || len(result.Snapshots) != 1 {
		t.Fatal(result, e)
	}
	status, e := reporter.FleetStatus(ctx)
	if e != nil {
		t.Fatal(e)
	}
	found := false
	for _, n := range status.Nodes {
		if n.WireGuard != nil {
			found = true
			if len(n.WireGuard.Views) != 1 || n.WireGuard.Views[0].HandshakeState != "never" {
				t.Fatal(n)
			}
		}
	}
	if !found {
		t.Fatal("missing fleet observation")
	}
	monitorRegister(t, reporter, "robot", wireGuardTestKey(3))
	expectMonitorCode(t, reporter.SubmitWireGuard(ctx, req), 409)
	catalog, e = reporter.MonitorPeers(ctx, "robot")
	if e != nil {
		t.Fatal(e)
	}
	req.Reporter = catalog.Self
	req.ID = wgstats.ID()
	req.ObservedAt = now.Add(time.Second)
	req.Peers[0].Sample.ObservedAt = req.ObservedAt
	if e = reporter.SubmitWireGuard(ctx, req); e != nil {
		t.Fatal(e)
	}
	monitorRegister(t, peer, "peer", wireGuardTestKey(4))
	expectMonitorCode(t, reporter.SubmitWireGuard(ctx, req), 409)
	if _, e = api.Admin(ctx, s.cfg.DataDir, api.AdminRequest{Operation: "node.remove", NodeID: "peer"}); e != nil {
		t.Fatal(e)
	}
	expectMonitorCode(t, reporter.SubmitWireGuard(ctx, req), 409)
	status, e = reporter.FleetStatus(ctx)
	if e != nil {
		t.Fatal(e)
	}
	for _, n := range status.Nodes {
		if n.WireGuard != nil && len(n.WireGuard.Views) != 0 {
			t.Fatal("removed peer remains live", n)
		}
	}
	credentials, e := pki.LoadCredentials(dir)
	if e != nil {
		t.Fatal(e)
	}
	cert, e := pki.ParseCertificate(credentials.ClientCert)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.authority.Revoke(certificateFingerprint(cert)); e != nil {
		t.Fatal(e)
	}
	if e = reporter.SubmitWireGuard(ctx, req); e == nil {
		t.Fatal("revoked write")
	}
	if _, e = reporter.FleetWireGuard(ctx, "robot", "1h", 10); e == nil {
		t.Fatal("revoked read")
	}

}

func TestWireGuardCertificateRenewalPreservesCounterBaseline(t *testing.T) {
	s, h := lifecycleServer(t)
	c, dir := lifecycleNode(t, s, h, "robot")
	p, _ := lifecycleNode(t, s, h, "peer")
	monitorRegister(t, c, "robot", wireGuardTestKey(1))
	monitorRegister(t, p, "peer", wireGuardTestKey(2))
	ctx := context.Background()
	catalog, e := c.MonitorPeers(ctx, "robot")
	if e != nil {
		t.Fatal(e)
	}
	initial, e := pki.LoadCredentials(dir)
	if e != nil {
		t.Fatal(e)
	}
	at := time.Now().UTC().Add(-10 * time.Second)
	rx := wgstats.Counter(100)
	r := wgstats.Report{ID: wgstats.ID(), ObservedAt: at, Reporter: catalog.Self, Interface: "wg0", Peers: []wgstats.Reading{{Peer: catalog.Peers[0], Sample: wgstats.Sample{ObservedAt: at, Generation: wgstats.ID(), Validity: "observed", RX: &rx, TX: &rx}}}}
	if e = c.SubmitWireGuard(ctx, r); e != nil {
		t.Fatal(e)
	}
	startNodePKI(t, c, dir, "robot")
	waitPKI(t, 6*time.Second, func() bool {
		current, e := pki.LoadCredentials(dir)
		return e == nil && current.ClientCert != initial.ClientCert
	})
	after, e := c.MonitorPeers(ctx, "robot")
	if e != nil || after.Self != catalog.Self || after.Peers[0] != catalog.Peers[0] {
		t.Fatal("certificate renewal changed WG binding", e)
	}
	r = r.Clone()
	r.ID = wgstats.ID()
	r.ObservedAt = at.Add(5 * time.Second)
	r.Peers[0].Sample.ObservedAt = r.ObservedAt
	*r.Peers[0].Sample.RX = 150
	*r.Peers[0].Sample.TX = 150
	if e = c.SubmitWireGuard(ctx, r); e != nil {
		t.Fatal(e)
	}
	result, e := c.FleetWireGuard(ctx, "robot", "1h", 1)
	if e != nil {
		t.Fatal(e)
	}
	v := result.Snapshots[0].Views[0]
	if v.RXPerSecond == nil || *v.RXPerSecond != 10 {
		t.Fatal("renewal reset counters", v)
	}
}

type wireGuardResponseLoss struct {
	*history.Store
	mu    sync.Mutex
	calls int
	first string
}

func (s *wireGuardResponseLoss) IngestWireGuard(ctx context.Context, r wgstats.Report, now time.Time) error {
	if e := s.Store.IngestWireGuard(ctx, r, now); e != nil {
		return e
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	if s.calls == 1 {
		s.first = r.ID
		return errors.New("response lost after commit")
	}
	if s.first != r.ID {
		return errors.New("retry changed identity")
	}
	return nil
}

type wireGuardSource struct{ key, peer, ip string }

func (s wireGuardSource) Discover() ([]peersource.Peer, error) {
	at := time.Now().UTC()
	n := wgstats.Counter(10)
	return []peersource.Peer{{LocalPublicKey: s.key, PublicKey: s.peer, VPNIP: s.ip, ProbePort: 51900, WireGuard: wgstats.Sample{ObservedAt: at, Generation: "00000000000000000000000000000001", Validity: "observed", RX: &n, TX: &n}}}, nil
}
func (s wireGuardSource) SelfIP() string        { return "" }
func (s wireGuardSource) InterfaceName() string { return "wg0" }
func TestWireGuardRealReporterResponseLossKeepsLocalCollection(t *testing.T) {
	s, h := lifecycleServer(t, "10m", "30m")
	c, dir := lifecycleNode(t, s, h, "robot")
	p, _ := lifecycleNode(t, s, h, "peer")
	monitorRegister(t, c, "robot", wireGuardTestKey(1))
	registered := monitorRegister(t, p, "peer", wireGuardTestKey(2))
	fault := &wireGuardResponseLoss{Store: s.history.(*history.Store)}
	s.history = fault
	uploader, e := monitor.NewHistoryReporter(h.URL, "robot", dir)
	if e != nil {
		t.Fatal(e)
	}
	mon, e := monitor.New(monitor.Config{History: uploader, Source: wireGuardSource{wireGuardTestKey(1), wireGuardTestKey(2), strings.Split(registered.VPNIP, "/")[0]}, Interval: 50 * time.Millisecond})
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); mon.Run(ctx) }()
	defer func() { cancel(); <-done }()
	waitPKI(t, 5*time.Second, func() bool { return uploader.Status().WireGuardDelivery.Delivered == 1 })
	q, e := c.FleetWireGuard(ctx, "robot", "1h", 10)
	if e != nil || q.Storage.Rows != 1 || len(q.Snapshots) != 1 {
		t.Fatal(q, e)
	}
	fault.mu.Lock()
	calls, first := fault.calls, fault.first
	fault.mu.Unlock()
	if calls != 2 || q.Snapshots[0].ID != first {
		t.Fatal("response-loss duplication", calls, q)
	}
	if snap := mon.Latest(); snap.Stale || snap.Time.Before(q.Snapshots[0].ObservedAt.Add(500*time.Millisecond)) {
		t.Fatal("delivery stopped local collection", snap)
	}
	if _, e = c.Register(ctx, api.RegisterRequest{Name: "robot", PubKey: wireGuardTestKey(1), DirectMode: "off"}); e != nil {
		t.Fatal("delivery affected registration", e)
	}
}

type wireGuardBlockedQuery struct {
	*history.Store
	entered, release chan struct{}
}

func (s *wireGuardBlockedQuery) QueryWireGuard(ctx context.Context, node string, now time.Time, window time.Duration, limit int) (history.WireGuardHistory, error) {
	close(s.entered)
	select {
	case <-s.release:
	case <-ctx.Done():
		return history.WireGuardHistory{}, ctx.Err()
	}
	return s.Store.QueryWireGuard(ctx, node, now, window, limit)
}
func TestWireGuardHistoryRechecksRemovalAndRevocationAfterQuery(t *testing.T) {
	for _, mode := range []string{"subject_removed", "caller_revoked"} {
		t.Run(mode, func(t *testing.T) {
			s, h := lifecycleServer(t, "10m", "30m")
			robot, _ := lifecycleNode(t, s, h, "robot")
			viewer, dir := lifecycleNode(t, s, h, "viewer")
			monitorRegister(t, robot, "robot", wireGuardTestKey(1))
			monitorRegister(t, viewer, "viewer", wireGuardTestKey(2))
			block := &wireGuardBlockedQuery{Store: s.history.(*history.Store), entered: make(chan struct{}), release: make(chan struct{})}
			s.history = block
			var once sync.Once
			release := func() { once.Do(func() { close(block.release) }) }
			defer release()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			result := make(chan error, 1)
			go func() { _, e := viewer.FleetWireGuard(ctx, "robot", "1h", 1); result <- e }()
			select {
			case <-block.entered:
			case <-ctx.Done():
				t.Fatal("query did not start")
			}
			if mode == "subject_removed" {
				if _, e := api.Admin(ctx, s.cfg.DataDir, api.AdminRequest{Operation: "node.remove", NodeID: "robot"}); e != nil {
					t.Fatal("query blocked removal", e)
				}
			} else {
				credentials, e := pki.LoadCredentials(dir)
				if e != nil {
					t.Fatal(e)
				}
				cert, e := pki.ParseCertificate(credentials.ClientCert)
				if e != nil {
					t.Fatal(e)
				}
				if e = s.authority.Revoke(certificateFingerprint(cert)); e != nil {
					t.Fatal(e)
				}
			}
			release()
			select {
			case e := <-result:
				if e == nil {
					t.Fatal("buffered history escaped revocation/removal")
				}
				if mode == "subject_removed" {
					expectMonitorCode(t, e, 404)
				}
			case <-ctx.Done():
				t.Fatal("read did not finish")
			}
		})
	}
}

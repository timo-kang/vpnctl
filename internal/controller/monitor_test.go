// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package controller

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"vpnctl/internal/agent"
	"vpnctl/internal/api"
	"vpnctl/internal/config"
	"vpnctl/internal/direct"
	"vpnctl/internal/history"
	"vpnctl/internal/monitor"
	"vpnctl/internal/peersource"
	"vpnctl/internal/pki"
	"vpnctl/internal/store"
)

type monitorTestSource struct{ peers []peersource.Peer }

func (s monitorTestSource) Discover() ([]peersource.Peer, error) { return s.peers, nil }
func (s monitorTestSource) SelfIP() string                       { return "" }
func (s monitorTestSource) InterfaceName() string                { return "test" }
func monitorRegister(t *testing.T, c *api.Client, id, key string) api.RegisterResponse {
	t.Helper()
	r, err := c.Register(context.Background(), api.RegisterRequest{Name: id, PubKey: key, DirectMode: "off"})
	if err != nil {
		t.Fatal(err)
	}
	return r
}
func monitorCatalog(t *testing.T, c *api.Client, id string) []api.MonitorPeer {
	t.Helper()
	r, err := c.MonitorPeers(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return r.Peers
}
func expectMonitorCode(t *testing.T, err error, code int) {
	t.Helper()
	var response *api.HTTPError
	if !errors.As(err, &response) || response.StatusCode != code {
		t.Fatalf("want HTTP %d got %v", code, err)
	}
}
func TestMonitorBindingOverMTLSChangesRevertsRemovalAndRevocation(t *testing.T) {
	s, h := lifecycleServer(t, "10m", "30m")
	reporter, dir := lifecycleNode(t, s, h, "robot")
	peer, _ := lifecycleNode(t, s, h, "peer")
	monitorRegister(t, reporter, "robot", "pub-robot")
	monitorRegister(t, peer, "peer", "pub-peer")
	catalog := monitorCatalog(t, reporter, "robot")
	if len(catalog) != 1 {
		t.Fatal(catalog)
	}
	p := catalog[0]
	now := time.Now().UTC().Truncate(time.Microsecond)
	req := api.MonitorMetricsRequest{NodeID: "robot", Peer: p, Observation: history.Observation{ID: "first", Timestamp: now, PeerID: "peer", Path: "unknown", Source: "monitor-overlay", Success: historyPtr(true), RTTMs: historyPtr(1.25)}}
	if err := reporter.SubmitMonitorMetrics(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if err := reporter.SubmitMonitorMetrics(context.Background(), req); err != nil {
		t.Fatal("same ID retry", err)
	}
	// Out-of-order arrival preserves measurement time and contributes once.
	older := req
	older.Observation.ID = "older"
	older.Observation.Timestamp = now.Add(-time.Minute)
	older.Observation.Success = nil
	older.Observation.RTTMs = nil
	older.Observation.Validity = "unknown"
	older.Observation.Reason = "collector_unavailable"
	if err := reporter.SubmitMonitorMetrics(context.Background(), older); err != nil {
		t.Fatal(err)
	}
	monitorRegister(t, peer, "peer", "pub-peer")
	if got := monitorCatalog(t, reporter, "robot")[0]; got != p {
		t.Fatal("heartbeat changed binding", got, p)
	}
	reg, err := store.LoadRegistry(s.regPath)
	if err != nil {
		t.Fatal(err)
	}
	if err = validateRegistryNodeMetadata(reg); err != nil {
		t.Fatal(err)
	}
	for _, n := range reg.Nodes {
		if n.ID == "peer" && monitorPeer(n) != p {
			t.Fatal("restart changed binding")
		}
	}
	reg.Nodes[0].ObservationEpoch = "invalid"
	if validateRegistryNodeMetadata(reg) == nil {
		t.Fatal("corrupt epoch accepted")
	}
	for _, key := range []string{"pub-replacement", "pub-peer"} {
		monitorRegister(t, peer, "peer", key)
		if got := monitorCatalog(t, reporter, "robot")[0]; got.Epoch == p.Epoch {
			t.Fatal("key ABA reused epoch")
		}
		expectMonitorCode(t, reporter.SubmitMonitorMetrics(context.Background(), req), 409)
	}
	req.Peer = monitorCatalog(t, reporter, "robot")[0]
	req.Observation.ID = "new-binding"
	wrong := req
	wrong.Peer.VPNIP = "10.7.0.99"
	expectMonitorCode(t, reporter.SubmitMonitorMetrics(context.Background(), wrong), 409)
	wrong = req
	wrong.NodeID = "peer"
	expectMonitorCode(t, reporter.SubmitMonitorMetrics(context.Background(), wrong), 403)
	wrong = req
	wrong.Observation.Path = "relay"
	expectMonitorCode(t, reporter.SubmitMonitorMetrics(context.Background(), wrong), 400)
	wrong = req
	wrong.Observation.PeerID = "controller"
	wrong.Peer.NodeID = "controller"
	expectMonitorCode(t, reporter.SubmitMonitorMetrics(context.Background(), wrong), 409)
	if err = reporter.SubmitMonitorMetrics(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	bs, err := s.history.(*history.Store).Query(context.Background(), "robot", time.Now(), time.Hour, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	var count, unknown int
	for _, b := range bs {
		count += b.Count
		unknown += b.UnknownCount
	}
	if count != 2 || unknown != 1 {
		t.Fatal("duplicate/reordered history", bs)
	}
	if _, err = api.Admin(context.Background(), s.cfg.DataDir, api.AdminRequest{Operation: "node.remove", NodeID: "peer"}); err != nil {
		t.Fatal(err)
	}
	expectMonitorCode(t, reporter.SubmitMonitorMetrics(context.Background(), req), 409)
	if peers := monitorCatalog(t, reporter, "robot"); len(peers) != 0 {
		t.Fatal("removed mapping", peers)
	}
	if _, err = s.registerNode(nodeRegistration{Name: "peer", PubKey: "pub-peer"}, false); !errors.Is(err, errNodeRemoved) {
		t.Fatal("tombstone identity recycled", err)
	}
	credentials, err := pki.LoadCredentials(dir)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := pki.ParseCertificate(credentials.ClientCert)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.authority.Revoke(certificateFingerprint(cert)); err != nil {
		t.Fatal(err)
	}
	_, err = reporter.MonitorPeers(context.Background(), "robot")
	if err == nil {
		t.Fatal("revoked reporter read mapping")
	}
	if err = reporter.SubmitMonitorMetrics(context.Background(), req); err == nil {
		t.Fatal("revoked reporter wrote history")
	}
}
func TestMonitorNoTLSAndLegacyBinding(t *testing.T) {
	s := &Server{}
	for _, route := range []string{"/monitor/peers?node_id=robot", "/monitor/metrics"} {
		rec := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, route, nil)
		if strings.Contains(route, "metrics") {
			r = httptest.NewRequest(http.MethodPost, route, strings.NewReader(`{"node_id":"robot"}`))
			s.handleMonitorMetrics(rec, r)
		} else {
			s.handleMonitorPeers(rec, r)
		}
		if rec.Code != 403 {
			t.Fatal(rec.Code, rec.Body.String())
		}
	}
	n := store.NodeInfo{ID: "legacy", PubKey: "pub", VPNIP: "10.7.0.2/32"}
	before := monitorPeer(n)
	path := filepath.Join(t.TempDir(), "registry.yaml")
	if err := store.SaveRegistry(path, &store.Registry{Nodes: []store.NodeInfo{n}}); err != nil {
		t.Fatal(err)
	}
	reg, err := store.LoadRegistry(path)
	if err != nil {
		t.Fatal(err)
	}
	if monitorPeer(reg.Nodes[0]) != before || len(before.Epoch) != 64 {
		t.Fatal("legacy restart changed binding")
	}
}
func loopbackMonitorRegistry(t *testing.T, s *Server) {
	t.Helper()
	allocator, err := newIPAM("127.77.0.0/16", "127.77.0.1/16", nil)
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	s.ipam = allocator
	s.mu.Unlock()
}
func TestMonitorActualUDPOverMTLSAndCredentialRenewal(t *testing.T) {
	s, h := lifecycleServer(t)
	loopbackMonitorRegistry(t, s)
	reporter, dir := lifecycleNode(t, s, h, "robot")
	monitorRegister(t, reporter, "robot", "pub-robot")
	creds, err := pki.LoadCredentials(dir)
	if err != nil {
		t.Fatal(err)
	}
	peers := []peersource.Peer{}
	for _, id := range []string{"success", "timeout", "unknown"} {
		c, _ := lifecycleNode(t, s, h, id)
		r := monitorRegister(t, c, id, "pub-"+id)
		ip := strings.Split(r.VPNIP, "/")[0]
		port := 0
		if id == "success" {
			responder, e := direct.StartResponder(net.JoinHostPort(ip, "0"))
			if e != nil {
				t.Fatal(e)
			}
			defer responder.Close()
			addr, _ := net.ResolveUDPAddr("udp", responder.LocalAddr())
			port = addr.Port
		}
		if id == "timeout" {
			conn, e := net.ListenPacket("udp", net.JoinHostPort(ip, "0"))
			if e != nil {
				t.Fatal(e)
			}
			defer conn.Close()
			port = conn.LocalAddr().(*net.UDPAddr).Port
		}
		peers = append(peers, peersource.Peer{PublicKey: "pub-" + id, VPNIP: ip, ProbePort: port, Name: "untrusted-label"})
	}
	uploader, err := monitor.NewHistoryReporter(h.URL, "robot", dir)
	if err != nil {
		t.Fatal(err)
	}
	mon, err := monitor.New(monitor.Config{History: uploader, Source: monitorTestSource{peers}, Interval: 100 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); mon.Run(ctx) }()
	defer func() { cancel(); <-done }()
	waitPKI(t, 12*time.Second, func() bool {
		resp, e := reporter.FleetHistoryQuery(context.Background(), "1h", "robot", "1h")
		if e != nil {
			return false
		}
		states := map[string]bool{}
		for _, n := range resp.Nodes {
			for _, b := range n.Buckets {
				if b.Source != "monitor-overlay" || b.Path != "unknown" || b.RelayID != "" || b.Uplink != "" {
					t.Error("invented route", b)
					return false
				}
				switch b.PeerID {
				case "success":
					states[b.PeerID] = b.Count > 0 && b.Successes == b.Count && b.AvgRTTMs != nil
				case "timeout":
					states[b.PeerID] = b.Count > 0 && b.Successes == 0 && b.AvgRTTMs == nil && b.LossPct != nil && *b.LossPct == 100
				case "unknown":
					states[b.PeerID] = b.Count == 0 && b.UnknownCount > 0 && b.AvgRTTMs == nil && b.LossPct == nil
				}
			}
		}
		current, e := pki.LoadCredentials(dir)
		return e == nil && current.ClientCert != creds.ClientCert && states["success"] && states["timeout"] && states["unknown"]
	})
	snap := mon.Latest()
	if len(snap.Peers) != 3 || snap.History.Delivery.Delivered < 3 {
		t.Fatal(snap)
	}
	for _, p := range snap.Peers {
		if p.Peer.ProbePort == 0 && p.Quality.SampleCount != 0 {
			t.Fatal("unattempted target counted", p)
		}
	}
}

func TestMonitorAndDirectRealProducersVariableScale(t *testing.T) {
	for _, schema := range []int{5, 6, 7} {
		for _, size := range []int{1, 3, 8, 32} {
			t.Run(fmt.Sprintf("schema_%d_nodes_%d", schema, size), func(t *testing.T) {
				s, h := lifecycleServer(t, "10m", "30m")
				loopbackMonitorRegistry(t, s)
				ctx, cancel := context.WithCancel(context.Background())
				var wg sync.WaitGroup
				defer func() { cancel(); wg.Wait() }()
				st := s.history.(*history.Store)
				if schema >= 6 {
					if err := st.EnableTiering(ctx, time.Now()); err != nil {
						t.Fatal(err)
					}
				}
				if schema == 7 {
					if err := st.EnableReclamation(ctx); err != nil {
						t.Fatal(err)
					}
				}
				clients := make([]*api.Client, size)
				dirs := make([]string, size)
				peers := make([]peersource.Peer, size)
				uploaders := make([]*monitor.HistoryReporter, size)
				for i := 0; i < size; i++ {
					id := fmt.Sprintf("node-%02d", i)
					clients[i], dirs[i] = lifecycleNode(t, s, h, id)
					r := monitorRegister(t, clients[i], id, "pub-"+id)
					conn, err := net.ListenPacket("udp", "127.0.0.1:0")
					if err != nil {
						t.Fatal(err)
					}
					port := conn.LocalAddr().(*net.UDPAddr).Port
					conn.Close()
					peers[i] = peersource.Peer{PublicKey: "pub-" + id, VPNIP: strings.Split(r.VPNIP, "/")[0], ProbePort: port}
					cfg := config.NodeConfig{Name: id, Controller: h.URL, PKIDir: dirs[i], WGPublicKey: peers[i].PublicKey, ProbePort: port, AdvertisePublicAddr: net.JoinHostPort(peers[i].VPNIP, fmt.Sprint(port)), DirectMode: "auto", DirectIntervalSec: 1, CandidatesIntervalSec: 1, KeepaliveIntervalSec: 60}
					wg.Add(1)
					go func() { defer wg.Done(); _ = agent.Run(ctx, cfg) }()
				}
				for i := 0; i < size; i++ {
					id := fmt.Sprintf("node-%02d", i)
					var list []peersource.Peer
					for j, p := range peers {
						if i != j {
							list = append(list, p)
						}
					}
					uploader, err := monitor.NewHistoryReporter(h.URL, id, dirs[i])
					if err != nil {
						t.Fatal(err)
					}
					uploaders[i] = uploader
					m, err := monitor.New(monitor.Config{History: uploader, Source: monitorTestSource{list}, Interval: time.Second})
					if err != nil {
						t.Fatal(err)
					}
					wg.Add(1)
					go func() { defer wg.Done(); m.Run(ctx) }()
				}
				waitPKI(t, 45*time.Second, func() bool {
					if size == 1 {
						return uploaders[0].Status().MappingReady
					}
					latest := st.Latest(time.Time{})
					for i := 0; i < size; i++ {
						id := fmt.Sprintf("node-%02d", i)
						sources := map[string]int{}
						for _, m := range latest[id] {
							if m.SampleCount > 0 {
								sources[m.Source]++
							}
						}
						if schema == 5 && size == 32 { // The legacy global 256-stream budget cannot hold 1,984 relations.
							continue
						}
						if sources["monitor-overlay"] != size-1 || sources["agent-direct"] != size-1 {
							return false
						}
					}
					if schema == 5 && size == 32 {
						var quota uint64
						for _, u := range uploaders {
							quota += u.Status().Delivery.QuotaDropped
						}
						return quota > 0 && len(latest) > 0
					}
					return true
				})
				if size == 1 {
					resp, err := clients[0].FleetHistoryQuery(ctx, "1h", "node-00", "1h")
					if err != nil {
						t.Fatal(err)
					}
					for _, n := range resp.Nodes {
						for _, b := range n.Buckets {
							if b.Count+b.UnknownCount != 0 {
								t.Fatal("single node fabricated peer", b)
							}
						}
					}
				}
				if schema >= 6 && size > 1 {
					for _, source := range []string{"agent-direct", "monitor-overlay"} {
						count, cursor := 0, ""
						for {
							resp, err := clients[0].FleetHistoryPage(ctx, "1h", "node-00", "1h", source, cursor)
							if err != nil {
								t.Fatal(err)
							}
							if resp.SchemaVersion != schema-3 {
								t.Fatal("API version", resp.SchemaVersion)
							}
							if schema == 7 && (resp.Tiering == nil || resp.Tiering.Coverage == nil) {
								t.Fatal("missing coverage")
							}
							for _, n := range resp.Nodes {
								for _, b := range n.Buckets {
									if b.Source != source {
										t.Fatal("source mixed", b)
									}
									count += b.Count
								}
							}
							cursor = resp.Tiering.NextCursor
							if cursor == "" {
								break
							}
						}
						if count < size-1 {
							t.Fatal("missing real samples", source, count)
						}
					}
				}
				t.Logf("actual producers: schema=%d nodes=%d directed relations/source=%d", schema, size, size*(size-1))
			})
		}
	}
}

// The store commits before its first error response; the real monitor queue
// must resend that exact observation, while other ready observations progress.
type monitorFaultHistory struct {
	history.Storage
	mu        sync.Mutex
	mode      string
	lost      bool
	first     history.Observation
	retried   bool
	committed map[string]bool
}

func (s *monitorFaultHistory) Ingest(ctx context.Context, node string, batch []history.Observation, now time.Time) error {
	s.mu.Lock()
	mode := s.mode
	bad := len(batch) == 1 && batch[0].PeerID == "bad"
	lose := bad && !s.lost
	if lose {
		s.lost = true
		s.first = batch[0]
	}
	if bad && s.first.ID == batch[0].ID && !lose {
		if !reflect.DeepEqual(s.first, batch[0]) {
			s.mu.Unlock()
			return errors.New("retry changed observation")
		}
		s.retried = true
	}
	s.mu.Unlock()
	if bad && mode == "quota" {
		return &history.QuotaError{Resource: "node_streams", Limit: 16}
	}
	if bad && mode == "sealed" {
		return history.ErrSealed
	}
	if err := s.Storage.Ingest(ctx, node, batch, now); err != nil {
		return err
	}
	s.mu.Lock()
	if s.committed == nil {
		s.committed = map[string]bool{}
	}
	for _, o := range batch {
		s.committed[o.ID] = true
	}
	s.mu.Unlock()
	if lose {
		return errors.New("injected response loss after durable commit")
	}
	return nil
}
func TestMonitorRealRetryQuotaAndSealedKeepOtherPeerFlowing(t *testing.T) {
	s, h := lifecycleServer(t, "10m", "30m")
	loopbackMonitorRegistry(t, s)
	client, dir := lifecycleNode(t, s, h, "robot")
	monitorRegister(t, client, "robot", "pub-robot")
	var peers []peersource.Peer
	for _, id := range []string{"bad", "good"} {
		c, _ := lifecycleNode(t, s, h, id)
		r := monitorRegister(t, c, id, "pub-"+id)
		ip := strings.Split(r.VPNIP, "/")[0]
		remote, err := direct.StartResponder(net.JoinHostPort(ip, "0"))
		if err != nil {
			t.Fatal(err)
		}
		defer remote.Close()
		addr, _ := net.ResolveUDPAddr("udp", remote.LocalAddr())
		peers = append(peers, peersource.Peer{PublicKey: "pub-" + id, VPNIP: ip, ProbePort: addr.Port})
	}
	base := s.history.(*history.Store)
	faults := &monitorFaultHistory{Storage: s.history}
	s.history = faults
	reporter, err := monitor.NewHistoryReporter(h.URL, "robot", dir)
	if err != nil {
		t.Fatal(err)
	}
	mon, err := monitor.New(monitor.Config{History: reporter, Source: monitorTestSource{peers}, Interval: 50 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); mon.Run(ctx) }()
	defer func() { cancel(); <-done }()
	waitPKI(t, 8*time.Second, func() bool { faults.mu.Lock(); defer faults.mu.Unlock(); return faults.retried })
	for _, mode := range []string{"quota", "sealed"} {
		before := reporter.Status().Delivery
		faults.mu.Lock()
		faults.mode = mode
		faults.mu.Unlock()
		waitPKI(t, 3*time.Second, func() bool {
			now := reporter.Status().Delivery
			return now.Delivered > before.Delivered && now.Dropped > before.Dropped && (mode != "quota" || now.QuotaDropped > before.QuotaDropped)
		})
		work, stop := context.WithTimeout(ctx, time.Second)
		_, err := client.Register(work, api.RegisterRequest{Name: "robot", PubKey: "pub-robot", DirectMode: "off"})
		stop()
		if err != nil {
			t.Fatal("telemetry blocked control", mode, err)
		}
	}
	cancel()
	<-done
	// Join any HTTP handler whose commit outlived client cancellation.
	s.mutationAdmission.Lock()
	s.mutationAdmission.Unlock()
	faults.mu.Lock()
	first := faults.first
	unique := len(faults.committed)
	faults.mu.Unlock()
	// The failed acknowledgement must not duplicate the committed first sample.
	out, err := base.Query(context.Background(), "robot", time.Now(), time.Hour, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	total := 0
	for _, b := range out {
		total += b.Count
	}
	if first.ID == "" || total != unique || total == 0 {
		t.Fatal("committed probes duplicated or lost", total, unique)
	}
	if status := mon.Latest(); len(status.Peers) != 2 || !status.Peers[0].Success || !status.Peers[1].Success {
		t.Fatal("storage rejection changed local network outcome", status)
	}
}

func TestMonitorControllerOutageDoesNotStopActualLocalProbes(t *testing.T) {
	s, h := lifecycleServer(t, "10m", "30m")
	loopbackMonitorRegistry(t, s)
	client, dir := lifecycleNode(t, s, h, "robot")
	monitorRegister(t, client, "robot", "pub-robot")
	peer, _ := lifecycleNode(t, s, h, "peer")
	r := monitorRegister(t, peer, "peer", "pub-peer")
	ip := strings.Split(r.VPNIP, "/")[0]
	remote, err := direct.StartResponder(net.JoinHostPort(ip, "0"))
	if err != nil {
		t.Fatal(err)
	}
	defer remote.Close()
	addr, _ := net.ResolveUDPAddr("udp", remote.LocalAddr())
	uploader, err := monitor.NewHistoryReporter(h.URL, "robot", dir)
	if err != nil {
		t.Fatal(err)
	}
	local, err := monitor.OpenStore(t.TempDir() + "/local.db")
	if err != nil {
		t.Fatal(err)
	}
	defer local.Close()
	mon, err := monitor.New(monitor.Config{History: uploader, Store: local, Source: monitorTestSource{[]peersource.Peer{{PublicKey: "pub-peer", VPNIP: ip, ProbePort: addr.Port}}}, Interval: 100 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); mon.Run(ctx) }()
	defer func() { cancel(); <-done }()
	waitPKI(t, 5*time.Second, func() bool { return uploader.Status().Delivery.Delivered > 0 })
	h.Close() // Actual transport outage, rather than a crafted metrics error.
	before := mon.Latest().Time
	waitPKI(t, 8*time.Second, func() bool {
		status := uploader.Status()
		return status.ErrorReason == "catalog_unavailable" && status.MappingDropped > 1 && mon.Latest().Time.After(before.Add(time.Second))
	})
	snap := mon.Latest()
	if len(snap.Peers) != 1 || !snap.Peers[0].Success || snap.Stale {
		t.Fatal("controller loss stopped local measurement", snap)
	}
	cancel()
	<-done
	if status := uploader.Status(); status.Delivery.Pending != 0 || status.Delivery.Dropped == 0 {
		t.Fatal("undelivered shutdown work unaccounted", status)
	}
	rows, err := local.QueryAll(time.Hour)
	if err != nil || len(rows) < 3 {
		t.Fatal("lost local measurements", len(rows), err)
	}
}

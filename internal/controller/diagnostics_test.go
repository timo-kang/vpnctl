package controller

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"vpnctl/internal/agent"
	"vpnctl/internal/api"
	"vpnctl/internal/atomicfile"
	"vpnctl/internal/config"
	"vpnctl/internal/history"
	"vpnctl/internal/pki"
)

func eventResults(t *testing.T, s *Server, node string) map[string]history.Event {
	t.Helper()
	out, err := s.history.(history.EventStorage).QueryEvents(context.Background(), node, time.Now(), time.Hour, 1000)
	if err != nil {
		t.Fatal(err)
	}
	results := map[string]history.Event{}
	for _, e := range out.Events {
		results[e.Current] = e
	}
	return results
}

func TestAutomaticCertificateTimelineThroughTLS(t *testing.T) {
	s, h := lifecycleServer(t, "30s")
	stop := s.startDiagnosticEvents()
	defer stop()
	c, dir := lifecycleNode(t, s, h, "robot")
	var producer agent.EventSupervisor
	ctx := producer.Configure(context.Background(), config.NodeConfig{Name: "robot", Controller: h.URL, PKIDir: dir})
	defer producer.Stop()
	if err := c.SyncCredentials(ctx, filepath.Join(dir, "missing"), "robot"); err == nil {
		t.Fatal("missing credential fault not exercised")
	}
	if _, err := s.adminPKI(api.AdminRequest{Operation: "ca.prepare"}); err != nil {
		t.Fatal(err)
	}
	if err := c.SyncCredentials(ctx, dir, "robot"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.adminPKI(api.AdminRequest{Operation: "ca.activate"}); err != nil {
		t.Fatal(err)
	}
	if err := c.SyncCredentials(ctx, dir, "robot"); err != nil {
		t.Fatal(err)
	}
	waitPKI(t, 3*time.Second, func() bool {
		results := eventResults(t, s, "")
		nodes := eventResults(t, s, "robot")
		return results["issue:success"].Kind != "" && results["renew:success"].Kind != "" && results["ca.activate:success"].Kind != "" && nodes["installed"].Kind != "" && nodes["up"].Target == "sync" && nodes["up"].Previous == "down"
	})
	out, err := c.FleetEvents(context.Background(), "", "1h", 100)
	if err != nil || out.Scope != "controller" || len(out.Events) < 4 {
		t.Fatal(out, err)
	}
	if !strings.Contains(eventResults(t, s, "")["renew:success"].Message, "fingerprint=") {
		t.Fatal("renewal identity missing")
	}
	creds, err := pki.LoadCredentials(dir)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := pki.ParseCertificate(creds.ClientCert)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.adminPKI(api.AdminRequest{Operation: "pki.revoke", Fingerprint: pki.Fingerprint(cert)}); err != nil {
		t.Fatal(err)
	}
	if _, err = c.FleetStatus(context.Background()); err == nil {
		t.Fatal("revocation not enforced")
	}
	waitPKI(t, time.Second, func() bool { return eventResults(t, s, "")["pki.revoke:success"].Target == pki.Fingerprint(cert) })
}

func TestControllerEventScopeCannotBeClaimedByNode(t *testing.T) {
	s := newIdentityTestServer(t)
	now := time.Now()
	e := history.Event{ID: "spoof", Timestamp: now, Kind: "certificate", Source: "controller-pki", Severity: "info", Validity: "observed"}
	for _, node := range []string{"", "node-b"} {
		raw, _ := json.Marshal(api.EventRequest{NodeID: node, Event: e})
		rec := httptest.NewRecorder()
		s.requireClientCert(s.handleEvent)(rec, requestWithNodeCertificate(t, "POST", "/events", raw, "node-a"))
		if rec.Code != 400 && rec.Code != 403 {
			t.Fatal(rec.Code, rec.Body.String())
		}
	}
	// The embedded owner and source are untrusted; the authenticated envelope wins.
	e.NodeID = ""
	raw, _ := json.Marshal(api.EventRequest{NodeID: "node-a", Event: e})
	rec := httptest.NewRecorder()
	s.requireClientCert(s.handleEvent)(rec, requestWithNodeCertificate(t, "POST", "/events", raw, "node-a"))
	if rec.Code != 204 {
		t.Fatal(rec.Code, rec.Body.String())
	}
	if len(eventResults(t, s, "")) != 0 {
		t.Fatal("node wrote global events")
	}
	for _, target := range []string{"/fleet/events?scope=controller&node_id=node-a", "/fleet/events?scope=other"} {
		rec = httptest.NewRecorder()
		s.handleAuthorizedEvents(rec, requestWithNodeCertificate(t, "GET", target, nil, "node-a"))
		if rec.Code != 400 {
			t.Fatal(target, rec.Code)
		}
	}
	rec = httptest.NewRecorder()
	s.handleAuthorizedEvents(rec, httptest.NewRequest("GET", "/fleet/events?scope=controller", nil))
	if rec.Code != 401 {
		t.Fatal("anonymous controller event read", rec.Code)
	}
}

type blockedEvents struct {
	*history.Store
	started chan struct{}
}

func (b *blockedEvents) IngestEvent(ctx context.Context, node string, e history.Event, now time.Time) error {
	select {
	case b.started <- struct{}{}:
	default:
	}
	<-ctx.Done()
	return ctx.Err()
}
func TestBlockedDiagnosticStorageDoesNotBlockSecurityOrHealthyReads(t *testing.T) {
	s, h := lifecycleServer(t, "30s")
	a, dir := lifecycleNode(t, s, h, "a")
	b, _ := lifecycleNode(t, s, h, "b")
	blocked := &blockedEvents{Store: s.history.(*history.Store), started: make(chan struct{}, 1)}
	s.history = blocked
	stop := s.startDiagnosticEvents()
	defer stop()
	<-blocked.started
	if _, err := s.adminPKI(api.AdminRequest{Operation: "ca.prepare"}); err != nil {
		t.Fatal(err)
	}
	// Adversarial repetition overflows the diagnostic queue without changing PKI admission.
	for i := 0; i < 100; i++ {
		if _, err := s.adminPKI(api.AdminRequest{Operation: "ca.prepare"}); !errors.Is(err, pki.ErrTransitionBlocked) {
			t.Fatal(err)
		}
	}
	creds, _ := pki.LoadCredentials(dir)
	cert, _ := pki.ParseCertificate(creds.ClientCert)
	if _, err := s.adminPKI(api.AdminRequest{Operation: "pki.revoke", Fingerprint: pki.Fingerprint(cert)}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.FleetStatus(context.Background()); err == nil {
		t.Fatal("revocation delayed by event history")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := b.FleetStatus(ctx); err != nil {
		t.Fatal("healthy read blocked", err)
	}
}

func TestPKIPersistenceFailureDoesNotEmitSuccess(t *testing.T) {
	s, _ := lifecycleServer(t, "30s")
	stop := s.startDiagnosticEvents()
	defer stop()
	path := filepath.Join(s.cfg.DataDir, "pki", "authority.json")
	if err := os.Rename(path, path+".saved"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	defer func() { os.Remove(path); os.Rename(path+".saved", path) }()
	if _, err := s.adminPKI(api.AdminRequest{Operation: "ca.prepare"}); err == nil {
		t.Fatal("write failure not injected")
	}
	waitPKI(t, time.Second, func() bool { return eventResults(t, s, "")["ca.prepare:failed"].Kind != "" })
	if s.authority.Status().Phase != "stable" || eventResults(t, s, "")["ca.prepare:success"].Kind != "" {
		t.Fatal("phantom transition")
	}
	s.recordPKIResult("renew", "robot", &atomicfile.CommitError{Err: syscall.EIO})
	waitPKI(t, time.Second, func() bool { return eventResults(t, s, "")["renew:uncertain"].Validity == "unknown" })
}

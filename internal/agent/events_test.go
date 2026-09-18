package agent

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/stun/v3"
	"vpnctl/internal/api"
	"vpnctl/internal/config"
	"vpnctl/internal/history"
)

func TestAutomaticDiscoveryAndNATTimelineWithRealUDP(t *testing.T) {
	store, err := history.Open(t.TempDir()+"/history.db", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	var candidatesFail, stunFail atomic.Bool
	candidatesFail.Store(true)
	var mappedPort atomic.Int32
	mappedPort.Store(41001)
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	doneUDP := make(chan struct{})
	go func() {
		defer close(doneUDP)
		buf := make([]byte, 2048)
		for {
			n, remote, err := udp.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if stunFail.Load() {
				continue
			}
			msg := &stun.Message{Raw: buf[:n]}
			if msg.Decode() != nil {
				continue
			}
			response := stun.MustBuild(stun.NewTransactionIDSetter(msg.TransactionID), stun.BindingSuccess, &stun.XORMappedAddress{IP: net.ParseIP("203.0.113.7"), Port: int(mappedPort.Load())})
			udp.WriteToUDP(response.Raw, remote)
		}
	}()
	defer func() { udp.Close(); <-doneUDP }()
	controller := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/register":
			json.NewEncoder(w).Encode(api.RegisterResponse{NodeID: "robot", VPNIP: "10.7.0.2/32"})
		case "/candidates":
			if candidatesFail.Load() {
				http.Error(w, "unavailable", 503)
			} else {
				json.NewEncoder(w).Encode(api.CandidatesResponse{})
			}
		case "/nat-probe":
			w.WriteHeader(204)
		case "/events":
			var req api.EventRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "invalid", 400)
				return
			}
			if err := store.IngestEvent(r.Context(), req.NodeID, req.Event, time.Now()); err != nil {
				http.Error(w, err.Error(), 503)
				return
			}
			w.WriteHeader(204)
		default:
			w.WriteHeader(404)
		}
	}))
	defer controller.Close()
	reserved, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	port := reserved.LocalAddr().(*net.UDPAddr).Port
	reserved.Close()
	cfg := config.NodeConfig{Name: "robot", Controller: controller.URL, DirectMode: "auto", ProbePort: port, KeepaliveIntervalSec: 1, STUNIntervalSec: 1, CandidatesIntervalSec: 1, DirectIntervalSec: 60, STUNServers: []string{udp.LocalAddr().String()}, ServerPublicKey: "unused", ServerEndpoint: "127.0.0.1:51820", ServerAllowedIPs: []string{"10.7.0.0/24"}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, cfg) }()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("agent shutdown blocked")
		}
	}()
	wait := func(match func(history.Event) bool) {
		t.Helper()
		deadline := time.Now().Add(9 * time.Second)
		for time.Now().Before(deadline) {
			out, err := store.QueryEvents(context.Background(), "robot", time.Now(), time.Hour, 100)
			if err != nil {
				t.Fatal(err)
			}
			for _, e := range out.Events {
				if match(e) {
					return
				}
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatal("missing automatic event")
	}
	wait(func(e history.Event) bool { return e.Kind == "nat_remap" && strings.Contains(e.Current, "41001") })
	wait(func(e history.Event) bool { return e.Target == "candidates" && e.Current == "down" })
	candidatesFail.Store(false)
	mappedPort.Store(41002)
	wait(func(e history.Event) bool {
		return e.Target == "candidates" && e.Previous == "down" && e.Current == "up"
	})
	wait(func(e history.Event) bool {
		return e.Kind == "nat_remap" && strings.Contains(e.Previous, "41001") && strings.Contains(e.Current, "41002")
	})
	stunFail.Store(true)
	wait(func(e history.Event) bool { return e.Target == "stun" && e.Previous == "up" && e.Current == "down" })
	stunFail.Store(false)
	wait(func(e history.Event) bool { return e.Target == "stun" && e.Previous == "down" && e.Current == "up" })
	out, err := store.QueryEvents(context.Background(), "robot", time.Now(), time.Hour, 100)
	if err != nil {
		t.Fatal(err)
	}
	nat := 0
	for _, e := range out.Events {
		if e.Target == "server-config" {
			t.Fatal("cached configuration claimed network discovery", e)
		}
		if e.Kind == "nat_remap" {
			nat++
		}
	}
	if nat != 2 {
		t.Fatalf("unchanged mappings produced %d events", nat)
	}
}

func TestEventSupervisorSurvivesRegistrationFailureAndReconfigures(t *testing.T) {
	var fail atomic.Bool
	fail.Store(true)
	received := make(chan api.EventRequest, 20)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/events" {
			var req api.EventRequest
			json.NewDecoder(r.Body).Decode(&req)
			received <- req
			w.WriteHeader(204)
			return
		}
		if fail.Load() {
			w.WriteHeader(503)
			return
		}
		json.NewEncoder(w).Encode(api.RegisterResponse{NodeID: "robot"})
	}))
	defer server.Close()
	cfg := config.NodeConfig{Name: "robot", Controller: server.URL, DirectMode: "off", ServerPublicKey: "key", ServerEndpoint: "127.0.0.1:51820", ServerAllowedIPs: []string{"10.7.0.0/24"}}
	var events EventSupervisor
	defer events.Stop()
	var probes ProbeSupervisor
	defer probes.Close()
	ctx := events.Configure(context.Background(), cfg)
	if err := probes.RunSession(ctx, cfg); err == nil {
		t.Fatal("registration failure not injected")
	}
	q := events.queue
	ctx = events.Configure(context.Background(), cfg)
	if q != events.queue {
		t.Fatal("same config discarded pending events")
	}
	fail.Store(false)
	work, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- probes.RunSession(work, cfg) }()
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	for {
		select {
		case e := <-received:
			if e.Event.Target == "registration" && e.Event.Previous == "down" && e.Event.Current == "up" {
				cancel()
				<-done
				cfg.Name = "replacement"
				events.Configure(context.Background(), cfg)
				if events.queue == q {
					t.Fatal("identity reused old queue")
				}
				return
			}
		case <-deadline.C:
			cancel()
			<-done
			t.Fatal("recovery missing")
		}
	}
}

func TestEventSupervisorAccountsForLateOutcomeBeforeOwnerStop(t *testing.T) {
	received := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received <- struct{}{}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	parent, cancel := context.WithCancel(context.Background())
	var events EventSupervisor
	events.Configure(parent, config.NodeConfig{Name: "robot", Controller: server.URL})
	defer events.Stop()
	cancel()
	// A durable install can finish just after parent cancellation. Its lifecycle
	// owner has not joined that producer yet, so delivery must still be alive.
	events.queue.Emit(history.Event{Kind: "certificate", Source: "node-pki", Target: "renew", Current: "installed", Severity: "info", Validity: "observed"})
	select {
	case <-received:
	case <-events.done:
		t.Fatal("delivery stopped before producer joined")
	case <-time.After(time.Second):
		t.Fatal("late outcome lost before owner stop")
	}
}

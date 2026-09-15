package agent

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/stun/v3"
	"vpnctl/internal/api"
	"vpnctl/internal/config"
)

func TestRunContinuesAfterSTUN(t *testing.T) {
	for _, reply := range []bool{true, false} {
		name := "unresponsive"
		if reply {
			name = "success"
		}
		t.Run(name, func(t *testing.T) {
			stunServer, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
			if err != nil {
				t.Fatal(err)
			}
			defer stunServer.Close()
			firstProbe := make(chan time.Time, 1)
			readerDone := make(chan struct{})
			go func() {
				defer close(readerDone)
				buf := make([]byte, 2048)
				for {
					n, remote, err := stunServer.ReadFromUDP(buf)
					if err != nil {
						return
					}
					select {
					case firstProbe <- time.Now():
					default:
					}
					if !reply {
						continue
					}
					msg := &stun.Message{Raw: buf[:n]}
					if msg.Decode() != nil {
						continue
					}
					response := stun.MustBuild(stun.NewTransactionIDSetter(msg.TransactionID), stun.BindingSuccess, &stun.XORMappedAddress{IP: remote.IP, Port: remote.Port})
					stunServer.WriteToUDP(response.Raw, remote)
				}
			}()
			defer func() { stunServer.Close(); <-readerDone }()
			var lastRegister atomic.Int64
			var natReports atomic.Int64
			ctrl := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/register":
					lastRegister.Store(time.Now().UnixNano())
					json.NewEncoder(w).Encode(api.RegisterResponse{NodeID: "test-node", VPNIP: "10.7.0.2/32"})
				case "/nat-probe":
					natReports.Add(1)
					w.WriteHeader(http.StatusNoContent)
				case "/candidates":
					json.NewEncoder(w).Encode(api.CandidatesResponse{})
				default:
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer ctrl.Close()
			portReservation, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
			if err != nil {
				t.Fatal(err)
			}
			port := portReservation.LocalAddr().(*net.UDPAddr).Port
			portReservation.Close()
			cfg := config.NodeConfig{Name: "test-node", Controller: ctrl.URL, DirectMode: "auto", ProbePort: port,
				KeepaliveIntervalSec: 1, STUNIntervalSec: 1, CandidatesIntervalSec: 1, DirectIntervalSec: 60,
				STUNServers: []string{stunServer.LocalAddr().String()}, ServerPublicKey: "unused", ServerEndpoint: "127.0.0.1:51820", ServerAllowedIPs: []string{"10.7.0.0/24"}}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- Run(ctx, cfg) }()
			var sent time.Time
			select {
			case sent = <-firstProbe:
			case err := <-done:
				t.Fatalf("agent stopped before STUN: %v", err)
			case <-time.After(3 * time.Second):
				t.Fatal("agent did not probe STUN")
			}
			deadline := time.Now().Add(7 * time.Second)
			completed := false
			for time.Now().Before(deadline) {
				if reply {
					completed = natReports.Load() >= 2 && lastRegister.Load() > sent.UnixNano()
				} else {
					// Run uses a 5s STUN budget. A later heartbeat proves control returned
					// to its owning select loop after the timeout.
					completed = lastRegister.Load() > sent.Add(5*time.Second).UnixNano()
				}
				if completed {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			cancel()
			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("agent shutdown: %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("agent stuck during STUN shutdown")
			}
			if !completed {
				t.Fatal("agent did not resume heartbeat/NAT reporting after STUN")
			}
		})
	}
}

package controller

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
	"vpnctl/internal/api"
	"vpnctl/internal/store"
	"vpnctl/internal/wireguard"

	"vpnctl/internal/config"
)

func TestStartupFailureClosesProbe(t *testing.T) {
	for i := 0; i < 5; i++ {
		port, err := net.ListenUDP("udp", &net.UDPAddr{})
		if err != nil {
			t.Fatal(err)
		}
		number := port.LocalAddr().(*net.UDPAddr).Port
		port.Close()
		dir := t.TempDir()
		lock, err := AcquireStateLock(dir)
		if err != nil {
			t.Fatal(err)
		}
		s, err := NewServer(config.ControllerConfig{DataDir: dir, VPNCIDR: "10.7.0.0/24", WGAddress: "10.7.0.1/24", Listen: "invalid-listen-address", ProbePort: number})
		if err != nil {
			lock.Close()
			t.Fatal(err)
		}
		if err := s.ListenAndServe(); err == nil {
			t.Fatal("invalid listener succeeded")
		}
		probe, err := net.ListenUDP("udp", &net.UDPAddr{Port: number})
		s.StopProbeResponder()
		lock.Close()
		if err != nil {
			t.Fatalf("failed startup retained probe port: %v", err)
		}
		probe.Close()
	}
}

func TestAdminStartupFailureClosesProbe(t *testing.T) {
	for i := 0; i < 5; i++ {
		dir := t.TempDir()
		lock, err := AcquireStateLock(dir)
		if err != nil {
			t.Fatal(err)
		}
		conn, err := net.ListenUDP("udp", &net.UDPAddr{})
		if err != nil {
			t.Fatal(err)
		}
		port := conn.LocalAddr().(*net.UDPAddr).Port
		conn.Close()
		if err := os.WriteFile(api.AdminSocketPath(dir), []byte("not a socket"), 0600); err != nil {
			t.Fatal(err)
		}
		s, err := NewServer(config.ControllerConfig{DataDir: dir, VPNCIDR: "10.7.0.0/24", WGAddress: "10.7.0.1/24", Listen: "127.0.0.1:0", ProbePort: port})
		if err != nil {
			t.Fatal(err)
		}
		if err := s.ListenAndServe(); err == nil {
			t.Fatal("admin failure not returned")
		}
		lock.Close()
		conn, err = net.ListenUDP("udp", &net.UDPAddr{Port: port})
		if err != nil {
			t.Fatalf("probe leaked after admin startup failure: %v", err)
		}
		conn.Close()
	}
}

func TestShutdownRetainsOwnershipAfterGrace(t *testing.T) {
	dir := t.TempDir()
	lock, err := AcquireStateLock(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	entered := make(chan struct{}, 2)
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	services := make([]*managedHTTP, 2)
	clients := make(chan error, 2)
	for i := range services {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			entered <- struct{}{}
			<-release
			if err := os.WriteFile(filepath.Join(dir, fmt.Sprint(i)), []byte("committed"), 0600); err != nil {
				t.Error(err)
			}
			w.WriteHeader(http.StatusNoContent)
		})
		services[i] = startHTTP(&http.Server{Handler: handler}, listener, false)
		services[i].grace = 20 * time.Millisecond
		go func() {
			resp, err := http.Get("http://" + listener.Addr().String())
			if resp != nil {
				resp.Body.Close()
			}
			clients <- err
		}()
	}
	for i := 0; i < 2; i++ {
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("handler did not enter")
		}
	}
	stopped := make(chan struct{})
	go func() { stopHTTP(services...); lock.Close(); close(stopped) }()
	for i := 0; i < 2; i++ {
		select {
		case <-clients:
		case <-time.After(time.Second):
			t.Fatal("grace did not close client")
		}
	}
	select {
	case <-stopped:
		t.Fatal("owner released while mutation could still write")
	default:
	}
	if next, err := AcquireStateLock(dir); err == nil {
		next.Close()
		t.Fatal("second owner admitted during drain")
	}
	for _, s := range services {
		conn, err := net.DialTimeout("tcp", s.listener.Addr().String(), 50*time.Millisecond)
		if err == nil {
			conn.Close()
			t.Fatal("listener still accepts during drain")
		}
		for n := 0; n < 100; n++ {
			rec := httptest.NewRecorder()
			s.server.Handler.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
			if rec.Code != http.StatusServiceUnavailable {
				t.Fatal("request admitted after stop")
			}
		}
	}
	unblock()
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("shutdown did not finish after mutations")
	}
	for i := range services {
		data, err := os.ReadFile(filepath.Join(dir, fmt.Sprint(i)))
		if err != nil || string(data) != "committed" {
			t.Fatal("mutation lost", err)
		}
	}
	next, err := AcquireStateLock(dir)
	if err != nil {
		t.Fatal(err)
	}
	next.Close()
}

type timedWGRunner struct {
	state    string
	failNext bool
}

func (r *timedWGRunner) Run(name string, args ...string) error {
	return r.RunContext(context.Background(), name, args...)
}
func (r *timedWGRunner) Output(name string, args ...string) (string, error) {
	return r.OutputContext(context.Background(), name, args...)
}
func (r *timedWGRunner) OutputContext(ctx context.Context, name string, args ...string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if name == "wg" {
		return r.state, nil
	}
	return "", nil
}
func (r *timedWGRunner) RunContext(ctx context.Context, name string, args ...string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if name != "wg" {
		return nil
	}
	data, err := os.ReadFile(args[len(args)-1])
	if err != nil {
		return err
	}
	r.state = string(data) // simulate a partially applied command before timeout
	if r.failNext {
		r.failNext = false
		timer, cancel := context.WithTimeout(ctx, 30*time.Millisecond)
		defer cancel()
		<-timer.Done()
		return timer.Err()
	}
	return nil
}

func TestCommandTimeoutRollsBackAndNextMutationSucceeds(t *testing.T) {
	s, err := NewServer(config.ControllerConfig{DataDir: t.TempDir(), VPNCIDR: "10.7.0.0/24", WGAddress: "10.7.0.1/24", WGInterface: "test-wg", WGPrivateKey: "test-private", WGApply: true})
	if err != nil {
		t.Fatal(err)
	}
	runner := &timedWGRunner{}
	s.wg = wireguard.NewManager(runner)
	if _, err := s.registerNode(nodeRegistration{Name: "a", PubKey: "pub-a"}, true); err != nil {
		t.Fatal(err)
	}
	before := runner.state
	runner.failNext = true
	if _, err := s.registerNode(nodeRegistration{Name: "b", PubKey: "pub-b"}, true); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deadline lost: %v", err)
	}
	if runner.state != before || len(s.reg.Nodes) != 1 {
		t.Fatal("timeout failed to rollback live state")
	}
	disk, err := store.LoadRegistry(s.regPath)
	if err != nil || len(disk.Nodes) != 1 {
		t.Fatal("timeout changed durable registry", err)
	}
	if _, err := s.registerNode(nodeRegistration{Name: "b", PubKey: "pub-b"}, true); err != nil {
		t.Fatal("subsequent mutation failed", err)
	}
	if len(s.reg.Nodes) != 2 || runner.state == before {
		t.Fatal("subsequent mutation was not applied")
	}
}

type blockingMutationRunner struct {
	timedWGRunner
	entered, release chan struct{}
	blocked          bool
}

func (r *blockingMutationRunner) RunContext(ctx context.Context, name string, args ...string) error {
	if name == "wg" && !r.blocked {
		r.blocked = true
		close(r.entered)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-r.release:
		}
	}
	return r.timedWGRunner.RunContext(ctx, name, args...)
}
func TestClientCancellationDoesNotCancelAdmittedMutation(t *testing.T) {
	s, err := NewServer(config.ControllerConfig{DataDir: t.TempDir(), VPNCIDR: "10.7.0.0/24", WGAddress: "10.7.0.1/24", WGInterface: "test-wg", WGPrivateKey: "test-private", WGApply: true})
	if err != nil {
		t.Fatal(err)
	}
	runner := &blockingMutationRunner{entered: make(chan struct{}), release: make(chan struct{})}
	var once sync.Once
	release := func() { once.Do(func() { close(runner.release) }) }
	defer release()
	s.wg = wireguard.NewManager(runner)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(`{"name":"a","pub_key":"pub-a"}`)).WithContext(ctx)
	rec := httptest.NewRecorder()
	done := make(chan struct{})
	go func() { defer close(done); s.httpHandler().ServeHTTP(rec, req) }()
	select {
	case <-runner.entered:
	case <-time.After(time.Second):
		t.Fatal("mutation not admitted")
	}
	cancel()
	release()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("mutation did not finish")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("client cancellation changed mutation result: %d %s", rec.Code, rec.Body.String())
	}
	reg, err := store.LoadRegistry(s.regPath)
	if err != nil || len(reg.Nodes) != 1 || len(s.reg.Nodes) != 1 || !strings.Contains(runner.state, "pub-a") {
		t.Fatal("admitted mutation lost consistency", err)
	}
}

func TestShutdownClosesSlowClients(t *testing.T) {
	for _, body := range []bool{false, true} {
		t.Run(fmt.Sprintf("body_%v", body), func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			entered := make(chan struct{})
			service := startHTTP(&http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { close(entered); _, _ = io.Copy(io.Discard, r.Body) })}, listener, false)
			service.grace = 20 * time.Millisecond
			defer service.stop()
			conn, err := net.Dial("tcp", listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			payload := "POST / HTTP/1.1\r\nHost: test\r\n"
			if body {
				payload += "Content-Length: 100\r\n\r\nx"
			}
			if _, err := io.WriteString(conn, payload); err != nil {
				t.Fatal(err)
			}
			if body {
				select {
				case <-entered:
				case <-time.After(time.Second):
					t.Fatal("body reader did not enter")
				}
			}
			done := make(chan struct{})
			go func() { service.stop(); close(done) }()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("slow client retained controller")
			}
			_ = conn.SetReadDeadline(time.Now().Add(time.Second))
			var b [1]byte
			if _, err := conn.Read(b[:]); err == nil {
				t.Fatal("slow client connection still open")
			}
		})
	}
}

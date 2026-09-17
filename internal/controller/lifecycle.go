package controller

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"
)

const shutdownGrace = 10 * time.Second

// requestGate stops admission before waiting, so Wait cannot race a new Add.
// Closing HTTP connections alone does not prove that mutations have stopped.
type requestGate struct {
	mu     sync.Mutex
	closed bool
	active sync.WaitGroup
}

func (g *requestGate) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		g.mu.Lock()
		if g.closed {
			g.mu.Unlock()
			http.Error(w, "controller shutting down", http.StatusServiceUnavailable)
			return
		}
		g.active.Add(1)
		g.mu.Unlock()
		defer g.active.Done()
		next.ServeHTTP(w, r)
	})
}
func (g *requestGate) close() { g.mu.Lock(); g.closed = true; g.mu.Unlock() }

type managedHTTP struct {
	server   *http.Server
	listener net.Listener
	gate     requestGate
	done     chan struct{}
	err      error
	stopOnce sync.Once
	grace    time.Duration
}

func startHTTP(server *http.Server, listener net.Listener, tlsEnabled bool) *managedHTTP {
	s := &managedHTTP{server: server, listener: listener, done: make(chan struct{}), grace: shutdownGrace}
	server.Handler = s.gate.wrap(server.Handler)
	go func() {
		defer close(s.done)
		if tlsEnabled {
			s.err = server.ServeTLS(listener, "", "")
		} else {
			s.err = server.Serve(listener)
		}
	}()
	return s
}

func (s *managedHTTP) stopAccepting() {
	s.gate.close()
	s.server.SetKeepAlivesEnabled(false)
	_ = s.listener.Close()
}

func (s *managedHTTP) stop() {
	s.stopOnce.Do(func() {
		s.stopAccepting()
		ctx, cancel := context.WithTimeout(context.Background(), s.grace)
		defer cancel()
		if err := s.server.Shutdown(ctx); err != nil {
			slog.Warn("controller shutdown grace elapsed; retaining state ownership until handlers finish")
			_ = s.server.Close()
		}
		// A handler may still be saving or rolling back after Close. Retain ownership.
		s.gate.active.Wait()
		<-s.done
	})
}

func stopHTTP(services ...*managedHTTP) {
	for _, s := range services {
		s.stopAccepting()
	}
	var done sync.WaitGroup
	for _, s := range services {
		done.Add(1)
		go func() { defer done.Done(); s.stop() }()
	}
	done.Wait()
}

func serveResult(ctx context.Context, service *managedHTTP) error {
	if ctx.Err() != nil && (errors.Is(service.err, http.ErrServerClosed) || errors.Is(service.err, net.ErrClosed)) {
		return nil
	}
	return service.err
}

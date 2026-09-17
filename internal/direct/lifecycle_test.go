package direct

import (
	"context"
	"errors"
	"fmt"
	"net"
	"runtime"
	"testing"
	"time"
)

func silentUDP(t *testing.T) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

func awaitProbe(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(time.Second):
		t.Fatal("probe did not finish within one second")
		return nil
	}
}

func TestSharedSTUNTimeoutReturns(t *testing.T) {
	server := silentUDP(t)
	shared, err := ListenShared("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer shared.Close()
	done := make(chan error, 1)
	go func() {
		_, err := shared.ProbeSTUN(context.Background(), server.LocalAddr().String(), 20*time.Millisecond)
		done <- err
	}()
	if err := awaitProbe(t, done); err == nil {
		t.Fatal("silent STUN server succeeded")
	}
}

func TestCompletedProbesReleaseResources(t *testing.T) {
	responder, err := StartResponder("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer responder.Close()
	baseline := runtime.NumGoroutine()
	for i := 0; i < 128; i++ {
		if _, err := ProbePeer(context.Background(), "127.0.0.1:0", responder.LocalAddr(), time.Second); err != nil {
			t.Fatal(err)
		}
		if _, _, err := PerfProbe(context.Background(), "127.0.0.1:0", responder.LocalAddr(), 64, 1, time.Second); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(time.Second)
	for runtime.NumGoroutine() > baseline+8 && time.Now().Before(deadline) {
		runtime.Gosched()
		time.Sleep(time.Millisecond)
	}
	if n := runtime.NumGoroutine(); n > baseline+8 {
		t.Fatalf("completed probes retained goroutines: before=%d after=%d", baseline, n)
	}
}

func TestStandaloneProbeCancellationAndTimeout(t *testing.T) {
	for _, kind := range []string{"peer", "perf"} {
		for _, mode := range []string{"cancel", "deadline", "probe-timeout"} {
			t.Run(kind+"/"+mode, func(t *testing.T) {
				server := silentUDP(t)
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				var expire context.CancelFunc
				if mode == "deadline" {
					ctx, expire = context.WithTimeout(ctx, 40*time.Millisecond)
					defer expire()
				}
				done := make(chan error, 1)
				timeout := time.Minute
				if mode == "probe-timeout" {
					timeout = 40 * time.Millisecond
				}
				go func() {
					var err error
					if kind == "peer" {
						_, err = ProbePeer(ctx, "127.0.0.1:0", server.LocalAddr().String(), timeout)
					} else {
						var loss float64
						_, loss, err = PerfProbe(ctx, "127.0.0.1:0", server.LocalAddr().String(), 64, 1, timeout)
						if mode == "probe-timeout" && err == nil && loss != 100 {
							err = fmt.Errorf("silent peer loss=%v", loss)
						}
					}
					done <- err
				}()
				readPacket(t, server)
				if mode == "cancel" {
					cancel()
				}
				err := awaitProbe(t, done)
				if mode == "cancel" && !errors.Is(err, context.Canceled) {
					t.Fatalf("cancel: %v", err)
				}
				if mode == "deadline" && !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("deadline: %v", err)
				}
				if mode == "probe-timeout" {
					if kind == "peer" && err == nil {
						t.Fatal("silent peer succeeded")
					}
					if kind == "perf" && err != nil {
						t.Fatalf("measurement timeout should return loss: %v", err)
					}
				}
			})
		}
	}
}

func TestProbeDNSCancellation(t *testing.T) {
	original := net.DefaultResolver
	defer func() { net.DefaultResolver = original }()
	started := make(chan struct{}, 16)
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		select {
		case started <- struct{}{}:
		default:
		}
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	for _, kind := range []string{"peer", "perf", "shared-peer", "stun"} {
		t.Run(kind, func(t *testing.T) {
			shared := newShared(t)
			done := make(chan error, 1)
			ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
			defer cancel()
			go func() {
				var err error
				switch kind {
				case "peer":
					_, err = ProbePeer(ctx, "127.0.0.1:0", "probe.invalid:1234", 0)
				case "perf":
					_, _, err = PerfProbe(ctx, "127.0.0.1:0", "probe.invalid:1234", 64, 1, 0)
				case "shared-peer":
					_, err = shared.ProbePeer(ctx, "probe.invalid:1234", 0)
				case "stun":
					_, err = shared.ProbeSTUN(ctx, "probe.invalid:1234", 0)
				}
				done <- err
			}()
			select {
			case <-started:
			case <-time.After(time.Second):
				t.Fatal("DNS was not attempted")
			}
			err := awaitProbe(t, done)
			if err == nil {
				t.Fatal("unresolved peer succeeded")
			}
		})
	}
}

func TestSharedCloseInterruptsDNS(t *testing.T) {
	original := net.DefaultResolver
	defer func() { net.DefaultResolver = original }()
	started := make(chan struct{}, 16)
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		select {
		case started <- struct{}{}:
		default:
		}
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	for _, kind := range []string{"peer", "stun"} {
		t.Run(kind, func(t *testing.T) {
			shared := newShared(t)
			done := make(chan error, 1)
			go func() {
				var err error
				if kind == "peer" {
					_, err = shared.ProbePeer(context.Background(), "close.invalid:1234", 0)
				} else {
					_, err = shared.ProbeSTUN(context.Background(), "close.invalid:1234", 0)
				}
				done <- err
			}()
			select {
			case <-started:
			case <-time.After(time.Second):
				t.Fatal("DNS was not attempted")
			}
			shared.Close()
			if err := awaitProbe(t, done); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("close during DNS: %v", err)
			}
		})
	}
}

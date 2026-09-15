package direct

import (
	"context"
	"errors"
	"net"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/stun/v3"
)

func newShared(t *testing.T) *Shared {
	t.Helper()
	s, err := ListenShared("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func readPacket(t *testing.T, conn *net.UDPConn) ([]byte, *net.UDPAddr) {
	t.Helper()
	conn.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 2048)
	n, addr, err := conn.ReadFromUDP(buf)
	if err != nil {
		t.Fatal(err)
	}
	return buf[:n], addr
}

func stunReply(t *testing.T, request []byte) []byte {
	t.Helper()
	msg := &stun.Message{Raw: request}
	if err := msg.Decode(); err != nil {
		t.Fatal(err)
	}
	reply := stun.MustBuild(stun.NewTransactionIDSetter(msg.TransactionID), stun.BindingSuccess, &stun.XORMappedAddress{IP: net.ParseIP("192.0.2.7"), Port: 54321})
	return reply.Raw
}

func TestSharedSTUNSuccessAndRetransmission(t *testing.T) {
	server := silentUDP(t)
	shared := newShared(t)
	for attempt := 0; attempt < 3; attempt++ {
		done := make(chan error, 1)
		go func() {
			mapped, err := shared.ProbeSTUN(context.Background(), "stun:"+server.LocalAddr().String(), 2*time.Second)
			if err == nil && mapped != "192.0.2.7:54321" {
				err = errors.New("wrong mapped address: " + mapped)
			}
			done <- err
		}()
		request, addr := readPacket(t, server)
		if attempt == 0 {
			retry, _ := readPacket(t, server)
			if string(retry) != string(request) {
				t.Fatal("retransmission changed transaction")
			}
		}
		server.WriteToUDP(stunReply(t, request), addr)
		if err := awaitProbe(t, done); err != nil {
			t.Fatal(err)
		}
		if _, err := ProbePeer(context.Background(), "127.0.0.1:0", shared.LocalAddr(), time.Second); err != nil {
			t.Fatalf("STUN closed shared socket: %v", err)
		}
	}
}

func TestSharedSTUNCancellationCloseAndMissingAttribute(t *testing.T) {
	for _, mode := range []string{"cancel", "close", "missing-mapped-address", "error-response"} {
		t.Run(mode, func(t *testing.T) {
			server := silentUDP(t)
			shared := newShared(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { _, err := shared.ProbeSTUN(ctx, server.LocalAddr().String(), 0); done <- err }()
			request, addr := readPacket(t, server)
			switch mode {
			case "cancel":
				cancel()
			case "close":
				shared.Close()
			default:
				msg := &stun.Message{Raw: request}
				if err := msg.Decode(); err != nil {
					t.Fatal(err)
				}
				typ := stun.BindingSuccess
				if mode == "error-response" {
					typ = stun.BindingError
				}
				// Even an error response carrying a mapped address must not succeed.
				var setters = []stun.Setter{stun.NewTransactionIDSetter(msg.TransactionID), typ}
				if mode == "error-response" {
					setters = append(setters, &stun.XORMappedAddress{IP: net.ParseIP("192.0.2.7"), Port: 54321})
				}
				server.WriteToUDP(stun.MustBuild(setters...).Raw, addr)
			}
			err := awaitProbe(t, done)
			if err == nil {
				t.Fatal("expected failure")
			}
			if mode == "cancel" && !errors.Is(err, context.Canceled) {
				t.Fatalf("cancel: %v", err)
			}
			if mode == "close" && !errors.Is(err, net.ErrClosed) {
				t.Fatalf("close: %v", err)
			}
		})
	}
}

func TestSharedRejectsForgedAcks(t *testing.T) {
	server, attacker := silentUDP(t), silentUDP(t)
	shared := newShared(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := shared.ProbePeer(ctx, server.LocalAddr().String(), time.Second); done <- err }()
	request, addr := readPacket(t, server)
	ack := []byte(ackPrefix + strings.TrimPrefix(string(request), probePrefix))
	for i := 0; i < 100; i++ {
		attacker.WriteToUDP(ack, addr)
	}
	select {
	case err := <-done:
		t.Fatalf("wrong sender completed probe: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	server.WriteToUDP(ack, addr)
	if err := awaitProbe(t, done); err != nil {
		t.Fatal(err)
	}
}

func TestSharedSTUNInvalidTrafficDoesNotBlockDirect(t *testing.T) {
	server, attacker := silentUDP(t), silentUDP(t)
	shared := newShared(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := shared.ProbeSTUN(ctx, server.LocalAddr().String(), time.Second); done <- err }()
	request, addr := readPacket(t, server)
	valid := stunReply(t, request)
	wrongID := append([]byte(nil), valid...)
	wrongID[8] ^= 1
	malformed := append([]byte(nil), valid...)
	malformed[2], malformed[3] = 0xff, 0xff
	for i := 0; i < 100; i++ {
		attacker.WriteToUDP(valid, addr)
		server.WriteToUDP(wrongID, addr)
		server.WriteToUDP(malformed, addr)
	}
	select {
	case err := <-done:
		t.Fatalf("invalid traffic completed STUN: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	if _, err := ProbePeer(context.Background(), "127.0.0.1:0", shared.LocalAddr(), 500*time.Millisecond); err != nil {
		t.Fatalf("STUN blocked direct responder: %v", err)
	}
	server.WriteToUDP(valid, addr)
	if err := awaitProbe(t, done); err != nil {
		t.Fatal(err)
	}
}

func TestSharedConcurrentCancelAndClose(t *testing.T) {
	for _, size := range []int{1, 3, 8, 32, 64} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			server := silentUDP(t)
			shared := newShared(t)
			done := make(chan error, size)
			cancellations := make([]context.CancelFunc, size)
			for i := 0; i < size; i++ {
				ctx, cancel := context.WithCancel(context.Background())
				cancellations[i] = cancel
				defer cancel()
				go func() { _, err := shared.ProbePeer(ctx, server.LocalAddr().String(), 0); done <- err }()
			}
			for i := 0; i < size; i++ {
				readPacket(t, server)
			}
			for i := 0; i < size; i += 2 {
				cancellations[i]()
			}
			shared.Close()
			for i := 0; i < size; i++ {
				err := awaitProbe(t, done)
				if !errors.Is(err, context.Canceled) && !errors.Is(err, net.ErrClosed) {
					t.Fatalf("pending request: %v", err)
				}
			}
			shared.mu.Lock()
			remaining := len(shared.pending)
			shared.mu.Unlock()
			if remaining != 0 {
				t.Fatalf("retained %d pending requests", remaining)
			}
		})
	}
}

func TestSharedConcurrentSuccessWithSTUN(t *testing.T) {
	responder, err := StartResponder("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer responder.Close()
	shared := newShared(t)
	server := silentUDP(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stunDone := make(chan error, 1)
	go func() { _, err := shared.ProbeSTUN(ctx, server.LocalAddr().String(), 0); stunDone <- err }()
	readPacket(t, server)
	done := make(chan error, 64)
	for i := 0; i < 64; i++ {
		go func() {
			_, err := shared.ProbePeer(context.Background(), responder.LocalAddr(), time.Second)
			done <- err
		}()
	}
	for i := 0; i < 64; i++ {
		if err := awaitProbe(t, done); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := shared.ProbeSTUN(ctx, server.LocalAddr().String(), time.Second); err == nil {
		t.Fatal("overlapping STUN accepted")
	}
	cancel()
	if err := awaitProbe(t, stunDone); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestSharedSTUNRepeatedCleanup(t *testing.T) {
	shared := newShared(t)
	server := silentUDP(t)
	baseline := runtime.NumGoroutine()
	for i := 0; i < 50; i++ {
		if _, err := shared.ProbeSTUN(context.Background(), server.LocalAddr().String(), time.Millisecond); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("timeout %d: %v", i, err)
		}
	}
	deadline := time.Now().Add(time.Second)
	for runtime.NumGoroutine() > baseline+8 && time.Now().Before(deadline) {
		runtime.Gosched()
		time.Sleep(time.Millisecond)
	}
	if n := runtime.NumGoroutine(); n > baseline+8 {
		t.Fatalf("STUN retained goroutines: before=%d after=%d", baseline, n)
	}
	shared.mu.Lock()
	defer shared.mu.Unlock()
	if shared.stunConn != nil {
		t.Fatal("STUN slot retained")
	}
}

func TestSharedWriteCancellationDoesNotPoisonNextRequest(t *testing.T) {
	shared := newShared(t)
	responder, err := StartResponder("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer responder.Close()
	var wg sync.WaitGroup
	var successes atomic.Int64
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			if _, err := shared.ProbePeer(ctx, responder.LocalAddr(), time.Second); !errors.Is(err, context.Canceled) {
				return
			}
			if _, err := shared.ProbePeer(context.Background(), responder.LocalAddr(), time.Second); err == nil {
				successes.Add(1)
			}
		}()
	}
	wg.Wait()
	if n := successes.Load(); n != 64 {
		t.Fatalf("only %d requests recovered after cancellation", n)
	}
}

func TestSharedSTUNSlowConsumerDoesNotBlockReader(t *testing.T) {
	shared := newShared(t)
	server := silentUDP(t)
	request := stun.MustBuild(stun.TransactionID, stun.BindingRequest)
	adapter := &stunConn{shared: shared, ctx: context.Background(), remote: server.LocalAddr().(*net.UDPAddr), transaction: request.TransactionID, packets: make(chan []byte, 1), closed: make(chan struct{})}
	shared.mu.Lock()
	shared.stunConn = adapter
	shared.mu.Unlock()
	defer adapter.Close()
	remote := shared.conn.LocalAddr().(*net.UDPAddr)
	reply := stunReply(t, request.Raw)
	for i := 0; i < 1000; i++ {
		server.WriteToUDP(reply, remote)
	}
	if _, err := ProbePeer(context.Background(), "127.0.0.1:0", shared.LocalAddr(), time.Second); err != nil {
		t.Fatalf("slow STUN consumer blocked direct traffic: %v", err)
	}
	if n := len(adapter.packets); n != 1 {
		t.Fatalf("bounded STUN queue has %d packets", n)
	}
}

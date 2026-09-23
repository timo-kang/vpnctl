package observation

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"vpnctl/internal/history"
)

func fixture() history.Observation {
	return history.Observation{PeerID: "peer", Path: "direct", Source: "agent-direct", Validity: "unknown", Reason: "collector_unavailable"}
}
func TestRetryPreservesPayloadAndDeduplicatesCommittedResponseLoss(t *testing.T) {
	store, err := history.Open(t.TempDir()+"/history.db", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	q := New()
	q.Emit(fixture())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var first history.Observation
	calls := 0
	q.Run(ctx, func(ctx context.Context, e history.Observation) (bool, error) {
		calls++
		if calls == 1 {
			first = e
		} else if !reflect.DeepEqual(first, e) {
			t.Fatal("retry mutated payload")
		}
		if err := store.Ingest(ctx, "robot", []history.Observation{e}, time.Now()); err != nil {
			t.Fatal(err)
		}
		if calls == 1 {
			return true, errors.New("response lost after commit")
		}
		cancel()
		return false, nil
	})
	out, err := store.Query(context.Background(), "robot", time.Now(), time.Hour, time.Hour)
	if err != nil || len(out) != 1 || out[0].UnknownCount != 1 || out[0].Count != 0 || calls != 2 {
		t.Fatalf("calls=%d history=%+v err=%v", calls, out, err)
	}
}
func TestQueueOverflowCancellationAndRestartIdentity(t *testing.T) {
	q := New()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				q.Emit(fixture())
			}
		}()
	}
	wg.Wait()
	if len(q.pending) != Capacity || q.dropped.Load() != 800-Capacity {
		t.Fatalf("pending=%d dropped=%d", len(q.pending), q.dropped.Load())
	}
	first := q.pending[0].e
	ctx, cancel := context.WithCancel(context.Background())
	started, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		q.Run(ctx, func(ctx context.Context, e history.Observation) (bool, error) {
			close(started)
			<-ctx.Done()
			return true, ctx.Err()
		})
	}()
	<-started
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("shutdown blocked")
	}
	if !q.closed || len(q.pending) != 0 || q.dropped.Load() != 800 {
		t.Fatalf("shutdown dropped=%d pending=%d", q.dropped.Load(), len(q.pending))
	}
	q.Emit(fixture())
	if q.dropped.Load() != 801 {
		t.Fatal("post-stop producer not accounted")
	}
	restarted := New()
	restarted.Emit(fixture())
	if next := restarted.pending[0].e; next.ID == first.ID {
		t.Fatal("restart reused ID")
	}
}
func TestFiniteRetriesAndPermanentRejection(t *testing.T) {
	t.Parallel()
	for _, retry := range []bool{false, true} {
		synctest.Test(t, func(t *testing.T) {
			q := New()
			q.Emit(fixture())
			calls := 0
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			go q.Run(ctx, func(context.Context, history.Observation) (bool, error) {
				calls++
				return retry, errors.New("unavailable")
			})
			time.Sleep(16 * time.Second)
			cancel()
			synctest.Wait()
			want := 1
			if retry {
				want = Attempts
			}
			if calls != want || q.dropped.Load() != 1 {
				t.Fatalf("calls=%d dropped=%d", calls, q.dropped.Load())
			}
		})
	}
}

func TestQueueDetachesCallerPointersAndPreservesObservationTime(t *testing.T) {
	q := New()
	success, ms := true, 12.0
	at := time.Now().Add(-time.Hour).UTC().Truncate(time.Microsecond)
	q.Emit(history.Observation{Timestamp: at, PeerID: "peer", Path: "direct", Source: "agent-direct", Success: &success, RTTMs: &ms})
	success = false
	ms = 999
	o := q.pending[0].e
	if o.Success == nil || !*o.Success || *o.RTTMs != 12 || !o.Timestamp.Equal(at) || len(o.ID) != 22 || o.Validity != "observed" {
		t.Fatal(o)
	}
}

func TestBackoffDoesNotDelayReadyPeerOrMutateRetry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		q := New()
		bad, good := fixture(), fixture()
		bad.PeerID, good.PeerID = "unavailable", "healthy"
		q.Emit(bad)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		order := make(chan history.Observation, 3)
		calls := 0
		start := time.Now()
		go q.Run(ctx, func(_ context.Context, e history.Observation) (bool, error) {
			order <- e
			calls++
			if e.PeerID == "healthy" && time.Since(start) != 0 {
				t.Error("ready peer waited through backoff")
			}
			if calls == 3 {
				cancel()
				return false, nil
			}
			if e.PeerID == "unavailable" {
				return true, errors.New("temporary")
			}
			return false, nil
		})
		synctest.Wait()
		// Wake a worker that is already sleeping for the failed peer's retry.
		q.Emit(good)
		synctest.Wait()
		if len(order) != 2 {
			t.Fatal("ready peer blocked", len(order))
		}
		first, second := <-order, <-order
		if second.PeerID != "healthy" {
			t.Fatal("wrong order", first, second)
		}
		time.Sleep(time.Second)
		synctest.Wait()
		if len(order) != 1 {
			t.Fatal("retry lost", len(order))
		}
		if retry := <-order; !reflect.DeepEqual(first, retry) {
			t.Fatal("retry mutated", first, retry)
		}
	})
}

func TestPendingRetriesAndInflightShareCapacity(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		q := New()
		for i := 0; i < Capacity; i++ {
			o := fixture()
			o.PeerID = fmt.Sprint(i)
			q.Emit(o)
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		calls := 0
		go q.Run(ctx, func(work context.Context, _ history.Observation) (bool, error) {
			calls++
			if calls == Capacity {
				<-work.Done() // one in flight, Capacity-1 waiting for retry
			}
			return true, errors.New("temporary")
		})
		synctest.Wait()
		if calls != Capacity {
			t.Fatal("initial work blocked on retry", calls)
		}
		for i := 0; i < 800; i++ {
			o := fixture()
			o.PeerID = fmt.Sprint(i + Capacity)
			q.Emit(o)
		}
		if q.dropped.Load() != 800 {
			t.Fatal("in-flight/retry work escaped capacity", q.dropped.Load())
		}
		cancel()
		synctest.Wait()
		if q.dropped.Load() != 800+Capacity || q.outstanding != 0 || len(q.pending) != 0 {
			t.Fatal("shutdown failed to account for every event", q.dropped.Load(), q.outstanding)
		}
	})
}

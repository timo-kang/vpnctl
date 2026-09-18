package diagnostic

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"vpnctl/internal/history"
)

func fixture() history.Event {
	return history.Event{Kind: "certificate", Source: "test", Current: "renew:success", Severity: "info", Validity: "observed"}
}
func TestRetryPreservesPayloadAndDeduplicatesCommittedResponseLoss(t *testing.T) {
	store, err := history.Open(t.TempDir()+"/history.db", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	q := New("node", "robot")
	q.Emit(fixture())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var first history.Event
	calls := 0
	q.Run(ctx, func(ctx context.Context, e history.Event) (bool, error) {
		calls++
		if calls == 1 {
			first = e
		} else if !reflect.DeepEqual(first, e) {
			t.Fatal("retry mutated payload")
		}
		if err := store.IngestEvent(ctx, "robot", e, time.Now()); err != nil {
			t.Fatal(err)
		}
		if calls == 1 {
			return true, errors.New("response lost after commit")
		}
		cancel()
		return false, nil
	})
	out, err := store.QueryEvents(context.Background(), "robot", time.Now(), time.Hour, 10)
	if err != nil || len(out.Events) != 1 || calls != 2 {
		t.Fatalf("calls=%d events=%+v err=%v", calls, out, err)
	}
}
func TestQueueOverflowCancellationAndRestartIdentity(t *testing.T) {
	q := New("node", "robot")
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
	first := <-q.pending
	q.Emit(fixture())
	ctx, cancel := context.WithCancel(context.Background())
	started, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		q.Run(ctx, func(ctx context.Context, e history.Event) (bool, error) {
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
	restarted := New("node", "robot")
	restarted.Emit(fixture())
	if next := <-restarted.pending; next.ID == first.ID {
		t.Fatal("restart reused ID")
	}
}
func TestFiniteRetriesAndPermanentRejection(t *testing.T) {
	t.Parallel()
	for _, retry := range []bool{false, true} {
		q := New("node", "robot")
		q.Emit(fixture())
		calls := 0
		q.deliver(context.Background(), <-q.pending, func(context.Context, history.Event) (bool, error) { calls++; return retry, errors.New("unavailable") })
		want := 1
		if retry {
			want = Attempts
		}
		if calls != want || q.dropped.Load() != 1 {
			t.Fatalf("calls=%d dropped=%d", calls, q.dropped.Load())
		}
	}
}
func TestTransitionStateSurvivesRetriesButRestartsAsBaseline(t *testing.T) {
	q := New("node", "robot")
	e := fixture()
	e.Current = "down"
	q.Observe("sync", e)
	q.Observe("sync", e)
	e.Current = "up"
	q.Observe("sync", e)
	a, b := <-q.pending, <-q.pending
	if len(q.pending) != 0 || a.Previous != "" || b.Previous != "down" || b.Current != "up" {
		t.Fatal(a, b)
	}
	q2 := New("node", "robot")
	q2.Observe("sync", e)
	if (<-q2.pending).Previous != "" {
		t.Fatal("restart invented prior state")
	}
}

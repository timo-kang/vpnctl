package direct

import (
	"context"
	"testing"
	"time"
)

func TestProbePeer_RoundTrip(t *testing.T) {
	t.Parallel()

	resp, err := StartResponder(":0")
	if err != nil {
		t.Fatalf("StartResponder: %v", err)
	}
	defer resp.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	rtt, err := ProbePeer(ctx, ":0", resp.LocalAddr(), 2*time.Second)
	if err != nil {
		t.Fatalf("ProbePeer: %v", err)
	}
	if rtt <= 0 {
		t.Fatalf("rtt=%s", rtt)
	}
}

func TestPerfProbe_RoundTrip(t *testing.T) {
	t.Parallel()

	resp, err := StartResponder(":0")
	if err != nil {
		t.Fatalf("StartResponder: %v", err)
	}
	defer resp.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	throughput, loss, err := PerfProbe(ctx, ":0", resp.LocalAddr(), 200, 50, 2*time.Second)
	if err != nil {
		t.Fatalf("PerfProbe: %v", err)
	}
	if loss != 0 {
		t.Fatalf("loss=%.2f", loss)
	}
	if throughput <= 0 {
		t.Fatalf("throughput=%.2f", throughput)
	}
}

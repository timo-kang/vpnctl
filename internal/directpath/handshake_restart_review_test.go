// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package directpath

import (
	"context"
	"testing"
)

// Transport can finish between the retry decision and the ordinary removal
// ownership readback. A ready peer visible in that last snapshot must survive.
type handshakeReadyOnRemovalSnapshot struct {
	*fakeKernel
	key       string
	snapshots int
}

func (k *handshakeReadyOnRemovalSnapshot) Snapshot(ctx context.Context) (snapshot, error) {
	k.snapshots++
	if k.snapshots == 2 {
		k.mu.Lock()
		p := k.s.Peers[k.key]
		p.Handshake, p.RX, p.TX = 10, 296, 776
		k.s.Peers[k.key] = p
		k.mu.Unlock()
	}
	return k.fakeKernel.Snapshot(ctx)
}
func TestHandshakeRestartPreservesReadyRemovalReadback(t *testing.T) {
	e, k, c := fixture(t)
	k.mode = "stage-silent"
	if err := e.add(context.Background(), []Candidate{c}); err != nil {
		t.Fatal(err)
	}
	observed := &handshakeReadyOnRemovalSnapshot{fakeKernel: k, key: c.Key}
	e.backend = observed
	restarted, err := e.restartStalled(context.Background(), []Candidate{c})
	if err != nil {
		t.Fatal(err)
	}
	if k.removes != 0 || restarted[c.ID] || k.s.Peers[c.Key].Handshake == 0 {
		t.Fatalf("latest removal snapshot proved transport ready, but it was reset: removes=%d restarted=%v handshake=%d snapshots=%d", k.removes, restarted[c.ID], k.s.Peers[c.Key].Handshake, observed.snapshots)
	}
}

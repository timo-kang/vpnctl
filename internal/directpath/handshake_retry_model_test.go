// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package directpath

import (
	"fmt"
	"os"
	"sort"
	"testing"
	"time"
)

// This diagnostic model follows the Linux WireGuard control flow in noise.c,
// send.c and timers.c; it does not implement cryptography or establish the VM
// failure's cause. Two crossed initiations consume each other's initiation
// state, and each response updates the rate-limit timestamp without moving the
// already-scheduled retransmit timer. A rate-limited one-shot timer is not
// rearmed. The relevant v6.1 (guest) and v6.8 timer/rate-limit/state transitions
// agree; their random-helper names and timer-deletion APIs differ. Sources:
// https://github.com/torvalds/linux/tree/v6.1/drivers/net/wireguard
// https://github.com/torvalds/linux/tree/v6.8/drivers/net/wireguard
// No host networking, wall clock, kernel state, or production code is changed.
type handshakeModelPeer struct {
	staged                                  bool
	completedAt                             time.Duration
	initiated, complete, queued             bool
	seq, nextSeq                            int
	lastSent, retryAt, keepaliveAt, nudgeAt time.Duration
	nudgeEvery                              time.Duration
	resetEvery, workerPhase                 time.Duration
	resets                                  int
	pulseEvery                              time.Duration
	rx, tx                                  uint64
	nudges                                  int
}
type handshakeModelEvent struct {
	at        time.Duration
	kind      string
	peer, seq int
}
type handshakeTimerModel struct {
	now, restore time.Duration
	peers        [2]handshakeModelPeer
	events       []handshakeModelEvent
	jitter       func(peer, seq int) time.Duration
	latency      func(kind string, peer, seq int) time.Duration
	resetLatency time.Duration
	workerPeriod time.Duration
}

func (m *handshakeTimerModel) schedule(at time.Duration, kind string, peer, seq int) {
	m.events = append(m.events, handshakeModelEvent{at, kind, peer, seq})
}
func (m *handshakeTimerModel) progress(peer int) {
	p := &m.peers[peer]
	if p.nudgeEvery > 0 && !p.complete {
		p.nudgeAt = m.now + p.nudgeEvery
		m.schedule(p.nudgeAt, "nudge", peer, 0)
	}
}
func (m *handshakeTimerModel) traverse(peer int) {
	p := &m.peers[peer]
	p.keepaliveAt = m.now + time.Second
	m.schedule(p.keepaliveAt, "keepalive", peer, 0)
}
func (m *handshakeTimerModel) sendInitiation(peer int) {
	p := &m.peers[peer]
	if !p.queued || p.complete || m.now-p.lastSent < 5*time.Second {
		return
	}
	p.lastSent = m.now
	p.seq++
	p.initiated = true
	p.tx += 148
	m.progress(peer)
	m.traverse(peer)
	jitter := 100 * time.Millisecond
	if p.seq >= 3 {
		jitter = 200 * time.Millisecond
	}
	if m.jitter != nil {
		jitter = m.jitter(peer, p.seq)
	}
	p.retryAt = m.now + 5*time.Second + jitter
	m.schedule(p.retryAt, "retry", peer, 0)
	delay := 50 * time.Millisecond
	if p.seq == 4 {
		delay = 250 * time.Millisecond
	}
	if m.latency != nil {
		delay = m.latency("init", peer, p.seq)
	}
	m.schedule(m.now+delay, "init", 1-peer, p.seq)
}
func (m *handshakeTimerModel) process(e handshakeModelEvent) {
	p := &m.peers[e.peer]
	switch e.kind {
	case "reset":
		if p.complete {
			return
		}
		p.resets++
		p.staged = false
		p.initiated = false
		p.nextSeq = 0
		p.retryAt = 0
		p.keepaliveAt = 0
		p.rx = 0
		p.tx = 0
		m.schedule(m.now+m.resetLatency, "stage", e.peer, 0)
	case "stage":
		p.staged = true
		p.queued = true
		p.lastSent = -time.Hour
		m.sendInitiation(e.peer)
		if p.pulseEvery > 0 {
			m.schedule(m.now+p.pulseEvery, "pulse", e.peer, 0)
		}
		if p.resetEvery > 0 {
			due := m.now + p.resetEvery
			if m.workerPeriod > 0 {
				elapsed := due - p.workerPhase
				due = p.workerPhase + (elapsed+m.workerPeriod-1)/m.workerPeriod*m.workerPeriod
			}
			m.schedule(due, "reset", e.peer, 0)
		}
	case "pulse":
		if p.complete {
			return
		}
		p.nudges++
		// The 0-to-1 transition allocates an empty packet, even after purge.
		// It still uses WireGuard's ordinary last-sent rate limit.
		p.queued = true
		m.sendInitiation(e.peer)
		m.schedule(m.now+p.pulseEvery, "pulse", e.peer, 0)
	case "retry":
		if e.at != p.retryAt {
			return
		}
		p.retryAt = 0
		m.sendInitiation(e.peer)
	case "keepalive":
		if e.at != p.keepaliveAt {
			return
		}
		p.keepaliveAt = 0
		if p.complete {
			return
		}
		// No current key: the staged empty packet remains queued. A rejected
		// initiation cannot restart this timer because no traversal occurred.
		m.sendInitiation(e.peer)
	case "nudge":
		if e.at != p.nudgeAt || p.complete {
			return
		}
		p.nudges++
		p.nudgeAt = 0
		// Reapplying persistent-keepalive=1 reaches send_staged_packets, but
		// does not allocate a new empty packet when the queue was purged.
		m.sendInitiation(e.peer)
		if p.nudgeAt == 0 {
			p.nudgeAt = m.now + time.Second
			m.schedule(p.nudgeAt, "nudge", e.peer, 0)
		}
	case "init":
		if !p.staged || m.now < m.restore {
			return
		}
		p.rx += 148
		p.initiated = false // consume-init, create-response, begin-session/zero
		p.nextSeq = e.seq
		p.lastSent = m.now
		p.tx += 92
		m.progress(e.peer)
		m.traverse(e.peer)
		delay := 50 * time.Millisecond
		if e.seq == 4 {
			delay = 250 * time.Millisecond
		}
		if m.latency != nil {
			delay = m.latency("response", e.peer, e.seq)
		}
		m.schedule(m.now+delay, "response", 1-e.peer, e.seq)
	case "response":
		if m.now < m.restore || !p.initiated || p.seq != e.seq {
			return
		}
		p.initiated = false
		p.complete = true
		p.completedAt = m.now
		p.queued = false
		p.retryAt = 0
		p.rx += 92
		p.tx += 32
		delay := 50 * time.Millisecond
		if m.latency != nil {
			delay = m.latency("confirm", e.peer, e.seq)
		}
		m.schedule(m.now+delay, "confirm", 1-e.peer, e.seq)
	case "confirm":
		if m.now < m.restore || p.nextSeq != e.seq {
			return
		}
		p.complete = true
		p.completedAt = m.now
		p.queued = false
		p.retryAt = 0
		p.rx += 32
	}
}
func (m *handshakeTimerModel) run(until time.Duration) {
	for len(m.events) > 0 {
		sort.SliceStable(m.events, func(i, j int) bool { return m.events[i].at < m.events[j].at })
		e := m.events[0]
		if e.at > until {
			break
		}
		m.events = m.events[1:]
		m.now = e.at
		m.process(e)
	}
	m.now = until
}
func collisionTimerFixture(nudge bool) *handshakeTimerModel {
	m := &handshakeTimerModel{restore: 6100 * time.Millisecond}
	for i := range m.peers {
		p := &m.peers[i]
		p.staged = true
		p.queued = true
		p.lastSent = -time.Hour
		if nudge {
			p.nudgeEvery = time.Duration(6+2*i) * time.Second
		}
		m.sendInitiation(i)
	}
	return m
}

func TestWireGuardCrossedResponseCanConsumeBothRetryTimers(t *testing.T) {
	m := collisionTimerFixture(false)
	m.run(30 * time.Second)
	for i, p := range m.peers {
		if p.complete || p.rx != 296 || p.tx != 776 || p.retryAt != 0 || p.keepaliveAt != 0 || !p.queued {
			t.Fatalf("peer%d did not reproduce the stalled control state: %+v", i, p)
		}
	}
}
func TestSixEightSecondProgressNudgeCannotEnsureFifteenSecondRestore(t *testing.T) {
	m := collisionTimerFixture(true)
	m.run(m.restore + 15*time.Second)
	for i, p := range m.peers {
		if p.complete || p.rx != 296 || p.tx != 776 || p.nudges != 0 {
			t.Fatalf("peer%d did not reproduce the late first nudge: %+v", i, p)
		}
	}
	m.run(22 * time.Second)
	for i, p := range m.peers {
		if !p.complete {
			t.Fatalf("queued-packet nudge did not eventually recover peer%d: %+v", i, p)
		}
	}
}
func TestIdenticalKeepaliveNudgeCannotRecreatePurgedPacket(t *testing.T) {
	m := &handshakeTimerModel{}
	for i := range m.peers {
		p := &m.peers[i]
		p.lastSent = -time.Hour
		p.nudgeEvery = time.Duration(6+2*i) * time.Second
		m.progress(i)
	}
	m.run(30 * time.Second)
	for i, p := range m.peers {
		if p.complete || p.tx != 0 || p.nudges == 0 {
			t.Fatalf("same-setting nudge invented queued data for peer%d: %+v", i, p)
		}
	}
}

func TestResidenceKeepalivePulseDoesNotBypassHandshakeRateLimit(t *testing.T) {
	m := collisionTimerFixture(false)
	for i := range m.peers {
		p := &m.peers[i]
		p.pulseEvery = time.Duration(6+2*i) * time.Second
		m.schedule(p.pulseEvery, "pulse", i, 0)
	}
	m.run(m.restore + 15*time.Second)
	for i, p := range m.peers {
		if p.complete || p.nudges == 0 {
			t.Fatalf("peer%d did not exercise the pulse rate-limit counterexample: %+v", i, p)
		}
		t.Logf("peer%d at restore+15s: rx=%d tx=%d pulses=%d lastSent=%s retry=%s", i, p.rx, p.tx, p.nudges, p.lastSent, p.retryAt)
	}
	m.run(120 * time.Second)
	t.Logf("at 120s: complete=%v/%v", m.peers[0].complete, m.peers[1].complete)
}

// These are design counterexamples, not a substitute for the Engine
// nonce/counter model or the VM gates. Each direction uses a legal native retry
// jitter and a bounded packet transit time. A failed case is evidence against
// claiming that the proposed wake policy guarantees the existing 15s gate.
func TestResidenceKeepalivePulseCadenceCounterexamples(t *testing.T) {
	cases := []struct {
		cadence [2]time.Duration
		jitter  [2]time.Duration
		restore time.Duration
	}{
		{[2]time.Duration{6 * time.Second, 8 * time.Second}, [2]time.Duration{20 * time.Millisecond, 20 * time.Millisecond}, 10500 * time.Millisecond},
		{[2]time.Duration{time.Second, 1500 * time.Millisecond}, [2]time.Duration{20 * time.Millisecond, 20 * time.Millisecond}, 0},
		{[2]time.Duration{time.Second, 1700 * time.Millisecond}, [2]time.Duration{100 * time.Millisecond, 20 * time.Millisecond}, 0},
		{[2]time.Duration{time.Second, 2 * time.Second}, [2]time.Duration{20 * time.Millisecond, 20 * time.Millisecond}, 0},
		{[2]time.Duration{time.Second, 1750 * time.Millisecond}, [2]time.Duration{100 * time.Millisecond, 100 * time.Millisecond}, 0},
	}
	for _, tc := range cases {
		t.Run(fmt.Sprintf("%s_%s", tc.cadence[0], tc.cadence[1]), func(t *testing.T) {
			m := &handshakeTimerModel{restore: tc.restore}
			m.jitter = func(peer, seq int) time.Duration { return tc.jitter[peer] }
			m.latency = func(kind string, peer, seq int) time.Duration { return 25 * time.Millisecond }
			for i := range m.peers {
				m.peers[i].pulseEvery = tc.cadence[i]
				m.schedule(0, "stage", i, 0)
			}
			m.run(tc.restore + 15*time.Second)
			if m.peers[0].complete && m.peers[1].complete {
				t.Fatal("counterexample no longer exposes the pulse/rate-limit interaction")
			}
			if m.peers[0].nudges == 0 || m.peers[1].nudges == 0 {
				t.Fatal("counterexample did not execute both proposed pulse cadences")
			}
		})
	}
}

// A reset applies only to a prefix-free peer without completed transport proof.
// Removal invalidates the native timers and pending handshake index; re-stage
// recreates the empty keepalive and permits a fresh, non-rate-limited initiation.
func TestStagedPeerRecreationPhaseSearch(t *testing.T) {
	skews := []time.Duration{-3 * time.Second, -2 * time.Second, 0, 500 * time.Millisecond, 3 * time.Second}
	latencies := []time.Duration{25 * time.Millisecond, 450 * time.Millisecond}
	jitters := []time.Duration{20 * time.Millisecond, 100 * time.Millisecond}
	if os.Getenv("VPNCTL_FULL_HANDSHAKE_MODEL") == "1" {
		skews = []time.Duration{-3 * time.Second, -2500 * time.Millisecond, -2 * time.Second, -1500 * time.Millisecond, -time.Second, -500 * time.Millisecond, 0, 500 * time.Millisecond, time.Second, 1500 * time.Millisecond, 2 * time.Second, 2500 * time.Millisecond, 3 * time.Second}
		latencies = []time.Duration{25 * time.Millisecond, 100 * time.Millisecond, 250 * time.Millisecond, 450 * time.Millisecond}
		jitters = []time.Duration{20 * time.Millisecond, 100 * time.Millisecond, 200 * time.Millisecond, 300 * time.Millisecond}
	}

	cases, missed := 0, 0
	var worst time.Duration
	var worstCase, example string
	for _, resetLatency := range []time.Duration{0, 100 * time.Millisecond} {
		for _, skew := range skews {
			for _, latency := range latencies {
				for _, jitter0 := range jitters {
					for _, jitter1 := range jitters {
						for _, restore := range handshakeRestorePhases(120 * time.Second) {
							m := &handshakeTimerModel{restore: restore, resetLatency: resetLatency, workerPeriod: time.Second}
							m.jitter = func(peer, seq int) time.Duration {
								if peer == 0 {
									return jitter0
								}
								return jitter1
							}
							m.latency = func(kind string, peer, seq int) time.Duration { return latency }
							stages := [2]time.Duration{max(0, -skew), max(0, skew)}
							for i := range m.peers {
								m.peers[i].resetEvery = handshakeRestartDelay(key(byte(3+i)), key(byte(4-i)))
								m.peers[i].workerPhase = stages[i]
								m.schedule(stages[i], "stage", i, 0)
							}
							m.run(restore + 15*time.Second)
							cases++
							desc := func() string {
								return fmt.Sprintf("stage skew=%s one-way=%s native jitters=%s/%s restore=%s reset latency=%s", skew, latency, jitter0, jitter1, restore, resetLatency)
							}
							if !m.peers[0].complete || !m.peers[1].complete {
								missed++
								if example == "" {
									example = desc()
								}
							} else {
								gap := max(m.peers[0].completedAt, m.peers[1].completedAt) - restore
								if gap > worst {
									worst = gap
									worstCase = desc()
								}
							}
						}
					}
				}
			}
		}
	}
	t.Logf("%d/%d miss restore+15s; worst completed gap=%s (%s); first miss=%s", missed, cases, worst, worstCase, example)
	if missed != 0 {
		t.Fatalf("staged recreation still misses the unchanged 15s handshake gate in %d cases", missed)
	}
	// Reserve the next 1s worker turn and two full 1s nonce requests. These are
	// a budget, not simulated application proofs: the separate Engine model
	// verifies actual route occupancy, counters, and two successful nonces.
	if worst+3*time.Second > 15*time.Second {
		t.Fatalf("handshake %s plus worker/two-proof budget 3s exceeds 15s: %s", worst, worstCase)
	}
	t.Logf("worst with next-worker/two-proof budget: %s", worst+3*time.Second)
}

// The exhaustive matrix is an opt-in design audit; fixed counterexamples and
// representative restore/phase boundaries remain in every ordinary test run.
// The 20/100/200/300ms jitters are multiples of both 4ms and 10ms kernel ticks.
func handshakeRestorePhases(maximum time.Duration) []time.Duration {
	if os.Getenv("VPNCTL_FULL_HANDSHAKE_MODEL") == "1" {
		phases := []time.Duration{}
		for at := time.Duration(0); at <= maximum; at += 500 * time.Millisecond {
			phases = append(phases, at)
		}
		return phases
	}
	phases := []time.Duration{}
	for _, at := range []time.Duration{0, 5500 * time.Millisecond, 6100 * time.Millisecond, 10500 * time.Millisecond, 12 * time.Second, 30 * time.Second, 60 * time.Second, 95 * time.Second, 120 * time.Second} {
		if at <= maximum {
			phases = append(phases, at)
		}
	}
	return phases
}

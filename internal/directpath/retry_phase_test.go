// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package directpath

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

// The real engines run on independent one-second workers in a synctest clock.
// Only the kernel and nonce transport are simulated. Context deadlines, probe
// duration, worker overruns and journal latency all consume virtual time.
// Route occupancy is measured at Add/Remove, not when Step finishes logging.
type retryPhaseModel struct {
	mu                sync.Mutex
	base              time.Time
	nodes             [2]*retryPhaseNode
	restoreAt         time.Duration
	handshakeDelay    time.Duration
	innerBlackhole    bool
	activeDuringFault bool
	maxGap            time.Duration
	activeAt          time.Duration
	transitions       []string
}

type retryPhaseNode struct {
	model      *retryPhaseModel
	engine     *Engine
	kernel     *fakeKernel
	candidate  Candidate
	index      int
	phase      time.Duration
	staged     time.Time
	installed  time.Time
	promotions int
	removed    time.Duration
	persisted  time.Duration
	state      string
}

func newRetryPhaseModel(t *testing.T, phase, removeA, removeB time.Duration) *retryPhaseModel {
	t.Helper()
	m := &retryPhaseModel{base: time.Now(), restoreAt: -1, activeAt: -1, handshakeDelay: 500 * time.Millisecond}
	for i := range m.nodes {
		e, k, c := fixture(t)
		e.cfg.WGPublicKey, c.Key = key(3), key(4)
		if i == 1 {
			e.cfg.WGPublicKey, e.cfg.VPNIP = key(4), "10.7.0.3/32"
			c.Key, c.Address, c.Endpoint = key(3), "10.7.0.2", "192.0.2.2:51820"
		}
		k.s.Identity.PublicKey = e.cfg.WGPublicKey
		e.j.Identity = k.s.Identity
		n := &retryPhaseNode{model: m, engine: e, kernel: k, candidate: c, index: i, staged: m.base, installed: m.base, state: "active"}
		n.removed = []time.Duration{removeA, removeB}[i]
		n.persisted = 20 * time.Millisecond
		if i == 1 {
			n.phase = phase
		}
		m.nodes[i] = n
		e.relayVerified = m.base
		// The fault starts with an already verified pair, as in the production
		// loss test. Retries and promotion run through Engine.Step itself.
		e.j.Peers[c.Key] = c
		k.saved = &e.j
		k.s.Peers[c.Key] = kernelPeer{Key: c.Key, Endpoint: c.Endpoint, Prefixes: []string{c.Address + "/32"}, Keepalive: c.Keepalive, Handshake: 1, RX: 100, TX: 100}
		e.successes[c.Key] = 2
		e.backend = n
		e.save = func(j journal) error {
			time.Sleep(n.persisted)
			m.mu.Lock()
			defer m.mu.Unlock()
			saved := j
			k.saved = &saved
			return nil
		}
	}
	return m
}

func (n *retryPhaseNode) Snapshot(ctx context.Context) (snapshot, error) {
	n.model.mu.Lock()
	defer n.model.mu.Unlock()
	n.model.updateHandshakes()
	return n.kernel.Snapshot(ctx)
}

// Stage creates a peer that can exchange authenticated WireGuard handshakes
// but owns no VPN destination. It never fabricates a nonce or application proof.
func (n *retryPhaseNode) Stage(_ context.Context, candidates []Candidate) error {
	n.model.mu.Lock()
	defer n.model.mu.Unlock()
	for _, c := range candidates {
		if n.kernel.saved == nil || n.kernel.saved.Peers[c.Key] != c {
			return errors.New("staging before durable intent")
		}
		n.kernel.s.Peers[c.Key] = kernelPeer{Key: c.Key, Endpoint: c.Endpoint, Keepalive: 1}
	}
	n.staged = time.Now()
	n.installed = time.Time{}
	n.model.transitions = append(n.model.transitions, fmt.Sprintf("n%d stage %s", n.index, time.Since(n.model.base)))
	return nil
}

func (n *retryPhaseNode) Add(ctx context.Context, candidates []Candidate) error {
	n.model.mu.Lock()
	defer n.model.mu.Unlock()
	prior := n.kernel.s.Peers[n.candidate.Key]
	if err := n.kernel.Add(ctx, candidates); err != nil {
		return err
	}
	// Updating AllowedIPs/keepalive on an existing WG peer preserves its
	// authenticated transport session and counters; remove/re-add would not.
	if prior.Key != "" {
		p := n.kernel.s.Peers[n.candidate.Key]
		p.Handshake, p.RX, p.TX = prior.Handshake, prior.RX, prior.TX
		n.kernel.s.Peers[n.candidate.Key] = p
	}
	if n.staged.IsZero() {
		n.staged = time.Now()
	}
	n.installed = time.Now()
	n.promotions++
	n.model.transitions = append(n.model.transitions, fmt.Sprintf("n%d add %s", n.index, time.Since(n.model.base)))
	return nil
}

func (n *retryPhaseNode) Remove(ctx context.Context, keys []string) error {
	time.Sleep(n.removed)
	n.model.mu.Lock()
	defer n.model.mu.Unlock()
	if err := n.kernel.Remove(ctx, keys); err != nil {
		return err
	}
	n.staged, n.installed = time.Time{}, time.Time{}
	n.model.transitions = append(n.model.transitions, fmt.Sprintf("n%d remove %s", n.index, time.Since(n.model.base)))
	return nil
}

func (n *retryPhaseNode) Probe(ctx context.Context, c Candidate) error {
	if c.Key == n.engine.cfg.ServerPublicKey {
		n.model.mu.Lock()
		defer n.model.mu.Unlock()
		return n.kernel.Probe(ctx, c)
	}
	// ProbeInterface sends one nonce datagram, then waits for that reply.
	// A request sent before the remote has its /32 is dropped; a later route
	// installation cannot rescue it without the next worker's fresh request.
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	n.model.mu.Lock()
	sent := n.model.directReady()
	n.model.mu.Unlock()
	if sent {
		timer := time.NewTimer(50 * time.Millisecond)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			n.model.mu.Lock()
			if n.model.directReady() {
				err := n.kernel.Probe(ctx, c)
				n.model.mu.Unlock()
				return err
			}
			n.model.mu.Unlock()
		}
	}
	<-ctx.Done()
	return ctx.Err()
}

// Call with m.mu held. WireGuard handshakes are independent of AllowedIPs and
// inner nonce reachability. They need both peer entries and a transport-ready
// interval, including after the underlay fault itself clears.
func (m *retryPhaseModel) transportReady() bool {
	readySince := m.base
	if !m.innerBlackhole {
		if m.restoreAt < 0 {
			return false
		}
		readySince = m.base.Add(m.restoreAt)
	}
	for _, n := range m.nodes {
		if n.staged.IsZero() {
			return false
		}
		if n.staged.After(readySince) {
			readySince = n.staged
		}
	}
	return time.Since(readySince) >= m.handshakeDelay
}

func (m *retryPhaseModel) updateHandshakes() {
	if !m.transportReady() {
		return
	}
	for _, n := range m.nodes {
		p := n.kernel.s.Peers[n.candidate.Key]
		if p.Handshake == 0 {
			p.Handshake = time.Now().Unix()
			// Empty authenticated keepalives consume WG transport bytes.
			// They do not satisfy the separate overlay nonce Probe.
			p.RX += 32
			p.TX += 32
			n.kernel.s.Peers[n.candidate.Key] = p
		}
	}
}

func (m *retryPhaseModel) directReady() bool {
	if m.restoreAt < 0 || time.Since(m.base) < m.restoreAt || !m.transportReady() {
		return false
	}
	m.updateHandshakes()
	for _, n := range m.nodes {
		if n.installed.IsZero() || n.kernel.s.Peers[n.candidate.Key].Handshake == 0 {
			return false
		}
	}
	return true
}

func retryPhaseWait(ctx context.Context, delay time.Duration) bool {
	// A due worker can run immediately; it does not need a zero-delay timer.
	// This also avoids Go 1.25.0 synctest's inline timer firing path under -race.
	if delay <= 0 {
		return ctx.Err() == nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return ctx.Err() == nil
	}
}

func (m *retryPhaseModel) run(t *testing.T, until time.Duration) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	var workers sync.WaitGroup
	errs := make(chan error, len(m.nodes))
	for _, n := range m.nodes {
		workers.Go(func() {
			if !retryPhaseWait(ctx, n.phase) {
				return
			}
			for {
				started := time.Now()
				work, stop := context.WithTimeout(ctx, 4*time.Second)
				status, err := n.engine.Step(work, []Candidate{n.candidate})
				stop()
				if ctx.Err() != nil {
					return
				}
				if err != nil || len(status) != 1 {
					errs <- fmt.Errorf("n%d Step: statuses=%v err=%v", n.index, status, err)
					return
				}
				m.mu.Lock()
				n.state = status[0].State
				if n.state == "active" && (m.restoreAt < 0 || time.Since(m.base) < m.restoreAt) {
					m.activeDuringFault = true
				}
				if m.nodes[0].state == "active" && m.nodes[1].state == "active" && m.directReady() && m.activeAt < 0 {
					m.activeAt = time.Since(m.base)
				}
				m.mu.Unlock()
				// Match runDataplaneWorker: pending verification gets another
				// opportunity before its fixed installation deadline.
				interval := time.Second
				if status[0].State == "probing" {
					interval = VerificationInterval
				}
				if !retryPhaseWait(ctx, time.Until(started.Add(interval))) {
					return
				}
			}
		})
	}
	lastReply := time.Duration(0)
	for elapsed := time.Duration(0); elapsed <= until; elapsed += 100 * time.Millisecond {
		time.Sleep(time.Until(m.base.Add(elapsed)))
		synctest.Wait()
		m.mu.Lock()
		m.maxGap = max(m.maxGap, elapsed-lastReply)
		// A one-sided direct host route can blackhole the return direction.
		// Relay round trips resume only when both host routes are removed.
		if (m.nodes[0].installed.IsZero() && m.nodes[1].installed.IsZero()) || m.directReady() {
			lastReply = elapsed
		}
		m.mu.Unlock()
	}
	cancel()
	workers.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
}

func TestRetryApplicationGapIncludesIndependentWorkerPhase(t *testing.T) {
	for _, inner := range []bool{false, true} {
		for _, phase := range []time.Duration{0, 854 * time.Millisecond, 1250 * time.Millisecond} {
			t.Run(fmt.Sprintf("inner_%t_phase_%s", inner, phase), func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					m := newRetryPhaseModel(t, phase, 20*time.Millisecond, 100*time.Millisecond)
					m.innerBlackhole = inner
					m.run(t, 35*time.Second)
					if m.maxGap > 5*time.Second {
						t.Fatalf("nonce reply gap %s exceeds 5s with worker phase %s; actual kernel changes: %v", m.maxGap, phase, m.transitions)
					}
					if m.activeDuringFault {
						t.Fatal("handshake without nonce success was reported active")
					}
					if inner && (m.nodes[0].promotions < 2 || m.nodes[1].promotions < 2) {
						t.Fatalf("inner blackhole did not exercise repeated route verification: promotions=%d/%d", m.nodes[0].promotions, m.nodes[1].promotions)
					}
				})
			})
		}
	}
}

func TestRetryWorkerPhasesStillReconnectAfterBlackhole(t *testing.T) {
	for _, handshakeDelay := range []time.Duration{500 * time.Millisecond, 5 * time.Second} {
		for _, inner := range []bool{false, true} {
			for phase := time.Duration(0); phase <= 3*time.Second; phase += 250 * time.Millisecond {
				for _, restoreAt := range []time.Duration{5 * time.Second, 15 * time.Second, 30 * time.Second, time.Minute} {
					t.Run(fmt.Sprintf("handshake_%s_inner_%t_phase_%s_restore_%s", handshakeDelay, inner, phase, restoreAt), func(t *testing.T) {
						synctest.Test(t, func(t *testing.T) {
							m := newRetryPhaseModel(t, phase, 20*time.Millisecond, 100*time.Millisecond)
							m.handshakeDelay = handshakeDelay
							m.innerBlackhole = inner
							m.restoreAt = restoreAt
							m.run(t, m.restoreAt+15*time.Second)
							if m.activeAt < m.restoreAt || m.activeAt-m.restoreAt > 15*time.Second {
								t.Fatalf("pair did not regain two consecutive direct proofs within 15s after fault cleared: states=%s/%s changes=%v", m.nodes[0].state, m.nodes[1].state, m.transitions)
							}
							if m.activeDuringFault {
								t.Fatal("path reported active while nonce traffic was blackholed")
							}
						})
					})
				}
			}
		}
	}
}

// retryWaveKernel separates the slow active probe from a new peer's nonce and
// records when route removal actually happens, before Step itself completes.
type retryWaveKernel struct {
	*fakeKernel
	slowKey   string
	slowDelay time.Duration
	silentKey string
	removedAt map[string]time.Time
}

func (k *retryWaveKernel) Probe(ctx context.Context, c Candidate) error {
	if c.Key == k.silentKey {
		<-ctx.Done()
		return ctx.Err()
	}
	if c.Key == k.slowKey && !retryPhaseWait(ctx, k.slowDelay) {
		return ctx.Err()
	}
	return k.fakeKernel.Probe(ctx, c)
}

func (k *retryWaveKernel) Remove(ctx context.Context, keys []string) error {
	if err := k.fakeKernel.Remove(ctx, keys); err != nil {
		return err
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	for _, key := range keys {
		k.removedAt[key] = time.Now()
	}
	return nil
}

func retryWaveFixture(t *testing.T) (*Engine, *retryWaveKernel, Candidate, Candidate) {
	t.Helper()
	e, kernel, active := fixture(t)
	for range 2 {
		if _, err := e.Step(context.Background(), []Candidate{active}); err != nil {
			t.Fatal(err)
		}
	}
	pending := active
	pending.ID, pending.Key, pending.Address = "pending", key(4), "10.7.0.4"
	if _, err := e.Step(context.Background(), []Candidate{active, pending}); err != nil {
		t.Fatal(err)
	}
	if e.successes[active.Key] != 2 || e.successes[pending.Key] != 1 {
		t.Fatal("fixture must have one active peer and one pending second proof")
	}
	k := &retryWaveKernel{fakeKernel: kernel, slowKey: active.Key, removedAt: map[string]time.Time{}}
	e.backend = k
	return e, k, active, pending
}

func TestPendingExpiryDoesNotTruncateActiveVerification(t *testing.T) {
	for _, healthy := range []bool{false, true} {
		t.Run(fmt.Sprintf("active_healthy_%t", healthy), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				e, k, active, pending := retryWaveFixture(t)
				deadline := e.trialStarted[pending.Key].Add(InitialTrialWindow)
				time.Sleep(time.Until(deadline.Add(-200 * time.Millisecond)))
				k.silentKey = pending.Key
				k.slowDelay = 1500 * time.Millisecond
				if healthy {
					k.slowDelay = 900 * time.Millisecond
				}
				began := time.Now()
				statuses, err := e.Step(context.Background(), []Candidate{active, pending})
				if err != nil {
					t.Fatal(err)
				}
				if at := k.removedAt[pending.Key]; at.IsZero() || at.After(deadline) {
					t.Fatalf("pending route escaped deadline while active probe ran: removed=%s deadline=%s", at, deadline)
				}
				if time.Since(began) < 900*time.Millisecond {
					t.Fatalf("active probe budget was truncated by pending expiry: elapsed=%s", time.Since(began))
				}
				_, installed := k.s.Peers[active.Key]
				if installed != healthy {
					t.Fatalf("active outcome does not match full probe: healthy=%t installed=%t statuses=%v", healthy, installed, statuses)
				}
			})
		})
	}
}

func TestTimelySecondProofSurvivesSlowerActiveVerification(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e, k, active, pending := retryWaveFixture(t)
		deadline := e.trialStarted[pending.Key].Add(InitialTrialWindow)
		time.Sleep(time.Until(deadline.Add(-200 * time.Millisecond)))
		k.slowDelay = 900 * time.Millisecond
		// Pending's second nonce and counters succeed immediately, 200 ms
		// before its deadline. Active's valid reply arrives 700 ms after it.
		statuses, err := e.Step(context.Background(), []Candidate{active, pending})
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range []Candidate{active, pending} {
			if _, installed := k.s.Peers[c.Key]; !installed || e.successes[c.Key] != 2 {
				t.Fatalf("timely proof lost while waiting for unrelated peer: peer=%s statuses=%v", c.ID, statuses)
			}
		}
	})
}

type retryWaveErrorKernel struct {
	*retryWaveKernel
	fault    string
	deadline time.Time
	exited   chan struct{}
}

func (k *retryWaveErrorKernel) Probe(ctx context.Context, c Candidate) error {
	if c.Key == k.slowKey {
		<-ctx.Done()
		// Model socket teardown taking time after cancellation. Step must
		// join it before an error lets the worker start cleanup or new work.
		time.Sleep(50 * time.Millisecond)
		close(k.exited)
		return ctx.Err()
	}
	return k.retryWaveKernel.Probe(ctx, c)
}

func (k *retryWaveErrorKernel) Snapshot(ctx context.Context) (snapshot, error) {
	if k.fault == "readback" && !time.Now().Before(k.deadline) {
		return snapshot{}, errors.New("simulated expiry readback failure")
	}
	return k.retryWaveKernel.Snapshot(ctx)
}

func (k *retryWaveErrorKernel) Remove(ctx context.Context, keys []string) error {
	if k.fault == "remove" {
		return errors.New("simulated expiry removal failure")
	}
	return k.retryWaveKernel.Remove(ctx, keys)
}

func TestPendingExpiryErrorsCancelAndJoinActiveProbe(t *testing.T) {
	for _, fault := range []string{"remove", "readback"} {
		t.Run(fault, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				e, delayed, active, pending := retryWaveFixture(t)
				deadline := e.trialStarted[pending.Key].Add(InitialTrialWindow)
				time.Sleep(time.Until(deadline.Add(-200 * time.Millisecond)))
				k := &retryWaveErrorKernel{retryWaveKernel: delayed, fault: fault, deadline: deadline, exited: make(chan struct{})}
				if fault == "remove" {
					k.silentKey = pending.Key
				}
				e.backend = k
				if _, err := e.Step(context.Background(), []Candidate{active, pending}); err == nil {
					t.Fatal("expiry backend failure was ignored")
				}
				select {
				case <-k.exited:
				default:
					t.Fatal("Step returned before canceled active probe finished")
				}
			})
		})
	}
}

type retrySnapshotCounter struct {
	backend
	count int
}

func (k *retrySnapshotCounter) Snapshot(ctx context.Context) (snapshot, error) {
	k.count++
	return k.backend.Snapshot(ctx)
}

func TestActiveOnlyVerificationKeepsTwoKernelReadbacks(t *testing.T) {
	e, _, c := fixture(t)
	for range 2 {
		if _, err := e.Step(context.Background(), []Candidate{c}); err != nil {
			t.Fatal(err)
		}
	}
	counter := &retrySnapshotCounter{backend: e.backend}
	e.backend = counter
	if statuses, err := e.Step(context.Background(), []Candidate{c}); err != nil || statuses[0].State != "active" {
		t.Fatal(statuses, err)
	}
	if counter.count != 2 {
		t.Fatalf("stable active verification made %d snapshots; want before and after", counter.count)
	}
}

func TestInitialVerificationSupportsSubsecondNonceRoundTrips(t *testing.T) {
	for _, rtt := range []time.Duration{600 * time.Millisecond, 900 * time.Millisecond} {
		t.Run(rtt.String(), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				e, kernel, c := fixture(t)
				k := &retryWaveKernel{fakeKernel: kernel, slowKey: c.Key, slowDelay: rtt, removedAt: map[string]time.Time{}}
				e.backend = k
				began := time.Now()
				for _, want := range []string{"probing", "active"} {
					started := time.Now()
					statuses, err := e.Step(context.Background(), []Candidate{c})
					if err != nil || len(statuses) != 1 || statuses[0].State != want || statuses[0].Reason != "" {
						t.Fatalf("supported %s nonce RTT did not produce consecutive proofs: statuses=%v err=%v", rtt, statuses, err)
					}
					// Preserve the worker's faster cadence without replacing the
					// nonce request's existing one-second response budget.
					time.Sleep(max(0, VerificationInterval-time.Since(started)))
				}
				if elapsed := time.Since(began); elapsed >= InitialTrialWindow {
					t.Fatalf("proofs escaped initial route budget: elapsed=%s", elapsed)
				}
			})
		})
	}
}

// Copyright 2025 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package predictor

import (
	"context"
	"math"
	"sync"
	"time"
)

// AR2RTT is a second-order autoregressive predictor specialised for
// rtt_ms with online least-squares parameter fitting. It serves as the
// fallback RTT predictor per predictor-design §4.1 — a small, always-
// available model that produces a real forecast even before the LSTM
// (Phase-B) has been trained.
//
// Signals other than RTT are handed off to a Persistence predictor
// composed inside AR2RTT. This keeps the interface uniform (a single
// Predictor object) while isolating the AR mechanism to its target
// signal.
//
// The model: q̂[0](t+Δ) = a * q[0](t) + b * q[0](t-1) + c
// Parameters (a, b, c) are refit whenever Update is called with a new
// ground-truth sample. Fitting uses a small ring buffer of recent
// (input, target) pairs and closed-form least-squares.
type AR2RTT struct {
	mu sync.Mutex

	horizon      time.Duration
	baseline     *Persistence // used for signals other than RTT
	windowSize   int

	// Fitted coefficients. Initialised to a stable pass-through
	// (a=1, b=0, c=0) so cold-start predictions equal persistence.
	a, b, c float64

	// Ring of (x1=RTT(t), x2=RTT(t-1), y=RTT(t+Δ)) training samples.
	buf      []arSample
	bufIndex int
	bufFull  bool

	// residualStd is the running estimate of prediction residual
	// standard deviation, used for the CI in Forecast. Updated on
	// each Update call.
	residualStd float64
}

type arSample struct {
	x1, x2, y float64
}

// NewAR2RTT constructs an AR(2) predictor for RTT with the given
// horizon and buffer size. Pass windowSize = 300 to hold ~30 s of
// samples at 10 Hz — a reasonable default that trades adaptivity for
// stability.
func NewAR2RTT(horizon time.Duration, windowSize int) *AR2RTT {
	if horizon <= 0 {
		horizon = 2 * time.Second
	}
	if windowSize < 10 {
		windowSize = 300
	}
	return &AR2RTT{
		horizon:     horizon,
		baseline:    NewPersistence(horizon),
		windowSize:  windowSize,
		a:           1,
		b:           0,
		c:           0,
		buf:         make([]arSample, windowSize),
		residualStd: 10, // initial coarse guess: 10 ms
	}
}

// Name implements Predictor.
func (p *AR2RTT) Name() string { return "ar2-rtt" }

// Horizon implements Predictor.
func (p *AR2RTT) Horizon() time.Duration { return p.horizon }

// Ready reports true when at least two RTT samples are available to
// evaluate the AR(2) form. Below that, downstream should treat the
// predictor as effectively persistence — which it is.
func (p *AR2RTT) Ready() bool { return true }

// Update ingests a completed (input, target) pair — a prediction made
// at input time and the RTT actually observed one horizon later.
// The predictor refits its coefficients periodically as new samples
// arrive. Callers typically invoke Update after each control tick using
// the historical pairing (t - horizon, t).
func (p *AR2RTT) Update(x1, x2, y float64) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Store the sample in the ring buffer.
	p.buf[p.bufIndex] = arSample{x1: x1, x2: x2, y: y}
	p.bufIndex = (p.bufIndex + 1) % p.windowSize
	if p.bufIndex == 0 {
		p.bufFull = true
	}

	// Refit every 10 new samples once the buffer holds enough.
	n := p.filled()
	if n < 20 {
		return
	}
	if p.bufIndex%10 != 0 {
		return
	}
	p.refit()
}

// filled returns the number of populated ring-buffer slots.
func (p *AR2RTT) filled() int {
	if p.bufFull {
		return p.windowSize
	}
	return p.bufIndex
}

// refit computes closed-form OLS estimates of (a, b, c) from the
// current buffer contents.
func (p *AR2RTT) refit() {
	n := p.filled()
	var sx1, sx2, sy, sx1x1, sx2x2, sx1x2, sx1y, sx2y float64
	for i := 0; i < n; i++ {
		s := p.buf[i]
		sx1 += s.x1
		sx2 += s.x2
		sy += s.y
		sx1x1 += s.x1 * s.x1
		sx2x2 += s.x2 * s.x2
		sx1x2 += s.x1 * s.x2
		sx1y += s.x1 * s.y
		sx2y += s.x2 * s.y
	}
	nf := float64(n)
	// Normal equations for y = a*x1 + b*x2 + c on a centered basis.
	// Build the 3x3 system and solve by inversion.
	// Row-major: [ sx1x1  sx1x2  sx1 ] [a]   [ sx1y ]
	//            [ sx1x2  sx2x2  sx2 ] [b] = [ sx2y ]
	//            [ sx1    sx2    nf  ] [c]   [ sy   ]
	det := determinant3(
		sx1x1, sx1x2, sx1,
		sx1x2, sx2x2, sx2,
		sx1, sx2, nf,
	)
	if math.Abs(det) < 1e-9 {
		return // ill-conditioned; keep previous fit
	}
	a := determinant3(
		sx1y, sx1x2, sx1,
		sx2y, sx2x2, sx2,
		sy, sx2, nf,
	) / det
	b := determinant3(
		sx1x1, sx1y, sx1,
		sx1x2, sx2y, sx2,
		sx1, sy, nf,
	) / det
	c := determinant3(
		sx1x1, sx1x2, sx1y,
		sx1x2, sx2x2, sx2y,
		sx1, sx2, sy,
	) / det

	// Sanity: reject fits that produce absurd magnitudes.
	if math.IsNaN(a) || math.IsNaN(b) || math.IsNaN(c) ||
		math.Abs(a) > 10 || math.Abs(b) > 10 || math.Abs(c) > 10_000 {
		return
	}

	// Update residual std from in-sample residuals.
	var rss float64
	for i := 0; i < n; i++ {
		s := p.buf[i]
		yhat := a*s.x1 + b*s.x2 + c
		diff := yhat - s.y
		rss += diff * diff
	}
	if n > 3 {
		p.residualStd = math.Sqrt(rss / float64(n-3))
	}

	p.a, p.b, p.c = a, b, c
}

// determinant3 computes the determinant of a 3x3 matrix given in
// row-major order.
func determinant3(a00, a01, a02, a10, a11, a12, a20, a21, a22 float64) float64 {
	return a00*(a11*a22-a12*a21) -
		a01*(a10*a22-a12*a20) +
		a02*(a10*a21-a11*a20)
}

// Predict returns a Forecast where q̂[0] uses the AR(2) formula and
// signals 1..4 are delegated to the Persistence baseline.
func (p *AR2RTT) Predict(ctx context.Context, obs Observation) (Forecast, error) {
	base, err := p.baseline.Predict(ctx, obs)
	if err != nil {
		return Forecast{}, err
	}

	// AR(2) requires two most-recent samples.
	if len(obs.RTTHistory) < 2 {
		// Fall back to persistence output.
		base.PredictorName = p.Name() + "/persistence-fallback"
		return base, nil
	}

	p.mu.Lock()
	a, b, c, sigma := p.a, p.b, p.c, p.residualStd
	p.mu.Unlock()

	x1 := obs.RTTHistory[len(obs.RTTHistory)-1].Value
	x2 := obs.RTTHistory[len(obs.RTTHistory)-2].Value
	yhat := a*x1 + b*x2 + c
	if yhat < 0 {
		yhat = 0
	}

	// ~1.645 * sigma covers ~90% under Gaussian residuals.
	const ninetyPctZ = 1.645
	lo := yhat - ninetyPctZ*sigma
	hi := yhat + ninetyPctZ*sigma
	if lo < 0 {
		lo = 0
	}

	base.Q[SignalRTT] = yhat
	base.QLo[SignalRTT] = lo
	base.QHi[SignalRTT] = hi
	base.Health[SignalRTT] = healthFromResidualStd(sigma)
	base.PredictorName = p.Name()
	return base, nil
}

// healthFromResidualStd maps residual std to a health score in [0, 1]:
// well-fit models (sigma near zero) get health near 1; badly-fit
// models get health approaching 0. The scaling constant 40 is a
// coarse default that treats "std of 40 ms" as roughly break-even
// between "useful" and "not"; tune in Phase-B.
func healthFromResidualStd(sigma float64) float64 {
	const scale = 40.0
	h := scale / (scale + sigma)
	return h
}

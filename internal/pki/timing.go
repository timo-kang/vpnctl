package pki

import (
	"time"
	"vpnctl/internal/metrics"
)

// Stages are fixed at call sites; identities, fingerprints and paths are excluded.
func observeAuthority(stage string, start time.Time) {
	metrics.PKIAuthoritySeconds.WithLabelValues(stage).Observe(time.Since(start).Seconds())
}

func (a *Authority) lockWriter() func() {
	started := time.Now()
	a.mu.Lock()
	observeAuthority("writer_wait", started)
	held := time.Now()
	return func() { a.mu.Unlock(); observeAuthority("writer_hold", held) }
}

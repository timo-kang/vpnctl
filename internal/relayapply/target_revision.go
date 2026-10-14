// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayapply

import (
	"crypto/sha256"
	"encoding/json"
)

func nextRouteRevision(revision uint64) uint64 {
	if revision != ^uint64(0) {
		revision++
	}
	return revision
}

// An in-memory fence for the current Engine only, while ownership is retained.
// Owner distinguishes recreated reservations; RouteRevision distinguishes ABA.
// Hashing now freezes nested fields instead of retaining pointers to the guard.
type targetObservationFence struct {
	owner        *Engine
	node, domain string
	target       string
	digest       [32]byte
}

func targetGuardDigest(g TargetGuard) [32]byte {
	b, _ := json.Marshal(g) // Only validated journal values enter this boundary.
	return sha256.Sum256(b)
}

func (e *Engine) targetObservationFence(g TargetGuard) targetObservationFence {
	return targetObservationFence{e, e.journal.Node, e.journal.Domain, g.TargetID, targetGuardDigest(g)}
}

func (f targetObservationFence) current(e *Engine) (int, TargetGuard, bool) {
	if f.owner != e || e.closed || e.uncertain || f.node != e.journal.Node || f.domain != e.journal.Domain {
		return -1, TargetGuard{}, false
	}
	i := e.targetIndex(f.target)
	if i < 0 {
		return -1, TargetGuard{}, false
	}
	g := e.journal.Targets[i]
	return i, g, g.RouteRevision != ^uint64(0) && targetGuardDigest(g) == f.digest
}

// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package controller

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"vpnctl/internal/api"
	"vpnctl/internal/store"
)

const directReadinessTTL = 2 * time.Minute

type directPairKey struct{ A, B string }
type directPairState struct {
	Generation string
	Next       uint64
	Received   map[string]uint64
}
type directTicket struct {
	From       string `json:"from"`
	To         string `json:"to"`
	Generation string `json:"generation"`
	IssuedAt   int64  `json:"issued_at"`
	Sequence   uint64 `json:"sequence"`
}

func pairKey(a, b string) directPairKey {
	if a > b {
		a, b = b, a
	}
	return directPairKey{a, b}
}
func (s *Server) directClock() time.Time {
	if s.directNow != nil {
		return s.directNow()
	}
	return time.Now()
}
func (s *Server) directPairLocked(a, b string) *directPairState {
	if s.directPairs == nil {
		s.directPairs = make(map[directPairKey]*directPairState)
	}
	if s.directSecret == "" {
		s.directSecret = newObservationEpoch() + newObservationEpoch()
	}
	key := pairKey(a, b)
	state := s.directPairs[key]
	if state == nil {
		state = &directPairState{Generation: newObservationEpoch(), Received: make(map[string]uint64)}
		s.directPairs[key] = state
	}
	return state
}
func (s *Server) directTicketLocked(from, to string) (string, string) {
	pair := s.directPairLocked(from, to)
	if pair.Next == ^uint64(0) {
		return "", ""
	}
	pair.Next++
	ticket := directTicket{from, to, pair.Generation, s.directClock().UnixNano(), pair.Next}
	data, _ := json.Marshal(ticket)
	mac := hmac.New(sha256.New, []byte(s.directSecret))
	_, _ = mac.Write(data)
	return pair.Generation, base64.RawURLEncoding.EncodeToString(data) + "." + hex.EncodeToString(mac.Sum(nil))
}

// Validate the original candidate ticket; never issue a new ticket for a result
// that has already been measured. A controller restart rotates the secret and
// loses readiness, so old results cannot authorize a new process generation.
func (s *Server) acceptDirectLocked(req api.DirectResultRequest) (time.Time, error) {
	invalid := errors.New("direct probe ticket is missing, expired, superseded or replayed; fetch fresh candidates")
	if len(req.ProbeToken) == 0 || len(req.ProbeToken) > 2048 {
		return time.Time{}, invalid
	}
	parts := strings.Split(req.ProbeToken, ".")
	if len(parts) != 2 {
		return time.Time{}, invalid
	}
	data, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return time.Time{}, invalid
	}
	signature, err := hex.DecodeString(parts[1])
	if err != nil {
		return time.Time{}, invalid
	}
	mac := hmac.New(sha256.New, []byte(s.directSecret))
	_, _ = mac.Write(data)
	if s.directSecret == "" || !hmac.Equal(signature, mac.Sum(nil)) {
		return time.Time{}, invalid
	}
	var ticket directTicket
	if json.Unmarshal(data, &ticket) != nil || ticket.From != req.NodeID || ticket.To != req.PeerID {
		return time.Time{}, invalid
	}
	pair := s.directPairs[pairKey(req.NodeID, req.PeerID)]
	issued := time.Unix(0, ticket.IssuedAt)
	age := s.directClock().Sub(issued)
	if pair == nil || ticket.Generation != pair.Generation || ticket.Sequence == 0 || ticket.Sequence > pair.Next || ticket.Sequence <= pair.Received[req.NodeID] || age < 0 || age >= directReadinessTTL {
		return time.Time{}, invalid
	}
	pair.Received[req.NodeID] = ticket.Sequence
	if !req.Success {
		s.invalidateDirectPairLocked(req.NodeID, req.PeerID)
	}
	return issued, nil
}
func (s *Server) invalidateDirectPairLocked(a, b string) {
	delete(s.directPairs, pairKey(a, b))
	delete(s.directOK[a], b)
	delete(s.directOK[b], a)
}
func (s *Server) invalidateDirectNodeLocked(id string) {
	for key := range s.directPairs {
		if key.A == id || key.B == id {
			delete(s.directPairs, key)
		}
	}
	delete(s.directOK, id)
	for peer, successes := range s.directOK {
		delete(successes, id)
		if len(successes) == 0 {
			delete(s.directOK, peer)
		}
	}
}

type directNodeBinding struct {
	ID, Key, IP, Endpoint, PublicAddr, NAT string
	Port                                   int
	Pending                                bool
}

func directBinding(n store.NodeInfo) directNodeBinding {
	return directNodeBinding{n.ID, n.PubKey, n.VPNIP, n.Endpoint, n.PublicAddr, n.NATType, n.ProbePort, n.EnrollmentPending}
}

// Run only on publication, including a visible but durability-uncertain commit.
// Invalidating on each committed change also prevents A -> B -> A replay.
func (s *Server) invalidateDirectRegistryLocked(previous, next *store.Registry) {
	current := make(map[string]directNodeBinding, len(next.Nodes))
	for _, node := range next.Nodes {
		current[node.ID] = directBinding(node)
	}
	for _, node := range previous.Nodes {
		if nextBinding, exists := current[node.ID]; !exists || nextBinding != directBinding(node) {
			s.invalidateDirectNodeLocked(node.ID)
		}
	}
}

// Observed endpoints are a separate volatile input. A failed inventory clears
// dynamic endpoints instead of silently retaining readiness for the last one.
// Explicitly advertised endpoints retain precedence over roaming observations.
func (s *Server) refreshDirectEndpoints() {
	s.mu.Lock()
	if s.directObservedIssued == ^uint64(0) {
		s.mu.Unlock()
		return
	}
	s.directObservedIssued++
	sequence := s.directObservedIssued
	s.mu.Unlock()
	observed := map[string]string{}
	if s.wg != nil && s.cfg.WGInterface != "" {
		if current, err := s.wg.PeerEndpoints(s.cfg.WGInterface); err == nil {
			observed = current
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// A slow earlier request cannot overwrite a newer completed inventory.
	// External I/O remains concurrent and never holds the registry mutex.
	if sequence <= s.directObservedApplied {
		return
	}
	s.directObservedApplied = sequence
	for _, node := range s.reg.Nodes {
		if node.Endpoint == "" && s.directObserved[node.PubKey] != observed[node.PubKey] {
			s.invalidateDirectNodeLocked(node.ID)
		}
	}
	s.directObserved = observed
}
func (s *Server) directCandidates(nodeID string) []api.PeerCandidate {
	s.refreshDirectEndpoints()
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.directCandidatesLocked(nodeID)
}

// Ticket issuance belongs to the API snapshot, not registry mutation results.
// Internal enrollment/heartbeat writers must not create O(nodes²) unused tickets.
func (s *Server) directCandidatesLocked(nodeID string) []api.PeerCandidate {
	peers := s.peersLocked(nodeID)
	for i := range peers {
		peers[i].DirectGeneration, peers[i].ProbeToken = s.directTicketLocked(nodeID, peers[i].ID)
	}
	return peers
}

// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayapply

import (
	"bytes"
	"slices"
	"strconv"
	"strings"
)

// One bounded, uncached interface dump replaces six separate WG queries. The
// format is wireguard-tools src/show.c dump_print. Unlike a relay's learned
// endpoints, this node's endpoint is pinned and must match the approval.
// The private key and PSK stay in slices of the original buffer and are erased
// on every exit, never copied into errors, reports or shared inventories.
func validateNodeWire(raw []byte, e Entry, partial bool) (bool, error) {
	defer clear(raw)
	if len(raw) == 0 || len(raw) > 512<<10 {
		return false, ErrConflict
	}
	lines := bytes.Split(bytes.TrimSpace(raw), []byte{'\n'})
	if len(lines) < 1 || len(lines) > 2 {
		return false, ErrConflict // Exactly one approved peer, or a partial link.
	}
	header := bytes.Fields(lines[0])
	if len(header) != 4 {
		return false, ErrConflict
	}
	if string(header[1]) != e.Candidate.PublicKey && !(partial && bytes.Equal(header[1], []byte("(none)"))) {
		return false, ErrConflict
	}
	// The local listen port is allocated by WG, not an approved fixed port.
	if _, err := strconv.ParseUint(string(header[2]), 10, 16); err != nil {
		return false, ErrConflict
	}
	mark := uint64(0)
	if !bytes.Equal(header[3], []byte("off")) {
		var err error
		mark, err = strconv.ParseUint(string(header[3]), 0, 32)
		if err != nil {
			return false, ErrConflict
		}
	}
	if mark != uint64(e.Candidate.Pin.FWMark) && !(partial && mark == 0) {
		return false, ErrConflict
	}
	if len(lines) == 1 {
		if partial {
			return true, nil
		}
		return false, ErrConflict
	}
	peer := bytes.Fields(lines[1])
	if len(peer) != 8 || string(peer[0]) != e.Candidate.RelayPublicKey || !bytes.Equal(peer[1], []byte("(none)")) || !bytes.Equal(peer[7], []byte("off")) {
		return false, ErrConflict
	}
	if string(peer[2]) != e.Candidate.Endpoint && !(partial && bytes.Equal(peer[2], []byte("(none)"))) {
		return false, ErrConflict
	}
	// Handshake and counters are syntactic fields only. They do not establish
	// connectivity or replace either bound TCP or unbound application proofs.
	for _, field := range peer[4:7] {
		if _, err := strconv.ParseUint(string(field), 10, 64); err != nil {
			return false, ErrConflict
		}
	}
	if partial && bytes.Equal(peer[3], []byte("(none)")) {
		return true, nil
	}
	got := strings.Split(string(peer[3]), ",")
	slices.Sort(got)
	want := prefixes(e)
	for i, prefix := range got {
		if !slices.Contains(want, prefix) || i > 0 && got[i-1] == prefix {
			return false, ErrConflict
		}
	}
	if !partial && !slices.Equal(got, want) {
		return false, ErrConflict
	}
	return true, nil
}

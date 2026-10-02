// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayapply

import (
	"bytes"
	"strconv"
)

// Read the WG configuration in one bounded query instead of seven independent
// process/netlink dumps. The dump format is defined by wireguard-tools show.c.
// It contains a private-key column; keep slices into the original buffer, never
// return raw data, and erase it on every exit. Endpoints/handshake/counters are
// volatile learned state and do not confer ownership or uplink readiness.
func validateDeploymentWire(raw []byte, e DeploymentEntry) (bool, error) {
	defer clear(raw)
	if len(raw) == 0 || len(raw) > 512<<10 {
		return false, ErrConflict
	}
	lines := bytes.Split(bytes.TrimSpace(raw), []byte{'\n'})
	header := bytes.Fields(lines[0])
	if len(header) != 4 {
		return false, ErrConflict
	}
	complete := true
	if bytes.Equal(header[1], []byte("(none)")) {
		complete = false
	} else if string(header[1]) != e.PublicKey {
		return false, ErrConflict
	}
	if bytes.Equal(header[2], []byte("0")) {
		complete = false
	} else if string(header[2]) != strconv.Itoa(e.ListenPort) {
		return false, ErrConflict
	}
	if !bytes.Equal(header[3], []byte("off")) && !bytes.Equal(header[3], []byte("0")) {
		return false, ErrConflict
	}
	want := make(map[string]string, len(e.Peers))
	for _, p := range e.Peers {
		want[p.PublicKey] = p.Address
	}
	seen := make(map[string]bool, len(e.Peers))
	for _, line := range lines[1:] {
		fields := bytes.Fields(line)
		if len(fields) != 8 {
			return false, ErrConflict
		}
		key := string(fields[0])
		address, ok := want[key]
		if !ok || seen[key] {
			return false, ErrConflict
		}
		seen[key] = true
		if !bytes.Equal(fields[1], []byte("(none)")) || !bytes.Equal(fields[7], []byte("off")) {
			return false, ErrConflict
		}
		if bytes.Equal(fields[3], []byte("(none)")) {
			complete = false
		} else if string(fields[3]) != address {
			return false, ErrConflict
		}
	}
	return complete && len(seen) == len(want), nil
}

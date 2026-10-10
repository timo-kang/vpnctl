// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayapply

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"

	"vpnctl/internal/relaycatalog"
)

const counterSnapshotPrivate = "snapshot-private-must-not-leak"
const counterSnapshotPSK = "snapshot-psk-must-not-leak"

func counterSnapshotWire(entry Entry, handshake, rx, tx string) []byte {
	return []byte(fmt.Sprintf("%s\t%s\t43210\t%s\n%s\t(none)\t%s\t%s\t%s\t%s\t%s\toff\n",
		counterSnapshotPrivate, entry.Candidate.PublicKey, hexMark(entry.Candidate.Pin.FWMark),
		entry.Candidate.RelayPublicKey, entry.Candidate.Endpoint, strings.Join(prefixes(entry), ","), handshake, rx, tx))
}

func assertCounterSnapshotErased(t *testing.T, raw []byte) {
	t.Helper()
	if !bytes.Equal(raw, make([]byte, len(raw))) {
		t.Error("counter command output was not erased")
	}
}

func assertCounterSnapshotNoSecretError(t *testing.T, err error) {
	t.Helper()
	if err != nil && (strings.Contains(err.Error(), counterSnapshotPrivate) || strings.Contains(err.Error(), counterSnapshotPSK)) {
		t.Error("counter error exposed sensitive command output")
	}
}

func TestTargetCounterSnapshotOneFreshCommand(t *testing.T) {
	entry, _ := kernelFixture(t)
	reads, dumps, cycle := 0, 0, 0
	var outputs [][]byte
	k := kernel{run: func(_ context.Context, input, name string, args ...string) ([]byte, error) {
		if input != "" || name != "wg" || len(args) != 3 || args[0] != "show" || args[1] != entry.Candidate.Pin.WGInterface {
			t.Fatal("unexpected counter command")
		}
		reads++
		handshake, rx, tx := 100+cycle, 200+cycle, 300+cycle
		switch args[2] {
		case "dump":
			dumps++
			raw := counterSnapshotWire(entry, fmt.Sprint(handshake), fmt.Sprint(rx), fmt.Sprint(tx))
			outputs = append(outputs, raw)
			return raw, nil
		// Keep the old implementation functional: RED must demonstrate the
		// two-process cost, not an unsupported fake-command failure.
		case "latest-handshakes":
			return fmt.Appendf(nil, "%s %d", entry.Candidate.RelayPublicKey, handshake), nil
		case "transfer":
			return fmt.Appendf(nil, "%s %d %d", entry.Candidate.RelayPublicKey, rx, tx), nil
		default:
			t.Fatal("unexpected counter operation")
			return nil, errors.New("unexpected counter operation")
		}
	}}
	for cycle = 0; cycle < 2; cycle++ {
		before := reads
		got, err := k.targetCounters(context.Background(), entry)
		want := targetCounters{handshake: int64(100 + cycle), rx: uint64(200 + cycle), tx: uint64(300 + cycle)}
		if err != nil || got != want {
			t.Fatal("counter values did not reflect the current live sample")
		}
		if reads-before != 1 {
			t.Errorf("counter sample used %d external commands; want 1", reads-before)
		}
	}
	if dumps != 2 {
		t.Errorf("fresh dump count = %d; want 2", dumps)
	}
	for _, raw := range outputs {
		assertCounterSnapshotErased(t, raw)
	}
}

func TestTargetCounterSnapshotRejectsInvalidDumpAndErasesOutput(t *testing.T) {
	entry, _ := kernelFixture(t)
	for _, tc := range []struct {
		name   string
		change func([]string, []string) string
		valid  bool
		want   targetCounters
	}{
		{name: "valid", valid: true, want: targetCounters{123, 456, 789}},
		{name: "psk-is-not-copied", valid: true, want: targetCounters{123, 456, 789}, change: func(h, p []string) string { p[1] = counterSnapshotPSK; return "" }},
		{name: "zero", valid: true, want: targetCounters{}, change: func(h, p []string) string { p[4], p[5], p[6] = "0", "0", "0"; return "" }},
		{name: "maximum", valid: true, want: targetCounters{9223372036854775807, 18446744073709551615, 18446744073709551615}, change: func(h, p []string) string {
			p[4], p[5], p[6] = "9223372036854775807", "18446744073709551615", "18446744073709551615"
			return ""
		}},
		{name: "wrong-peer", change: func(h, p []string) string { p[0] = public("foreign"); return "" }},
		{name: "extra-peer", change: func(h, p []string) string {
			return strings.Join(h, "\t") + "\n" + strings.Join(p, "\t") + "\n" + strings.Join(p, "\t") + "\n"
		}},
		{name: "missing-peer", change: func(h, p []string) string { return strings.Join(h, "\t") + "\n" }},
		{name: "missing-header", change: func(h, p []string) string { return strings.Join(p, "\t") + "\n" }},
		{name: "extra-header-field", change: func(h, p []string) string { return strings.Join(h, "\t") + "\textra\n" + strings.Join(p, "\t") + "\n" }},
		{name: "missing-peer-field", change: func(h, p []string) string { return strings.Join(h, "\t") + "\n" + strings.Join(p[:7], "\t") + "\n" }},
		{name: "negative-handshake", change: func(h, p []string) string { p[4] = "-1"; return "" }},
		{name: "overflow-handshake", change: func(h, p []string) string { p[4] = "9223372036854775808"; return "" }},
		{name: "malformed-handshake", change: func(h, p []string) string { p[4] = counterSnapshotPrivate; return "" }},
		{name: "negative-rx", change: func(h, p []string) string { p[5] = "-1"; return "" }},
		{name: "overflow-rx", change: func(h, p []string) string { p[5] = "18446744073709551616"; return "" }},
		{name: "malformed-rx", change: func(h, p []string) string { p[5] = counterSnapshotPSK; return "" }},
		{name: "negative-tx", change: func(h, p []string) string { p[6] = "-1"; return "" }},
		{name: "overflow-tx", change: func(h, p []string) string { p[6] = "18446744073709551616"; return "" }},
		{name: "malformed-tx", change: func(h, p []string) string { p[6] = counterSnapshotPSK; return "" }},
		{name: "truncated-secrets", change: func(h, p []string) string { return counterSnapshotPrivate + "\n" + counterSnapshotPSK + "\n" }},
		{name: "oversized", change: func(h, p []string) string { return strings.Repeat("x", 512<<10) + counterSnapshotPSK }},
		{name: "whitespace-only", change: func(h, p []string) string { return "\n \t\n" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lines := strings.Split(strings.TrimSpace(string(counterSnapshotWire(entry, "123", "456", "789"))), "\n")
			h, p := strings.Fields(lines[0]), strings.Fields(lines[1])
			raw := ""
			if tc.change != nil {
				raw = tc.change(h, p)
			}
			if raw == "" {
				raw = strings.Join(h, "\t") + "\n" + strings.Join(p, "\t") + "\n"
			}
			buf := []byte(raw)
			k := kernel{run: func(context.Context, string, string, ...string) ([]byte, error) { return buf, nil }}
			got, err := k.targetCounters(context.Background(), entry)
			if (err == nil) != tc.valid || tc.valid && got != tc.want || !tc.valid && got != (targetCounters{}) {
				t.Error("counter snapshot validity or scalar values differ from contract")
			}
			assertCounterSnapshotNoSecretError(t, err)
			assertCounterSnapshotErased(t, buf)
		})
	}
}

func TestTargetCounterSnapshotCommandFailureAndCancellationEraseOutput(t *testing.T) {
	entry, _ := kernelFixture(t)
	for _, mode := range []string{"command-error", "canceled-before-command", "canceled-during-command"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "canceled-before-command" {
				cancel()
			}
			var returned [][]byte
			k := kernel{run: func(context.Context, string, string, ...string) ([]byte, error) {
				buf := counterSnapshotWire(entry, "123", "456", "789")
				// Even command failures can return partial output with a PSK.
				if mode == "command-error" {
					buf = bytes.Replace(buf, []byte("\t(none)\t"), []byte("\t"+counterSnapshotPSK+"\t"), 1)
				}
				returned = append(returned, buf)
				if mode == "command-error" {
					return buf, errors.New("kernel command failed")
				}
				cancel()
				// Exercise cancellation racing a successful process exit.
				return buf, nil
			}}
			got, err := k.targetCounters(ctx, entry)
			if err == nil || got != (targetCounters{}) {
				t.Error("failed or canceled command produced usable counters")
			}
			assertCounterSnapshotNoSecretError(t, err)
			for _, raw := range returned {
				assertCounterSnapshotErased(t, raw)
			}
		})
	}
}

func TestTargetCounterSnapshotBracketsTCPWithLiveSamples(t *testing.T) {
	entry, _ := kernelFixture(t)
	for _, mode := range []string{"success", "unchanged-counters", "wrong-peer-after-tcp", "error-after-tcp"} {
		t.Run(mode, func(t *testing.T) {
			dialed, reads, dumpReads := false, 0, 0
			var outputs [][]byte
			k := kernel{
				targetLookup: func(ctx context.Context, _ Entry, _ relaycatalog.Target) error { return ctx.Err() },
				run: func(_ context.Context, input, name string, args ...string) ([]byte, error) {
					if input != "" || name != "wg" || len(args) != 3 || args[0] != "show" || args[1] != entry.Candidate.Pin.WGInterface {
						t.Fatal("unexpected counter command")
					}
					reads++
					rx, tx := 100, 200
					peer := entry.Candidate.RelayPublicKey
					if dialed {
						if mode != "unchanged-counters" {
							rx, tx = 180, 296
						}
						if mode == "wrong-peer-after-tcp" {
							peer = public("foreign")
						}
						if mode == "error-after-tcp" {
							return nil, errors.New("kernel command failed")
						}
					}
					switch args[2] {
					case "dump":
						dumpReads++
						raw := counterSnapshotWire(entry, "123", fmt.Sprint(rx), fmt.Sprint(tx))
						raw = bytes.ReplaceAll(raw, []byte(entry.Candidate.RelayPublicKey), []byte(peer))
						outputs = append(outputs, raw)
						return raw, nil
					case "latest-handshakes":
						return fmt.Appendf(nil, "%s 123", peer), nil
					case "transfer":
						return fmt.Appendf(nil, "%s %d %d", peer, rx, tx), nil
					default:
						t.Fatal("unexpected counter operation")
						return nil, errors.New("unexpected counter operation")
					}
				},
			}
			proof, err := k.probeTargetWithDial(context.Background(), entry, entry.Candidate.Targets[0], func(context.Context, Entry, relaycatalog.Target) (net.Conn, error) {
				if reads != 1 {
					t.Errorf("pre-TCP counter commands = %d; want 1", reads)
				}
				dialed = true
				a, b := net.Pipe()
				_ = b.Close()
				return a, nil
			})
			if mode == "success" {
				if err != nil || proof.handshake != 123 || proof.rx != 80 || proof.tx != 96 || reads != 2 || dumpReads != 2 {
					t.Errorf("successful proof omitted bounded live evidence: reads=%d dumps=%d", reads, dumpReads)
				}
			} else if err == nil || proof != (targetProof{}) {
				t.Error("invalid post-TCP counter evidence produced a proof")
			}
			assertCounterSnapshotNoSecretError(t, err)
			for _, raw := range outputs {
				assertCounterSnapshotErased(t, raw)
			}
		})
	}
}

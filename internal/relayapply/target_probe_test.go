// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayapply

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"syscall"
	"testing"
	"time"
	"vpnctl/internal/relaycatalog"
)

func TestObserveTargetRejectsUntrustedOrChangedCandidate(t *testing.T) {
	for _, mode := range []string{"verified", "unprepared", "pending", "expired", "conflict", "inventory", "changed-during-probe", "generation", "target", "controller", "timeout", "refused", "permission", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			e, k, _ := fixture(t, "robot")
			if mode != "unprepared" {
				if _, err := e.PrepareProbe(context.Background(), "p0", ""); err != nil {
					t.Fatal(err)
				}
			}
			target, controller := "app", ""
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch mode {
			case "pending":
				e.journal.Entries[0].Phase = "preparing"
			case "expired":
				e.journal.Entries[0].ApprovalUntil = time.Now().Add(-time.Second)
			case "conflict":
				k.foreign = true
			case "inventory":
				e.collector = &inventory{down: true}
			case "generation":
				e.journal.Entries[0].Generation++
			case "target":
				target = "other"
			case "controller":
				controller = "other"
			case "canceled":
				cancel()
			}
			called := 0
			probe := func(ctx context.Context, entry Entry, actual relaycatalog.Target) (targetProof, error) {
				called++
				if entry.Candidate.PathID != "p0" || actual.ID != "app" {
					t.Fatal(entry, actual)
				}
				switch mode {
				case "changed-during-probe":
					k.foreign = true
				case "timeout":
					return targetProof{}, classifyTargetConnect(context.DeadlineExceeded)
				case "refused":
					return targetProof{}, classifyTargetConnect(syscall.ECONNREFUSED)
				case "permission":
					return targetProof{}, syscall.EPERM
				}
				return targetProof{duration: time.Millisecond, handshake: 1, rx: 80, tx: 80}, nil
			}
			out, _ := e.observeTarget(ctx, target, controller, time.Second, probe)
			if mode == "target" || mode == "controller" || mode == "canceled" {
				if out.Valid {
					t.Fatal(out)
				}
				return
			}
			if !out.Valid || len(out.Paths) != 8 {
				t.Fatal(out)
			}
			state := "unknown"
			if mode == "verified" {
				state = "reachable"
			}
			if mode == "timeout" || mode == "refused" {
				state = "unreachable"
			}
			if out.Paths[0].State != state {
				t.Fatal(out.Paths[0])
			}
			if mode == "verified" && called != 1 {
				t.Fatal(called)
			}
			if (mode == "expired" || mode == "conflict" || mode == "pending" || mode == "generation" || mode == "inventory" || mode == "unprepared") && called != 0 {
				t.Fatal("probed untrusted candidate", called)
			}
			if k.steps != 0 && k.steps != 10 {
				t.Fatal("observer mutated candidate", k.steps)
			}
		})
	}
}
func TestTargetCountersAreStrictAndNeverReadSecrets(t *testing.T) {
	entry := Entry{}
	e, _, _ := fixture(t, "robot")
	if _, err := e.PrepareProbe(context.Background(), "p0", ""); err != nil {
		t.Fatal(err)
	}
	entry = e.journal.Entries[0]
	for _, mode := range []string{"valid", "extra-peer", "wrong-peer", "negative", "overflow", "malformed"} {
		t.Run(mode, func(t *testing.T) {
			k := kernel{run: func(_ context.Context, input, name string, args ...string) ([]byte, error) {
				if input != "" || name != "wg" || len(args) != 3 || args[0] != "show" || args[1] != entry.Candidate.Pin.WGInterface || (args[2] != "transfer" && args[2] != "latest-handshakes") {
					t.Fatal("unexpected command", name, args)
				}
				data := entry.Candidate.RelayPublicKey + " 123"
				if args[2] == "transfer" {
					data += " 456"
				}
				switch mode {
				case "extra-peer":
					data += "\n" + data
				case "wrong-peer":
					data = strings.ReplaceAll(data, entry.Candidate.RelayPublicKey, public("other"))
				case "negative":
					data = strings.ReplaceAll(data, "123", "-1")
				case "overflow":
					data = strings.ReplaceAll(data, "123", "18446744073709551616")
				case "malformed":
					data = "not counters"
				}
				return []byte(data), nil
			}}
			v, err := k.targetCounters(context.Background(), entry)
			if (err == nil) != (mode == "valid") {
				t.Fatal(v, err)
			}
		})
	}
}
func TestConnectFailureClassification(t *testing.T) {
	for _, err := range []error{syscall.EPERM, syscall.EMFILE, context.Canceled, fmt.Errorf("broken inventory")} {
		var failure *targetConnectError
		if errors.As(classifyTargetConnect(err), &failure) {
			t.Fatal("unknown converted into network failure", err)
		}
	}
	for _, err := range []error{context.DeadlineExceeded, syscall.ECONNREFUSED, syscall.ENETUNREACH, syscall.EHOSTUNREACH} {
		var failure *targetConnectError
		if !errors.As(classifyTargetConnect(err), &failure) {
			t.Fatal("known network failure lost", err)
		}
	}
}

func TestTargetRouteRejectsLocalGatewayAndWrongSource(t *testing.T) {
	e, _, _ := fixture(t, "robot")
	if _, err := e.PrepareProbe(context.Background(), "p0", ""); err != nil {
		t.Fatal(err)
	}
	entry := e.journal.Entries[0]
	target := entry.Candidate.Targets[0]
	for _, mode := range []string{"valid", "local", "gateway", "source", "interface", "multiple"} {
		t.Run(mode, func(t *testing.T) {
			r := object{"dev": entry.Candidate.Pin.WGInterface, "from": strings.TrimSuffix(entry.Candidate.InnerAddress, "/32")}
			switch mode {
			case "local":
				r["type"] = "local"
			case "gateway":
				r["gateway"] = "192.0.2.1"
			case "source":
				r["from"] = "10.99.0.2"
			case "interface":
				r["dev"] = "other"
			}
			rows := []object{r}
			if mode == "multiple" {
				rows = append(rows, r)
			}
			k := kernel{run: func(context.Context, string, string, ...string) ([]byte, error) { return json.Marshal(rows) }}
			if err := k.targetRoute(context.Background(), entry, target); (err == nil) != (mode == "valid") {
				t.Fatal(err)
			}
		})
	}
}

type observationIssuer struct{ view relaycatalog.View }

func (i observationIssuer) RelayCatalog(context.Context, string) (relaycatalog.View, error) {
	// Model the real API boundary: monotonic process-local time components
	// cannot be transported in JSON or treated as controller approval time.
	b, err := json.Marshal(i.view)
	if err != nil {
		return relaycatalog.View{}, err
	}
	var view relaycatalog.View
	err = json.Unmarshal(b, &view)
	return view, err
}
func (i observationIssuer) BindRelayPath(context.Context, relaycatalog.BindRequest) (relaycatalog.View, error) {
	return relaycatalog.View{}, errors.New("unexpected rebinding")
}
func TestObservationExpiresDuringSuccessfulProbe(t *testing.T) {
	e, _, _ := fixture(t, "robot")
	r, err := e.cache.Status()
	if err != nil {
		t.Fatal(err)
	}
	v := *r.Catalog
	v.Generation++
	v.ExpiresAt = time.Now().Add(2 * time.Second)
	v.IssuedAt = v.ExpiresAt.Add(-time.Minute)
	if _, err = e.cache.Refresh(context.Background(), observationIssuer{v}); err != nil {
		t.Fatal(err)
	}
	if _, err = e.PrepareProbe(context.Background(), "p0", ""); err != nil {
		t.Fatal(err)
	}
	called := false
	report, err := e.observeTarget(context.Background(), "app", "", time.Second, func(context.Context, Entry, relaycatalog.Target) (targetProof, error) {
		called = true
		time.Sleep(time.Until(v.ExpiresAt) + 20*time.Millisecond)
		return targetProof{duration: time.Millisecond, handshake: 1, rx: 80, tx: 80}, nil
	})
	if err != nil || !called || report.Valid || report.Reason != "approval_expired_or_changed" {
		t.Fatal(report, err, called)
	}
}

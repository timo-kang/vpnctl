// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayapply

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"vpnctl/internal/relayplan"
)

// Exercise the real LinuxCollector parsing, per-endpoint routing and final link
// readback. ReadIP is the only substituted boundary: no host command is run.
type preparationEndpointReader struct {
	t              *testing.T
	underlay       relayplan.Underlay
	wanted         string
	source         string
	blockUnrelated bool
	failWanted     bool
	changeLink     bool
	addresses      int
	wantedReads    int
	unrelatedReads int
}

func (r *preparationEndpointReader) read(ctx context.Context, args ...string) ([]byte, error) {
	r.t.Helper()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	encode := func(value any) ([]byte, error) { return json.Marshal(value) }
	if strings.Join(args, " ") == "-j address show dev "+r.underlay.Interface {
		r.addresses++
		index := 7
		if r.changeLink && r.addresses > 1 {
			index = 8
		}
		return encode([]object{{
			"ifindex": index, "ifname": r.underlay.Interface,
			"flags": []string{"UP", "LOWER_UP"}, "operstate": "UP",
			"addr_info": []object{{"family": "inet", "local": r.source, "prefixlen": 24, "scope": "global"}},
		}})
	}
	if len(args) != 9 || strings.Join(args[:4], " ") != "-j -4 route get" || args[5] != "from" || args[6] != r.source || args[7] != "oif" || args[8] != r.underlay.Interface {
		r.t.Fatalf("unexpected inventory command: %v", args)
	}
	if args[4] == r.wanted {
		r.wantedReads++
		if r.failWanted {
			return nil, errors.New("fixture: current endpoint route unavailable")
		}
	} else {
		r.unrelatedReads++
		if r.blockUnrelated {
			deadline, ok := ctx.Deadline()
			if !ok || time.Until(deadline) > NodeRebuildDuration {
				r.t.Fatal("unrelated query escaped the existing rebuild deadline")
			}
			<-ctx.Done()
			return nil, ctx.Err()
		}
	}
	return encode([]object{{"dev": r.underlay.Interface, "dst": args[4], "from": r.source}})
}

func preparationEndpointFixture(t *testing.T, path string) (*Engine, PreparationIntent, relayplan.Candidate, *preparationEndpointReader) {
	t.Helper()
	e, _, _, _ := preparationFixture(t)
	report, err := e.cache.Status()
	if err != nil {
		t.Fatal(err)
	}
	full, err := relayplan.Build(context.Background(), report.NodeID, report.ControllerID, report, e.underlays, e.collector)
	if err != nil || len(full.Paths) != 8 {
		t.Fatal("complete catalog fixture unavailable", err)
	}
	for _, candidate := range full.Paths {
		if candidate.PathID != path {
			continue
		}
		endpoint, err := netip.ParseAddrPort(candidate.Endpoint)
		if err != nil || candidate.State != "eligible" || candidate.Pin == nil {
			t.Fatal("requested fixture candidate is not eligible", err)
		}
		for _, underlay := range e.underlays {
			if underlay.ID == candidate.UnderlayID {
				reader := &preparationEndpointReader{t: t, underlay: underlay, wanted: endpoint.Addr().String(), source: "192.0.2.10"}
				e.collector = relayplan.LinuxCollector{ReadIP: reader.read}
				return e, PreparationIntent{PathID: path, Controller: report.ControllerID}, candidate, reader
			}
		}
	}
	t.Fatal("requested fixture path missing")
	return nil, PreparationIntent{}, relayplan.Candidate{}, nil
}

func TestPreparationApprovalDoesNotWaitForUnrelatedEndpoint(t *testing.T) {
	// p0's route is read before the unrelated endpoint; p7's is read after it.
	// Both pins must retain their original positions in the eight-path catalog.
	for _, path := range []string{"p0", "p7"} {
		t.Run(path, func(t *testing.T) {
			e, intent, want, reader := preparationEndpointFixture(t, path)
			reader.blockUnrelated = true
			ctx, cancel := context.WithTimeout(context.Background(), NodeRebuildDuration)
			defer cancel()
			got, until, reason, err := e.preparationApproval(ctx, intent)
			if err != nil {
				t.Fatalf("healthy candidate blocked by unrelated endpoint within %s: reason=%s err=%v target_reads=%d unrelated_reads=%d", NodeRebuildDuration, reason, err, reader.wantedReads, reader.unrelatedReads)
			}
			if ctx.Err() != nil || !time.Now().Before(until) || !reflect.DeepEqual(got.Candidate, want) {
				t.Fatal("current authority, fresh inventory or catalog slot changed", reason, ctx.Err())
			}
			if reader.wantedReads != 1 || reader.addresses != 2 || reader.unrelatedReads != 0 {
				t.Fatalf("incomplete or unrelated inventory work: target=%d address=%d unrelated=%d", reader.wantedReads, reader.addresses, reader.unrelatedReads)
			}
		})
	}
}

func TestPreparationApprovalEndpointStillRejectsCurrentFailure(t *testing.T) {
	for _, mode := range []string{"current-route-unavailable", "link-changed-during-readback"} {
		t.Run(mode, func(t *testing.T) {
			e, intent, _, reader := preparationEndpointFixture(t, "p7")
			reader.failWanted = mode == "current-route-unavailable"
			reader.changeLink = mode == "link-changed-during-readback"
			ctx, cancel := context.WithTimeout(context.Background(), NodeRebuildDuration)
			defer cancel()
			got, _, _, err := e.preparationApproval(ctx, intent)
			if err == nil || got.Candidate.Pin != nil || reader.wantedReads != 1 || reader.addresses != 2 {
				t.Fatal("current route or link readback failure accepted", err, reader.wantedReads, reader.addresses)
			}
		})
	}
}

func TestPreparationApprovalEndpointRechecksCurrentSource(t *testing.T) {
	e, intent, want, reader := preparationEndpointFixture(t, "p7")
	for _, source := range []string{"192.0.2.10", "192.0.2.11"} {
		reader.source = source
		before := reader.wantedReads
		ctx, cancel := context.WithTimeout(context.Background(), NodeRebuildDuration)
		got, _, _, err := e.preparationApproval(ctx, intent)
		cancel()
		if err != nil || got.Candidate.Pin == nil {
			t.Fatal("fresh current source rejected", err)
		}
		if reader.wantedReads != before+1 || got.Candidate.Pin.Source != source || got.Candidate.Pin.Table != want.Pin.Table {
			t.Fatal("stale current route or changed catalog slot", reader.wantedReads)
		}
	}
}

func TestPreparationApprovalEndpointUsesCurrentCatalog(t *testing.T) {
	for _, change := range []string{"previous-endpoint", "disabled", "draining"} {
		t.Run(change, func(t *testing.T) {
			e, intent, previous, reader := preparationEndpointFixture(t, "p7")
			intent.Previous = &PreparationIdentity{Pin: *previous.Pin}
			r, err := e.cache.Status()
			if err != nil {
				t.Fatal(err)
			}
			v := *r.Catalog
			v.Generation++
			for i := range v.Spec.Paths {
				if v.Spec.Paths[i].ID == intent.PathID {
					v.Spec.Paths[i].Disabled = change == "disabled"
					v.Spec.Paths[i].Drain = change == "draining"
				}
			}
			// The prior installation may refer to an endpoint that is no longer
			// approved. Its removal identity must never choose inventory input.
			intent.Previous.Pin.EndpointPrefix = "192.0.2.99/32"
			if _, err := e.cache.Refresh(context.Background(), observationIssuer{v}); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), NodeRebuildDuration)
			defer cancel()
			got, _, reason, err := e.preparationApproval(ctx, intent)
			if change == "previous-endpoint" {
				if err != nil || got.Candidate.Endpoint != previous.Endpoint || got.Candidate.Pin == nil || got.Candidate.Pin.EndpointPrefix != previous.Pin.EndpointPrefix || reader.wantedReads != 1 || reader.unrelatedReads != 0 {
					t.Fatal("previous endpoint reused instead of current approval", reason, err, reader.wantedReads, reader.unrelatedReads)
				}
			} else if err == nil || got.Candidate.Pin != nil || reason != change || reader.addresses != 0 || reader.wantedReads != 0 || reader.unrelatedReads != 0 {
				t.Fatal("excluded current path triggered collection or approval", reason, err, reader.addresses, reader.wantedReads, reader.unrelatedReads)
			}
		})
	}
}

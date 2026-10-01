// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayapply

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// A stopped supervisor cannot leave an indefinitely usable dataplane. The
// absolute cutoff also covers suspend; the timed set bounds clock rollback.
const DeploymentLeaseDuration = 10 * time.Second
const DeploymentRearmWindow = 5 * time.Second

var ErrLeaseExpired = errors.New("relay lease expired; fresh controller approval required")

type DeploymentLease struct {
	Active   bool      `json:"active"`
	Deadline time.Time `json:"deadline"`
}

func leaseTable(e DeploymentEntry) string { return "vl" + e.Interface[2:] }

func leaseRules(e DeploymentEntry, deadline time.Time) string {
	var out strings.Builder
	for _, hook := range []string{"input", "forward", "output"} {
		keys := []string{"iif"}
		if hook == "output" {
			keys = []string{"oif"}
		}
		if hook == "forward" {
			keys = []string{"iif", "oif"}
		}
		for _, key := range keys {
			fmt.Fprintf(&out, "add rule inet %s %s meta %s %d meta time >= %d drop comment %q\n", leaseTable(e), hook, key, e.LinkIndex, deadline.Unix(), e.Alias)
			fmt.Fprintf(&out, "add rule inet %s %s meta %s %d meta %s != @alive drop comment %q\n", leaseTable(e), hook, key, e.LinkIndex, key, e.Alias)
		}
	}
	return out.String()
}

func leaseExpected(e DeploymentEntry, deadline time.Time) []object {
	table := leaseTable(e)
	rows := []object{{"table": object{"family": "inet", "name": table}}, {"set": object{"family": "inet", "name": "alive", "table": table, "type": "iface_index", "size": 1, "flags": []string{"timeout"}, "timeout": int(DeploymentLeaseDuration.Seconds())}}}
	match := func(key, op string, right any) object {
		return object{"match": object{"op": op, "left": object{"meta": object{"key": key}}, "right": right}}
	}
	for _, hook := range []string{"input", "forward", "output"} {
		rows = append(rows, object{"chain": object{"family": "inet", "table": table, "name": hook, "type": "filter", "hook": hook, "prio": -300, "policy": "accept"}})
	}
	for _, hook := range []string{"input", "forward", "output"} {
		keys := []string{"iif"}
		if hook == "output" {
			keys = []string{"oif"}
		}
		if hook == "forward" {
			keys = []string{"iif", "oif"}
		}
		for _, key := range keys {
			for _, condition := range []object{match("time", ">=", deadline.UTC().Format("2006-01-02 15:04:05")), match(key, "!=", "@alive")} {
				rows = append(rows, object{"rule": object{"family": "inet", "table": table, "chain": hook, "comment": e.Alias, "expr": []any{match(key, "==", decimal(e.LinkIndex)), condition, object{"drop": nil}}}})
			}
		}
	}
	return rows
}

func (k deploymentKernel) nftRows(ctx context.Context, args ...string) ([]object, error) {
	b, err := k.run(ctx, "", "nft", append([]string{"-j", "-n", "-T"}, args...)...)
	if err != nil {
		return nil, err
	}
	var document struct {
		NFTables []object `json:"nftables"`
	}
	if len(b) > 512<<10 || json.Unmarshal(b, &document) != nil || document.NFTables == nil || len(document.NFTables) > 4096 {
		return nil, errors.New("invalid lease inventory")
	}
	return document.NFTables, nil
}

// validateLease strips only kernel-generated handles and countdown values.
// Every rule, chain, set property and owner comment must otherwise match.
func validateLease(rows []object, e DeploymentEntry) (DeploymentLease, error) {
	state := DeploymentLease{}
	clean := []object{}
	for _, row := range rows {
		if len(row) != 1 {
			return state, ErrConflict
		}
		if _, ok := row["metainfo"]; ok {
			continue
		}
		for kind, value := range row {
			x, ok := value.(map[string]any)
			if !ok {
				return state, ErrConflict
			}
			delete(x, "handle")
			if kind == "table" {
				if comment, ok := x["comment"]; ok {
					if comment != e.Alias {
						return state, ErrConflict
					}
					delete(x, "comment")
				}
			}
			if kind == "set" {
				if elems, ok := x["elem"]; ok {
					list, ok := elems.([]any)
					if !ok || len(list) > 1 {
						return state, ErrConflict
					}
					for _, v := range list {
						outer, ok := v.(map[string]any)
						if !ok || len(outer) != 1 {
							return state, ErrConflict
						}
						item, ok := outer["elem"].(map[string]any)
						if !ok || !only(object(item), "val", "expires", "timeout") {
							return state, ErrConflict
						}
						if !leaseIndex(item["val"], e) {
							return state, ErrConflict
						}
						left, ok := item["expires"].(float64)
						if !ok || left < 0 || left > DeploymentLeaseDuration.Seconds() {
							return state, ErrConflict
						}
						if raw, ok := item["timeout"]; ok {
							timeout, ok := raw.(float64)
							if !ok || timeout <= 0 || timeout > DeploymentLeaseDuration.Seconds() || left > timeout {
								return state, ErrConflict
							}
						}
						// JSON rounds remaining time to seconds. At zero, do
						// not infer that a cached approval may rearm the gate.
						state.Active = left > 0
					}
					delete(x, "elem")
				}
			}
			if kind == "rule" {
				exprs, ok := x["expr"].([]any)
				if !ok {
					return state, ErrConflict
				}
				for _, raw := range exprs {
					expr, _ := raw.(map[string]any)
					m, _ := expr["match"].(map[string]any)
					left, _ := m["left"].(map[string]any)
					meta, _ := left["meta"].(map[string]any)
					if meta["key"] == "time" {
						s, ok := m["right"].(string)
						if !ok {
							return state, ErrConflict
						}
						d, err := time.ParseInLocation("2006-01-02 15:04:05", s, time.UTC)
						if err != nil || d.Unix() < 1 || d.Unix() > 1<<32-1 {
							return state, ErrConflict
						}
						if !state.Deadline.IsZero() && !state.Deadline.Equal(d) {
							return state, ErrConflict
						}
						state.Deadline = d
					}
					if (meta["key"] == "iif" || meta["key"] == "oif") && m["op"] == "==" && leaseIndex(m["right"], e) {
						m["right"] = decimal(e.LinkIndex)
					}
				}
			}
		}
		clean = append(clean, row)
	}
	if state.Deadline.IsZero() || deploymentHash(clean) != deploymentHash(leaseExpected(e, state.Deadline)) {
		return state, ErrConflict
	}
	state.Active = state.Active && time.Now().Before(state.Deadline)
	return state, nil
}
func leaseIndex(v any, e DeploymentEntry) bool {
	s, ok := v.(string)
	if ok {
		return s == decimal(e.LinkIndex) || s == e.Interface
	}
	n, ok := v.(float64)
	return ok && n == float64(e.LinkIndex)
}

func (k deploymentKernel) leaseRead(ctx context.Context, e DeploymentEntry) (DeploymentLease, bool, error) {
	rows, err := k.nftRows(ctx, "list", "tables")
	if err != nil {
		return DeploymentLease{}, false, err
	}
	exists := false
	for _, r := range rows {
		if table, ok := r["table"].(map[string]any); ok && table["family"] == "inet" && table["name"] == leaseTable(e) {
			exists = true
		}
	}
	if !exists {
		return DeploymentLease{}, false, nil
	}
	rows, err = k.nftRows(ctx, "list", "table", "inet", leaseTable(e))
	if err != nil {
		return DeploymentLease{}, true, err
	}
	s, err := validateLease(rows, e)
	return s, true, err
}

func (k deploymentKernel) noFlowtables(ctx context.Context) error {
	rows, err := k.nftRows(ctx, "list", "flowtables")
	if err != nil {
		return err
	}
	for _, r := range rows {
		if _, meta := r["metainfo"]; !meta {
			return errors.New("flow offload is incompatible with relay lease enforcement")
		}
	}
	return nil
}

func (k deploymentKernel) leaseCreate(ctx context.Context, e DeploymentEntry) error {
	if _, exists, err := k.leaseRead(ctx, e); err != nil {
		return err
	} else if exists {
		return ErrConflict
	}
	if err := k.noFlowtables(ctx); err != nil {
		return err
	}
	table := leaseTable(e)
	script := fmt.Sprintf("create table inet %s { comment %q; }\nadd set inet %s alive { type iface_index; flags timeout; timeout %ds; size 1; }\n", table, e.Alias, table, int(DeploymentLeaseDuration.Seconds()))
	for _, hook := range []string{"input", "forward", "output"} {
		script += fmt.Sprintf("add chain inet %s %s { type filter hook %s priority -300; policy accept; }\n", table, hook, hook)
	}
	script += leaseRules(e, time.Unix(1, 0))
	_, err := k.run(ctx, script, "nft", "-f", "/dev/stdin")
	return err
}

func leaseDeadline(active bool, expiry, authenticatedAt, now time.Time) (time.Time, error) {
	deadline := now.Add(DeploymentLeaseDuration)
	if expiry.Before(deadline) {
		deadline = expiry
	}
	if !active {
		// Bound the *resulting lease*, not just the age at a check that could
		// be followed by SIGSTOP, suspend or a stalled kernel command.
		if authenticatedAt.IsZero() || authenticatedAt.After(now) || !now.Before(authenticatedAt.Add(DeploymentRearmWindow)) {
			return time.Time{}, ErrLeaseExpired
		}
		if limit := authenticatedAt.Add(DeploymentRearmWindow); limit.Before(deadline) {
			deadline = limit
		}
	}
	deadline = deadline.Truncate(time.Second)
	if !now.Before(deadline) {
		if !active {
			return time.Time{}, ErrLeaseExpired
		}
		return time.Time{}, errors.New("relay approval has no remaining lease time")
	}
	return deadline, nil
}

func (k deploymentKernel) Lease(ctx context.Context, e DeploymentEntry, approvalExpiry, authenticatedAt time.Time) (DeploymentLease, error) {
	state, exists, err := k.leaseRead(ctx, e)
	if err != nil {
		return state, err
	}
	if !exists {
		return state, errors.New("relay lease missing")
	}
	if err = k.noFlowtables(ctx); err != nil {
		return state, err
	}
	deadline, err := leaseDeadline(state.Active, approvalExpiry, authenticatedAt, time.Now().UTC())
	if err != nil {
		return state, err
	}
	// A backward wall-clock step cannot turn a nearly expired approval into
	// another full lease period. Both clocks are bounded by remaining approval.
	timeoutMS := time.Until(deadline).Milliseconds()
	if timeoutMS < 1 && !state.Active {
		return state, ErrLeaseExpired // The already-closed rearm window elapsed before commit.
	}
	if timeoutMS < 1 || timeoutMS > DeploymentLeaseDuration.Milliseconds() {
		return state, errors.New("relay lease clock changed before commit")
	}
	table := leaseTable(e)
	script := fmt.Sprintf("flush set inet %s alive\nadd element inet %s alive { %d timeout %dms }\n", table, table, e.LinkIndex, timeoutMS)
	for _, hook := range []string{"input", "forward", "output"} {
		script += fmt.Sprintf("flush chain inet %s %s\n", table, hook)
	}
	script += leaseRules(e, deadline)
	if _, err = k.run(ctx, script, "nft", "-f", "/dev/stdin"); err != nil {
		return state, err
	}
	state, exists, err = k.leaseRead(ctx, e)
	if err == nil {
		if !exists || !state.Deadline.Equal(deadline) {
			err = errors.New("relay lease readback incomplete")
		} else if !state.Active {
			// The short rearm lease may expire (or round to a zero-second
			// countdown) between commit and readback. Its guard is intact and
			// closed; keep the link for a fresh response instead of tearing it
			// down as though the validated kernel inventory were corrupt.
			err = ErrLeaseExpired
		}
	}
	return state, err
}

func (k deploymentKernel) leaseBlock(ctx context.Context, e DeploymentEntry) error {
	_, exists, err := k.leaseRead(ctx, e)
	if err != nil || !exists {
		return err
	}
	_, err = k.run(ctx, "flush set inet "+leaseTable(e)+" alive\n", "nft", "-f", "/dev/stdin")
	return err
}
func (k deploymentKernel) leaseRemove(ctx context.Context, e DeploymentEntry) error {
	_, exists, err := k.leaseRead(ctx, e)
	if err != nil || !exists {
		return err
	}
	_, err = k.run(ctx, "delete table inet "+leaseTable(e)+"\n", "nft", "-f", "/dev/stdin")
	return err
}

func (k deploymentKernel) LeaseStatus(ctx context.Context, e DeploymentEntry) (DeploymentLease, error) {
	if err := k.noFlowtables(ctx); err != nil {
		return DeploymentLease{}, err
	}
	s, exists, err := k.leaseRead(ctx, e)
	if err == nil && !exists {
		err = errors.New("relay lease missing")
	}
	return s, err
}

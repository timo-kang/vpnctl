// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayapply

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

func stagedLeaseTestRows(e DeploymentEntry, deadline time.Time, selected, pending string) []object {
	rows := leaseExpected(e, deadline)
	rows[1]["set"].(object)["name"] = selected
	rows[1]["set"].(object)["comment"] = e.Alias
	for _, row := range rows {
		if rule, ok := row["rule"].(object); ok {
			for _, raw := range rule["expr"].([]any) {
				if m, ok := raw.(object)["match"].(object); ok && m["right"] == "@alive" {
					m["right"] = "@" + selected
				}
			}
		}
	}
	if pending != "" {
		set := object{"family": "inet", "table": leaseTable(e), "name": pending, "type": "iface_index", "size": 1, "flags": []string{"timeout"}, "timeout": 10, "comment": e.Alias}
		rows = append(rows, object{"set": set})
	}
	return rows
}

func TestStagedLeaseCancelledPreparationStaysClosedAndIsReclaimed(t *testing.T) {
	engine, _, _, _, options, _ := deploymentFixture(t, 1)
	approval, _ := engine.cache.Status()
	e, _ := desiredDeployment(approval, options.EndpointID, options.ListenPort)
	e.Alias, e.Group, e.LinkIndex, _ = token()
	selected := "lease_00000000000000000000000000000001"
	pending := ""
	deadline := time.Unix(1, 0)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cancelPreparation, active, activations, preparations := true, false, 0, 0
	k := deploymentKernel{kernel{run: func(_ context.Context, input, name string, args ...string) ([]byte, error) {
		encode := func(rows []object) ([]byte, error) { return json.Marshal(object{"nftables": rows}) }
		switch strings.Join(args, " ") {
		case "-j -n -T list tables":
			return encode(leaseExpected(e, deadline)[:1])
		case "-j -n -T list flowtables":
			return encode([]object{})
		case "-j -n -T list table inet " + leaseTable(e):
			rows := stagedLeaseTestRows(e, deadline, selected, pending)
			if active {
				rows[1]["set"].(object)["elem"] = []any{object{"elem": object{"val": e.LinkIndex, "expires": 2}}}
			}
			return encode(rows)
		case "-f /dev/stdin":
			if strings.Contains(input, "create set") {
				preparations++
				if pending != "" && !strings.Contains(input, "delete set inet "+leaseTable(e)+" "+pending) {
					t.Fatal("abandoned timer not reclaimed")
				}
				match := regexp.MustCompile(`create set inet [^ ]+ (lease_[0-9a-f]{32})`).FindStringSubmatch(input)
				if len(match) != 2 || match[1] == pending || match[1] == selected {
					t.Fatal("timer name reused", input)
				}
				pending = match[1]
				if strings.Contains(input, "flush chain") {
					t.Fatal("preparation granted traffic")
				}
				if cancelPreparation {
					cancel()
				}
				return nil, nil
			}
			activations++
			if strings.Contains(input, "add element") || strings.Contains(input, "timeout") || strings.Contains(input, "create set") {
				t.Fatal("activation can restart timer", input)
			}
			match := regexp.MustCompile(`meta time >= ([0-9]+)`).FindStringSubmatch(input)
			if len(match) != 2 {
				t.Fatal(input)
			}
			n, err := strconv.ParseInt(match[1], 10, 64)
			if err != nil {
				t.Fatal(err)
			}
			deadline = time.Unix(n, 0).UTC()
			selected, pending, active = pending, "", true
			return nil, nil
		default:
			t.Fatal(name, args)
			return nil, errors.New("unexpected command")
		}
	}}}
	if _, err := k.Lease(ctx, e, time.Now().Add(time.Hour), time.Now()); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if activations != 0 || pending == "" || active {
		t.Fatal("cancelled preparation selected", activations, pending, active)
	}
	cancelPreparation = false
	if state, err := k.Lease(context.Background(), e, time.Now().Add(time.Hour), time.Now()); err != nil || !state.Active {
		t.Fatal(state, err)
	}
	if preparations != 2 || activations != 1 || pending != "" {
		t.Fatal(preparations, activations, pending)
	}
}

func TestLeaseV1UpgradeQuiescesInsteadOfRenewing(t *testing.T) {
	e, k, c, _, options, _ := deploymentFixture(t, 1)
	if _, err := e.Apply(context.Background(), options); err != nil {
		t.Fatal(err)
	}
	e.journal.Entries[0].LeaseVersion = 1
	if err := e.persist(); err != nil {
		t.Fatal(err)
	}
	if e.result("", "").ExpiryEnforcement != "legacy_upgrade_required" {
		t.Fatal("v1 reported protected")
	}
	upgraded, err := openDeploymentEngine(c, "boot:net", k)
	if err != nil {
		t.Fatal(err)
	}
	if result, err := upgraded.Maintain(context.Background(), time.Now()); err != nil || result.State != "empty" || len(k.objects) != 0 {
		t.Fatal("v1 renewed", result, err)
	}
}

func TestStagedLeaseInventoryRequiresExactOwnershipAndSelection(t *testing.T) {
	engine, _, _, _, options, _ := deploymentFixture(t, 1)
	approval, _ := engine.cache.Status()
	e, _ := desiredDeployment(approval, options.EndpointID, options.ListenPort)
	e.Alias, e.Group, e.LinkIndex, _ = token()
	selected := "lease_00000000000000000000000000000001"
	pending := "lease_00000000000000000000000000000002"
	for _, mode := range []string{"valid", "metainfo", "pending-live-selected-dead", "pending-expired", "foreign-pending", "extra-rule", "duplicate", "third-set", "invalid-name", "wrong-selection", "missing-selected", "extra-property", "unbounded-pending"} {
		t.Run(mode, func(t *testing.T) {
			rows := stagedLeaseTestRows(e, time.Now().Add(8*time.Second).Truncate(time.Second), selected, pending)
			rows[1]["set"].(object)["elem"] = []any{object{"elem": object{"val": e.LinkIndex, "expires": 7}}}
			last := rows[len(rows)-1]["set"].(object)
			last["elem"] = []any{object{"elem": object{"val": e.LinkIndex, "expires": 7}}}
			switch mode {
			case "metainfo":
				rows = append([]object{{"metainfo": object{"version": "1.0.9"}}}, rows...)
			case "pending-live-selected-dead":
				delete(rows[1]["set"].(object), "elem")
			case "pending-expired":
				delete(last, "elem")
			case "foreign-pending":
				last["comment"] = "foreign"
			case "extra-rule":
				rows = append(rows, rows[5])
			case "duplicate":
				rows = append(rows, rows[1])
			case "third-set":
				copy := object{}
				for k, v := range last {
					copy[k] = v
				}
				copy["name"] = "lease_00000000000000000000000000000003"
				rows = append(rows, object{"set": copy})
			case "invalid-name":
				last["name"] = "lease_bad"
			case "wrong-selection":
				rows[6]["rule"].(object)["expr"].([]any)[1].(object)["match"].(object)["right"] = "@" + pending
			case "missing-selected":
				rows = append(rows[:1], rows[2:]...)
			case "extra-property":
				last["policy"] = "memory"
			case "unbounded-pending":
				last["timeout"] = 30
			}
			b, _ := json.Marshal(rows)
			json.Unmarshal(b, &rows)
			state, err := validateStagedLease(rows, e)
			valid := mode == "valid" || mode == "metainfo" || mode == "pending-live-selected-dead" || mode == "pending-expired"
			if (err == nil) != valid {
				t.Fatal(state, err)
			}
			if valid && (state.Active != (mode != "pending-live-selected-dead") || state.set != selected || len(state.staged) != 1 || state.staged[0] != pending) {
				t.Fatal(state)
			}
		})
	}
}

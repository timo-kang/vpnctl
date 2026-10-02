// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayapply

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"testing"
	"time"

	"vpnctl/internal/relaycatalog"
)

func policyFixture(t *testing.T) DeploymentEntry {
	t.Helper()
	e, _, _, _, options, _ := deploymentFixture(t, 3)
	r, err := e.cache.Status()
	if err != nil {
		t.Fatal(err)
	}
	v, err := desiredDeployment(r, options.EndpointID, options.ListenPort)
	if err != nil {
		t.Fatal(err)
	}
	v.Alias, v.Group, v.LinkIndex, err = token()
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestDeploymentGrantsKeepSourceTargetPairs(t *testing.T) {
	v := &relaycatalog.DeploymentView{Spec: relaycatalog.Spec{
		Targets: []relaycatalog.Target{{ID: "b", Prefixes: []string{"198.18.1.0/24"}}, {ID: "a", Prefixes: []string{"198.18.0.0/24"}}},
		Paths:   []relaycatalog.Path{{ID: "pa", EndpointID: "ep", TargetIDs: []string{"a"}}, {ID: "pb", EndpointID: "ep", TargetIDs: []string{"b"}}, {ID: "pc", EndpointID: "other", TargetIDs: []string{"a", "b"}}},
	}, Bindings: []relaycatalog.Binding{{PathID: "pa", InnerAddress: "10.78.0.1/32"}, {PathID: "pb", InnerAddress: "10.78.0.2/32"}, {PathID: "pc", InnerAddress: "10.78.0.3/32"}}}
	got := deploymentGrants(v, "ep")
	if len(got) != 2 || got[0].Target != "a" || !slices.Equal(got[0].Sources, []string{"10.78.0.1/32"}) || got[1].Target != "b" || !slices.Equal(got[1].Sources, []string{"10.78.0.2/32"}) {
		t.Fatal(got)
	}
	if len(deploymentGrants(v, "absent")) != 0 {
		t.Fatal("unknown endpoint got forwarding grants")
	}
}

func TestDeploymentPolicyExactReadback(t *testing.T) {
	e := policyFixture(t)
	for _, mode := range []string{"exact", "reordered-sets", "numeric-ifindex", "named-ifindex", "missing-rule", "extra-accept", "source-added", "target-expanded", "set-owner", "rule-owner", "hook", "priority", "state-new", "extra-property", "duplicate-set", "reordered-rules"} {
		t.Run(mode, func(t *testing.T) {
			wire, _ := json.Marshal(policyExpected(e))
			var rows []object
			json.Unmarshal(wire, &rows)
			var rules []map[string]any
			var sets []map[string]any
			for _, r := range rows {
				if x, ok := r["rule"].(map[string]any); ok {
					rules = append(rules, x)
				}
				if x, ok := r["set"].(map[string]any); ok {
					sets = append(sets, x)
				}
			}
			switch mode {
			case "reordered-sets":
				slices.Reverse(sets[0]["elem"].([]any))
				rows[1], rows[2] = rows[2], rows[1]
			case "numeric-ifindex", "named-ifindex":
				for _, rule := range rules {
					m := rule["expr"].([]any)[0].(map[string]any)["match"].(map[string]any)
					m["right"] = decimal(e.LinkIndex)
					if mode == "named-ifindex" {
						m["right"] = e.Interface
					}
				}
			case "missing-rule":
				rows = rows[:len(rows)-1]
			case "extra-accept":
				rules[1]["expr"].([]any)[3] = map[string]any{"accept": nil}
			case "source-added":
				sets[0]["elem"] = append(sets[0]["elem"].([]any), "10.78.255.255")
			case "target-expanded":
				sets[1]["elem"] = []any{"0.0.0.0"}
			case "set-owner":
				sets[0]["comment"] = "foreign"
			case "rule-owner":
				rules[0]["comment"] = "foreign"
			case "hook":
				rows[3]["chain"].(map[string]any)["hook"] = "prerouting"
			case "priority":
				rows[3]["chain"].(map[string]any)["prio"] = 1
			case "state-new":
				rules[2]["expr"].([]any)[3].(map[string]any)["match"].(map[string]any)["right"] = 8
			case "extra-property":
				sets[0]["timeout"] = 10
			case "duplicate-set":
				rows = append(rows, rows[1])
			case "reordered-rules":
				rows[len(rows)-3], rows[len(rows)-5] = rows[len(rows)-5], rows[len(rows)-3]
			}
			valid := mode == "exact" || mode == "reordered-sets" || mode == "numeric-ifindex" || mode == "named-ifindex"
			if err := validatePolicy(rows, e); (err == nil) != valid {
				t.Fatal(mode, err)
			}
		})
	}
}

func TestDeploymentPolicyTargetsInvalidateInstalledPeer(t *testing.T) {
	e, k, cache, issuer, options, _ := deploymentFixture(t, 1)
	if _, err := e.Apply(context.Background(), options); err != nil {
		t.Fatal(err)
	}
	// Changing the target definition while preserving the peer/key/address must
	// quiesce the old permission; a later explicit apply installs the new one.
	issuer.view.Generation++
	issuer.view.Spec.Targets[0].Prefixes = []string{"198.18.0.0/24"}
	for i := range issuer.view.Bindings {
		b := &issuer.view.Bindings[i]
		for _, p := range issuer.view.Spec.Paths {
			if p.ID == b.PathID {
				b.DefinitionHash = relaycatalog.DefinitionHash(issuer.view.Spec, p)
			}
		}
	}
	if _, err := cache.Refresh(context.Background(), issuer); err != nil {
		t.Fatal(err)
	}
	if result, err := e.Maintain(context.Background(), FreshApproval{At: time.Now()}); err != nil || result.State != "empty" || len(k.objects) != 0 {
		t.Fatal(result, err)
	}
	if _, err := e.Apply(context.Background(), options); err != nil {
		t.Fatal(err)
	}
	if got := e.journal.Entries[0].Grants[0].Prefixes; !slices.Equal(got, []string{"198.18.0.0/24"}) {
		t.Fatal(got)
	}
}

func TestDeploymentPolicyLegacyUpgradeQuiesces(t *testing.T) {
	e, k, cache, _, options, _ := deploymentFixture(t, 1)
	if _, err := e.Apply(context.Background(), options); err != nil {
		t.Fatal(err)
	}
	e.journal.Entries[0].PolicyVersion = 0
	e.journal.Entries[0].Grants = nil
	if err := e.persist(); err != nil {
		t.Fatal(err)
	}
	upgraded, err := openDeploymentEngine(cache, "boot:net", k)
	if err != nil {
		t.Fatal(err)
	}
	if upgraded.result("", "").ForwardingPolicy != "legacy_upgrade_required" {
		t.Fatal("legacy advertised forwarding policy")
	}
	if result, err := upgraded.Maintain(context.Background(), FreshApproval{At: time.Now()}); err != nil || result.State != "empty" || len(k.objects) != 0 {
		t.Fatal(result, err)
	}
}

func TestDeploymentPolicyCapacityRemainsBounded(t *testing.T) {
	e := policyFixture(t)
	e.Peers, e.Grants = nil, nil
	sources := []string{}
	for i := 0; i < relaycatalog.MaxNodes*relaycatalog.MaxPathsPerNode; i++ {
		source := fmt.Sprintf("10.78.%d.%d/32", i/250, i%250+1)
		sources = append(sources, source)
		e.Peers = append(e.Peers, DeploymentPeer{PathID: fmt.Sprintf("p%d", i), PublicKey: public(fmt.Sprint(i)), Address: source})
	}
	slices.Sort(sources)
	for i := 0; i < relaycatalog.MaxTargets; i++ {
		g := DeploymentGrant{Target: fmt.Sprintf("t%02d", i), Sources: slices.Clone(sources)}
		for j := 0; j < 8; j++ {
			g.Prefixes = append(g.Prefixes, fmt.Sprintf("198.19.%d.%d/32", i, j+1))
		}
		e.Grants = append(e.Grants, g)
	}
	if err := validateDeploymentGrants(e); err != nil {
		t.Fatal(err)
	}
	wire, _ := json.Marshal(policyExpected(e))
	if len(wire) > 400<<10 || len(policyScript(e)) > 200<<10 {
		t.Fatal("policy exceeds bounded command budget", len(wire), len(policyScript(e)))
	}
	var rows []object
	json.Unmarshal(wire, &rows)
	if err := validatePolicy(rows, e); err != nil {
		t.Fatal(err)
	}
}

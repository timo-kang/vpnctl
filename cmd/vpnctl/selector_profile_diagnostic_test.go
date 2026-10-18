//go:build linux && vpnctl_profile

package main

import "testing"

func TestSelectorProfileCommandIsolation(t *testing.T) {
	args := []string{"node", "relay", "target", "reconcile", "--config", "/private/node.yaml", "--target-id", "app2", "--watch", "--interval", "500ms"}
	if !selectorProfileCommand("1", args) {
		t.Fatal("fixture selector rejected")
	}
	for _, worker := range []string{"", "0", "true"} {
		if selectorProfileCommand(worker, args) {
			t.Fatal("non-worker enabled")
		}
	}
	for _, changed := range [][]string{
		nil, {"version"}, {"node", "relay", "target", "reconcile", "--target-id", "app2"},
		{"node", "relay", "target", "reconcile", "--target-id", "app", "--watch"},
		{"node", "relay", "select", "--target-id", "app2", "--watch"},
		append(append([]string{}, args...), "--target-id", "app2"),
		append(append([]string{}, args...), "--target-id=app"),
	} {
		if selectorProfileCommand("1", changed) {
			t.Fatal("non-fixture command enabled", changed)
		}
	}
}

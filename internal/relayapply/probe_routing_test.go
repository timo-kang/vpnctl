// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayapply

import (
	"context"
	"strings"
	"testing"
)

func TestProbePrepareFailureAndCrashRecovery(t *testing.T) {
	for _, step := range []string{"probe-targets", "probe-source"} {
		for _, mode := range []string{"before", "after", "crash", "save-failure"} {
			t.Run(step+"/"+mode, func(t *testing.T) {
				e, k, dir := fixture(t, "robot")
				k.fail, k.after, k.crash = step, mode != "before", mode == "crash"
				if mode == "save-failure" {
					k.fail = ""
					e.save = func([]byte) error { return ErrConflict }
				}
				if k.crash {
					func() {
						defer func() {
							if recover() == nil {
								t.Error("expected crash")
							}
						}()
						e.PrepareProbe(context.Background(), "p0", "")
					}()
					e = reopen(t, e, dir)
					if _, err := e.Recover(context.Background()); err != nil {
						t.Fatal(err)
					}
				} else {
					if _, err := e.PrepareProbe(context.Background(), "p0", ""); err == nil {
						t.Fatal("failure not surfaced")
					}
				}
				if len(k.objects) != 0 {
					t.Fatal("leaked candidate resources", k.objects)
				}
				if mode == "save-failure" {
					if k.steps != 0 {
						t.Fatal("mutated before durable intent")
					}
					return
				}
				k.fail, k.crash = "", false
				if _, err := e.PrepareProbe(context.Background(), "p0", ""); err != nil {
					t.Fatal(err)
				}
				before := k.steps
				if _, err := e.PrepareProbe(context.Background(), "p0", ""); err != nil || before != k.steps {
					t.Fatal("non-idempotent", err)
				}
				if _, err := e.Prepare(context.Background(), "p0", ""); err == nil {
					t.Fatal("silently changed probe mode")
				}
				if _, err := e.Release(context.Background(), "p0"); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}
func TestProbeRoutesRecognizeOnlyOwnedResources(t *testing.T) {
	for _, mode := range []string{"owned", "foreign-metric", "foreign-prefix", "foreign-source", "foreign-rule", "duplicate-rule", "priority-collision", "earlier-source-capture", "earlier-unrelated-source", "foreign-route-field"} {
		t.Run(mode, func(t *testing.T) {
			e, s := kernelFixture(t)
			e.ProbeRouting = true
			route := object{"dst": "198.18.0.2", "dev": e.Candidate.Pin.WGInterface, "prefsrc": strings.TrimSuffix(e.Candidate.InnerAddress, "/32"), "table": decimal(e.Candidate.Pin.Table), "protocol": "186", "metric": decimal(e.Metric), "scope": "link"}
			rule := object{"priority": decimal(probePriority(e)), "src": strings.TrimSuffix(e.Candidate.InnerAddress, "/32"), "table": decimal(e.Candidate.Pin.Table), "protocol": "186"}
			s.routes = append(s.routes, route)
			s.rules = append(s.rules, rule)
			switch mode {
			case "foreign-metric":
				route["metric"] = decimal(e.Metric + 1)
			case "foreign-prefix":
				route["dst"] = "203.0.113.2"
			case "foreign-source":
				route["prefsrc"] = "10.78.1.99"
			case "foreign-rule":
				rule["src"] = "all"
			case "duplicate-rule":
				s.rules = append(s.rules, rule)
			case "priority-collision":
				s.rules = append(s.rules, object{"priority": decimal(probePriority(e)), "src": "10.78.1.99", "table": "22"})
			case "earlier-source-capture":
				s.rules = append(s.rules, object{"priority": "27999", "src": "10.78.0.0/24", "table": "22"})
			case "earlier-unrelated-source":
				s.rules = append(s.rules, object{"priority": "27999", "src": "10.99.0.1/32", "table": "22"})
			case "foreign-route-field":
				route["nhid"] = "1"
			}
			err := conflicts(s, e, false)
			good := mode == "owned" || mode == "earlier-unrelated-source"
			if (err == nil) != good {
				t.Fatal(mode, err)
			}
			if conflicts(s, e, true) == nil {
				t.Fatal("fresh prepare adopted resources")
			}
		})
	}
}

func TestProbePrepareFinalSaveFailureRecoversDurableIntent(t *testing.T) {
	e, k, dir := fixture(t, "robot")
	save := e.save
	count := 0
	e.save = func(b []byte) error {
		count++
		if count == 2 {
			return ErrConflict
		}
		return save(b)
	}
	if _, err := e.PrepareProbe(context.Background(), "p0", ""); err == nil || !e.uncertain {
		t.Fatal("failed commit was accepted", err)
	}
	if len(k.objects["p0"]) != 10 {
		t.Fatal("fault was not after all prepare steps")
	}
	e = reopen(t, e, dir)
	if _, err := e.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(k.objects) != 0 {
		t.Fatal("recovered intent left probe resources")
	}
}

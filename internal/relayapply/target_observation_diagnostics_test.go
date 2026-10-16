// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayapply

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"
	"time"

	"vpnctl/internal/relayobserve"
)

func TestObservationStageDiagnosticsSeparateWaitingFromCommands(t *testing.T) {
	for _, phase := range []string{"precheck", "postcheck"} {
		for _, canceled := range []bool{false, true} {
			name := phase + "/granted"
			if canceled {
				name = phase + "/canceled"
			}
			t.Run(name, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					count := 1
					if phase == "precheck" {
						count = 2
					}
					gates := newObservationGates(count)
					release, err := gates[0].acquire(context.Background(), true)
					if err != nil {
						t.Fatal(err)
					}
					parent, cancel := context.WithCancel(context.Background())
					defer cancel()
					ctx, recorder := relayobserve.Start(parent)
					completed := make(chan error, 1)
					go func() {
						work, done, err := observationStage(ctx, phase, gates[count-1])
						if err == nil {
							commandDone := relayobserve.Command(work, false)
							time.Sleep(7 * time.Millisecond)
							commandDone()
						}
						done()
						completed <- err
					}()
					synctest.Wait()
					time.Sleep(20 * time.Millisecond)
					if canceled {
						cancel()
					} else {
						release()
					}
					err = <-completed
					if canceled {
						release()
					}
					if canceled && !errors.Is(err, context.Canceled) || !canceled && err != nil {
						t.Fatal("diagnostics changed admission result", err)
					}
					d := recorder.Snapshot()
					wait, total := d.Phases[phase+"_wait"], d.Phases[phase]
					if wait.Calls != 1 || wait.Duration != 20*time.Millisecond || wait.KernelCommands != 0 || wait.InventoryCommands != 0 || wait.CommandDuration != 0 {
						t.Fatalf("gate wait includes work or is missing: %+v", d.Phases)
					}
					workTime, commands := 7*time.Millisecond, 1
					if canceled {
						workTime, commands = 0, 0
					}
					if total.Calls != 1 || total.Duration != wait.Duration+workTime || total.KernelCommands != commands || total.CommandDuration != workTime {
						t.Fatalf("parent phase lost work/wait attribution: %+v", d.Phases)
					}
				})
			})
		}
	}
}

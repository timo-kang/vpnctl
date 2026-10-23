// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayapply

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"
)

// Keep the original 23 writes, but identify them within their installation
// operation. A deadline adds failure/cleanup writes and may replace an owner;
// counting every save globally would inject at a different durability boundary.
type installationStorageBoundary struct{ stage, write int }

const (
	storageEnrollment = -2
	storageOwnership  = -1
	storageCleanup    = -3
)

func installationBoundary(point int) installationStorageBoundary {
	switch {
	case point == 1:
		return installationStorageBoundary{storageEnrollment, 1}
	case point <= 3:
		return installationStorageBoundary{storageOwnership, point - 1}
	case point <= 21:
		return installationStorageBoundary{(point - 4) / 3, (point-4)%3 + 1}
	default:
		return installationStorageBoundary{len(deploymentInstallSteps), point - 21}
	}
}

type installationBoundaryCache struct {
	deploymentCache
	target, current installationStorageBoundary
	failures        int
	after, hit      bool
	hitAt           installationStorageBoundary
	hitBytes        []byte
	beforeBytes     []byte
	deadlines       int
}

func (c *installationBoundaryCache) begin(e *DeploymentEngine) {
	c.current = installationStorageBoundary{stage: storageOwnership}
	p := e.journal.Installations[0]
	c.failures = p.Failures
	if i := e.index(p.Endpoint); i >= 0 {
		c.current.stage = p.Step
		if p.InFlight || e.journal.Entries[i].Phase == "releasing" {
			c.current.stage = storageCleanup
		}
	}
}

func (c *installationBoundaryCache) SaveDeploymentJournal(b []byte) error {
	var env deploymentEnvelope
	if err := json.Unmarshal(b, &env); err != nil {
		return err
	}
	if len(env.Journal.Installations) != 1 {
		return errors.New("storage matrix lost its single installation")
	}
	p := env.Journal.Installations[0]
	// These are recovery writes, not a substitute for the requested fault.
	if c.current.stage == storageCleanup || p.Failures > c.failures {
		return c.deploymentCache.SaveDeploymentJournal(b)
	}
	c.current.write++
	if err := checkInstallationBoundaryShape(c.current, env.Journal); err != nil {
		return err
	}
	if c.current == c.target {
		if c.hit {
			return errors.New("storage boundary injected more than once")
		}
		previous, err := c.deploymentCache.DeploymentJournal()
		if err != nil {
			return err
		}
		c.beforeBytes = append([]byte(nil), previous...)
		c.hit, c.hitAt = true, c.current
		c.hitBytes = append([]byte(nil), b...)
		if c.after {
			if err := c.deploymentCache.SaveDeploymentJournal(b); err != nil {
				return err
			}
		}
		return errDeploymentStorageInjected
	}
	return c.deploymentCache.SaveDeploymentJournal(b)
}

// Check the actual bytes, not only a counter: cursor, in-flight, completion,
// ownership and final applied writes must retain their original meaning.
func checkInstallationBoundaryShape(at installationStorageBoundary, j deploymentJournal) error {
	p := j.Installations[0]
	step, inFlight, entries, phase := 0, false, 0, "preparing"
	valid := true
	switch at.stage {
	case storageEnrollment:
		valid = at.write == 1 && j.InstallCursor == ""
	case storageOwnership:
		valid = at.write == 1 || at.write == 2
		if at.write == 2 {
			entries = 1
		}
	default:
		entries, step = 1, at.stage
		if at.stage == len(deploymentInstallSteps) {
			valid = at.write == 1 || at.write == 2
			if at.write == 2 {
				phase = "applied"
			}
		} else {
			valid = at.stage >= 0 && at.stage < len(deploymentInstallSteps) && at.write >= 1 && at.write <= 3
			inFlight = at.write == 2
			if at.write == 3 {
				step++
			}
		}
	}
	valid = valid && p.Step == step && p.InFlight == inFlight && len(j.Entries) == entries
	if at.stage != storageEnrollment {
		valid = valid && j.InstallCursor == p.Endpoint
	}
	if entries == 1 && len(j.Entries) == 1 {
		valid = valid && j.Entries[0].Phase == phase
	}
	if !valid {
		return fmt.Errorf("unexpected storage boundary shape: stage=%d write=%d step=%d in_flight=%t entries=%d", at.stage, at.write, p.Step, p.InFlight, len(j.Entries))
	}
	return nil
}

// Stop only at the requested storage fault. Ordinary deadlines get the same
// bounded conservative recovery as installationReady: real backoff, fresh
// witnesses, at most three recoveries, 12 progress turns and a 30s outer bound.
func reachInstallationStorageBoundary(ctx context.Context, e *DeploymentEngine, fault *installationBoundaryCache) error {
	recoveries := 0
	for progress := 0; progress < 12; {
		if err := waitInstallationTestRetry(ctx, e, ""); err != nil {
			return err
		}
		fresh, err := ObserveApproval()
		if err != nil {
			return err
		}
		fault.begin(e)
		_, err = e.RebuildInstallations(ctx, fresh)
		if invalid := installationTestClosed(ctx, e); invalid != nil {
			return errors.Join(err, invalid)
		}
		if err != nil {
			if ctx.Err() != nil || e.uncertain || !installationDeadlineOnly(err) {
				return err
			}
			recoveries++
			fault.deadlines++
			if recoveries > 3 {
				return fmt.Errorf("storage matrix exceeded three deadline recoveries: %w", err)
			}
			progress = 0
			continue
		}
		progress++
	}
	return errors.New("storage boundary not reached within 12 progress turns")
}

type installationMatrixDelay struct {
	deploymentCache
	delayed  bool
	oldOwner string
}

func (c *installationMatrixDelay) SaveDeploymentJournal(b []byte) error {
	var env deploymentEnvelope
	if err := json.Unmarshal(b, &env); err != nil {
		return err
	}
	if err := c.deploymentCache.SaveDeploymentJournal(b); err != nil {
		return err
	}
	p := env.Journal.Installations[0]
	if !c.delayed && p.Step == 0 && p.InFlight && p.Failures == 0 {
		c.delayed = true
		c.oldOwner = env.Journal.Entries[0].Alias
		time.Sleep(DeploymentRebuildDuration + 50*time.Millisecond)
	}
	return nil
}

func checkInstallationStorageBoundary(t *testing.T, point int, after, slow bool) {
	t.Helper()
	e, k, cache, _, opts, dir := deploymentFixture(t, 1)
	delay := &installationMatrixDelay{deploymentCache: e.cache}
	if slow {
		e.cache = delay
	}
	fault := &installationBoundaryCache{deploymentCache: e.cache, target: installationBoundary(point), after: after, current: installationStorageBoundary{stage: storageEnrollment}}
	e.cache = fault
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, err := e.RequestInstallation(ctx, opts)
	if err == nil {
		err = reachInstallationStorageBoundary(ctx, e, fault)
	}
	if !errors.Is(err, errDeploymentStorageInjected) || !fault.hit || fault.hitAt != fault.target || !e.uncertain {
		t.Fatalf("wrong storage boundary failure: point=%d hit=%t at=%+v uncertain=%t err=%v", point, fault.hit, fault.hitAt, e.uncertain, err)
	}
	if slow && (!delay.delayed || fault.deadlines == 0) {
		t.Fatal("slow save did not exercise the real deadline before injection")
	}
	for _, v := range k.objects {
		if v.lease.Active {
			t.Fatal("failed persistence granted traffic")
		}
	}
	e, cache = reopenDeployment(t, e, cache, dir)
	if err := validateInstallations(e.journal); err != nil {
		t.Fatal(err)
	}
	// Assert exact disk contents for both sides of the fault. Cursor writes can
	// legitimately repeat identical bytes; absence of a change is not an error.
	wantBytes := fault.beforeBytes
	if after {
		wantBytes = fault.hitBytes
	}
	stored, err := cache.DeploymentJournal()
	if err != nil || !bytes.Equal(stored, wantBytes) {
		t.Fatal("storage boundary did not preserve the expected durable bytes", err)
	}
	var injected deploymentEnvelope
	if err := json.Unmarshal(fault.hitBytes, &injected); err != nil {
		t.Fatal(err)
	}
	if slow && injected.Journal.Entries[0].Alias == delay.oldOwner {
		t.Fatal("deadline recovery reused the interrupted owner")
	}
	if len(e.journal.Installations) == 0 {
		return
	}
	allowed, err := cache.InstallationConsent(opts.EndpointID, e.journal.Installations[0].Revision)
	if err != nil {
		t.Fatal(err)
	}
	if !allowed {
		if _, err := e.RebuildInstallations(ctx, installationWitness(t)); err != nil || len(k.objects) != 0 {
			t.Fatal("unconsented enrollment installed after reopening", err)
		}
		return
	}
	if err := awaitInstallationReady(ctx, e); err != nil {
		t.Fatal("storage fault did not recover after reopening", err)
	}
}

func TestRelayInstallationStorageBoundarySurvivesEarlierDeadline(t *testing.T) {
	for _, after := range []bool{false, true} {
		t.Run(fmt.Sprintf("after%v", after), func(t *testing.T) {
			// Original point 8 is the step-1 in-flight write, not the eighth
			// global save after a timeout adds failure and cleanup records.
			checkInstallationStorageBoundary(t, 8, after, true)
		})
	}
}

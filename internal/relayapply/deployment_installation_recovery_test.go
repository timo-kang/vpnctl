// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayapply

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// Real journal fsyncs can overrun the production cycle on a busy test runner.
// Model the supervisor's conservative next cycle, without extending that cycle
// or replacing real storage. Each attempt keeps the existing 12 progress turns;
// at most three deadline recoveries can start a fresh attempt, under the caller's
// overall 30s test bound. Non-deadline errors and uncertain storage remain fatal.
func awaitInstallationReady(ctx context.Context, e *DeploymentEngine) error {
	deadlineRecoveries := 0
	for progress := 0; progress < 12; {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("installation test recovery bound: %w", err)
		}
		if err := waitInstallationTestRetry(ctx, e, ""); err != nil {
			return err
		}
		fresh, err := ObserveApproval()
		if err != nil {
			return err
		}
		_, err = e.RebuildInstallations(ctx, fresh)
		if invalid := installationTestClosed(ctx, e); invalid != nil {
			return errors.Join(err, invalid)
		}
		if err != nil {
			if ctx.Err() != nil || e.uncertain || !installationDeadlineOnly(err) {
				return err
			}
			deadlineRecoveries++
			if deadlineRecoveries > 3 {
				return fmt.Errorf("installation test exceeded three deadline recoveries: %w", err)
			}
			// Cleanup may retire this owner and restart all installation steps.
			progress = 0
			continue
		}
		progress++
		if len(e.journal.Entries) == 1 && e.journal.Entries[0].Phase == "applied" {
			return nil
		}
	}
	return errors.New("installation failed to converge within 12 progress turns")
}

// An empty endpoint waits for all intents. Fairness tests wait only for their
// healthy endpoint while retaining deliberate retry pressure on the broken one.
func waitInstallationTestRetry(ctx context.Context, e *DeploymentEngine, endpoint string) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("installation test retry backoff: %w", err)
	}
	boot, err := leaseBootTime()
	if err != nil {
		return err
	}
	var wait time.Duration
	for _, p := range e.journal.Installations {
		if endpoint == "" || p.Endpoint == endpoint {
			wait = max(wait, time.Duration(p.RetryBootNS)-boot)
		}
	}
	if wait > 0 {
		timer := time.NewTimer(wait)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
			return fmt.Errorf("installation test retry backoff: %w", ctx.Err())
		}
	}
	return nil
}

func installationDeadlineOnly(err error) bool {
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		children := joined.Unwrap()
		if len(children) == 0 {
			return false
		}
		for _, child := range children {
			if !installationDeadlineOnly(child) {
				return false
			}
		}
		return true
	}
	if wrapped, ok := err.(interface{ Unwrap() error }); ok {
		return installationDeadlineOnly(wrapped.Unwrap())
	}
	return err == context.DeadlineExceeded
}

func installationTestClosed(ctx context.Context, e *DeploymentEngine) error {
	if err := validateInstallations(e.journal); err != nil {
		return err
	}
	for _, entry := range e.journal.Entries {
		lease, err := e.backend.LeaseStatus(ctx, entry)
		if err != nil {
			return err
		}
		if lease.Active {
			return errors.New("installation recovery granted traffic")
		}
	}
	return nil
}

type slowInstallationSave struct {
	deploymentCache
	delayed  bool
	oldOwner string
}

func (c *slowInstallationSave) SaveDeploymentJournal(b []byte) error {
	var env deploymentEnvelope
	if err := json.Unmarshal(b, &env); err != nil {
		return err
	}
	delay := !c.delayed && len(env.Journal.Installations) == 1 && env.Journal.Installations[0].Step == 1 && env.Journal.Installations[0].InFlight
	if err := c.deploymentCache.SaveDeploymentJournal(b); err != nil {
		return err
	}
	if delay {
		c.delayed = true
		c.oldOwner = env.Journal.Entries[0].Alias
		time.Sleep(DeploymentRebuildDuration + 50*time.Millisecond)
	}
	return nil
}

func TestRelayInstallationSlowRecoverySaveKeepsBudgetAndRecovers(t *testing.T) {
	e, k, cache, _, opts, dir := deploymentFixture(t, 1)
	fault := &failingDeploymentCache{deploymentCache: e.cache, failAt: 5}
	e.cache = fault
	_, err := e.RequestInstallation(context.Background(), opts)
	for n := 0; n < 12 && err == nil; n++ {
		_, err = e.RebuildInstallations(context.Background(), installationWitness(t))
	}
	if !errors.Is(err, errDeploymentStorageInjected) || fault.calls != 5 {
		t.Fatalf("wrong initial storage fault: calls=%d err=%v", fault.calls, err)
	}
	e, _ = reopenDeployment(t, e, cache, dir)
	slow := &slowInstallationSave{deploymentCache: e.cache}
	e.cache = slow
	var interrupted, removedOld bool
	base := e.backend
	e.backend = &installationRecoveryObserver{deploymentBackend: base, observe: func() {
		p := e.journal.Installations[0]
		if p.Reason == "installation_step_interrupted" && len(e.journal.Entries) == 1 && e.journal.Entries[0].Alias == slow.oldOwner {
			interrupted = true
			if !p.InFlight || p.Step != 1 || p.Failures != 1 || e.uncertain {
				t.Fatal("slow storage lost conservative recovery cursor")
			}
		}
	}, removing: func(entry DeploymentEntry) {
		boot, err := leaseBootTime()
		if err != nil || uint64(boot) < e.journal.Installations[0].RetryBootNS {
			t.Fatal("cleanup ignored installation retry backoff", err)
		}
		removedOld = removedOld || entry.Alias == slow.oldOwner
	}}
	installationReady(t, e)
	if !slow.delayed || !interrupted || !removedOld || e.journal.Entries[0].Alias == slow.oldOwner || k.objects[opts.EndpointID].lease.Active {
		t.Fatal("slow recovery skipped deadline, owner replacement, or closed lease invariant")
	}
}

type installationRecoveryObserver struct {
	deploymentBackend
	observe  func()
	removing func(DeploymentEntry)
}

func (b *installationRecoveryObserver) LeaseStatus(ctx context.Context, e DeploymentEntry) (DeploymentLease, error) {
	if b.observe != nil {
		b.observe()
	}
	return b.deploymentBackend.LeaseStatus(ctx, e)
}

func (b *installationRecoveryObserver) Remove(ctx context.Context, e DeploymentEntry) error {
	if b.removing != nil {
		b.removing(e)
	}
	return b.deploymentBackend.Remove(ctx, e)
}

func TestInstallationDeadlineClassificationIsStrict(t *testing.T) {
	for _, err := range []error{context.DeadlineExceeded, fmt.Errorf("operation: %w", context.DeadlineExceeded), errors.Join(context.DeadlineExceeded, context.DeadlineExceeded)} {
		if !installationDeadlineOnly(err) {
			t.Fatal("ordinary deadline was rejected", err)
		}
	}
	for _, err := range []error{nil, context.Canceled, errDeploymentStorageInjected, errors.Join(context.DeadlineExceeded, errDeploymentStorageInjected), fmt.Errorf("operation: %w", errors.Join(context.DeadlineExceeded, ErrConflict))} {
		if installationDeadlineOnly(err) {
			t.Fatal("non-deadline failure would be hidden", err)
		}
	}
}

type installationCheckError struct {
	deploymentBackend
	err   error
	calls int
}

func (b *installationCheckError) Check(context.Context, DeploymentEntry, bool) (bool, error) {
	b.calls++
	return false, b.err
}

type installationSaveError struct {
	deploymentCache
	calls int
}

func (c *installationSaveError) SaveDeploymentJournal([]byte) error {
	c.calls++
	return context.DeadlineExceeded
}

func TestInstallationReadinessRejectsMixedOrUncertainDeadline(t *testing.T) {
	for _, mode := range []string{"mixed", "uncertain"} {
		t.Run(mode, func(t *testing.T) {
			e, _, _, _, opts, _ := deploymentFixture(t, 1)
			if _, err := e.RequestInstallation(context.Background(), opts); err != nil {
				t.Fatal(err)
			}
			backend := &installationCheckError{deploymentBackend: e.backend, err: errors.Join(context.DeadlineExceeded, ErrConflict)}
			cache := &installationSaveError{deploymentCache: e.cache}
			if mode == "mixed" {
				e.backend = backend
			} else {
				e.cache = cache
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			err := awaitInstallationReady(ctx, e)
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatal("deadline failure lost", err)
			}
			if mode == "mixed" && (!errors.Is(err, ErrConflict) || backend.calls != 1) {
				t.Fatal("mixed failure was retried or masked", err, backend.calls)
			}
			if mode == "uncertain" && (!e.uncertain || cache.calls != 1) {
				t.Fatal("uncertain storage was retried", err, cache.calls)
			}
		})
	}
}

func TestInstallationReadinessCapsDeadlineRecovery(t *testing.T) {
	e, _, _, _, opts, _ := deploymentFixture(t, 1)
	if _, err := e.RequestInstallation(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	backend := &installationCheckError{deploymentBackend: e.backend, err: context.DeadlineExceeded}
	e.backend = backend
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	err := awaitInstallationReady(ctx, e)
	if !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "three deadline recoveries") || backend.calls != 4 {
		t.Fatal("repeated deadlines did not exhaust the explicit recovery allowance", err, backend.calls)
	}
}

func TestInstallationReadinessBoundsBackoffWait(t *testing.T) {
	e, k, _, _, opts, _ := deploymentFixture(t, 1)
	if _, err := e.RequestInstallation(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	boot, err := leaseBootTime()
	if err != nil {
		t.Fatal(err)
	}
	e.journal.Installations[0].RetryBootNS = uint64(boot + time.Hour)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	err = awaitInstallationReady(ctx, e)
	if !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "test retry backoff") || len(k.objects) != 0 {
		t.Fatal("test bound failed to stop backoff without creation", err)
	}
}

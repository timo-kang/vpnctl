// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayapply

import (
	"context"
	"encoding/hex"
	"errors"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"vpnctl/internal/relaycache"
	"vpnctl/internal/relaycatalog"
)

const DeploymentRebuildDuration = 750 * time.Millisecond

var deploymentInstallSteps = []string{"guard", "link", "tag", "wg", "up", "routes"}

// Installation intent is private local configuration, not controller authority
// or proof of kernel ownership. KeyFile is only a reference to an external key;
// it is never included in public reports. Version 2 refuses old-binary adoption.
type deploymentInstallation struct {
	Endpoint      string `json:"endpoint_id"`
	Controller    string `json:"controller_id"`
	PublicKey     string `json:"public_key"`
	KeyGeneration uint64 `json:"key_generation"`
	ListenPort    int    `json:"listen_port"`
	KeyFile       string `json:"key_file"`
	Revision      string `json:"revision"`
	Step          int    `json:"step"`
	InFlight      bool   `json:"in_flight,omitempty"`
	Failures      int    `json:"failures,omitempty"`
	RetryBootNS   uint64 `json:"retry_boot_ns,omitempty"`
	Attempts      uint64 `json:"attempts,omitempty"`
	Reason        string `json:"reason,omitempty"`
}

type DeploymentInstallationStatus struct {
	EndpointID        string `json:"endpoint_id"`
	Revision          string `json:"revision"`
	ControllerID      string `json:"controller_id"`
	KeyGeneration     uint64 `json:"key_generation"`
	ListenPort        int    `json:"listen_port"`
	Enabled           bool   `json:"enabled"`
	Phase             string `json:"phase"`
	Step              int    `json:"step"`
	InFlight          bool   `json:"in_flight,omitempty"`
	Attempts          uint64 `json:"attempts"`
	RetryBootNS       uint64 `json:"retry_boot_ns,omitempty"`
	Reason            string `json:"reason,omitempty"`
	LastAttemptReason string `json:"last_attempt_reason,omitempty"`
}

func validInstallKeyReference(path string) bool {
	return len(path) > 1 && len(path) <= 4096 && filepath.IsAbs(path) && filepath.Clean(path) == path && strings.IndexFunc(path, unicode.IsControl) < 0
}
func validateInstallations(j deploymentJournal) error {
	if len(j.Installations) > 8 || j.Version == 1 && (len(j.Installations) != 0 || j.InstallCursor != "") {
		return errors.New("invalid installation journal version or size")
	}
	seen := map[string]bool{}
	for _, p := range j.Installations {
		controller, ce := hex.DecodeString(p.Controller)
		revision, re := hex.DecodeString(p.Revision)
		if relaycache.ValidateDeploymentIdentity(j.Principal, p.Endpoint) != nil || seen[p.Endpoint] || ce != nil || len(controller) != 16 || hex.EncodeToString(controller) != p.Controller || re != nil || len(revision) != 16 || hex.EncodeToString(revision) != p.Revision || relaycatalog.ValidatePublicKey(p.PublicKey) != nil || p.KeyGeneration == 0 || p.ListenPort < 1 || p.ListenPort > 65535 || !validInstallKeyReference(p.KeyFile) || p.Failures < 0 || p.Failures > 6 || p.RetryBootNS > uint64(1<<63-1) || p.Attempts > 1<<32-1 || len(p.Reason) > 128 || p.Step < 0 || p.Step > len(deploymentInstallSteps) {
			return errors.New("invalid installation intent")
		}
		seen[p.Endpoint] = true
		entry := -1
		for i, e := range j.Entries {
			if e.Endpoint == p.Endpoint {
				entry = i
			}
		}
		if entry < 0 {
			if p.Step != 0 || p.InFlight {
				return errors.New("installation cursor without ownership")
			}
		} else {
			e := j.Entries[entry]
			if e.Controller != p.Controller || e.PublicKey != p.PublicKey || e.KeyGeneration != p.KeyGeneration || e.ListenPort != p.ListenPort || e.LeaseVersion != 3 || e.PolicyVersion != 1 || e.Phase == "applied" && (p.Step != len(deploymentInstallSteps) || p.InFlight) {
				return errors.New("installation ownership mismatch")
			}
		}
	}
	if j.InstallCursor != "" && !seen[j.InstallCursor] {
		return errors.New("invalid installation cursor")
	}
	return nil
}
func (e *DeploymentEngine) installationIndex(endpoint string) int {
	for i, p := range e.journal.Installations {
		if p.Endpoint == endpoint {
			return i
		}
	}
	return -1
}
func (e *DeploymentEngine) installationAuthorized(endpoint string, want DeploymentEntry) error {
	i := e.installationIndex(endpoint)
	if i < 0 {
		return nil
	} // Manual endpoints retain the explicit apply contract.
	p := e.journal.Installations[i]
	allowed, err := e.cache.InstallationConsent(endpoint, p.Revision)
	if err != nil || !allowed || p.Controller != want.Controller || p.PublicKey != want.PublicKey || p.KeyGeneration != want.KeyGeneration || p.ListenPort != want.ListenPort {
		return errors.Join(ErrRecovery, err)
	}
	return nil
}
func (e *DeploymentEngine) installationStatus() []DeploymentInstallationStatus {
	var out []DeploymentInstallationStatus
	for _, p := range e.journal.Installations {
		allowed, err := e.cache.InstallationConsent(p.Endpoint, p.Revision)
		phase := "waiting"
		if i := e.index(p.Endpoint); i >= 0 {
			phase = e.journal.Entries[i].Phase
		}
		reason := ""
		if err != nil {
			reason = "installation_consent_unavailable"
		} else if !allowed {
			reason = "installation_consent_revoked"
		}
		out = append(out, DeploymentInstallationStatus{EndpointID: p.Endpoint, Revision: p.Revision, ControllerID: p.Controller, KeyGeneration: p.KeyGeneration, ListenPort: p.ListenPort, Enabled: allowed && err == nil, Phase: phase, Step: p.Step, InFlight: p.InFlight, Attempts: p.Attempts, RetryBootNS: p.RetryBootNS, Reason: reason, LastAttemptReason: p.Reason})
	}
	return out
}

// RequestInstallation records explicit operator consent. It does not create
// kernel resources, arm a lease, or implicitly import an existing endpoint.
func (e *DeploymentEngine) RequestInstallation(ctx context.Context, o DeploymentOptions) (DeploymentResult, error) {
	if !e.mu.TryLock() {
		return DeploymentResult{}, relaycache.ErrBusy
	}
	defer e.mu.Unlock()
	if err := e.begin(); err != nil {
		return e.result("blocked", "reopen_required"), err
	}
	ctx, cancel := context.WithTimeout(ctx, MaxDuration)
	defer cancel()
	if ctx.Err() != nil {
		return e.result("blocked", "deadline"), ctx.Err()
	}
	path, err := filepath.Abs(o.KeyFile)
	if err != nil || o.KeyFile == "" || !validInstallKeyReference(path) {
		return e.result("blocked", "invalid_key_reference"), ErrConflict
	}
	r, err := e.enforce(ctx)
	if err != nil {
		return e.result("blocked", "approval_or_cleanup_failed"), err
	}
	want, err := desiredDeployment(r, o.EndpointID, o.ListenPort)
	if err != nil {
		return e.result("blocked", "approval_unavailable"), err
	}
	if o.KeyGeneration != want.KeyGeneration {
		return e.result("blocked", "local_key_generation_mismatch"), ErrConflict
	}
	if _, err := deploymentKey(path, want.PublicKey); err != nil {
		return e.result("blocked", "local_key_unavailable_or_mismatched"), err
	}
	if i := e.installationIndex(o.EndpointID); i >= 0 {
		p := e.journal.Installations[i]
		if p.KeyFile != path || p.ListenPort != o.ListenPort || e.installationAuthorized(o.EndpointID, want) != nil {
			return e.result("blocked", "release_previous_intent_first"), ErrConflict
		}
		return e.result("scheduled", "explicit_installation_intent"), nil
	}
	// Existing manual installations are not converted in place. Releasing first
	// makes adoption and replacement an explicit operator decision.
	if e.index(o.EndpointID) >= 0 {
		return e.result("blocked", "release_previous_endpoint_first"), ErrConflict
	}
	if len(e.journal.Installations) >= 8 {
		return e.result("blocked", "installation_limit"), ErrConflict
	}
	owner, _, _, err := token()
	if err != nil {
		return e.result("blocked", "intent_identity_unavailable"), err
	}
	if ctx.Err() != nil {
		return e.result("blocked", "deadline"), ctx.Err()
	}
	e.journal.Version = 2
	e.journal.Installations = append(e.journal.Installations, deploymentInstallation{Endpoint: o.EndpointID, Controller: want.Controller, PublicKey: want.PublicKey, KeyGeneration: o.KeyGeneration, ListenPort: o.ListenPort, KeyFile: path, Revision: owner[7:], Reason: "awaiting_fresh_approval"})
	if err := e.persist(); err != nil {
		return e.result("blocked", "journal_save_failed"), err
	}
	if err := e.cache.AllowInstallation(o.EndpointID, owner[7:]); err != nil {
		return e.result("blocked", "installation_consent_save_failed"), err
	}
	return e.result("scheduled", "explicit_installation_intent"), nil
}

func installationFresh(fresh FreshApproval) error {
	boot, err := leaseBootTime()
	age := time.Since(fresh.At)
	if err != nil || fresh.At.IsZero() || age < 0 || age >= DeploymentRearmWindow || fresh.BootNS == 0 || uint64(boot) < fresh.BootNS || uint64(boot)-fresh.BootNS >= uint64(DeploymentRearmWindow) {
		return errors.Join(ErrLeaseExpired, err)
	}
	return nil
}
func (e *DeploymentEngine) installationFailure(i int, reason string, cause error) error {
	p := &e.journal.Installations[i]
	p.Reason = reason
	p.Failures = min(p.Failures+1, 6)
	now, err := leaseBootTime()
	if err == nil {
		p.RetryBootNS = uint64(now + min(time.Second<<uint(p.Failures-1), 30*time.Second))
	}
	return errors.Join(cause, err, e.persist())
}

// RebuildInstallations advances at most one durable unit AFTER existing leases
// are maintained. Every creation unit needs the current cycle's authenticated
// request-start witness. All work stays within 750ms and the parent cycle;
// rollback never acquires an independent deadline. Only Maintain opens leases.
func (e *DeploymentEngine) RebuildInstallations(parent context.Context, fresh FreshApproval) (DeploymentResult, error) {
	if !e.mu.TryLock() {
		return DeploymentResult{}, relaycache.ErrBusy
	}
	defer e.mu.Unlock()
	if err := e.begin(); err != nil {
		return e.result("blocked", "reopen_required"), err
	}
	ctx, cancel := context.WithTimeout(parent, DeploymentRebuildDuration)
	defer cancel()
	now, err := leaseBootTime()
	if err != nil {
		return e.result("blocked", "boottime_unavailable"), err
	}
	budget := func() error {
		at, err := leaseBootTime()
		if err != nil {
			return err
		}
		if at < now || at-now >= DeploymentRebuildDuration {
			return context.DeadlineExceeded
		}
		return ctx.Err()
	}
	start := e.installationIndex(e.journal.InstallCursor) + 1
	for n := 0; n < len(e.journal.Installations); n++ {
		i := (start + n) % len(e.journal.Installations)
		p := e.journal.Installations[i]
		if err := budget(); err != nil {
			return e.result("blocked", "rebuild_budget_exhausted"), err
		}
		if p.RetryBootNS > uint64(now) {
			continue
		}
		allowed, consentErr := e.cache.InstallationConsent(p.Endpoint, p.Revision)
		index := e.index(p.Endpoint)
		if consentErr != nil {
			return e.result("blocked", "installation_consent_unavailable"), consentErr
		}
		if !allowed {
			if index >= 0 {
				if err := e.remove(ctx, index); err != nil {
					return e.result("blocked", "installation_cleanup_failed"), err
				}
			}
			e.journal.Installations = append(e.journal.Installations[:i], e.journal.Installations[i+1:]...)
			e.journal.InstallCursor = ""
			return e.result("disabled", "installation_consent_revoked"), e.persist()
		}
		if index >= 0 && (p.InFlight || e.journal.Entries[index].Phase == "releasing") {
			e.journal.InstallCursor = p.Endpoint
			if err := e.remove(ctx, index); err != nil {
				return e.result("blocked", "installation_cleanup_failed"), e.installationFailure(i, "interrupted_installation_cleanup", err)
			}
			return e.result("rebuilding", "interrupted_installation_removed"), nil
		}
		if index >= 0 && e.journal.Entries[index].Phase == "applied" && e.installationReady[e.journal.Entries[index].Alias] {
			continue
		}
		if err := installationFresh(fresh); err != nil {
			e.journal.Installations[i].Reason = "awaiting_fresh_approval"
			return e.result("waiting", "awaiting_fresh_approval"), err
		}
		current := func() (DeploymentEntry, error) {
			if err := budget(); err != nil {
				return DeploymentEntry{}, err
			}
			if err := installationFresh(fresh); err != nil {
				return DeploymentEntry{}, err
			}
			r, err := e.cache.Status()
			if err != nil {
				return DeploymentEntry{}, err
			}
			want, err := desiredDeployment(r, p.Endpoint, p.ListenPort)
			if err != nil {
				return DeploymentEntry{}, err
			}
			if err := e.installationAuthorized(p.Endpoint, want); err != nil {
				return DeploymentEntry{}, err
			}
			return want, nil
		}
		want, err := current()
		if err != nil {
			return e.result("blocked", "installation_approval_unavailable"), e.installationFailure(i, "installation_approval_unavailable", err)
		}
		key, err := deploymentKey(p.KeyFile, p.PublicKey)
		if err != nil {
			return e.result("blocked", "local_key_unavailable_or_mismatched"), e.installationFailure(i, "local_key_unavailable_or_mismatched", err)
		}
		e.journal.InstallCursor = p.Endpoint
		if err := e.persist(); err != nil {
			return e.result("blocked", "journal_save_failed"), err
		}
		if index < 0 {
			if len(e.journal.Entries) >= 8 {
				return e.result("blocked", "endpoint_limit"), e.installationFailure(i, "endpoint_limit", ErrConflict)
			}
			want.Alias, want.Group, want.LinkIndex, err = token()
			if err != nil {
				return e.result("blocked", "owner_unavailable"), err
			}
			if err := validateDeploymentEntry(want, e.journal); err != nil {
				return e.result("blocked", "invalid_installation"), err
			}
			if _, err := e.backend.Check(ctx, want, true); err != nil {
				return e.result("blocked", "resource_conflict_or_unavailable"), e.installationFailure(i, "resource_conflict_or_unavailable", err)
			}
			latest, err := current()
			if err != nil || !sameDeployment(want, latest) {
				return e.result("blocked", "approval_changed"), errors.Join(ErrRecovery, err)
			}
			e.journal.Entries = append(e.journal.Entries, want)
			e.journal.Installations[i].Attempts = min(p.Attempts+1, 1<<32-1)
			e.journal.Installations[i].Reason = "initially_closed_installation"
			return e.result("rebuilding", "ownership_recorded"), e.persist()
		}
		old := e.journal.Entries[index]
		if !sameDeployment(old, want) {
			if err := e.remove(ctx, index); err != nil {
				return e.result("blocked", "installation_cleanup_failed"), e.installationFailure(i, "approval_changed", err)
			}
			return e.result("rebuilding", "obsolete_installation_removed"), nil
		}
		if old.Phase == "applied" {
			ready, err := e.backend.Check(ctx, old, false)
			if err != nil {
				return e.result("blocked", "resource_conflict_or_unavailable"), e.installationFailure(i, "resource_conflict_or_unavailable", err)
			}
			if ready {
				continue
			} // An expired lease needs renewal, not reinstall.
			if err := e.remove(ctx, index); err != nil {
				return e.result("blocked", "installation_cleanup_failed"), e.installationFailure(i, "owned_configuration_drift", err)
			}
			return e.result("rebuilding", "owned_configuration_removed"), nil
		}
		if p.Step == len(deploymentInstallSteps) {
			ready, err := e.backend.Check(ctx, old, false)
			if err != nil || !ready {
				e.journal.Installations[i].InFlight = true
				return e.result("blocked", "installation_readback_failed"), e.installationFailure(i, "installation_readback_failed", errors.Join(ErrRecovery, err))
			}
			latest, err := current()
			if err != nil || !sameDeployment(old, latest) {
				return e.result("blocked", "approval_changed"), errors.Join(ErrRecovery, err)
			}
			e.journal.Entries[index].Phase = "applied"
			e.journal.Installations[i].Reason = "awaiting_fresh_lease"
			e.journal.Installations[i].Failures, e.journal.Installations[i].RetryBootNS = 0, 0
			return e.result("prepared", "awaiting_fresh_lease"), e.persist()
		}
		e.journal.Installations[i].InFlight = true
		if err := e.persist(); err != nil {
			return e.result("blocked", "journal_save_failed"), err
		}
		latest, err := current()
		if err == nil && !sameDeployment(old, latest) {
			err = ErrRecovery
		}
		if err == nil {
			secret := ""
			if deploymentInstallSteps[p.Step] == "wg" {
				secret = key
			}
			err = e.backend.Step(ctx, old, deploymentInstallSteps[p.Step], secret)
		}
		if err == nil {
			latest, err = current()
			if err == nil && !sameDeployment(old, latest) {
				err = ErrRecovery
			}
		}
		if err != nil {
			return e.result("blocked", "installation_step_interrupted"), e.installationFailure(i, "installation_step_interrupted", err)
		}
		e.journal.Installations[i].InFlight = false
		e.journal.Installations[i].Step++
		e.journal.Installations[i].Failures, e.journal.Installations[i].RetryBootNS = 0, 0
		e.journal.Installations[i].Reason = "initially_closed_installation"
		return e.result("rebuilding", "installation_step_completed"), e.persist()
	}
	return e.result("idle", ""), nil
}

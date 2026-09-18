// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package controller

import (
	"context"
	"errors"
	"fmt"
	"time"

	"vpnctl/internal/atomicfile"
	"vpnctl/internal/history"
	"vpnctl/internal/pki"
)

func (s *Server) startDiagnosticEvents() func() {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.diagnostics.Run(ctx, func(ctx context.Context, e history.Event) (bool, error) {
			storage, ok := s.history.(history.EventStorage)
			if !ok {
				return false, errors.New("event history unavailable")
			}
			err := storage.IngestEvent(ctx, "", e, time.Now())
			return !errors.Is(err, history.ErrInvalid) && !errors.Is(err, history.ErrConflict), err
		})
	}()
	return func() { cancel(); <-done }
}

// A successful operation may be an idempotent replay. Failures never assert
// committed success, including a replacement whose directory fsync failed.
func (s *Server) recordPKIResult(operation, target string, err error, detail ...string) {
	result, severity, validity := "success", "info", "observed"
	if err != nil {
		result, severity = "failed", "warning"
		if atomicfile.Replaced(err) {
			result, validity = "uncertain", "unknown"
		}
		if errors.Is(err, pki.ErrRenewalBlocked) || errors.Is(err, pki.ErrTransitionBlocked) || errors.Is(err, pki.ErrCertificateDenied) {
			result = "denied"
		}
	}
	message := ""
	if len(detail) > 0 {
		message = detail[0]
	}
	s.diagnostics.Emit(history.Event{Message: message, Kind: "certificate", Source: "controller-pki", Target: target, Current: operation + ":" + result, Severity: severity, Validity: validity})
}

func certificateEventDetail(certPEM string, generation uint64) string {
	cert, err := pki.ParseCertificate(certPEM)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("generation=%d fingerprint=%s", generation, pki.Fingerprint(cert))
}

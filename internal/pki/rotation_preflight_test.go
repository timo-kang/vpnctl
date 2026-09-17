package pki

import (
	"bytes"
	"errors"
	"testing"
)

func TestRotationPreflightDoesNotAuthorizeStaleDecision(t *testing.T) {
	a := testAuthority(t)
	original, _ := a.Snapshot()
	if err := a.CheckRotation("prepare", nil); err != nil {
		t.Fatal(err)
	}
	unchanged, _ := a.Snapshot()
	if !bytes.Equal(original, unchanged) {
		t.Fatal("preflight changed authority")
	}
	if err := a.Rotate("prepare", nil); err != nil {
		t.Fatal(err)
	}
	// The earlier successful check cannot authorize a second prepare.
	if err := a.Rotate("prepare", nil); !errors.Is(err, ErrTransitionBlocked) {
		t.Fatal("stale prepare accepted", err)
	}
	if err := a.CheckRotation("activate", []string{"node"}); !errors.Is(err, ErrTransitionBlocked) {
		t.Fatal("missing ack accepted", err)
	}
	cert := issueTestCert(t, a, "node")
	if err := a.Acknowledge("node", cert, a.Status().Generation); err != nil {
		t.Fatal(err)
	}
	if err := a.CheckRotation("activate", []string{"node"}); err != nil {
		t.Fatal(err)
	}
	if err := a.Revoke(Fingerprint(cert)); err != nil {
		t.Fatal(err)
	}
	before, _ := a.Snapshot()
	if err := a.Rotate("activate", []string{"node"}); !errors.Is(err, ErrTransitionBlocked) {
		t.Fatal("revoked ack accepted after preflight", err)
	}
	after, _ := a.Snapshot()
	if !bytes.Equal(before, after) {
		t.Fatal("rejected transition changed state")
	}
	// No fleet requires trust here; still preserve the minimum overlap gate.
	if err := a.Rotate("activate", nil); err != nil {
		t.Fatal(err)
	}
	if err := a.CheckRotation("retire", nil); !errors.Is(err, ErrTransitionBlocked) {
		t.Fatal("early retirement accepted", err)
	}
}

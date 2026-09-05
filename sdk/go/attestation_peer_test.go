// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package xkms

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"
)

// TestPeerAttestationSurface proves the SDK aliases are the canonical
// package: a verifier built here renders a fail-closed verdict on empty
// evidence, rejects an invalid policy with the aliased error type, and the
// qualifying-data helper computes the documented value.
func TestPeerAttestationSurface(t *testing.T) {
	verifier := NewPeerAttestationVerifier(WithPeerVerifierClock(func() time.Time {
		return time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	}))

	verdict, err := verifier.Verify(context.Background(), PeerEvidence{}, PeerPolicy{})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	// A policy that demands neither required PCRs nor a maximum age records
	// those two checks as holding; every check that needs evidence fails.
	if verdict.Passed || verdict.Failure != PeerFailureAbsence || verdict.Checks != (PeerChecks{RequiredPCRs: true, Freshness: true}) {
		t.Fatalf("empty evidence verdict = %+v", verdict)
	}

	_, err = verifier.Verify(context.Background(), PeerEvidence{}, PeerPolicy{MaxEvidenceAge: -time.Second})
	var pe *PeerPolicyError
	if !errors.As(err, &pe) {
		t.Fatalf("err = %v, want *PeerPolicyError", err)
	}

	nonce := []byte("nonce")
	binding := []byte("binding")
	want := sha256.Sum256(append(append([]byte{}, nonce...), binding...))
	if got := PeerQualifyingData(nonce, binding); !bytes.Equal(got, want[:]) {
		t.Fatalf("PeerQualifyingData = %x", got)
	}
	if PeerChannelBindingExporterLabel != "EXPORTER-attested-peer" || PeerChannelBindingLength != 32 {
		t.Fatal("exporter constants drifted")
	}
	if _, err := PeerChannelBinding(nil); err == nil {
		t.Fatal("nil connection state accepted")
	}
	if PeerFailureCryptographic.String() != "cryptographic" || PeerFailureNone.String() != "none" {
		t.Fatal("failure class names drifted")
	}
}

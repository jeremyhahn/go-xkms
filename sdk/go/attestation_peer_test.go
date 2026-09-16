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
	"crypto/x509"
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

// TestPeerFailureClassRoundTrip proves a persisted failure class parses back
// through the alias type's own MarshalText/UnmarshalText, and that an unknown
// name is rejected with the aliased typed error rather than a string.
func TestPeerFailureClassRoundTrip(t *testing.T) {
	for _, class := range []PeerFailureClass{PeerFailureNone, PeerFailureAbsence, PeerFailureCryptographic} {
		text, err := class.MarshalText()
		if err != nil {
			t.Fatalf("MarshalText(%v): %v", class, err)
		}
		if string(text) != class.String() {
			t.Fatalf("MarshalText(%v) = %q, want %q", class, text, class.String())
		}
		var parsed PeerFailureClass
		if err := parsed.UnmarshalText(text); err != nil {
			t.Fatalf("UnmarshalText(%q): %v", text, err)
		}
		if parsed != class {
			t.Fatalf("round trip of %q = %v, want %v", text, parsed, class)
		}
	}

	var garbage PeerFailureClass
	err := garbage.UnmarshalText([]byte("quarantine"))
	var fce *PeerFailureClassError
	if !errors.As(err, &fce) {
		t.Fatalf("err = %v, want *PeerFailureClassError", err)
	}
	if fce.Text != "quarantine" {
		t.Fatalf("rejected text = %q, want %q", fce.Text, "quarantine")
	}
	if garbage != PeerFailureNone {
		t.Fatalf("a rejected parse must leave the value untouched, got %v", garbage)
	}
}

// TestPeerDeviceTrustSurface proves the device-trust aliases reach the
// canonical primitives and fail closed: a consumer that reaches them through
// the SDK gets the same typed refusals, and can tell a rejected device
// (*PeerDevIDError) from its own misconfiguration (*PeerDevIDPolicyError).
func TestPeerDeviceTrustSurface(t *testing.T) {
	anchored := PeerDevIDPolicy{Anchors: x509.NewCertPool()}

	var de *PeerDevIDError
	if err := PeerVerifyIDevID(context.Background(), nil, anchored); !errors.As(err, &de) {
		t.Fatalf("err = %v, want *PeerDevIDError", err)
	}
	if de.Credential != "IDevID" {
		t.Fatalf("credential = %q, want IDevID", de.Credential)
	}
	if err := PeerVerifyIAK(context.Background(), nil, anchored); !errors.As(err, &de) || de.Credential != "IAK" {
		t.Fatalf("err = %v, want an IAK *PeerDevIDError", err)
	}

	// No anchors is the caller's mistake, not the device's, and must never be
	// answered by accepting the certificate.
	var pe *PeerDevIDPolicyError
	err := PeerVerifyIDevID(context.Background(), &x509.Certificate{}, PeerDevIDPolicy{})
	if !errors.As(err, &pe) || pe.Field != "Anchors" {
		t.Fatalf("err = %v, want *PeerDevIDPolicyError on Anchors", err)
	}

	if PeerIsIDevID(nil) || PeerIsIAK(nil) {
		t.Fatal("a nil certificate is not a device credential")
	}

	// The TLS helpers refuse a connection that yields no binding rather than
	// producing unbound evidence.
	var cbe *PeerChannelBindingError
	bound, err := PeerEvidenceFromTLS(nil, PeerEvidence{Nonce: []byte("nonce")})
	if !errors.As(err, &cbe) {
		t.Fatalf("err = %v, want *PeerChannelBindingError", err)
	}
	if bound.ChannelBinding != nil || bound.Evidence.Nonce != nil {
		t.Fatalf("a refused connection produced evidence: %+v", bound)
	}
	if _, err := PeerQualifyingDataFromTLS(nil, []byte("nonce")); !errors.As(err, &cbe) {
		t.Fatalf("err = %v, want *PeerChannelBindingError", err)
	}
}

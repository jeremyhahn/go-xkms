// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package piv

import (
	"context"
	"errors"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/pivcert"
)

func TestPIVFactor_Name(t *testing.T) {
	if got := New(Config{}).Name(); got != FactorName {
		t.Fatalf("Name() = %q, want %q", got, FactorName)
	}
}

func TestPIVFactor_FullRoundTrip_Software(t *testing.T) {
	ctx := context.Background()
	f := New(Config{})

	enrollment, err := f.Enroll(ctx, &qrdbsdk.AuthFactorEnrollParams{UserID: "custodian-1"})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if enrollment.FactorName != FactorName {
		t.Fatalf("FactorName = %q, want %q", enrollment.FactorName, FactorName)
	}
	if enrollment.UserID != "custodian-1" {
		t.Fatalf("UserID = %q, want custodian-1", enrollment.UserID)
	}
	if len(enrollment.PublicKey) == 0 {
		t.Fatal("PublicKey is empty; expected PEM-encoded cert")
	}
	if enrollment.Metadata["slot"] != string(pivcert.PIVSlotAuthentication) {
		t.Fatalf("default slot = %q, want %q", enrollment.Metadata["slot"], pivcert.PIVSlotAuthentication)
	}

	challenge, err := f.Challenge(ctx, enrollment)
	if err != nil {
		t.Fatalf("Challenge: %v", err)
	}
	if len(challenge.Nonce) != nonceLength {
		t.Fatalf("nonce length = %d, want %d", len(challenge.Nonce), nonceLength)
	}
	if challenge.EnrollmentID != enrollment.EnrollmentID {
		t.Fatalf("challenge.EnrollmentID = %q, want %q", challenge.EnrollmentID, enrollment.EnrollmentID)
	}

	sig, err := f.SignNonce(ctx, pivcert.PIVSlotAuthentication, challenge.Nonce)
	if err != nil {
		t.Fatalf("SignNonce: %v", err)
	}

	response := &qrdbsdk.AuthFactorResponse{
		Value: sig,
		Metadata: map[string]string{
			"public_key_pem": string(enrollment.PublicKey),
		},
	}

	if err := f.Verify(ctx, challenge, response); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestPIVFactor_Enroll_RejectsNilParams(t *testing.T) {
	var inv *qrdbsdk.AuthFactorEnrollmentInvalidError
	if _, err := New(Config{}).Enroll(context.Background(), nil); !errors.As(err, &inv) {
		t.Fatalf("Enroll(nil) err = %v, want EnrollmentInvalidError", err)
	}
}

func TestPIVFactor_Verify_RejectsExpiredChallenge(t *testing.T) {
	ctx := context.Background()
	f := New(Config{ChallengeTTLSeconds: 1})
	enrollment, _ := f.Enroll(ctx, &qrdbsdk.AuthFactorEnrollParams{UserID: "u1"})
	challenge, _ := f.Challenge(ctx, enrollment)
	// Force expiry by manually moving ExpiresAt into the past.
	challenge.ExpiresAt = challenge.ExpiresAt.Add(-1000 * 1000 * 1000) // -1s in nanoseconds
	var expired *qrdbsdk.AuthFactorChallengeExpiredError
	err := f.Verify(ctx, challenge, &qrdbsdk.AuthFactorResponse{
		Metadata: map[string]string{"public_key_pem": string(enrollment.PublicKey)},
	})
	if !errors.As(err, &expired) {
		t.Fatalf("Verify(expired) err = %v, want ChallengeExpiredError", err)
	}
}

func TestPIVFactor_Verify_RejectsMissingPublicKey(t *testing.T) {
	ctx := context.Background()
	f := New(Config{})
	enrollment, _ := f.Enroll(ctx, &qrdbsdk.AuthFactorEnrollParams{UserID: "u1"})
	challenge, _ := f.Challenge(ctx, enrollment)
	var failed *qrdbsdk.AuthFactorVerificationFailedError
	err := f.Verify(ctx, challenge, &qrdbsdk.AuthFactorResponse{Metadata: map[string]string{}})
	if !errors.As(err, &failed) {
		t.Fatalf("Verify(missing pub) err = %v, want VerificationFailedError", err)
	}
}

func TestPIVFactor_Verify_RejectsBadSignature(t *testing.T) {
	ctx := context.Background()
	f := New(Config{})
	enrollment, _ := f.Enroll(ctx, &qrdbsdk.AuthFactorEnrollParams{UserID: "u1"})
	challenge, _ := f.Challenge(ctx, enrollment)
	var failed *qrdbsdk.AuthFactorVerificationFailedError
	err := f.Verify(ctx, challenge, &qrdbsdk.AuthFactorResponse{
		Value:    []byte("not-a-valid-DER-signature"),
		Metadata: map[string]string{"public_key_pem": string(enrollment.PublicKey)},
	})
	if !errors.As(err, &failed) {
		t.Fatalf("Verify(bad sig) err = %v, want VerificationFailedError", err)
	}
}

func TestPIVFactor_NewDefaults(t *testing.T) {
	f := New(Config{})
	if f.cfg.DefaultSlot != pivcert.PIVSlotAuthentication {
		t.Fatalf("default slot = %q, want %q", f.cfg.DefaultSlot, pivcert.PIVSlotAuthentication)
	}
	if f.cfg.DefaultAlgorithm != defaultAlgorithm {
		t.Fatalf("default algorithm = %q, want %q", f.cfg.DefaultAlgorithm, defaultAlgorithm)
	}
	if f.cfg.ChallengeTTLSeconds != defaultChallengeTTLSeconds {
		t.Fatalf("default TTL = %d, want %d", f.cfg.ChallengeTTLSeconds, defaultChallengeTTLSeconds)
	}
	if f.cfg.Generator == nil {
		t.Fatal("default Generator must not be nil")
	}
}

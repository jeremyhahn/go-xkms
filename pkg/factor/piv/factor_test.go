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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	challengemsg "github.com/jeremyhahn/go-xkms/pkg/factor/internal/challenge"
	"github.com/jeremyhahn/go-xkms/pkg/pivcert"
)

// TestPIVFactor_Enroll_UsesCanonicalIssuer locks in that Enroll's
// certificate is issued through pkg/ca.Issuer (buildSelfSignedCert) with
// selfSignedProfile, rather than a hand-rolled x509.CreateCertificate call.
// It reads the profile's current KeyUsage live rather than hardcoding the
// expected flags, so a change to selfSignedProfile is observable here
// without editing this test.
func TestPIVFactor_Enroll_UsesCanonicalIssuer(t *testing.T) {
	ctx := context.Background()
	f := New(Config{})

	enrollment, err := f.Enroll(ctx, &qrdbsdk.AuthFactorEnrollParams{UserID: "custodian-profile"})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}

	block, _ := pem.Decode(enrollment.PublicKey)
	if block == nil {
		t.Fatal("expected a PEM-encoded certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse enrolled certificate: %v", err)
	}

	want := selfSignedProfile()
	if cert.KeyUsage != want.KeyUsage() {
		t.Errorf("KeyUsage = %v, want %v (from selfSignedProfile)", cert.KeyUsage, want.KeyUsage())
	}
	if len(cert.ExtKeyUsage) != 0 {
		t.Errorf("ExtKeyUsage = %v, want none", cert.ExtKeyUsage)
	}
	if !cert.BasicConstraintsValid {
		t.Error("expected BasicConstraintsValid true")
	}
	if cert.IsCA {
		t.Error("expected IsCA false for a PIV factor enrollment certificate")
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

	sig, err := f.SignChallenge(ctx, pivcert.PIVSlotAuthentication, challenge.ChallengeID, "", challenge.Nonce)
	if err != nil {
		t.Fatalf("SignChallenge: %v", err)
	}

	if got := challenge.MethodData[methodDataEnrolledCert]; got != string(enrollment.PublicKey) {
		t.Fatalf("challenge MethodData[%q] = %v, want the enrolled certificate", methodDataEnrolledCert, got)
	}

	// The response carries only the signature: the verification key comes
	// from the challenge.
	response := &qrdbsdk.AuthFactorResponse{Value: sig}

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
	err := f.Verify(ctx, challenge, &qrdbsdk.AuthFactorResponse{})
	if !errors.As(err, &expired) {
		t.Fatalf("Verify(expired) err = %v, want ChallengeExpiredError", err)
	}
}

// TestPIVFactor_Verify_RejectsAttackerKeyInResponse is the #1282 regression:
// a response signed by a key the attacker controls, carrying that key's
// certificate in its metadata, must not verify against the enrollment.
func TestPIVFactor_Verify_RejectsAttackerKeyInResponse(t *testing.T) {
	ctx := context.Background()
	f := New(Config{})
	enrollment, err := f.Enroll(ctx, &qrdbsdk.AuthFactorEnrollParams{UserID: "victim"})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	challenge, err := f.Challenge(ctx, enrollment)
	if err != nil {
		t.Fatalf("Challenge: %v", err)
	}

	attackerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	attackerCert, err := buildSelfSignedCert(attackerKey, pkix.Name{CommonName: "attacker"}, 1)
	if err != nil {
		t.Fatalf("buildSelfSignedCert: %v", err)
	}
	digest := sha256.Sum256(challengemsg.Message(challenge))
	sig, err := ecdsa.SignASN1(rand.Reader, attackerKey, digest[:])
	if err != nil {
		t.Fatalf("ecdsa.SignASN1: %v", err)
	}

	var failed *qrdbsdk.AuthFactorVerificationFailedError
	err = f.Verify(ctx, challenge, &qrdbsdk.AuthFactorResponse{
		Value:    sig,
		Metadata: map[string]string{"public_key_pem": string(attackerCert)},
	})
	if !errors.As(err, &failed) {
		t.Fatalf("Verify(attacker key) err = %v, want VerificationFailedError", err)
	}
}

// TestPIVFactor_Verify_RejectsChallengeWithoutEnrolledCert proves Verify has
// no second source for the key: with the enrolled certificate absent from the
// challenge it refuses, even when the response carries the genuine one.
func TestPIVFactor_Verify_RejectsChallengeWithoutEnrolledCert(t *testing.T) {
	ctx := context.Background()
	f := New(Config{})
	enrollment, err := f.Enroll(ctx, &qrdbsdk.AuthFactorEnrollParams{UserID: "u1"})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	challenge, err := f.Challenge(ctx, enrollment)
	if err != nil {
		t.Fatalf("Challenge: %v", err)
	}
	sig, err := f.SignChallenge(ctx, pivcert.PIVSlotAuthentication, challenge.ChallengeID, "", challenge.Nonce)
	if err != nil {
		t.Fatalf("SignChallenge: %v", err)
	}
	delete(challenge.MethodData, methodDataEnrolledCert)

	var failed *qrdbsdk.AuthFactorVerificationFailedError
	err = f.Verify(ctx, challenge, &qrdbsdk.AuthFactorResponse{
		Value:    sig,
		Metadata: map[string]string{"public_key_pem": string(enrollment.PublicKey)},
	})
	if !errors.As(err, &failed) {
		t.Fatalf("Verify(no enrolled cert) err = %v, want VerificationFailedError", err)
	}
}

func TestPIVFactor_Verify_RejectsBadSignature(t *testing.T) {
	ctx := context.Background()
	f := New(Config{})
	enrollment, _ := f.Enroll(ctx, &qrdbsdk.AuthFactorEnrollParams{UserID: "u1"})
	challenge, _ := f.Challenge(ctx, enrollment)
	var failed *qrdbsdk.AuthFactorVerificationFailedError
	err := f.Verify(ctx, challenge, &qrdbsdk.AuthFactorResponse{
		Value: []byte("not-a-valid-DER-signature"),
	})
	if !errors.As(err, &failed) {
		t.Fatalf("Verify(bad sig) err = %v, want VerificationFailedError", err)
	}
}

// TestPIVFactor_Verify_BindsTheChallengeMessage pins the proof to go-qrdb's
// challenge message (#1684): SignChallenge over the challenge's own ID,
// purpose and nonce verifies, while the old proof over SHA-256(nonce) and a
// proof made for another purpose with the same nonce are both refused.
func TestPIVFactor_Verify_BindsTheChallengeMessage(t *testing.T) {
	ctx := context.Background()
	f := New(Config{})
	slot := pivcert.PIVSlotAuthentication
	enrollment, err := f.Enroll(ctx, &qrdbsdk.AuthFactorEnrollParams{UserID: "u1"})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	challenge, err := f.Challenge(ctx, enrollment)
	if err != nil {
		t.Fatalf("Challenge: %v", err)
	}
	challenge.MethodData[qrdbsdk.QuorumChallengePurposeKey] = "quorum:a"

	valid, err := f.SignChallenge(ctx, slot, challenge.ChallengeID, "quorum:a", challenge.Nonce)
	if err != nil {
		t.Fatalf("SignChallenge: %v", err)
	}
	if err := f.Verify(ctx, challenge, &qrdbsdk.AuthFactorResponse{Value: valid}); err != nil {
		t.Fatalf("Verify(challenge message) = %v, want nil", err)
	}

	signer, err := f.cfg.Generator.GetPIVSigner(slot, "PIV "+string(slot))
	if err != nil {
		t.Fatalf("GetPIVSigner: %v", err)
	}
	digest := sha256.Sum256(challenge.Nonce)
	bareNonce, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("sign bare nonce: %v", err)
	}
	otherPurpose, err := f.SignChallenge(ctx, slot, challenge.ChallengeID, "quorum:b", challenge.Nonce)
	if err != nil {
		t.Fatalf("SignChallenge(other purpose): %v", err)
	}
	for proof, sig := range map[string][]byte{"bare nonce": bareNonce, "other purpose": otherPurpose} {
		var failed *qrdbsdk.AuthFactorVerificationFailedError
		if err := f.Verify(ctx, challenge, &qrdbsdk.AuthFactorResponse{Value: sig}); !errors.As(err, &failed) {
			t.Errorf("Verify(%s) err = %v, want VerificationFailedError", proof, err)
		}
	}
}

// TestPIVFactor_EmptyNonceIsRefused verifies that neither the prover nor the
// verifier accepts a challenge carrying no nonce.
func TestPIVFactor_EmptyNonceIsRefused(t *testing.T) {
	ctx := context.Background()
	f := New(Config{})
	var empty *EmptyNonceError
	if _, err := f.SignChallenge(ctx, pivcert.PIVSlotAuthentication, "challenge-id", "", nil); !errors.As(err, &empty) {
		t.Fatalf("SignChallenge(empty nonce) err = %v, want EmptyNonceError", err)
	}

	enrollment, err := f.Enroll(ctx, &qrdbsdk.AuthFactorEnrollParams{UserID: "u1"})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	challenge, err := f.Challenge(ctx, enrollment)
	if err != nil {
		t.Fatalf("Challenge: %v", err)
	}
	sig, err := f.SignChallenge(ctx, pivcert.PIVSlotAuthentication, challenge.ChallengeID, "", challenge.Nonce)
	if err != nil {
		t.Fatalf("SignChallenge: %v", err)
	}
	challenge.Nonce = nil
	var failed *qrdbsdk.AuthFactorVerificationFailedError
	if err := f.Verify(ctx, challenge, &qrdbsdk.AuthFactorResponse{Value: sig}); !errors.As(err, &failed) {
		t.Fatalf("Verify(empty nonce) err = %v, want VerificationFailedError", err)
	}
}

func TestPIVFactor_NewDefaults(t *testing.T) {
	f := New(Config{})
	if got := f.Name(); got != FactorName {
		t.Fatalf("Name() = %q, want %q", got, FactorName)
	}
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

// TestPIVFactor_Challenge_TTLOverride asserts that a positive integer "ttl"
// in the enrollment metadata sets the challenge lifetime, and that a zero,
// negative or non-numeric value falls back to Config.ChallengeTTLSeconds.
func TestPIVFactor_Challenge_TTLOverride(t *testing.T) {
	const configuredTTL = 7
	tests := []struct {
		name string
		ttl  string
		want time.Duration
	}{
		{name: "valid override", ttl: "30", want: 30 * time.Second},
		{name: "zero falls back", ttl: "0", want: configuredTTL * time.Second},
		{name: "negative falls back", ttl: "-5", want: configuredTTL * time.Second},
		{name: "non-numeric falls back", ttl: "abc", want: configuredTTL * time.Second},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			f := New(Config{ChallengeTTLSeconds: configuredTTL})
			enrollment, err := f.Enroll(ctx, &qrdbsdk.AuthFactorEnrollParams{UserID: "u1"})
			if err != nil {
				t.Fatalf("Enroll: %v", err)
			}
			enrollment.Metadata["ttl"] = tt.ttl

			before := time.Now()
			challenge, err := f.Challenge(ctx, enrollment)
			after := time.Now()
			if err != nil {
				t.Fatalf("Challenge: %v", err)
			}
			earliest, latest := before.Add(tt.want), after.Add(tt.want)
			if challenge.ExpiresAt.Before(earliest) || challenge.ExpiresAt.After(latest) {
				t.Fatalf("ExpiresAt = %v, want within [%v, %v]", challenge.ExpiresAt, earliest, latest)
			}
		})
	}
}

// TestPIVFactor_Verify_RejectsUnsupportedKeyType asserts that an enrolled
// public key of a type PIV does not sign with (DSA) is refused rather than
// treated as a valid signer.
func TestPIVFactor_Verify_RejectsUnsupportedKeyType(t *testing.T) {
	der := dsaPublicKeyDER(t)
	challenge := &qrdbsdk.AuthFactorChallenge{
		ChallengeID: qrdbsdk.NewAuthFactorChallengeID(),
		Nonce:       []byte("nonce"),
		ExpiresAt:   time.Now().Add(time.Minute),
		MethodData: map[string]any{
			methodDataEnrolledCert: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})),
		},
	}

	err := New(Config{}).Verify(context.Background(), challenge, &qrdbsdk.AuthFactorResponse{Value: []byte("sig")})
	var failed *qrdbsdk.AuthFactorVerificationFailedError
	if !errors.As(err, &failed) {
		t.Fatalf("Verify(X25519 key) err = %v, want VerificationFailedError", err)
	}
	if failed.Reason != "unsupported public key type" {
		t.Fatalf("Reason = %q, want %q", failed.Reason, "unsupported public key type")
	}
}

// dsaPublicKeyDER returns a PKIX SubjectPublicKeyInfo for a DSA key built from
// small fixed values (RFC 3279 section 2.3.2). x509.ParsePKIXPublicKey yields
// a *dsa.PublicKey for it, and building it needs no FIPS-restricted primitive.
func dsaPublicKeyDER(t *testing.T) []byte {
	t.Helper()
	params, err := asn1.Marshal(struct{ P, Q, G *big.Int }{big.NewInt(23), big.NewInt(11), big.NewInt(4)})
	if err != nil {
		t.Fatalf("marshal DSA parameters: %v", err)
	}
	y, err := asn1.Marshal(big.NewInt(8))
	if err != nil {
		t.Fatalf("marshal DSA public value: %v", err)
	}
	der, err := asn1.Marshal(struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}{
		Algorithm: pkix.AlgorithmIdentifier{
			Algorithm:  asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 1},
			Parameters: asn1.RawValue{FullBytes: params},
		},
		PublicKey: asn1.BitString{Bytes: y, BitLength: 8 * len(y)},
	})
	if err != nil {
		t.Fatalf("marshal SubjectPublicKeyInfo: %v", err)
	}
	return der
}

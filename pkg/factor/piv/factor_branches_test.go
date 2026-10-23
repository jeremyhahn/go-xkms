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
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/pivcert"
)

// =============================================================================
// Test doubles
// =============================================================================

// stubGenerator is a minimal PIVKeyGenerator double used to drive error
// branches the real software generator cannot easily reach (e.g., a
// downstream key-generation failure or an unsupported public key type).
type stubGenerator struct {
	genErr    error
	signerErr error
	signer    crypto.Signer
}

func (g *stubGenerator) GeneratePIVKey(_ pivcert.PIVSlot, _ string, _ string) (crypto.Signer, error) {
	if g.genErr != nil {
		return nil, g.genErr
	}
	return g.signer, nil
}

func (g *stubGenerator) GetPIVSigner(_ pivcert.PIVSlot, _ string) (crypto.Signer, error) {
	if g.signerErr != nil {
		return nil, g.signerErr
	}
	return g.signer, nil
}

// unsupportedPublicKey carries a Public() implementation x509.CreateCertificate
// cannot recognise. Used to force buildSelfSignedCert into its CreateCertificate
// error branch.
type unsupportedPublicKey struct{}

// unsupportedSigner satisfies crypto.Signer but returns an unrecognised public
// key type so CreateCertificate fails before any signing occurs.
type unsupportedSigner struct{}

func (unsupportedSigner) Public() crypto.PublicKey { return unsupportedPublicKey{} }
func (unsupportedSigner) Sign(_ io.Reader, _ []byte, _ crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("unsupportedSigner: sign not reachable in this test")
}

// =============================================================================
// Enroll
// =============================================================================

func TestPIVFactor_Enroll_CustomSlotAndAlgorithm(t *testing.T) {
	// Drives the params.MethodParams["slot"] and ["algorithm"] branches that
	// the default-only round trip skips.
	f := New(Config{})
	enrollment, err := f.Enroll(context.Background(), &qrdbsdk.AuthFactorEnrollParams{
		UserID: "u-custom",
		MethodParams: map[string]any{
			"slot":      "9c",
			"algorithm": "ecdsap384",
		},
	})
	if err != nil {
		t.Fatalf("Enroll custom: %v", err)
	}
	if enrollment.Metadata["slot"] != "9c" {
		t.Fatalf("slot = %q, want 9c", enrollment.Metadata["slot"])
	}
	if enrollment.Metadata["algorithm"] != "ecdsap384" {
		t.Fatalf("algorithm = %q, want ecdsap384", enrollment.Metadata["algorithm"])
	}
}

func TestPIVFactor_Enroll_GeneratePIVKeyError(t *testing.T) {
	// Inject a generator that always fails so the GeneratePIVKey error branch
	// is exercised end-to-end as an EnrollmentInvalidError.
	stub := &stubGenerator{genErr: errors.New("hardware offline")}
	f := New(Config{Generator: stub})

	var inv *qrdbsdk.AuthFactorEnrollmentInvalidError
	_, err := f.Enroll(context.Background(), &qrdbsdk.AuthFactorEnrollParams{UserID: "u1"})
	if !errors.As(err, &inv) {
		t.Fatalf("expected EnrollmentInvalidError, got %v", err)
	}
}

func TestPIVFactor_Enroll_BuildCertError(t *testing.T) {
	// Inject a signer whose Public() returns an unsupported type. The dispatch
	// reaches buildSelfSignedCert, x509.CreateCertificate fails, and Enroll
	// wraps the failure as an EnrollmentInvalidError.
	stub := &stubGenerator{signer: unsupportedSigner{}}
	f := New(Config{Generator: stub})

	var inv *qrdbsdk.AuthFactorEnrollmentInvalidError
	_, err := f.Enroll(context.Background(), &qrdbsdk.AuthFactorEnrollParams{UserID: "u1"})
	if !errors.As(err, &inv) {
		t.Fatalf("expected EnrollmentInvalidError, got %v", err)
	}
}

// =============================================================================
// Challenge
// =============================================================================

func TestPIVFactor_Challenge_RejectsNilEnrollment(t *testing.T) {
	f := New(Config{})
	var inv *qrdbsdk.AuthFactorEnrollmentInvalidError
	_, err := f.Challenge(context.Background(), nil)
	if !errors.As(err, &inv) {
		t.Fatalf("expected EnrollmentInvalidError, got %v", err)
	}
}

func TestPIVFactor_Challenge_HonoursEnrollmentTTLOverride(t *testing.T) {
	// Metadata["ttl"] = "120" overrides cfg.ChallengeTTLSeconds. This exercises
	// the parseable-int branch of the TTL lookup.
	f := New(Config{ChallengeTTLSeconds: 5})
	enrollment, err := f.Enroll(context.Background(), &qrdbsdk.AuthFactorEnrollParams{UserID: "u1"})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	enrollment.Metadata["ttl"] = "120"

	ch, err := f.Challenge(context.Background(), enrollment)
	if err != nil {
		t.Fatalf("Challenge: %v", err)
	}
	// ExpiresAt should be ~120 seconds out, well past the configured 5s default.
	wantMinSecondsAhead := 60
	if delta := ch.ExpiresAt.Unix() - ch.ExpiresAt.Add(-120*1_000_000_000).Unix(); delta < int64(wantMinSecondsAhead) {
		t.Fatalf("ExpiresAt was not extended by TTL override")
	}
}

func TestPIVFactor_Challenge_IgnoresMalformedTTL(t *testing.T) {
	// A garbage "ttl" string falls through the strconv.Atoi branch; the
	// default TTL is preserved. This drives the !ok branch of the int parse.
	f := New(Config{ChallengeTTLSeconds: 7})
	enrollment, err := f.Enroll(context.Background(), &qrdbsdk.AuthFactorEnrollParams{UserID: "u1"})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	enrollment.Metadata["ttl"] = "not-an-int"
	if _, err := f.Challenge(context.Background(), enrollment); err != nil {
		t.Fatalf("Challenge: %v", err)
	}
}

// =============================================================================
// Verify
// =============================================================================

func TestPIVFactor_Verify_RejectsNilChallenge(t *testing.T) {
	var inv *qrdbsdk.AuthFactorEnrollmentInvalidError
	err := New(Config{}).Verify(context.Background(), nil, &qrdbsdk.AuthFactorResponse{})
	if !errors.As(err, &inv) {
		t.Fatalf("expected EnrollmentInvalidError, got %v", err)
	}
}

func TestPIVFactor_Verify_RejectsNilResponse(t *testing.T) {
	f := New(Config{})
	enrollment, err := f.Enroll(context.Background(), &qrdbsdk.AuthFactorEnrollParams{UserID: "u1"})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	ch, err := f.Challenge(context.Background(), enrollment)
	if err != nil {
		t.Fatalf("Challenge: %v", err)
	}

	var inv *qrdbsdk.AuthFactorEnrollmentInvalidError
	if err := f.Verify(context.Background(), ch, nil); !errors.As(err, &inv) {
		t.Fatalf("expected EnrollmentInvalidError, got %v", err)
	}
}

func TestPIVFactor_Verify_RejectsMalformedPEM(t *testing.T) {
	f := New(Config{})
	enrollment, err := f.Enroll(context.Background(), &qrdbsdk.AuthFactorEnrollParams{UserID: "u1"})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	ch, err := f.Challenge(context.Background(), enrollment)
	if err != nil {
		t.Fatalf("Challenge: %v", err)
	}

	ch.MethodData[methodDataEnrolledCert] = "not a PEM block"

	var failed *qrdbsdk.AuthFactorVerificationFailedError
	err = f.Verify(context.Background(), ch, &qrdbsdk.AuthFactorResponse{
		Value: []byte("ignored"),
	})
	if !errors.As(err, &failed) {
		t.Fatalf("expected VerificationFailedError, got %v", err)
	}
}

func TestPIVFactor_Verify_RejectsNonECDSAPublicKey(t *testing.T) {
	// Hand-craft an enrolled cert whose public key is RSA; the parser returns
	// it but Verify's *ecdsa.PublicKey type assertion must reject it.
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	pkixDER, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	rsaPubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pkixDER})

	f := New(Config{})
	enrollment, err := f.Enroll(context.Background(), &qrdbsdk.AuthFactorEnrollParams{UserID: "u1"})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	ch, err := f.Challenge(context.Background(), enrollment)
	if err != nil {
		t.Fatalf("Challenge: %v", err)
	}

	ch.MethodData[methodDataEnrolledCert] = string(rsaPubPEM)

	var failed *qrdbsdk.AuthFactorVerificationFailedError
	err = f.Verify(context.Background(), ch, &qrdbsdk.AuthFactorResponse{
		Value: []byte("ignored"),
	})
	if !errors.As(err, &failed) {
		t.Fatalf("expected VerificationFailedError, got %v", err)
	}
}

// =============================================================================
// SignChallenge
// =============================================================================

func TestPIVFactor_SignChallenge_PropagatesGetPIVSignerError(t *testing.T) {
	stub := &stubGenerator{signerErr: errors.New("no signer registered for slot")}
	f := New(Config{Generator: stub})
	_, err := f.SignChallenge(context.Background(), pivcert.PIVSlotAuthentication, "challenge-id", "", []byte("nonce"))
	if err == nil {
		t.Fatal("expected error from SignChallenge when GetPIVSigner fails")
	}
}

// =============================================================================
// buildSelfSignedCert — exercise CreateCertificate error branch directly
// =============================================================================

func TestBuildSelfSignedCert_RejectsUnsupportedSigner(t *testing.T) {
	_, err := buildSelfSignedCert(unsupportedSigner{}, pkix.Name{CommonName: "x"}, 30)
	if err == nil {
		t.Fatal("expected error when signer.Public() is an unsupported type")
	}
}

// =============================================================================
// parsePublicKeyFromPEM
// =============================================================================

func TestParsePublicKeyFromPEM_NoPEMBlock(t *testing.T) {
	var inv *qrdbsdk.AuthFactorEnrollmentInvalidError
	_, err := parsePublicKeyFromPEM([]byte("definitely not a PEM block"))
	if !errors.As(err, &inv) {
		t.Fatalf("expected EnrollmentInvalidError, got %v", err)
	}
}

func TestParsePublicKeyFromPEM_PublicKeyBlock(t *testing.T) {
	// Hits the "PUBLIC KEY" case, which the round-trip cert path does not
	// exercise.
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	pkixDER, err := x509.MarshalPKIXPublicKey(&ecKey.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pkixDER})

	got, err := parsePublicKeyFromPEM(pubPEM)
	if err != nil {
		t.Fatalf("parsePublicKeyFromPEM: %v", err)
	}
	if _, ok := got.(*ecdsa.PublicKey); !ok {
		t.Fatalf("got %T, want *ecdsa.PublicKey", got)
	}
}

func TestParsePublicKeyFromPEM_UnknownBlockType(t *testing.T) {
	weird := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: []byte{1, 2, 3}})
	var inv *qrdbsdk.AuthFactorEnrollmentInvalidError
	_, err := parsePublicKeyFromPEM(weird)
	if !errors.As(err, &inv) {
		t.Fatalf("expected EnrollmentInvalidError, got %v", err)
	}
}

func TestParsePublicKeyFromPEM_BadCertificateBytes(t *testing.T) {
	// A CERTIFICATE block with junk bytes: pem.Decode succeeds but
	// x509.ParseCertificate fails. Drives the cert-parse error branch.
	junk := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{0x00, 0x01, 0x02}})
	if _, err := parsePublicKeyFromPEM(junk); err == nil {
		t.Fatal("expected error parsing junk certificate")
	}
}

// =============================================================================
// verifyECDSA — signature-mismatch branch (DER-valid sig, wrong nonce)
// =============================================================================

func TestVerifyECDSA_RejectsWrongNonceSignature(t *testing.T) {
	// Build a valid DER-encoded ECDSA signature over nonce A, then verify it
	// against nonce B. Decodes successfully but ecdsa.Verify returns false,
	// driving the "signature invalid" branch.
	f := New(Config{})
	enrollment, err := f.Enroll(context.Background(), &qrdbsdk.AuthFactorEnrollParams{UserID: "u1"})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	signedNonce := []byte("the original nonce")
	sig, err := f.SignChallenge(context.Background(), pivcert.PIVSlotAuthentication, "challenge-id", "", signedNonce)
	if err != nil {
		t.Fatalf("SignChallenge: %v", err)
	}

	verifyNonce := []byte("a different nonce entirely")
	ch, err := f.Challenge(context.Background(), enrollment)
	if err != nil {
		t.Fatalf("Challenge: %v", err)
	}
	ch.Nonce = verifyNonce // overwrite

	var failed *qrdbsdk.AuthFactorVerificationFailedError
	err = f.Verify(context.Background(), ch, &qrdbsdk.AuthFactorResponse{
		Value: sig,
	})
	if !errors.As(err, &failed) {
		t.Fatalf("expected VerificationFailedError, got %v", err)
	}
}

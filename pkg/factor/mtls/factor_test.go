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

package mtls

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
)

// ---------------------------------------------------------------------------
// Key-pair helpers
// ---------------------------------------------------------------------------

type keyPair struct {
	certPEM string
	sign    func(nonce []byte) []byte
}

func ecdsaKeyPair(t *testing.T, notAfter time.Time) keyPair {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ecdsa key: %v", err)
	}
	certPEM := selfSignedCert(t, priv, priv.Public(), notAfter)
	return keyPair{
		certPEM: certPEM,
		sign: func(nonce []byte) []byte {
			digest := sha256.Sum256(nonce)
			sig, signErr := priv.Sign(rand.Reader, digest[:], crypto.SHA256)
			if signErr != nil {
				t.Fatalf("ecdsa sign: %v", signErr)
			}
			return sig
		},
	}
}

func rsaKeyPair(t *testing.T, notAfter time.Time) keyPair {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	certPEM := selfSignedCert(t, priv, priv.Public(), notAfter)
	return keyPair{
		certPEM: certPEM,
		sign: func(nonce []byte) []byte {
			digest := sha256.Sum256(nonce)
			sig, signErr := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, digest[:])
			if signErr != nil {
				t.Fatalf("rsa sign: %v", signErr)
			}
			return sig
		},
	}
}

func ed25519KeyPair(t *testing.T, notAfter time.Time) keyPair {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	certPEM := selfSignedCert(t, priv, pub, notAfter)
	return keyPair{
		certPEM: certPEM,
		sign: func(nonce []byte) []byte {
			return ed25519.Sign(priv, nonce)
		},
	}
}

// selfSignedCert builds a minimal self-signed PEM certificate for the given
// signer and public key, expiring at notAfter.
func selfSignedCert(t *testing.T, signer crypto.Signer, pub crypto.PublicKey, notAfter time.Time) string {
	t.Helper()
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("serial: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().UTC().Add(-time.Minute),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, signer)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestMTLSFactor_Name(t *testing.T) {
	if got := New(Config{}).Name(); got != FactorName {
		t.Fatalf("Name() = %q, want %q", got, FactorName)
	}
}

func TestMTLSFactor_NewDefaults(t *testing.T) {
	f := New(Config{})
	if f.cfg.ChallengeTTLSeconds != defaultChallengeTTLSeconds {
		t.Fatalf("ChallengeTTLSeconds = %d, want %d", f.cfg.ChallengeTTLSeconds, defaultChallengeTTLSeconds)
	}
}

// ---------------------------------------------------------------------------
// Enroll
// ---------------------------------------------------------------------------

func TestMTLSFactor_Enroll_HappyPath(t *testing.T) {
	ctx := context.Background()
	f := New(Config{})
	kp := ecdsaKeyPair(t, time.Now().Add(24*time.Hour))

	enrollment, err := f.Enroll(ctx, &qrdbsdk.AuthFactorEnrollParams{
		UserID:       "custodian-1",
		MethodParams: map[string]any{"cert_pem": kp.certPEM},
	})
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
		t.Fatal("PublicKey is empty")
	}
	if string(enrollment.PublicKey) != kp.certPEM {
		t.Fatal("PublicKey does not match supplied cert_pem")
	}
	if enrollment.Metadata["cert_cn"] != "test" {
		t.Fatalf("cert_cn = %q, want test", enrollment.Metadata["cert_cn"])
	}
	if enrollment.Metadata["cert_serial"] == "" {
		t.Fatal("cert_serial is empty")
	}
	if enrollment.Metadata["cert_not_before"] == "" {
		t.Fatal("cert_not_before is empty")
	}
	if enrollment.Metadata["cert_not_after"] == "" {
		t.Fatal("cert_not_after is empty")
	}
	if enrollment.Metadata["cert_spki_thumbprint"] == "" {
		t.Fatal("cert_spki_thumbprint is empty")
	}
	if enrollment.Metadata["ttl"] == "" {
		t.Fatal("ttl is empty")
	}
}

func TestMTLSFactor_Enroll_RejectsNilParams(t *testing.T) {
	var inv *qrdbsdk.AuthFactorEnrollmentInvalidError
	if _, err := New(Config{}).Enroll(context.Background(), nil); !errors.As(err, &inv) {
		t.Fatalf("Enroll(nil) err = %v, want EnrollmentInvalidError", err)
	}
}

func TestMTLSFactor_Enroll_RejectsMissingCertPEM(t *testing.T) {
	var inv *qrdbsdk.AuthFactorEnrollmentInvalidError
	_, err := New(Config{}).Enroll(context.Background(), &qrdbsdk.AuthFactorEnrollParams{
		UserID:       "u1",
		MethodParams: map[string]any{},
	})
	if !errors.As(err, &inv) {
		t.Fatalf("Enroll(no cert) err = %v, want EnrollmentInvalidError", err)
	}
}

func TestMTLSFactor_Enroll_RejectsGarbagePEM(t *testing.T) {
	var inv *qrdbsdk.AuthFactorEnrollmentInvalidError
	_, err := New(Config{}).Enroll(context.Background(), &qrdbsdk.AuthFactorEnrollParams{
		UserID:       "u1",
		MethodParams: map[string]any{"cert_pem": "not-a-pem-block"},
	})
	if !errors.As(err, &inv) {
		t.Fatalf("Enroll(garbage) err = %v, want EnrollmentInvalidError", err)
	}
}

func TestMTLSFactor_Enroll_RejectsExpiredCert(t *testing.T) {
	var inv *qrdbsdk.AuthFactorEnrollmentInvalidError
	kp := ecdsaKeyPair(t, time.Now().Add(-time.Hour))
	_, err := New(Config{}).Enroll(context.Background(), &qrdbsdk.AuthFactorEnrollParams{
		UserID:       "u1",
		MethodParams: map[string]any{"cert_pem": kp.certPEM},
	})
	if !errors.As(err, &inv) {
		t.Fatalf("Enroll(expired cert) err = %v, want EnrollmentInvalidError", err)
	}
}

// ---------------------------------------------------------------------------
// Challenge
// ---------------------------------------------------------------------------

func TestMTLSFactor_Challenge_HappyPath(t *testing.T) {
	ctx := context.Background()
	f := New(Config{})
	kp := ecdsaKeyPair(t, time.Now().Add(24*time.Hour))
	enrollment, err := f.Enroll(ctx, &qrdbsdk.AuthFactorEnrollParams{
		UserID:       "u1",
		MethodParams: map[string]any{"cert_pem": kp.certPEM},
	})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	challenge, err := f.Challenge(ctx, enrollment)
	if err != nil {
		t.Fatalf("Challenge: %v", err)
	}
	if len(challenge.Nonce) != nonceLength {
		t.Fatalf("nonce length = %d, want %d", len(challenge.Nonce), nonceLength)
	}
	if challenge.EnrollmentID != enrollment.EnrollmentID {
		t.Fatalf("EnrollmentID mismatch")
	}
	if challenge.Expired() {
		t.Fatal("freshly issued challenge must not be expired")
	}
	encoded, ok := challenge.MethodData[methodDataEnrolledKey].(string)
	if !ok || encoded == "" {
		t.Fatal("enrolled_public_key_der missing or empty in MethodData")
	}
	if _, present := challenge.MethodData["enrolled_cert_pem"]; present {
		t.Fatal("challenge must not expose the enrolled certificate")
	}
	der, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("decode enrolled_public_key_der: %v", err)
	}
	if _, err := x509.ParsePKIXPublicKey(der); err != nil {
		t.Fatalf("enrolled_public_key_der is not a PKIX public key: %v", err)
	}
}

func TestMTLSFactor_Challenge_RejectsCorruptEnrollment(t *testing.T) {
	enrollment := &qrdbsdk.AuthFactorEnrollment{EnrollmentID: "e1", PublicKey: []byte("not a certificate")}
	var inv *qrdbsdk.AuthFactorEnrollmentInvalidError
	if _, err := New(Config{}).Challenge(context.Background(), enrollment); !errors.As(err, &inv) {
		t.Fatalf("Challenge(corrupt) err = %v, want EnrollmentInvalidError", err)
	}
	if inv.EnrollmentID != "e1" {
		t.Errorf("EnrollmentID = %q, want e1", inv.EnrollmentID)
	}
}

func TestMTLSFactor_Challenge_RejectsNilEnrollment(t *testing.T) {
	var inv *qrdbsdk.AuthFactorEnrollmentInvalidError
	if _, err := New(Config{}).Challenge(context.Background(), nil); !errors.As(err, &inv) {
		t.Fatalf("Challenge(nil) err = %v, want EnrollmentInvalidError", err)
	}
}

// ---------------------------------------------------------------------------
// Verify — full round-trip per key type
// ---------------------------------------------------------------------------

func TestMTLSFactor_RoundTrip_ECDSA(t *testing.T) {
	ctx := context.Background()
	f := New(Config{})
	kp := ecdsaKeyPair(t, time.Now().Add(24*time.Hour))

	enrollment, err := f.Enroll(ctx, &qrdbsdk.AuthFactorEnrollParams{
		UserID:       "c1",
		MethodParams: map[string]any{"cert_pem": kp.certPEM},
	})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	challenge, err := f.Challenge(ctx, enrollment)
	if err != nil {
		t.Fatalf("Challenge: %v", err)
	}
	if err := f.Verify(ctx, challenge, &qrdbsdk.AuthFactorResponse{Value: kp.sign(challenge.Nonce)}); err != nil {
		t.Fatalf("Verify ECDSA: %v", err)
	}
}

func TestMTLSFactor_RoundTrip_RSA(t *testing.T) {
	ctx := context.Background()
	f := New(Config{})
	kp := rsaKeyPair(t, time.Now().Add(24*time.Hour))

	enrollment, err := f.Enroll(ctx, &qrdbsdk.AuthFactorEnrollParams{
		UserID:       "c1",
		MethodParams: map[string]any{"cert_pem": kp.certPEM},
	})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	challenge, err := f.Challenge(ctx, enrollment)
	if err != nil {
		t.Fatalf("Challenge: %v", err)
	}
	if err := f.Verify(ctx, challenge, &qrdbsdk.AuthFactorResponse{Value: kp.sign(challenge.Nonce)}); err != nil {
		t.Fatalf("Verify RSA: %v", err)
	}
}

func TestMTLSFactor_RoundTrip_Ed25519(t *testing.T) {
	ctx := context.Background()
	f := New(Config{})
	kp := ed25519KeyPair(t, time.Now().Add(24*time.Hour))

	enrollment, err := f.Enroll(ctx, &qrdbsdk.AuthFactorEnrollParams{
		UserID:       "c1",
		MethodParams: map[string]any{"cert_pem": kp.certPEM},
	})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	challenge, err := f.Challenge(ctx, enrollment)
	if err != nil {
		t.Fatalf("Challenge: %v", err)
	}
	if err := f.Verify(ctx, challenge, &qrdbsdk.AuthFactorResponse{Value: kp.sign(challenge.Nonce)}); err != nil {
		t.Fatalf("Verify Ed25519: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Verify — error cases
// ---------------------------------------------------------------------------

func TestMTLSFactor_Verify_RejectsNilChallenge(t *testing.T) {
	var inv *qrdbsdk.AuthFactorEnrollmentInvalidError
	if err := New(Config{}).Verify(context.Background(), nil, &qrdbsdk.AuthFactorResponse{}); !errors.As(err, &inv) {
		t.Fatalf("Verify(nil challenge) err = %v, want EnrollmentInvalidError", err)
	}
}

func TestMTLSFactor_Verify_RejectsNilResponse(t *testing.T) {
	var inv *qrdbsdk.AuthFactorEnrollmentInvalidError
	if err := New(Config{}).Verify(context.Background(), &qrdbsdk.AuthFactorChallenge{}, nil); !errors.As(err, &inv) {
		t.Fatalf("Verify(nil response) err = %v, want EnrollmentInvalidError", err)
	}
}

func TestMTLSFactor_Verify_RejectsExpiredChallenge(t *testing.T) {
	ctx := context.Background()
	f := New(Config{ChallengeTTLSeconds: 300})
	kp := ecdsaKeyPair(t, time.Now().Add(24*time.Hour))
	enrollment, _ := f.Enroll(ctx, &qrdbsdk.AuthFactorEnrollParams{
		UserID:       "u1",
		MethodParams: map[string]any{"cert_pem": kp.certPEM},
	})
	challenge, _ := f.Challenge(ctx, enrollment)
	challenge.ExpiresAt = challenge.ExpiresAt.Add(-time.Hour)

	var expired *qrdbsdk.AuthFactorChallengeExpiredError
	if err := f.Verify(ctx, challenge, &qrdbsdk.AuthFactorResponse{Value: kp.sign(challenge.Nonce)}); !errors.As(err, &expired) {
		t.Fatalf("Verify(expired) err = %v, want ChallengeExpiredError", err)
	}
}

func TestMTLSFactor_Verify_RejectsMissingEnrolledCertPEM(t *testing.T) {
	ctx := context.Background()
	f := New(Config{})
	kp := ecdsaKeyPair(t, time.Now().Add(24*time.Hour))
	enrollment, _ := f.Enroll(ctx, &qrdbsdk.AuthFactorEnrollParams{
		UserID:       "u1",
		MethodParams: map[string]any{"cert_pem": kp.certPEM},
	})
	challenge, _ := f.Challenge(ctx, enrollment)
	// Remove the enrolled cert from MethodData to simulate a tampered challenge.
	delete(challenge.MethodData, methodDataEnrolledKey)

	var failed *qrdbsdk.AuthFactorVerificationFailedError
	if err := f.Verify(ctx, challenge, &qrdbsdk.AuthFactorResponse{Value: kp.sign(challenge.Nonce)}); !errors.As(err, &failed) {
		t.Fatalf("Verify(missing cert) err = %v, want VerificationFailedError", err)
	}
}

func TestMTLSFactor_Verify_RejectsWrongSignature(t *testing.T) {
	ctx := context.Background()
	f := New(Config{})
	kp := ecdsaKeyPair(t, time.Now().Add(24*time.Hour))
	enrollment, _ := f.Enroll(ctx, &qrdbsdk.AuthFactorEnrollParams{
		UserID:       "u1",
		MethodParams: map[string]any{"cert_pem": kp.certPEM},
	})
	challenge, _ := f.Challenge(ctx, enrollment)

	var failed *qrdbsdk.AuthFactorVerificationFailedError
	if err := f.Verify(ctx, challenge, &qrdbsdk.AuthFactorResponse{Value: []byte("not-a-valid-signature")}); !errors.As(err, &failed) {
		t.Fatalf("Verify(bad sig) err = %v, want VerificationFailedError", err)
	}
}

func TestMTLSFactor_Verify_RejectsWrongKey(t *testing.T) {
	ctx := context.Background()
	f := New(Config{})
	kp := ecdsaKeyPair(t, time.Now().Add(24*time.Hour))
	otherKP := ecdsaKeyPair(t, time.Now().Add(24*time.Hour))

	enrollment, _ := f.Enroll(ctx, &qrdbsdk.AuthFactorEnrollParams{
		UserID:       "u1",
		MethodParams: map[string]any{"cert_pem": kp.certPEM},
	})
	challenge, _ := f.Challenge(ctx, enrollment)

	// Sign with a different key — must fail.
	var failed *qrdbsdk.AuthFactorVerificationFailedError
	if err := f.Verify(ctx, challenge, &qrdbsdk.AuthFactorResponse{Value: otherKP.sign(challenge.Nonce)}); !errors.As(err, &failed) {
		t.Fatalf("Verify(wrong key) err = %v, want VerificationFailedError", err)
	}
}

func TestMTLSFactor_Verify_RejectsCorruptEnrolledKey(t *testing.T) {
	ctx := context.Background()
	f := New(Config{})
	kp := ecdsaKeyPair(t, time.Now().Add(24*time.Hour))
	enrollment, _ := f.Enroll(ctx, &qrdbsdk.AuthFactorEnrollParams{
		UserID:       "u1",
		MethodParams: map[string]any{"cert_pem": kp.certPEM},
	})
	challenge, _ := f.Challenge(ctx, enrollment)
	// Replace the enrolled key in MethodData with garbage to simulate store
	// corruption: once not base64, once base64 of bytes that are no PKIX key.
	challenge.MethodData[methodDataEnrolledKey] = "!not base64!"
	var notBase64 *qrdbsdk.AuthFactorVerificationFailedError
	if err := f.Verify(ctx, challenge, &qrdbsdk.AuthFactorResponse{Value: kp.sign(challenge.Nonce)}); !errors.As(err, &notBase64) {
		t.Fatalf("Verify(non-base64 key) err = %v, want VerificationFailedError", err)
	}
	challenge.MethodData[methodDataEnrolledKey] = base64.StdEncoding.EncodeToString([]byte("garbage"))

	var failed *qrdbsdk.AuthFactorVerificationFailedError
	if err := f.Verify(ctx, challenge, &qrdbsdk.AuthFactorResponse{Value: kp.sign(challenge.Nonce)}); !errors.As(err, &failed) {
		t.Fatalf("Verify(corrupt key) err = %v, want VerificationFailedError", err)
	}
}

func TestMTLSFactor_Verify_RejectsTamperedNonce(t *testing.T) {
	ctx := context.Background()
	f := New(Config{})
	kp := ecdsaKeyPair(t, time.Now().Add(24*time.Hour))
	enrollment, _ := f.Enroll(ctx, &qrdbsdk.AuthFactorEnrollParams{
		UserID:       "u1",
		MethodParams: map[string]any{"cert_pem": kp.certPEM},
	})
	challenge, _ := f.Challenge(ctx, enrollment)

	// Sign the original nonce, then tamper so the signature no longer matches.
	sig := kp.sign(challenge.Nonce)
	challenge.Nonce[0] ^= 0xFF

	var failed *qrdbsdk.AuthFactorVerificationFailedError
	if err := f.Verify(ctx, challenge, &qrdbsdk.AuthFactorResponse{Value: sig}); !errors.As(err, &failed) {
		t.Fatalf("Verify(tampered nonce) err = %v, want VerificationFailedError", err)
	}
}

// ---------------------------------------------------------------------------
// parseCertPEM unit tests
// ---------------------------------------------------------------------------

func TestParseCertPEM_RejectsEmptyInput(t *testing.T) {
	if _, err := parseCertPEM(nil); err == nil {
		t.Fatal("expected error for nil input")
	}
}

func TestParseCertPEM_RejectsNonCertBlock(t *testing.T) {
	data := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte{0x01}})
	if _, err := parseCertPEM(data); err == nil {
		t.Fatal("expected error for non-CERTIFICATE PEM block")
	}
}

// ---------------------------------------------------------------------------
// verifyECDSA unit tests (helper coverage)
// ---------------------------------------------------------------------------

func TestVerifyECDSA_RejectsGarbageASN1(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	err := verifyECDSA(&priv.PublicKey, []byte("digest"), []byte("not-asn1"))
	var failed *qrdbsdk.AuthFactorVerificationFailedError
	if !errors.As(err, &failed) {
		t.Fatalf("verifyECDSA(bad asn1) err = %v, want VerificationFailedError", err)
	}
}

func TestVerifyECDSA_RejectsNonPositiveComponents(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	// Build an ASN.1 struct with R=0, S=1.
	type ecSig struct{ R, S *big.Int }
	sig, _ := asn1.Marshal(ecSig{R: big.NewInt(0), S: big.NewInt(1)})
	err := verifyECDSA(&priv.PublicKey, []byte("digest"), sig)
	var failed *qrdbsdk.AuthFactorVerificationFailedError
	if !errors.As(err, &failed) {
		t.Fatalf("verifyECDSA(non-positive R) err = %v, want VerificationFailedError", err)
	}
}

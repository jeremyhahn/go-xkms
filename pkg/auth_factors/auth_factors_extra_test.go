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

package auth_factors

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	xkmswebauthn "github.com/jeremyhahn/go-xkms/pkg/webauthn"
)

// ---------------------------------------------------------------------------
// Error type Error() method coverage
// ---------------------------------------------------------------------------

func TestNilTrustPoolError_Error(t *testing.T) {
	e := &NilTrustPoolError{}
	if e.Error() == "" {
		t.Fatal("NilTrustPoolError.Error() is empty")
	}
}

func TestMissingChallengeFieldError_Error(t *testing.T) {
	e := &MissingChallengeFieldError{Field: "nonce"}
	if e.Error() == "" {
		t.Fatal("MissingChallengeFieldError.Error() is empty")
	}
	// nil-receiver / empty field branches
	e2 := &MissingChallengeFieldError{}
	if e2.Error() == "" {
		t.Fatal("MissingChallengeFieldError{}.Error() is empty")
	}
}

func TestSignatureVerifyError_Error(t *testing.T) {
	e := &SignatureVerifyError{Reason: "bad sig"}
	if e.Error() == "" {
		t.Fatal("SignatureVerifyError.Error() is empty")
	}
	e2 := &SignatureVerifyError{}
	if e2.Error() == "" {
		t.Fatal("SignatureVerifyError{}.Error() is empty")
	}
}

func TestUnsupportedPublicKeyError_Error(t *testing.T) {
	e := &UnsupportedPublicKeyError{}
	if e.Error() == "" {
		t.Fatal("UnsupportedPublicKeyError.Error() is empty")
	}
}

func TestCertDecodeError_Error(t *testing.T) {
	e := &CertDecodeError{Reason: "invalid PEM"}
	if e.Error() == "" {
		t.Fatal("CertDecodeError.Error() is empty")
	}
	e2 := &CertDecodeError{}
	if e2.Error() == "" {
		t.Fatal("CertDecodeError{}.Error() is empty")
	}
}

func TestMissingFactorError_Error(t *testing.T) {
	e := &MissingFactorError{}
	if e.Error() == "" {
		t.Fatal("MissingFactorError.Error() is empty")
	}
}

func TestCredentialMismatchError_Error(t *testing.T) {
	e := &CredentialMismatchError{}
	if e.Error() == "" {
		t.Fatal("CredentialMismatchError.Error() is empty")
	}
}

func TestNilServiceError_Error(t *testing.T) {
	e := &NilServiceError{Adapter: "webauthn"}
	if e.Error() == "" {
		t.Fatal("NilServiceError.Error() is empty")
	}
	e2 := &NilServiceError{}
	if e2.Error() == "" {
		t.Fatal("NilServiceError{}.Error() is empty")
	}
}

func TestMissingMethodMetadataError_Error(t *testing.T) {
	e := &MissingMethodMetadataError{Field: "session_id"}
	if e.Error() == "" {
		t.Fatal("MissingMethodMetadataError.Error() is empty")
	}
	e2 := &MissingMethodMetadataError{}
	if e2.Error() == "" {
		t.Fatal("MissingMethodMetadataError{}.Error() is empty")
	}
}

func TestVerifyNotSupportedError_Error(t *testing.T) {
	e := &VerifyNotSupportedError{Reason: "no hardware"}
	if e.Error() == "" {
		t.Fatal("VerifyNotSupportedError.Error() is empty")
	}
	e2 := &VerifyNotSupportedError{}
	if e2.Error() == "" {
		t.Fatal("VerifyNotSupportedError{}.Error() is empty")
	}
}

func TestVerifyNotSupportedError_Is(t *testing.T) {
	e := &VerifyNotSupportedError{Reason: "test"}
	// Is() returns true for errBadChallenge sentinel.
	if !e.Is(errBadChallenge) {
		t.Fatal("expected Is(errBadChallenge) == true")
	}
	if e.Is(errors.New("other")) {
		t.Fatal("expected Is(other) == false")
	}
}

// ---------------------------------------------------------------------------
// PIV Verify: nil receiver
// ---------------------------------------------------------------------------

func TestPIVHardwareFactorVerifier_NilVerifier(t *testing.T) {
	var v *PIVHardwareFactorVerifier
	err := v.Verify(context.Background(), &qrdbsdk.AuthFactor{
		ID:   "f",
		Type: qrdbsdk.AuthFactorPIV,
	}, qrdbtransport.VerifyChallenge{})
	var nte *NilTrustPoolError
	if !errors.As(err, &nte) {
		t.Fatalf("expected *NilTrustPoolError, got %T (%v)", err, err)
	}
}

// ---------------------------------------------------------------------------
// PIV Verify: RSA public key in leaf certificate
// ---------------------------------------------------------------------------

// newPIVRSAFixture generates a CA + leaf chain with an RSA 2048 leaf key.
type pivRSAFixture struct {
	rootPool *x509.CertPool
	leafKey  *rsa.PrivateKey
	leafCert *x509.Certificate
	leafPEM  string
}

func newPIVRSAFixture(t *testing.T) *pivRSAFixture {
	t.Helper()

	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("root key: %v", err)
	}
	rootTpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "piv-rsa-root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTpl, rootTpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("root cert: %v", err)
	}
	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatalf("parse root: %v", err)
	}

	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa leaf key: %v", err)
	}
	leafTpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "piv-rsa-leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTpl, rootCert, &leafKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("leaf cert: %v", err)
	}
	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	leafPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}))

	pool := x509.NewCertPool()
	pool.AddCert(rootCert)

	return &pivRSAFixture{
		rootPool: pool,
		leafKey:  leafKey,
		leafCert: leafCert,
		leafPEM:  leafPEM,
	}
}

func TestPIVHardwareFactorVerifier_RSAKey_Success(t *testing.T) {
	fx := newPIVRSAFixture(t)
	v, err := NewPIVHardwareFactorVerifier(fx.rootPool, nil)
	if err != nil {
		t.Fatalf("verifier: %v", err)
	}

	sum := sha256.Sum256(fx.leafCert.Raw)
	nonce := []byte("piv-rsa-nonce-test")
	digest := sha256.Sum256(nonce)
	sig, err := rsa.SignPKCS1v15(rand.Reader, fx.leafKey, hashAlgo, digest[:])
	if err != nil {
		t.Fatalf("rsa sign: %v", err)
	}

	factor := &qrdbsdk.AuthFactor{
		ID:         "f-piv-rsa",
		UserID:     1,
		Type:       qrdbsdk.AuthFactorPIV,
		Credential: sum[:],
		Metadata:   map[string]string{"cert_pem": fx.leafPEM},
	}
	if err := v.Verify(context.Background(), factor, qrdbtransport.VerifyChallenge{
		Type:      qrdbtransport.FactorTypePIV,
		Nonce:     nonce,
		Signature: sig,
	}); err != nil {
		t.Fatalf("Verify RSA PIV: %v", err)
	}
}

func TestPIVHardwareFactorVerifier_RSAKey_BadSignature(t *testing.T) {
	fx := newPIVRSAFixture(t)
	v, err := NewPIVHardwareFactorVerifier(fx.rootPool, nil)
	if err != nil {
		t.Fatalf("verifier: %v", err)
	}

	sum := sha256.Sum256(fx.leafCert.Raw)
	factor := &qrdbsdk.AuthFactor{
		ID:         "f-piv-rsa-bad",
		UserID:     1,
		Type:       qrdbsdk.AuthFactorPIV,
		Credential: sum[:],
		Metadata:   map[string]string{"cert_pem": fx.leafPEM},
	}
	err = v.Verify(context.Background(), factor, qrdbtransport.VerifyChallenge{
		Type:      qrdbtransport.FactorTypePIV,
		Nonce:     []byte("nonce"),
		Signature: []byte("bad-rsa-signature"),
	})
	var sve *SignatureVerifyError
	if !errors.As(err, &sve) {
		t.Fatalf("expected *SignatureVerifyError, got %T (%v)", err, err)
	}
}

// ---------------------------------------------------------------------------
// PIV Verify: unsupported public key type in leaf certificate (Ed25519)
// ---------------------------------------------------------------------------

// newPIVEd25519Fixture generates a CA + Ed25519 leaf chain.
// Go's x509.CreateCertificate does support Ed25519 — we use ECDSA as the
// signing CA and Ed25519 as the leaf key so the chain is valid but the
// PIV adapter sees an unsupported key type at signature verification.
type pivEd25519Fixture struct {
	rootPool *x509.CertPool
	leafCert *x509.Certificate
	leafPEM  string
}

func newPIVEd25519Fixture(t *testing.T) *pivEd25519Fixture {
	t.Helper()

	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("root key: %v", err)
	}
	rootTpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "piv-ed25519-root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTpl, rootTpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("root cert: %v", err)
	}
	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatalf("parse root: %v", err)
	}

	leafPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 leaf key: %v", err)
	}
	leafTpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "piv-ed25519-leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTpl, rootCert, leafPub, rootKey)
	if err != nil {
		t.Fatalf("ed25519 leaf cert: %v", err)
	}
	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("parse ed25519 leaf: %v", err)
	}
	leafPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}))

	pool := x509.NewCertPool()
	pool.AddCert(rootCert)

	return &pivEd25519Fixture{
		rootPool: pool,
		leafCert: leafCert,
		leafPEM:  leafPEM,
	}
}

func TestPIVHardwareFactorVerifier_UnsupportedKeyType(t *testing.T) {
	fx := newPIVEd25519Fixture(t)
	v, err := NewPIVHardwareFactorVerifier(fx.rootPool, nil)
	if err != nil {
		t.Fatalf("verifier: %v", err)
	}

	sum := sha256.Sum256(fx.leafCert.Raw)
	factor := &qrdbsdk.AuthFactor{
		ID:         "f-piv-ed25519",
		UserID:     1,
		Type:       qrdbsdk.AuthFactorPIV,
		Credential: sum[:],
		Metadata:   map[string]string{"cert_pem": fx.leafPEM},
	}
	err = v.Verify(context.Background(), factor, qrdbtransport.VerifyChallenge{
		Type:      qrdbtransport.FactorTypePIV,
		Nonce:     []byte("nonce"),
		Signature: []byte("sig"),
	})
	var uke *UnsupportedPublicKeyError
	if !errors.As(err, &uke) {
		t.Fatalf("expected *UnsupportedPublicKeyError, got %T (%v)", err, err)
	}
}

// ---------------------------------------------------------------------------
// decodeCertificate: cert_der fallback path and bad DER
// ---------------------------------------------------------------------------

func TestDecodeCertificate_CertDER_Valid(t *testing.T) {
	fx := newPIVTestFixture(t)
	// cert_der carries the raw DER bytes (not base64 — the code does
	// x509.ParseCertificate([]byte(derB64)) so we pass the DER bytes directly
	// as a string).
	factor := &qrdbsdk.AuthFactor{
		ID:     "f",
		Type:   qrdbsdk.AuthFactorPIV,
		UserID: 1,
		Metadata: map[string]string{
			"cert_der": string(fx.leafDER),
		},
	}
	cert, err := decodeCertificate(factor)
	if err != nil {
		t.Fatalf("decodeCertificate: %v", err)
	}
	if !bytes.Equal(cert.Raw, fx.leafCert.Raw) {
		t.Fatal("decoded cert does not match original")
	}
}

func TestDecodeCertificate_CertDER_BadBytes(t *testing.T) {
	factor := &qrdbsdk.AuthFactor{
		ID:     "f",
		Type:   qrdbsdk.AuthFactorPIV,
		UserID: 1,
		Metadata: map[string]string{
			"cert_der": "not-valid-der-bytes",
		},
	}
	_, err := decodeCertificate(factor)
	var cde *CertDecodeError
	if !errors.As(err, &cde) {
		t.Fatalf("expected *CertDecodeError for bad DER, got %T (%v)", err, err)
	}
}

func TestDecodeCertificate_NilMetadata(t *testing.T) {
	factor := &qrdbsdk.AuthFactor{
		ID:       "f",
		Type:     qrdbsdk.AuthFactorPIV,
		UserID:   1,
		Metadata: nil,
	}
	_, err := decodeCertificate(factor)
	var mfe *MissingChallengeFieldError
	if !errors.As(err, &mfe) {
		t.Fatalf("expected *MissingChallengeFieldError for nil metadata, got %T (%v)", err, err)
	}
}

func TestDecodeCertificate_BadPEMContent(t *testing.T) {
	// Valid PEM block but not a certificate.
	badPEM := "-----BEGIN CERTIFICATE-----\nYWJj\n-----END CERTIFICATE-----\n"
	factor := &qrdbsdk.AuthFactor{
		ID:       "f",
		Type:     qrdbsdk.AuthFactorPIV,
		UserID:   1,
		Metadata: map[string]string{"cert_pem": badPEM},
	}
	_, err := decodeCertificate(factor)
	var cde *CertDecodeError
	if !errors.As(err, &cde) {
		t.Fatalf("expected *CertDecodeError for bad PEM content, got %T (%v)", err, err)
	}
}

// ---------------------------------------------------------------------------
// decodePublicKey: bad base64 in public_key_der
// ---------------------------------------------------------------------------

func TestDecodePublicKey_BadBase64_DER(t *testing.T) {
	factor := &qrdbsdk.AuthFactor{
		ID:     "f",
		Type:   qrdbsdk.AuthFactorPKCS11,
		UserID: 1,
		Metadata: map[string]string{
			"public_key_der": "this-is-not-base64!!!",
		},
	}
	_, _, err := decodePublicKey(factor)
	var pde *PublicKeyDecodeError
	if !errors.As(err, &pde) {
		t.Fatalf("expected *PublicKeyDecodeError for bad base64, got %T (%v)", err, err)
	}
}

func TestDecodePublicKey_BadPKIX_PEM(t *testing.T) {
	// Valid PEM block (CERTIFICATE type) but not a PKIX public key.
	fx := newPIVTestFixture(t)
	certPEM := fx.leafPEM // This is a CERTIFICATE, not a PUBLIC KEY
	// Wrap it as a PUBLIC KEY block to fool the PEM decoder type check.
	block, _ := pem.Decode([]byte(certPEM))
	badPubKeyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: block.Bytes}))

	factor := &qrdbsdk.AuthFactor{
		ID:     "f",
		Type:   qrdbsdk.AuthFactorPKCS11,
		UserID: 1,
		Metadata: map[string]string{
			"public_key_pem": badPubKeyPEM,
		},
	}
	_, _, err := decodePublicKey(factor)
	var pde *PublicKeyDecodeError
	if !errors.As(err, &pde) {
		t.Fatalf("expected *PublicKeyDecodeError for bad PKIX PEM, got %T (%v)", err, err)
	}
}

// ---------------------------------------------------------------------------
// WebAuthn Verify: assertion supplied via challenge.Signature
// ---------------------------------------------------------------------------

func TestWebAuthnFactorVerifier_AssertionViaSignature(t *testing.T) {
	v := newStubVerifier(t)
	factor := &qrdbsdk.AuthFactor{
		ID:         "f1",
		UserID:     1,
		Type:       qrdbsdk.AuthFactorFIDO2,
		Credential: []byte("cred"),
	}
	// assertion is in challenge.Signature (not MethodMetadata["assertion"]).
	// The value is not a valid assertion so we expect a SignatureVerifyError
	// (parse failure), but the code path for reading from Signature is covered.
	err := v.Verify(context.Background(), factor, qrdbtransport.VerifyChallenge{
		Type:      qrdbtransport.FactorTypeFIDO2,
		Signature: []byte(`{"not":"valid-webauthn-assertion"}`),
		MethodMetadata: map[string]string{
			"credential_id": "cred",
			"session_id":    "abc",
			// no "assertion" key — falls back to Signature
		},
	})
	var sve *SignatureVerifyError
	if !errors.As(err, &sve) {
		t.Fatalf("expected *SignatureVerifyError for invalid assertion via Signature, got %T (%v)", err, err)
	}
}

// ---------------------------------------------------------------------------
// WebAuthn Verify: user_handle_b64 in MethodMetadata
// ---------------------------------------------------------------------------

func TestWebAuthnFactorVerifier_UserHandleB64_Invalid(t *testing.T) {
	v := newStubVerifier(t)
	factor := &qrdbsdk.AuthFactor{
		ID:         "f1",
		UserID:     0, // zero UserID — no derived handle fallback
		Type:       qrdbsdk.AuthFactorFIDO2,
		Credential: []byte("cred"),
	}
	// user_handle_b64 contains invalid base64 → decoded == nil → no user id.
	// assertion is also invalid → SignatureVerifyError.
	err := v.Verify(context.Background(), factor, qrdbtransport.VerifyChallenge{
		Type: qrdbtransport.FactorTypeFIDO2,
		MethodMetadata: map[string]string{
			"credential_id":   "cred",
			"session_id":      "sess-1",
			"assertion":       `{"not":"valid"}`,
			"user_handle_b64": "!!!invalid-base64!!!",
		},
	})
	var sve *SignatureVerifyError
	if !errors.As(err, &sve) {
		t.Fatalf("expected *SignatureVerifyError, got %T (%v)", err, err)
	}
}

func TestWebAuthnFactorVerifier_UserHandleB64_Valid_NonZeroUserID(t *testing.T) {
	v := newStubVerifier(t)
	factor := &qrdbsdk.AuthFactor{
		ID:         "f1",
		UserID:     42, // nonzero — would derive handle if no b64 given
		Type:       qrdbsdk.AuthFactorFIDO2,
		Credential: []byte("cred"),
	}
	// Provide valid base64 user handle — decoded successfully so derived handle is skipped.
	// assertion is invalid → SignatureVerifyError at parse.
	err := v.Verify(context.Background(), factor, qrdbtransport.VerifyChallenge{
		Type: qrdbtransport.FactorTypeFIDO2,
		MethodMetadata: map[string]string{
			"credential_id":   "cred",
			"session_id":      "sess-2",
			"assertion":       `{"not":"valid"}`,
			"user_handle_b64": "aGVsbG8=", // valid base64 = "hello"
		},
	})
	var sve *SignatureVerifyError
	if !errors.As(err, &sve) {
		t.Fatalf("expected *SignatureVerifyError, got %T (%v)", err, err)
	}
}

func TestWebAuthnFactorVerifier_DerivedUserID_NonZero(t *testing.T) {
	v := newStubVerifier(t)
	factor := &qrdbsdk.AuthFactor{
		ID:         "f1",
		UserID:     7, // nonzero — handle derived from UserID
		Type:       qrdbsdk.AuthFactorFIDO2,
		Credential: []byte("cred"),
	}
	// No user_handle_b64 → handle is derived from factor.UserID.
	// assertion is invalid → SignatureVerifyError at parse.
	err := v.Verify(context.Background(), factor, qrdbtransport.VerifyChallenge{
		Type: qrdbtransport.FactorTypeFIDO2,
		MethodMetadata: map[string]string{
			"credential_id": "cred",
			"session_id":    "sess-3",
			"assertion":     `{"not":"valid"}`,
		},
	})
	var sve *SignatureVerifyError
	if !errors.As(err, &sve) {
		t.Fatalf("expected *SignatureVerifyError, got %T (%v)", err, err)
	}
}

// ---------------------------------------------------------------------------
// WebAuthn Verify: MethodMetadata nil but not empty (session_id key missing)
// ---------------------------------------------------------------------------

func TestWebAuthnFactorVerifier_EmptySessionID(t *testing.T) {
	v := newStubVerifier(t)
	factor := &qrdbsdk.AuthFactor{
		ID:         "f1",
		UserID:     1,
		Type:       qrdbsdk.AuthFactorFIDO2,
		Credential: []byte("cred"),
	}
	// MethodMetadata present but session_id is "".
	err := v.Verify(context.Background(), factor, qrdbtransport.VerifyChallenge{
		Type: qrdbtransport.FactorTypeFIDO2,
		MethodMetadata: map[string]string{
			"credential_id": "cred",
			"session_id":    "", // explicitly empty
		},
	})
	var mme *MissingMethodMetadataError
	if !errors.As(err, &mme) || mme.Field != "session_id" {
		t.Fatalf("expected MissingMethodMetadataError{session_id}, got %T (%v)", err, err)
	}
}

// ---------------------------------------------------------------------------
// WebAuthn BeginChallenge
// ---------------------------------------------------------------------------

func TestWebAuthnBeginChallenge_NilVerifier(t *testing.T) {
	var v *WebAuthnFactorVerifier
	_, _, _, err := v.BeginChallenge(context.Background(), "tenant", qrdbtransport.FactorTypeFIDO2, "")
	var nse *NilServiceError
	if !errors.As(err, &nse) {
		t.Fatalf("expected *NilServiceError, got %T (%v)", err, err)
	}
}

func TestWebAuthnBeginChallenge_WrongFactorType(t *testing.T) {
	v := newStubVerifier(t)
	_, _, _, err := v.BeginChallenge(context.Background(), "tenant", qrdbtransport.FactorTypePIV, "")
	var ftue *qrdbsdk.FactorTypeUnsupportedError
	if !errors.As(err, &ftue) {
		t.Fatalf("expected *FactorTypeUnsupportedError, got %T (%v)", err, err)
	}
}

func TestWebAuthnBeginChallenge_DiscoverableFlow(t *testing.T) {
	// No hint → nil userID → discoverable-credential flow.
	// BeginDiscoverableLogin should succeed even with empty credential store.
	v := newStubVerifier(t)
	_, _, _, err := v.BeginChallenge(context.Background(), "tenant", qrdbtransport.FactorTypeFIDO2, "")
	if err != nil {
		t.Fatalf("BeginChallenge (discoverable): %v", err)
	}
}

func TestWebAuthnBeginChallenge_HintUserNotFound(t *testing.T) {
	// Hint given but user not in store → GetUserByEmail returns error → userID stays nil.
	// Falls through to discoverable flow.
	v := newStubVerifier(t)
	_, _, _, err := v.BeginChallenge(context.Background(), "tenant", qrdbtransport.FactorTypeFIDO2, "noone@example.com")
	// Should succeed via discoverable flow fallback.
	if err != nil {
		t.Fatalf("BeginChallenge (hint-not-found): %v", err)
	}
}

// ---------------------------------------------------------------------------
// WebAuthn Verify: nil service defensive check (bypasses constructor)
// ---------------------------------------------------------------------------

func TestWebAuthnFactorVerifier_NilService_InVerify(t *testing.T) {
	// Bypass the constructor to create a verifier with nil service.
	v := &WebAuthnFactorVerifier{service: nil}
	err := v.Verify(context.Background(), &qrdbsdk.AuthFactor{
		ID:   "f",
		Type: qrdbsdk.AuthFactorFIDO2,
	}, qrdbtransport.VerifyChallenge{})
	var nse *NilServiceError
	if !errors.As(err, &nse) {
		t.Fatalf("expected *NilServiceError, got %T (%v)", err, err)
	}
}

// ---------------------------------------------------------------------------
// WebAuthn BeginChallenge: hint found in user store → BeginLogin with userID
// (user has no credentials so BeginLogin returns ErrNoCredentials error)
// ---------------------------------------------------------------------------

func TestWebAuthnBeginChallenge_HintUserFound_NoCredentials(t *testing.T) {
	cfg := &xkmswebauthn.Config{
		RPID:          "localhost",
		RPDisplayName: "test",
		RPOrigins:     []string{"https://localhost"},
	}
	users := xkmswebauthn.NewMemoryUserStore()
	creds := xkmswebauthn.NewMemoryCredentialStore()
	sessions := xkmswebauthn.NewMemorySessionStore()

	svc, err := xkmswebauthn.NewService(xkmswebauthn.ServiceParams{
		Config:          cfg,
		UserStore:       users,
		SessionStore:    sessions,
		CredentialStore: creds,
	})
	if err != nil {
		t.Fatalf("webauthn service: %v", err)
	}

	// Create a user in the store so GetUserByEmail returns it.
	ctx := context.Background()
	if _, err := users.Create(ctx, "test@example.com", "Test User"); err != nil {
		t.Fatalf("create user: %v", err)
	}

	v, err := NewWebAuthnFactorVerifier(svc)
	if err != nil {
		t.Fatalf("verifier: %v", err)
	}

	// Hint given and user found → userID = u.WebAuthnID() → BeginLogin(ctx, userID).
	// User has no credentials → BeginLogin returns ErrNoCredentials.
	_, _, _, err = v.BeginChallenge(ctx, "tenant", qrdbtransport.FactorTypeFIDO2, "test@example.com")
	if err == nil {
		t.Fatal("expected error from BeginLogin (no credentials)")
	}
}

// hashAlgo is crypto.SHA256 — used in PIV RSA test to avoid importing "crypto"
// directly in this file (it is already imported transitively via piv.go).
const hashAlgo = 5 // crypto.SHA256 == 5

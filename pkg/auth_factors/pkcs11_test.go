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
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"testing"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
)

// ---------------------------------------------------------------------------
// Test fixture helpers
// ---------------------------------------------------------------------------

// pkcs11ECDSAFixture generates an ECDSA P-256 key, serialises the public key
// to PEM and DER, and computes the SPKI-SHA256 credential hash.
type pkcs11ECDSAFixture struct {
	priv         *ecdsa.PrivateKey
	pkixDER      []byte
	pubKeyPEM    string
	pubKeyDERb64 string
	credential   []byte
}

func newPKCS11ECDSAFixture(t *testing.T) *pkcs11ECDSAFixture {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa gen: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("marshal pkix: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	sum := sha256.Sum256(der)
	return &pkcs11ECDSAFixture{
		priv:         priv,
		pkixDER:      der,
		pubKeyPEM:    string(pemBytes),
		pubKeyDERb64: base64.StdEncoding.EncodeToString(der),
		credential:   sum[:],
	}
}

// pkcs11RSAFixture generates an RSA 2048 key similarly.
type pkcs11RSAFixture struct {
	priv       *rsa.PrivateKey
	pkixDER    []byte
	pubKeyPEM  string
	credential []byte
}

func newPKCS11RSAFixture(t *testing.T) *pkcs11RSAFixture {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa gen: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("marshal pkix rsa: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	sum := sha256.Sum256(der)
	return &pkcs11RSAFixture{
		priv:       priv,
		pkixDER:    der,
		pubKeyPEM:  string(pemBytes),
		credential: sum[:],
	}
}

// pkcs11Ed25519Fixture generates an Ed25519 key similarly.
type pkcs11Ed25519Fixture struct {
	pub        ed25519.PublicKey
	priv       ed25519.PrivateKey
	pkixDER    []byte
	pubKeyPEM  string
	credential []byte
}

func newPKCS11Ed25519Fixture(t *testing.T) *pkcs11Ed25519Fixture {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 gen: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("marshal pkix ed25519: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	sum := sha256.Sum256(der)
	return &pkcs11Ed25519Fixture{
		pub:        pub,
		priv:       priv,
		pkixDER:    der,
		pubKeyPEM:  string(pemBytes),
		credential: sum[:],
	}
}

// ---------------------------------------------------------------------------
// Constructor
// ---------------------------------------------------------------------------

func TestNewPKCS11FactorVerifier(t *testing.T) {
	v := NewPKCS11FactorVerifier()
	if v == nil {
		t.Fatal("expected non-nil verifier")
	}
	if v.Type() != qrdbtransport.FactorTypePKCS11 {
		t.Fatalf("Type() = %q, want %q", v.Type(), qrdbtransport.FactorTypePKCS11)
	}
}

// ---------------------------------------------------------------------------
// Happy paths — one per key type
// ---------------------------------------------------------------------------

func TestPKCS11FactorVerifier_ECDSA_Happy(t *testing.T) {
	fx := newPKCS11ECDSAFixture(t)
	v := NewPKCS11FactorVerifier()

	nonce := []byte("pkcs11-test-nonce")
	digest := sha256.Sum256(nonce)
	sig, err := ecdsa.SignASN1(rand.Reader, fx.priv, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	factor := &qrdbsdk.AuthFactor{
		ID:         "f-pkcs11-ecdsa",
		UserID:     1,
		Type:       qrdbsdk.AuthFactorPKCS11,
		Credential: fx.credential,
		Metadata:   map[string]string{"public_key_pem": fx.pubKeyPEM},
	}
	if err := v.Verify(context.Background(), factor, qrdbtransport.VerifyChallenge{
		Type:      qrdbtransport.FactorTypePKCS11,
		Nonce:     nonce,
		Signature: sig,
	}); err != nil {
		t.Fatalf("Verify ECDSA: %v", err)
	}
}

func TestPKCS11FactorVerifier_RSA_Happy(t *testing.T) {
	fx := newPKCS11RSAFixture(t)
	v := NewPKCS11FactorVerifier()

	nonce := []byte("pkcs11-rsa-nonce-test")
	digest := sha256.Sum256(nonce)
	sig, err := rsa.SignPKCS1v15(rand.Reader, fx.priv, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("rsa sign: %v", err)
	}

	factor := &qrdbsdk.AuthFactor{
		ID:         "f-pkcs11-rsa",
		UserID:     2,
		Type:       qrdbsdk.AuthFactorPKCS11,
		Credential: fx.credential,
		Metadata:   map[string]string{"public_key_pem": fx.pubKeyPEM},
	}
	if err := v.Verify(context.Background(), factor, qrdbtransport.VerifyChallenge{
		Type:      qrdbtransport.FactorTypePKCS11,
		Nonce:     nonce,
		Signature: sig,
	}); err != nil {
		t.Fatalf("Verify RSA: %v", err)
	}
}

func TestPKCS11FactorVerifier_Ed25519_Happy(t *testing.T) {
	fx := newPKCS11Ed25519Fixture(t)
	v := NewPKCS11FactorVerifier()

	nonce := []byte("pkcs11-ed25519-nonce")
	sig := ed25519.Sign(fx.priv, nonce)

	factor := &qrdbsdk.AuthFactor{
		ID:         "f-pkcs11-ed25519",
		UserID:     3,
		Type:       qrdbsdk.AuthFactorPKCS11,
		Credential: fx.credential,
		Metadata:   map[string]string{"public_key_pem": fx.pubKeyPEM},
	}
	if err := v.Verify(context.Background(), factor, qrdbtransport.VerifyChallenge{
		Type:      qrdbtransport.FactorTypePKCS11,
		Nonce:     nonce,
		Signature: sig,
	}); err != nil {
		t.Fatalf("Verify Ed25519: %v", err)
	}
}

func TestPKCS11FactorVerifier_DERFallback_Happy(t *testing.T) {
	fx := newPKCS11ECDSAFixture(t)
	v := NewPKCS11FactorVerifier()

	nonce := []byte("der-fallback-nonce")
	digest := sha256.Sum256(nonce)
	sig, err := ecdsa.SignASN1(rand.Reader, fx.priv, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	// Use public_key_der (base64 DER) instead of public_key_pem.
	factor := &qrdbsdk.AuthFactor{
		ID:         "f-pkcs11-der",
		UserID:     4,
		Type:       qrdbsdk.AuthFactorPKCS11,
		Credential: fx.credential,
		Metadata:   map[string]string{"public_key_der": fx.pubKeyDERb64},
	}
	if err := v.Verify(context.Background(), factor, qrdbtransport.VerifyChallenge{
		Type:      qrdbtransport.FactorTypePKCS11,
		Nonce:     nonce,
		Signature: sig,
	}); err != nil {
		t.Fatalf("Verify DER fallback: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Error paths
// ---------------------------------------------------------------------------

func TestPKCS11FactorVerifier_NilFactor(t *testing.T) {
	v := NewPKCS11FactorVerifier()
	err := v.Verify(context.Background(), nil, qrdbtransport.VerifyChallenge{})
	var mfe *MissingFactorError
	if !errors.As(err, &mfe) {
		t.Fatalf("expected *MissingFactorError, got %T (%v)", err, err)
	}
}

func TestPKCS11FactorVerifier_Revoked(t *testing.T) {
	v := NewPKCS11FactorVerifier()
	now := time.Now().UTC()
	factor := &qrdbsdk.AuthFactor{
		ID:        "f",
		UserID:    1,
		Type:      qrdbsdk.AuthFactorPKCS11,
		RevokedAt: &now,
	}
	err := v.Verify(context.Background(), factor, qrdbtransport.VerifyChallenge{})
	var fre *qrdbsdk.FactorRevokedError
	if !errors.As(err, &fre) {
		t.Fatalf("expected *FactorRevokedError, got %T (%v)", err, err)
	}
}

func TestPKCS11FactorVerifier_WrongType(t *testing.T) {
	v := NewPKCS11FactorVerifier()
	factor := &qrdbsdk.AuthFactor{
		ID:     "f",
		UserID: 1,
		Type:   qrdbsdk.AuthFactorPIV,
	}
	err := v.Verify(context.Background(), factor, qrdbtransport.VerifyChallenge{
		Nonce: []byte("n"), Signature: []byte("s"),
	})
	var fte *qrdbsdk.FactorTypeUnsupportedError
	if !errors.As(err, &fte) {
		t.Fatalf("expected *FactorTypeUnsupportedError, got %T (%v)", err, err)
	}
}

func TestPKCS11FactorVerifier_MissingNonce(t *testing.T) {
	v := NewPKCS11FactorVerifier()
	factor := &qrdbsdk.AuthFactor{
		ID: "f", UserID: 1, Type: qrdbsdk.AuthFactorPKCS11,
	}
	err := v.Verify(context.Background(), factor, qrdbtransport.VerifyChallenge{
		Signature: []byte("s"),
	})
	var mfe *MissingChallengeFieldError
	if !errors.As(err, &mfe) || mfe.Field != "nonce" {
		t.Fatalf("expected MissingChallengeFieldError{nonce}, got %v", err)
	}
}

func TestPKCS11FactorVerifier_MissingSignature(t *testing.T) {
	v := NewPKCS11FactorVerifier()
	factor := &qrdbsdk.AuthFactor{
		ID: "f", UserID: 1, Type: qrdbsdk.AuthFactorPKCS11,
	}
	err := v.Verify(context.Background(), factor, qrdbtransport.VerifyChallenge{
		Nonce: []byte("n"),
	})
	var mfe *MissingChallengeFieldError
	if !errors.As(err, &mfe) || mfe.Field != "signature" {
		t.Fatalf("expected MissingChallengeFieldError{signature}, got %v", err)
	}
}

func TestPKCS11FactorVerifier_BadPEM(t *testing.T) {
	v := NewPKCS11FactorVerifier()
	factor := &qrdbsdk.AuthFactor{
		ID:         "f",
		UserID:     1,
		Type:       qrdbsdk.AuthFactorPKCS11,
		Credential: []byte("any"),
		Metadata:   map[string]string{"public_key_pem": "not-a-pem"},
	}
	err := v.Verify(context.Background(), factor, qrdbtransport.VerifyChallenge{
		Nonce: []byte("n"), Signature: []byte("s"),
	})
	var pde *PublicKeyDecodeError
	if !errors.As(err, &pde) {
		t.Fatalf("expected *PublicKeyDecodeError, got %T (%v)", err, err)
	}
}

func TestPKCS11FactorVerifier_BadDER(t *testing.T) {
	v := NewPKCS11FactorVerifier()
	// Valid base64 but not valid PKIX DER.
	factor := &qrdbsdk.AuthFactor{
		ID:         "f",
		UserID:     1,
		Type:       qrdbsdk.AuthFactorPKCS11,
		Credential: []byte("any"),
		Metadata:   map[string]string{"public_key_der": base64.StdEncoding.EncodeToString([]byte("not-a-der"))},
	}
	err := v.Verify(context.Background(), factor, qrdbtransport.VerifyChallenge{
		Nonce: []byte("n"), Signature: []byte("s"),
	})
	var pde *PublicKeyDecodeError
	if !errors.As(err, &pde) {
		t.Fatalf("expected *PublicKeyDecodeError, got %T (%v)", err, err)
	}
}

func TestPKCS11FactorVerifier_MissingPublicKey(t *testing.T) {
	v := NewPKCS11FactorVerifier()
	factor := &qrdbsdk.AuthFactor{
		ID:     "f",
		UserID: 1,
		Type:   qrdbsdk.AuthFactorPKCS11,
		// No Metadata at all.
	}
	err := v.Verify(context.Background(), factor, qrdbtransport.VerifyChallenge{
		Nonce: []byte("n"), Signature: []byte("s"),
	})
	var mfe *MissingChallengeFieldError
	if !errors.As(err, &mfe) {
		t.Fatalf("expected *MissingChallengeFieldError, got %T (%v)", err, err)
	}
}

func TestPKCS11FactorVerifier_CredentialMismatch(t *testing.T) {
	fx := newPKCS11ECDSAFixture(t)
	v := NewPKCS11FactorVerifier()

	factor := &qrdbsdk.AuthFactor{
		ID:         "f",
		UserID:     1,
		Type:       qrdbsdk.AuthFactorPKCS11,
		Credential: []byte("not-the-real-spki-sha256"),
		Metadata:   map[string]string{"public_key_pem": fx.pubKeyPEM},
	}
	err := v.Verify(context.Background(), factor, qrdbtransport.VerifyChallenge{
		Nonce: []byte("n"), Signature: []byte("s"),
	})
	var cme *CredentialMismatchError
	if !errors.As(err, &cme) {
		t.Fatalf("expected *CredentialMismatchError, got %T (%v)", err, err)
	}
}

func TestPKCS11FactorVerifier_BadSignature_ECDSA(t *testing.T) {
	fx := newPKCS11ECDSAFixture(t)
	v := NewPKCS11FactorVerifier()

	factor := &qrdbsdk.AuthFactor{
		ID:         "f",
		UserID:     1,
		Type:       qrdbsdk.AuthFactorPKCS11,
		Credential: fx.credential,
		Metadata:   map[string]string{"public_key_pem": fx.pubKeyPEM},
	}
	err := v.Verify(context.Background(), factor, qrdbtransport.VerifyChallenge{
		Nonce:     []byte("nonce"),
		Signature: []byte{0x30, 0x00}, // structurally valid but wrong
	})
	var sve *SignatureVerifyError
	if !errors.As(err, &sve) {
		t.Fatalf("expected *SignatureVerifyError, got %T (%v)", err, err)
	}
}

func TestPKCS11FactorVerifier_BadSignature_RSA(t *testing.T) {
	fx := newPKCS11RSAFixture(t)
	v := NewPKCS11FactorVerifier()

	factor := &qrdbsdk.AuthFactor{
		ID:         "f",
		UserID:     2,
		Type:       qrdbsdk.AuthFactorPKCS11,
		Credential: fx.credential,
		Metadata:   map[string]string{"public_key_pem": fx.pubKeyPEM},
	}
	err := v.Verify(context.Background(), factor, qrdbtransport.VerifyChallenge{
		Nonce:     []byte("nonce"),
		Signature: []byte("not-a-valid-rsa-signature"),
	})
	var sve *SignatureVerifyError
	if !errors.As(err, &sve) {
		t.Fatalf("expected *SignatureVerifyError, got %T (%v)", err, err)
	}
}

func TestPKCS11FactorVerifier_BadSignature_Ed25519(t *testing.T) {
	fx := newPKCS11Ed25519Fixture(t)
	v := NewPKCS11FactorVerifier()

	factor := &qrdbsdk.AuthFactor{
		ID:         "f",
		UserID:     3,
		Type:       qrdbsdk.AuthFactorPKCS11,
		Credential: fx.credential,
		Metadata:   map[string]string{"public_key_pem": fx.pubKeyPEM},
	}
	// Use a valid-length but wrong signature.
	badSig := make([]byte, ed25519.SignatureSize)
	err := v.Verify(context.Background(), factor, qrdbtransport.VerifyChallenge{
		Nonce:     []byte("nonce"),
		Signature: badSig,
	})
	var sve *SignatureVerifyError
	if !errors.As(err, &sve) {
		t.Fatalf("expected *SignatureVerifyError, got %T (%v)", err, err)
	}
}

func TestPKCS11FactorVerifier_UnsupportedKeyType(t *testing.T) {
	// Build a DH-like "unsupported" key by re-encoding an ECDSA key as an
	// X25519 key via marshaling — we cannot create an unknown key type directly,
	// so we abuse the verifier by constructing a PEM that parses to a known type
	// and then swap the key in the factor so credential mismatch happens first.
	// Instead, test verifyPKCS11Signature directly with a nil interface value
	// that maps to the default case.
	//
	// Actually test via an x509.Certificate.PublicKey type that is not one of
	// the three known types. We do this by creating a fake pem that parses but
	// yields an unexpected key type — which isn't straightforward. So instead
	// we exercise the helper directly.
	err := verifyPKCS11Signature(struct{}{}, []byte("nonce"), []byte("sig"))
	var uke *UnsupportedPublicKeyError
	if !errors.As(err, &uke) {
		t.Fatalf("expected *UnsupportedPublicKeyError for unknown key type, got %T (%v)", err, err)
	}
}

// ---------------------------------------------------------------------------
// PublicKeyDecodeError message smoke test
// ---------------------------------------------------------------------------

func TestPublicKeyDecodeError_Message(t *testing.T) {
	e := &PublicKeyDecodeError{Reason: "bad input"}
	if e.Error() == "" {
		t.Fatal("PublicKeyDecodeError.Error() is empty")
	}
	e2 := &PublicKeyDecodeError{}
	if e2.Error() == "" {
		t.Fatal("PublicKeyDecodeError{}.Error() is empty")
	}
}

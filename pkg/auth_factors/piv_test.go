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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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
)

// pivTestFixture builds a minimal CA + leaf chain for verifier tests.
type pivTestFixture struct {
	rootKey   *ecdsa.PrivateKey
	rootCert  *x509.Certificate
	rootDER   []byte
	leafKey   *ecdsa.PrivateKey
	leafCert  *x509.Certificate
	leafDER   []byte
	leafPEM   string
	rootsPool *x509.CertPool
}

func newPIVTestFixture(t *testing.T) *pivTestFixture {
	t.Helper()

	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("root key: %v", err)
	}
	rootTpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test root"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
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

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("leaf key: %v", err)
	}
	leafTpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "piv-test-leaf"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
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

	return &pivTestFixture{
		rootKey:   rootKey,
		rootCert:  rootCert,
		rootDER:   rootDER,
		leafKey:   leafKey,
		leafCert:  leafCert,
		leafDER:   leafDER,
		leafPEM:   leafPEM,
		rootsPool: pool,
	}
}

func TestPIVHardwareFactorVerifier_New(t *testing.T) {
	if _, err := NewPIVHardwareFactorVerifier(nil, nil); err == nil {
		t.Fatalf("expected error for nil roots pool")
	}
	pool := x509.NewCertPool()
	v, err := NewPIVHardwareFactorVerifier(pool, nil)
	if err != nil {
		t.Fatalf("expected success: %v", err)
	}
	if v.Type() != qrdbtransport.FactorTypePIV {
		t.Fatalf("Type = %q want %q", v.Type(), qrdbtransport.FactorTypePIV)
	}
}

func TestPIVHardwareFactorVerifier_Success(t *testing.T) {
	fx := newPIVTestFixture(t)
	v, err := NewPIVHardwareFactorVerifier(fx.rootsPool, nil)
	if err != nil {
		t.Fatalf("verifier: %v", err)
	}

	sum := sha256.Sum256(fx.leafCert.Raw)
	factor := &qrdbsdk.AuthFactor{
		ID:         "f-piv-1",
		UserID:     1,
		Type:       qrdbsdk.AuthFactorPIV,
		Credential: sum[:],
		Metadata: map[string]string{
			"cert_pem": fx.leafPEM,
		},
	}

	// Sign nonce with leaf private key.
	nonce := []byte("piv-test-nonce-12345678901234567890")
	digest := sha256.Sum256(nonce)
	sig, err := ecdsa.SignASN1(rand.Reader, fx.leafKey, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	challenge := qrdbtransport.VerifyChallenge{
		Type:      qrdbtransport.FactorTypePIV,
		Nonce:     nonce,
		Signature: sig,
	}
	if err := v.Verify(context.Background(), factor, challenge); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestPIVHardwareFactorVerifier_NilFactor(t *testing.T) {
	fx := newPIVTestFixture(t)
	v, _ := NewPIVHardwareFactorVerifier(fx.rootsPool, nil)
	err := v.Verify(context.Background(), nil, qrdbtransport.VerifyChallenge{})
	var mfe *MissingFactorError
	if !errors.As(err, &mfe) {
		t.Fatalf("expected *MissingFactorError, got %T (%v)", err, err)
	}
}

func TestPIVHardwareFactorVerifier_Revoked(t *testing.T) {
	fx := newPIVTestFixture(t)
	v, _ := NewPIVHardwareFactorVerifier(fx.rootsPool, nil)
	now := time.Now().UTC()
	factor := &qrdbsdk.AuthFactor{
		ID: "f", UserID: 1, Type: qrdbsdk.AuthFactorPIV, RevokedAt: &now,
	}
	err := v.Verify(context.Background(), factor, qrdbtransport.VerifyChallenge{})
	var fre *qrdbsdk.FactorRevokedError
	if !errors.As(err, &fre) {
		t.Fatalf("expected *FactorRevokedError, got %T (%v)", err, err)
	}
}

func TestPIVHardwareFactorVerifier_WrongType(t *testing.T) {
	fx := newPIVTestFixture(t)
	v, _ := NewPIVHardwareFactorVerifier(fx.rootsPool, nil)
	factor := &qrdbsdk.AuthFactor{
		ID: "f", UserID: 1, Type: qrdbsdk.AuthFactorMTLS,
	}
	err := v.Verify(context.Background(), factor, qrdbtransport.VerifyChallenge{
		Nonce: []byte("n"), Signature: []byte("s"),
	})
	var fte *qrdbsdk.FactorTypeUnsupportedError
	if !errors.As(err, &fte) {
		t.Fatalf("expected *FactorTypeUnsupportedError, got %T (%v)", err, err)
	}
}

func TestPIVHardwareFactorVerifier_MissingNonce(t *testing.T) {
	fx := newPIVTestFixture(t)
	v, _ := NewPIVHardwareFactorVerifier(fx.rootsPool, nil)
	factor := &qrdbsdk.AuthFactor{
		ID: "f", UserID: 1, Type: qrdbsdk.AuthFactorPIV,
	}
	err := v.Verify(context.Background(), factor, qrdbtransport.VerifyChallenge{
		Signature: []byte("s"),
	})
	var mfe *MissingChallengeFieldError
	if !errors.As(err, &mfe) || mfe.Field != "nonce" {
		t.Fatalf("expected nonce field, got %v", err)
	}
}

func TestPIVHardwareFactorVerifier_MissingSignature(t *testing.T) {
	fx := newPIVTestFixture(t)
	v, _ := NewPIVHardwareFactorVerifier(fx.rootsPool, nil)
	factor := &qrdbsdk.AuthFactor{
		ID: "f", UserID: 1, Type: qrdbsdk.AuthFactorPIV,
	}
	err := v.Verify(context.Background(), factor, qrdbtransport.VerifyChallenge{
		Nonce: []byte("n"),
	})
	var mfe *MissingChallengeFieldError
	if !errors.As(err, &mfe) || mfe.Field != "signature" {
		t.Fatalf("expected signature field, got %v", err)
	}
}

func TestPIVHardwareFactorVerifier_CredentialMismatch(t *testing.T) {
	fx := newPIVTestFixture(t)
	v, _ := NewPIVHardwareFactorVerifier(fx.rootsPool, nil)

	factor := &qrdbsdk.AuthFactor{
		ID:         "f",
		UserID:     1,
		Type:       qrdbsdk.AuthFactorPIV,
		Credential: []byte("not-the-real-sha256-of-cert"),
		Metadata: map[string]string{
			"cert_pem": fx.leafPEM,
		},
	}
	err := v.Verify(context.Background(), factor, qrdbtransport.VerifyChallenge{
		Nonce: []byte("nonce"), Signature: []byte("sig"),
	})
	var cme *CredentialMismatchError
	if !errors.As(err, &cme) {
		t.Fatalf("expected *CredentialMismatchError, got %T (%v)", err, err)
	}
}

func TestPIVHardwareFactorVerifier_BadSignature(t *testing.T) {
	fx := newPIVTestFixture(t)
	v, _ := NewPIVHardwareFactorVerifier(fx.rootsPool, nil)

	sum := sha256.Sum256(fx.leafCert.Raw)
	factor := &qrdbsdk.AuthFactor{
		ID:         "f",
		UserID:     1,
		Type:       qrdbsdk.AuthFactorPIV,
		Credential: sum[:],
		Metadata:   map[string]string{"cert_pem": fx.leafPEM},
	}

	err := v.Verify(context.Background(), factor, qrdbtransport.VerifyChallenge{
		Nonce:     []byte("nonce"),
		Signature: []byte{0x30, 0x00}, // structurally valid but wrong content
	})
	var sve *SignatureVerifyError
	if !errors.As(err, &sve) {
		t.Fatalf("expected *SignatureVerifyError, got %T (%v)", err, err)
	}
}

func TestPIVHardwareFactorVerifier_MissingCert(t *testing.T) {
	fx := newPIVTestFixture(t)
	v, _ := NewPIVHardwareFactorVerifier(fx.rootsPool, nil)
	factor := &qrdbsdk.AuthFactor{
		ID:         "f",
		UserID:     1,
		Type:       qrdbsdk.AuthFactorPIV,
		Credential: []byte("any"),
		// No Metadata at all
	}
	err := v.Verify(context.Background(), factor, qrdbtransport.VerifyChallenge{
		Nonce: []byte("n"), Signature: []byte("s"),
	})
	var mfe *MissingChallengeFieldError
	if !errors.As(err, &mfe) {
		t.Fatalf("expected *MissingChallengeFieldError, got %T (%v)", err, err)
	}
}

func TestPIVHardwareFactorVerifier_BadPEM(t *testing.T) {
	fx := newPIVTestFixture(t)
	v, _ := NewPIVHardwareFactorVerifier(fx.rootsPool, nil)
	factor := &qrdbsdk.AuthFactor{
		ID:         "f",
		UserID:     1,
		Type:       qrdbsdk.AuthFactorPIV,
		Credential: []byte("any"),
		Metadata:   map[string]string{"cert_pem": "not a pem"},
	}
	err := v.Verify(context.Background(), factor, qrdbtransport.VerifyChallenge{
		Nonce: []byte("n"), Signature: []byte("s"),
	})
	var cde *CertDecodeError
	if !errors.As(err, &cde) {
		t.Fatalf("expected *CertDecodeError, got %T (%v)", err, err)
	}
}

func TestPIVHardwareFactorVerifier_ChainNotTrusted(t *testing.T) {
	// Use a different root pool — the leaf will not chain.
	fx := newPIVTestFixture(t)
	otherRoots := x509.NewCertPool()
	v, _ := NewPIVHardwareFactorVerifier(otherRoots, nil)

	sum := sha256.Sum256(fx.leafCert.Raw)
	factor := &qrdbsdk.AuthFactor{
		ID:         "f",
		UserID:     1,
		Type:       qrdbsdk.AuthFactorPIV,
		Credential: sum[:],
		Metadata:   map[string]string{"cert_pem": fx.leafPEM},
	}
	err := v.Verify(context.Background(), factor, qrdbtransport.VerifyChallenge{
		Nonce: []byte("n"), Signature: []byte{0x30, 0x00},
	})
	if err == nil {
		t.Fatalf("expected chain verification to fail")
	}
}

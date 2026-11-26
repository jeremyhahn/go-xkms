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

// Package ca coverage boost, seventh pass: targets remaining sub-91% and
// low-coverage functions not yet exercised by the six prior passes.
// All tests are in-memory, fast, race-free.
package ca

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// verification.go — VerifySignature (not initialized / nil cert)
// =============================================================================

func TestVerifySignature_NotInitialized(t *testing.T) {
	t.Parallel()
	ca := &CA{}
	err := ca.VerifySignature(&x509.Certificate{})
	assert.ErrorIs(t, err, ErrNotInitialized)
}

func TestVerifySignature_NilCert(t *testing.T) {
	t.Parallel()
	ca := setupTestCA(t)
	err := ca.VerifySignature(nil)
	assert.ErrorIs(t, err, ErrInvalidCertificate)
}

// =============================================================================
// verification.go — verifyRSASignature PSS success and zero-hash branches
// =============================================================================

func TestVerifyRSASignature_ZeroHash(t *testing.T) {
	t.Parallel()
	key := generateTestRSAKey(t)
	tmpl := &x509.Certificate{
		SerialNumber:       big.NewInt(1),
		Subject:            pkix.Name{CommonName: "rsa-zero-hash-b7"},
		NotBefore:          time.Now().Add(-time.Hour),
		NotAfter:           time.Now().Add(24 * time.Hour),
		SignatureAlgorithm: x509.SHA256WithRSA,
		KeyUsage:           x509.KeyUsageDigitalSignature,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	// Call verifyRSASignature directly with hashAlgo=0 to exercise the zero-hash guard.
	err = verifyRSASignature(cert, &key.PublicKey, 0)
	assert.Error(t, err)
	var ve *VerificationError
	assert.True(t, errors.As(err, &ve))
}

func TestVerifyRSASignature_PSS_Success(t *testing.T) {
	t.Parallel()
	cert := buildRSAPSSCert(t)
	rsaPub, ok := cert.PublicKey.(*rsa.PublicKey)
	require.True(t, ok, "expected RSA public key")
	err := verifyRSASignature(cert, rsaPub, crypto.SHA256)
	assert.NoError(t, err)
}

// =============================================================================
// verification.go — verifyECDSASignature zero-hash branch
// =============================================================================

func TestVerifyECDSASignature_ZeroHash(t *testing.T) {
	t.Parallel()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "ecdsa-zero-hash-b7"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	err = verifyECDSASignature(cert, &key.PublicKey, 0)
	assert.Error(t, err)
	var ve *VerificationError
	assert.True(t, errors.As(err, &ve))
}

// =============================================================================
// ca_extensions.go — Issued / Exists
// =============================================================================

func TestExists_NotFound_B7(t *testing.T) {
	t.Parallel()
	ca := setupTestCA(t)
	found, err := ca.Exists(context.Background(), "ghost-b7", x509.ECDSA)
	require.NoError(t, err)
	assert.False(t, found)
}

// =============================================================================
// trust_chain.go — TrustedRootCertPool not-initialized / no root
// =============================================================================

func TestTrustedRootCertPool_NoRoot_B7(t *testing.T) {
	t.Parallel()
	ca := setupTestCA(t)
	ca.mu.Lock()
	ca.rootCert = nil
	ca.mu.Unlock()
	_, err := ca.TrustedRootCertPool(nil)
	assert.ErrorIs(t, err, ErrRootNotFound)
}

// =============================================================================
// trust_chain_extensions.go — TrustedRoot not-initialized / no root
// =============================================================================

func TestTrustedRoot_NoRoot_B7(t *testing.T) {
	t.Parallel()
	ca := setupTestCA(t)
	ca.mu.Lock()
	ca.rootCert = nil
	ca.mu.Unlock()
	_, err := ca.TrustedRoot()
	assert.ErrorIs(t, err, ErrRootNotFound)
}

// =============================================================================
// trust_chain_extensions.go — TrustedIntermediate
// =============================================================================

func TestTrustedIntermediate_NotInitialized_B7(t *testing.T) {
	t.Parallel()
	ca := &CA{}
	_, err := ca.TrustedIntermediate()
	assert.ErrorIs(t, err, ErrNotInitialized)
}

// =============================================================================
// trust_chain_extensions.go — TrustedRootCertPoolWithXSigner with xsigner
// =============================================================================

func TestTrustedRootCertPoolWithXSigner_WithSigner_B7(t *testing.T) {
	t.Parallel()
	ca := setupTestCA(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	pool, err := ca.TrustedRootCertPoolWithXSigner(nil, key)
	require.NoError(t, err)
	assert.NotNil(t, pool)
}

// =============================================================================
// trust_chain_extensions.go — TrustedIntermediateCertPoolWithXSigner with xsigner
// =============================================================================

func TestTrustedIntermediateCertPoolWithXSigner_WithSigner_B7(t *testing.T) {
	t.Parallel()
	ca := setupTestCAWithRealIntermediate(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	leaf := &x509.Certificate{Subject: pkix.Name{CommonName: "leaf-b7"}}
	pool, err := ca.TrustedIntermediateCertPoolWithXSigner(leaf, key)
	require.NoError(t, err)
	assert.NotNil(t, pool)
}

// =============================================================================
// trust_chain_extensions.go — ParseBundle error branches
// =============================================================================

func TestParseBundle_NoCerts_B7(t *testing.T) {
	t.Parallel()
	ca := setupTestCA(t)
	_, err := ca.ParseBundle([]byte("not a pem block"))
	assert.ErrorIs(t, err, ErrInvalidPEM)
}

// =============================================================================
// tcg_oids.go — bool-false round-trip on Residency/Fixed extensions
// =============================================================================

// The tcg-cap-* assertions are certificate POLICY identifiers carrying "No
// data" (TCG DevID v1 r12 §8.2). The boolean-valued standalone extensions this
// test covered are gone; the assertions are pinned on issued certificates by
// the certificate policy regression suite in certpolicy_test.go.

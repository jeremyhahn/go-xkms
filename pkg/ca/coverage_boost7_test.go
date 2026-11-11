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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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
// verification.go — VerifyChain success path
// =============================================================================

// =============================================================================
// verification.go — VerifyWithOptions nil options + revocation path
// =============================================================================

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
// verification.go — VerifyCertificateAgainstPublicKey unsupported key type
// (non-duplicate: verification_test.go test has a different name)
// =============================================================================

// =============================================================================
// ca_extensions.go — DefaultSignatureAlgorithm nil-identity branch
// =============================================================================

// =============================================================================
// ca_extensions.go — CAKeyAttributes empty store-type (allowed) vs mismatch
// =============================================================================

// =============================================================================
// ca_extensions.go — CASigner algorithm mismatch
// =============================================================================

// =============================================================================
// ca_extensions.go — CABundleFiltered additional algorithm filter branches
// =============================================================================

func TestCABundleFiltered_WithIntermediate_ECDSAFilter(t *testing.T) {
	t.Parallel()
	ca := setupTestCAWithRealIntermediate(t)
	bundle, err := ca.CABundleFiltered("", x509.ECDSA)
	require.NoError(t, err)
	assert.NotEmpty(t, bundle)
}

// =============================================================================
// ca_extensions.go — PubKey nil attrs
// =============================================================================

// =============================================================================
// ca_extensions.go — Blob not found / ImportBlob round-trip
// =============================================================================

// =============================================================================
// ca_extensions.go — Issued / Exists
// =============================================================================

func TestExists_AlgorithmMismatch_B7(t *testing.T) {
	t.Parallel()
	ca := setupTestCA(t)
	issueCertAndSaveToKeyStore(t, ca, "exists-algo-mismatch-b7")
	found, err := ca.Exists(context.Background(), "exists-algo-mismatch-b7", x509.RSA)
	require.NoError(t, err)
	assert.False(t, found)
}

func TestExists_EmptyCN_B7(t *testing.T) {
	t.Parallel()
	ca := setupTestCA(t)
	_, err := ca.Exists(context.Background(), "", x509.ECDSA)
	assert.ErrorIs(t, err, ErrInvalidCertificate)
}

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

func TestTrustedRootCertPool_NotInitialized_B7(t *testing.T) {
	t.Parallel()
	ca := &CA{}
	_, err := ca.TrustedRootCertPool(nil)
	assert.ErrorIs(t, err, ErrNotInitialized)
}

func TestTrustedRootCertPool_NoRoot_B7(t *testing.T) {
	t.Parallel()
	ca := setupTestCA(t)
	ca.mu.Lock()
	ca.rootCert = nil
	ca.mu.Unlock()
	_, err := ca.TrustedRootCertPool(nil)
	assert.ErrorIs(t, err, ErrRootNotFound)
}

func TestTrustedRootCertPool_Success_B7(t *testing.T) {
	t.Parallel()
	ca := setupTestCA(t)
	pool, err := ca.TrustedRootCertPool(nil)
	require.NoError(t, err)
	assert.NotNil(t, pool)
}

// =============================================================================
// trust_chain.go — TrustedIntermediateCertPool
// =============================================================================

func TestTrustedIntermediateCertPool_NotInitialized_B7(t *testing.T) {
	t.Parallel()
	ca := &CA{}
	_, err := ca.TrustedIntermediateCertPool(nil)
	assert.ErrorIs(t, err, ErrNotInitialized)
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
// trust_chain_extensions.go — RootCertificate nil-input
// =============================================================================

// =============================================================================
// tls_extensions.go — TLSBundleWithCrossSigner with signer but no xsigned certs
// =============================================================================

// =============================================================================
// ca_extensions.go — Certificate fallback to certStore
// =============================================================================

func TestCertificate_FallbackToCertStore_B7(t *testing.T) {
	t.Parallel()
	ca := setupTestCA(t)
	issueCertAndSaveToKeyStore(t, ca, "cert-fallback-b7")
	attrs := softwareKeyAttrs("cert-fallback-b7")
	cert, err := ca.Certificate(context.Background(), attrs)
	require.NoError(t, err)
	assert.NotNil(t, cert)
}

// =============================================================================
// ca_extensions.go — ImportCertificatePEM
// =============================================================================

// =============================================================================
// ca_extensions.go — RevokeCert with object store (recordRevocation /
// putRevocationBlobIfAbsent round-trip)
// =============================================================================

// =============================================================================
// tcg_oids.go — ParseTPMSpecificationExtension with garbage data
// =============================================================================

// =============================================================================
// tcg_oids.go — CreateTenantIDExtension large ID
// =============================================================================

// =============================================================================
// bundle.go — CABundle PEM validity cross-check
// =============================================================================

// =============================================================================
// tcg_oids.go — bool-false round-trip on Residency/Fixed extensions
// =============================================================================

// The tcg-cap-* assertions are certificate POLICY identifiers carrying "No
// data" (TCG DevID v1 r12 §8.2). The boolean-valued standalone extensions this
// test covered are gone; the assertions are pinned on issued certificates by
// the certificate policy regression suite in certpolicy_test.go.

// =============================================================================
// Additional targeted gap coverage
// =============================================================================

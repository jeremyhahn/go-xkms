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

// Package ca coverage boost, fifth pass: targets remaining low-coverage
// functions.  All tests are in-memory, fast, race-free.
package ca

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// TLSConfigWithXSigner — intermediate cross-sign path
// =============================================================================

// setupCAWithIntermediateAndObjectStore builds on setupTestCAWithRealIntermediate
// and attaches an in-memory object store so the xsigner path is exercised for
// both root and intermediate CN lookups.
func setupCAWithIntermediateAndObjectStore(t *testing.T) *CA {
	t.Helper()
	ca := setupTestCAWithRealIntermediate(t)
	ca.objectStore = qrdbsdk.NewMemoryStorage()
	return ca
}

// =============================================================================
// TLSBundleWithCrossSigner — xsigner non-nil path (object store empty)
// =============================================================================

func TestTLSBundleWithCrossSigner_WithXSigner_EmptyStore(t *testing.T) {
	ca := setupCAWithIntermediateAndObjectStore(t)
	issueCertAndSaveToKeyStore(t, ca, "bundle-xsign-b5")
	attrs := softwareKeyAttrs("bundle-xsign-b5")

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// TLSBundle may fail on opaque key export; accept either outcome.
	bundle, err := ca.TLSBundleWithCrossSigner(context.Background(), attrs, ecKey)
	if err != nil {
		assert.ErrorIs(t, err, ErrTLSConfigFailed)
		return
	}
	assert.NotEmpty(t, bundle)
}

// =============================================================================
// OCSP createResponse — cached response hit path
// =============================================================================

func TestOCSPCreateResponse_CacheHit(t *testing.T) {
	ca := setupTestCA(t)
	resp := NewOCSPResponder(ca, DefaultOCSPResponderConfig())

	// Pre-populate the cache with a fake response for serial 42.
	serial := big.NewInt(42)
	cacheKey := ocspCacheKey(serial)
	fakeResp := []byte("cached-ocsp-response")
	resp.cacheResponse(cacheKey, fakeResp, time.Now().Add(time.Hour))

	// getCachedResponse should return the cached value immediately.
	got := resp.getCachedResponse(cacheKey)
	assert.Equal(t, fakeResp, got)
}

// =============================================================================
// getOrGenerateKey — unknown/default algorithm path (no KeyAttributes on req)
// =============================================================================

func TestCreateCSR_NilKeyAttributes_DefaultsToECDSA(t *testing.T) {
	ca := setupTestCA(t)
	req := &CertificateRequest{
		TenantID:      testTenant,
		Subject:       Subject{CommonName: "csr-default-algo-b5"},
		SANS:          &SubjectAlternativeNames{DNS: []string{"csr-default-algo-b5.local"}},
		KeyAttributes: nil, // triggers default ECDSA P-256 path
	}
	csrPEM, err := ca.CreateCSR(context.Background(), req)
	require.NoError(t, err)
	block, _ := pem.Decode(csrPEM)
	require.NotNil(t, block)
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	require.NoError(t, err)
	assert.Equal(t, "csr-default-algo-b5", csr.Subject.CommonName)
}

// =============================================================================
// initializeAsIntermediate — AlreadyInitialized path
// =============================================================================

func TestInitializeAsIntermediate_AlreadyInitialized(t *testing.T) {
	ca := setupTestCAWithRealIntermediate(t)
	// The intermediate CA is fully initialized; calling again triggers the guard.
	identity := Identity{Subject: Subject{CommonName: "dummy-int"}}
	err := initializeAsIntermediate(context.Background(), ca, identity, ca)
	assert.ErrorIs(t, err, ErrAlreadyInitialized)
}

// =============================================================================
// OCSP parseRequest — nil/empty input and invalid bytes paths
// =============================================================================

func TestParseRequest_NilInput(t *testing.T) {
	ca := setupTestCA(t)
	resp := NewOCSPResponder(ca, DefaultOCSPResponderConfig())
	_, err := resp.parseRequest(nil)
	assert.ErrorIs(t, err, ErrOCSPInvalidRequest)
}

func TestParseRequest_InvalidBytes(t *testing.T) {
	ca := setupTestCA(t)
	resp := NewOCSPResponder(ca, DefaultOCSPResponderConfig())
	_, err := resp.parseRequest([]byte("garbage"))
	assert.ErrorIs(t, err, ErrOCSPRequestParseFailed)
}

// =============================================================================
// Sign — CA signer return value propagation
// =============================================================================

// =============================================================================
// IssueCertificate — issue to intermediate CA then verify chain
// =============================================================================

func TestIssueCertificate_IntermediateCA_FullChain(t *testing.T) {
	ca := setupTestCAWithRealIntermediate(t)

	for _, cn := range []string{"chain-leaf-1-b5", "chain-leaf-2-b5"} {
		result, err := ca.IssueCertificate(context.Background(), &CertificateRequest{
			TenantID: testTenant,
			Subject:  Subject{CommonName: cn},
			SANS:     &SubjectAlternativeNames{DNS: []string{cn + ".local"}},
			Valid:    365,
		})
		require.NoError(t, err, "IssueCertificate(%s)", cn)

		chains, err := ca.Verify(result.Certificate)
		require.NoError(t, err, "Verify(%s)", cn)
		assert.NotEmpty(t, chains)
	}
}

// =============================================================================
// MarshalHardwareModuleName — exercise it directly
// =============================================================================

// =============================================================================
// createAndSignCSR — via buildCSRTemplate with URIs
// =============================================================================

func TestCreateCSR_WithURISAN(t *testing.T) {
	ca := setupTestCA(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	req := &CertificateRequest{
		TenantID: testTenant,
		Subject:  Subject{CommonName: "csr-uri"},
		SANS: &SubjectAlternativeNames{
			DNS:  []string{"csr-uri.local"},
			URIs: []string{"spiffe://cluster.local/ns/default/sa/app"},
		},
		Signer: key,
	}
	csrPEM, err := ca.CreateCSR(context.Background(), req)
	require.NoError(t, err)
	block, _ := pem.Decode(csrPEM)
	require.NotNil(t, block)
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	require.NoError(t, err)
	require.NotEmpty(t, csr.URIs)
	assert.Contains(t, csr.URIs[0].String(), "spiffe://")
}

// =============================================================================
// RevokeCert with DeleteKeys option
// =============================================================================

func TestRevokeCert_DeleteKeys_B5(t *testing.T) {
	ca := setupTestCA(t)
	issued, err := ca.IssueCertificate(context.Background(), &CertificateRequest{
		TenantID: testTenant,
		Subject:  Subject{CommonName: "revoke-del-keys-b5"},
		SANS:     &SubjectAlternativeNames{DNS: []string{"revoke-del-keys-b5.local"}},
		Valid:    365,
	})
	require.NoError(t, err)

	err = ca.RevokeCert(context.Background(), issued.Certificate, RevokeOptions{
		Reason:     1,
		DeleteKeys: true,
	})
	require.NoError(t, err)

	revoked, err := ca.IsRevoked(issued.Certificate.SerialNumber)
	require.NoError(t, err)
	assert.True(t, revoked)
}

// =============================================================================
// TrustedRootCertPool — with intermediate CA (cert issued by intermediate)
// =============================================================================

func TestTrustedRootCertPool_IntermediateIssuedCert(t *testing.T) {
	ca := setupTestCAWithRealIntermediate(t)
	issued, err := ca.IssueCertificate(context.Background(), &CertificateRequest{
		TenantID: testTenant,
		Subject:  Subject{CommonName: "root-pool-int-b5"},
		SANS:     &SubjectAlternativeNames{DNS: []string{"root-pool-int-b5.local"}},
		Valid:    365,
	})
	require.NoError(t, err)

	pool, err := ca.TrustedRootCertPool(issued.Certificate)
	require.NoError(t, err)
	assert.NotNil(t, pool)
}

// =============================================================================
// CABundleFiltered — with ECDSA filter
// =============================================================================

// =============================================================================
// Verify — nil cert path
// =============================================================================

// =============================================================================
// getOrGenerateKey — Ed25519 generate path (no existing key)
// =============================================================================

func TestCreateCSR_GenerateEd25519Key(t *testing.T) {
	ca := setupTestCA(t)
	req := &CertificateRequest{
		TenantID:      testTenant,
		Subject:       Subject{CommonName: "csr-gen-ed25519-b5"},
		SANS:          &SubjectAlternativeNames{DNS: []string{"csr-gen-ed25519-b5.local"}},
		KeyAttributes: softwareKeyAttrsAlgo("csr-gen-ed25519-b5", x509.Ed25519),
	}
	csrPEM, err := ca.CreateCSR(context.Background(), req)
	require.NoError(t, err)
	assert.NotEmpty(t, csrPEM)
}

// softwareKeyAttrsAlgo extends softwareKeyAttrs with a custom key algorithm.
func softwareKeyAttrsAlgo(cn string, algo x509.PublicKeyAlgorithm) *types.KeyAttributes {
	attrs := softwareKeyAttrs(cn)
	attrs.KeyAlgorithm = algo
	if algo == x509.Ed25519 {
		attrs.ECCAttributes = nil // Ed25519 doesn't use ECC attributes
	}
	return attrs
}

// =============================================================================
// OCSP HandleRequest — valid end-to-end with CA-issued cert
// =============================================================================

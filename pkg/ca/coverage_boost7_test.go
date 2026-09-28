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
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/types"
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

func TestVerifyChain_Success(t *testing.T) {
	t.Parallel()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "verify-chain-root-b7"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	pool := x509.NewCertPool()
	pool.AddCert(cert)

	chains, err := VerifyChain(cert, nil, pool)
	require.NoError(t, err)
	assert.NotEmpty(t, chains)
}

// =============================================================================
// verification.go — VerifyWithOptions nil options + revocation path
// =============================================================================

func TestVerifyWithOptions_NilOpts_ErrorExpected(t *testing.T) {
	t.Parallel()
	cert, _ := makeSelfSignedCert(t, "nil-opts-b7")
	// With nil opts, no root pool is provided — chain verification should fail.
	_, err := VerifyWithOptions(cert, nil)
	assert.Error(t, err)
}

func TestVerifyWithOptions_RevocationPath(t *testing.T) {
	t.Parallel()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(9901),
		Subject:               pkix.Name{CommonName: "revoked-b7"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	// Build a DER-encoded CRL revoking serial 9901.
	crlTemplate := &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: time.Now().Add(-time.Minute),
		NextUpdate: time.Now().Add(24 * time.Hour),
		RevokedCertificateEntries: []x509.RevocationListEntry{
			{SerialNumber: big.NewInt(9901), RevocationTime: time.Now().Add(-time.Minute)},
		},
	}
	crlDER, err := x509.CreateRevocationList(rand.Reader, crlTemplate, cert, key)
	require.NoError(t, err)

	pool := x509.NewCertPool()
	pool.AddCert(cert)

	opts := &VerifyOptions{
		Roots:           pool,
		CheckRevocation: true,
		CRL:             crlDER,
		CurrentTime:     time.Now(),
	}
	_, err = VerifyWithOptions(cert, opts)
	assert.Error(t, err)
	var ve *VerificationError
	assert.True(t, errors.As(err, &ve))
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
// verification.go — VerifyCertificateAgainstPublicKey unsupported key type
// (non-duplicate: verification_test.go test has a different name)
// =============================================================================

func TestVerifyCertificateAgainstPublicKey_UnsupportedKey_B7(t *testing.T) {
	t.Parallel()
	cert, _ := makeSelfSignedCert(t, "unsupported-key-b7")
	type fakeKey struct{}
	err := VerifyCertificateAgainstPublicKey(cert, fakeKey{})
	assert.Error(t, err)
	var ve *VerificationError
	assert.True(t, errors.As(err, &ve))
}

// =============================================================================
// ca_extensions.go — DefaultSignatureAlgorithm nil-identity branch
// =============================================================================

func TestDefaultSignatureAlgorithm_NilIdentity_B7(t *testing.T) {
	t.Parallel()
	ca := &CA{config: &MultiIdentityCAConfig{}}
	algo := ca.DefaultSignatureAlgorithm()
	assert.Equal(t, x509.UnknownSignatureAlgorithm, algo)
}

func TestDefaultSignatureAlgorithm_Success_B7(t *testing.T) {
	t.Parallel()
	ca := setupTestCA(t)
	algo := ca.DefaultSignatureAlgorithm()
	assert.NotEqual(t, x509.UnknownSignatureAlgorithm, algo)
}

// =============================================================================
// ca_extensions.go — CAKeyAttributes empty store-type (allowed) vs mismatch
// =============================================================================

func TestCAKeyAttributes_EmptyStoreType(t *testing.T) {
	t.Parallel()
	ca := setupTestCA(t)
	attrs, err := ca.CAKeyAttributes("")
	require.NoError(t, err)
	assert.NotNil(t, attrs)
}

// =============================================================================
// ca_extensions.go — CASigner algorithm mismatch
// =============================================================================

func TestCASigner_AlgorithmMismatch_B7(t *testing.T) {
	t.Parallel()
	ca := setupTestCA(t)
	_, err := ca.CASigner(context.Background(), "", x509.RSA)
	assert.ErrorIs(t, err, ErrInvalidKeyAlgorithm)
}

func TestCASigner_UnknownAlgorithmSucceeds(t *testing.T) {
	t.Parallel()
	ca := setupTestCA(t)
	signer, err := ca.CASigner(context.Background(), "", x509.UnknownPublicKeyAlgorithm)
	require.NoError(t, err)
	assert.NotNil(t, signer)
}

// =============================================================================
// ca_extensions.go — CABundleFiltered additional algorithm filter branches
// =============================================================================

func TestCABundleFiltered_NoFilters_B7(t *testing.T) {
	t.Parallel()
	ca := setupTestCA(t)
	bundle, err := ca.CABundleFiltered("", x509.UnknownPublicKeyAlgorithm)
	require.NoError(t, err)
	assert.NotEmpty(t, bundle)
}

func TestCABundleFiltered_AlgorithmFilter_ECDSA_B7(t *testing.T) {
	t.Parallel()
	ca := setupTestCA(t)
	bundle, err := ca.CABundleFiltered("", x509.ECDSA)
	require.NoError(t, err)
	assert.NotEmpty(t, bundle)
}

func TestCABundleFiltered_AlgorithmFilter_RSA_NoMatch(t *testing.T) {
	t.Parallel()
	ca := setupTestCA(t)
	_, err := ca.CABundleFiltered("", x509.RSA)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidCertificateChain)
}

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

func TestPubKey_NilAttrs_B7(t *testing.T) {
	t.Parallel()
	ca := setupTestCA(t)
	_, err := ca.PubKey(context.Background(), nil)
	assert.ErrorIs(t, err, ErrInvalidConfig)
}

// =============================================================================
// ca_extensions.go — Blob not found / ImportBlob round-trip
// =============================================================================

func TestBlob_NotFound_B7(t *testing.T) {
	t.Parallel()
	ca := setupTestCAWithObjectStore(t)
	_, err := ca.Blob([]byte("missing-key-b7"))
	assert.Error(t, err)
}

func TestBlob_ImportRoundtrip_B7(t *testing.T) {
	t.Parallel()
	ca := setupTestCAWithObjectStore(t)
	key := []byte("roundtrip-key-b7")
	data := []byte("test-blob-data-b7-payload")
	err := ca.ImportBlob(key, data)
	require.NoError(t, err)
	got, err := ca.Blob(key)
	require.NoError(t, err)
	assert.Equal(t, data, got)
}

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

func TestExists_AlgorithmMatch_B7(t *testing.T) {
	t.Parallel()
	ca := setupTestCA(t)
	issueCertAndSaveToKeyStore(t, ca, "exists-algo-match-b7")
	found, err := ca.Exists(context.Background(), "exists-algo-match-b7", x509.ECDSA)
	require.NoError(t, err)
	assert.True(t, found)
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

func TestTrustedIntermediateCertPool_IssuedByRoot_B7(t *testing.T) {
	t.Parallel()
	ca := setupTestCA(t)
	ca.mu.RLock()
	root := ca.rootCert
	ca.mu.RUnlock()
	require.NotNil(t, root)
	leaf := &x509.Certificate{Issuer: root.Subject}
	pool, err := ca.TrustedIntermediateCertPool(leaf)
	require.NoError(t, err)
	assert.NotNil(t, pool)
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

func TestTrustedRoot_Success_B7(t *testing.T) {
	t.Parallel()
	ca := setupTestCA(t)
	root, err := ca.TrustedRoot()
	require.NoError(t, err)
	assert.NotNil(t, root)
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

func TestTrustedIntermediate_Success_B7(t *testing.T) {
	t.Parallel()
	ca := setupTestCAWithRealIntermediate(t)
	intermediate, err := ca.TrustedIntermediate()
	require.NoError(t, err)
	assert.NotNil(t, intermediate)
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

func TestParseBundle_Success_B7(t *testing.T) {
	t.Parallel()
	ca := setupTestCA(t)
	ca.mu.RLock()
	root := ca.rootCert
	ca.mu.RUnlock()
	require.NotNil(t, root)

	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Raw})
	certs, err := ca.ParseBundle(pemBytes)
	require.NoError(t, err)
	assert.Len(t, certs, 1)
}

// =============================================================================
// trust_chain_extensions.go — RootCertificate nil-input
// =============================================================================

func TestRootCertificate_NilInput_B7(t *testing.T) {
	t.Parallel()
	ca := setupTestCA(t)
	_, err := ca.RootCertificate(nil)
	assert.ErrorIs(t, err, ErrInvalidCertificate)
}

// =============================================================================
// trust_chain_extensions.go — ImportIssuingCAs HTTP error path (new URL)
// =============================================================================

func TestImportIssuingCAs_HTTPError_B7(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer srv.Close()

	ca := setupTestCAWithObjectStore(t)
	cert := &x509.Certificate{
		Subject:               pkix.Name{CommonName: "aia-error-b7"},
		IssuingCertificateURL: []string{srv.URL + "/missing-b7.crt"},
	}
	err := ca.ImportIssuingCAs(context.Background(), cert)
	assert.Error(t, err)
}

// =============================================================================
// tls_extensions.go — TLSBundleWithCrossSigner with signer but no xsigned certs
// =============================================================================

func TestTLSBundleWithCrossSigner_WithSigner_NoXCerts_B7(t *testing.T) {
	ca := setupTestCA(t)
	issueCertAndSaveToKeyStore(t, ca, "tls-bundle-xsign-signer-b7")
	attrs := softwareKeyAttrs("tls-bundle-xsign-signer-b7")
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	bundle, err := ca.TLSBundleWithCrossSigner(context.Background(), attrs, key)
	// The software backend may wrap keys in an opaque type that cannot be
	// marshalled as PKCS#8, in which case ErrTLSConfigFailed is expected.
	if err != nil {
		assert.ErrorIs(t, err, ErrTLSConfigFailed)
		return
	}
	assert.NotEmpty(t, bundle)
}

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

func TestImportCertificatePEM_EmptyCNArg_B7(t *testing.T) {
	t.Parallel()
	ca := setupTestCA(t)
	cert, _ := makeSelfSignedCert(t, "import-pem-b7")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	err := ca.ImportCertificatePEM(context.Background(), "", pemBytes)
	assert.ErrorIs(t, err, ErrInvalidCertificate)
}

func TestImportCertificatePEM_Success_B7(t *testing.T) {
	t.Parallel()
	ca := setupTestCA(t)
	cert, _ := makeSelfSignedCert(t, "import-pem-ok-b7")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	err := ca.ImportCertificatePEM(context.Background(), "import-pem-ok-b7", pemBytes)
	require.NoError(t, err)
}

// =============================================================================
// ca_extensions.go — RevokeCert with object store (recordRevocation /
// putRevocationBlobIfAbsent round-trip)
// =============================================================================

func TestRevokeCert_WithObjectStore_RoundTrip_B7(t *testing.T) {
	ca := setupTestCAWithObjectStore(t)
	cert, _ := makeSelfSignedCert(t, "revoke-roundtrip-b7")
	err := ca.RevokeCert(context.Background(), cert, RevokeOptions{
		Reason: ReasonKeyCompromise,
	})
	require.NoError(t, err)
	revoked, err := ca.IsRevoked(cert.SerialNumber)
	require.NoError(t, err)
	assert.True(t, revoked)
}

// =============================================================================
// tcg_oids.go — ParseTPMSpecificationExtension with garbage data
// =============================================================================

func TestParseTPMSpecificationExtension_GarbageData_B7(t *testing.T) {
	t.Parallel()
	_, err := ParseTPMSpecificationExtension([]byte{0x0C, 0xFF, 0xFF})
	assert.ErrorIs(t, err, ErrTCGExtensionParsing)
}

// =============================================================================
// tcg_oids.go — CreateTenantIDExtension large ID
// =============================================================================

func TestCreateTenantIDExtension_LargeID_B7(t *testing.T) {
	t.Parallel()
	longID := make([]byte, 4096)
	for i := range longID {
		longID[i] = 'a'
	}
	ext, err := CreateTenantIDExtension(string(longID))
	require.NoError(t, err)
	assert.NotEmpty(t, ext.Value)
}

// =============================================================================
// bundle.go — CABundle PEM validity cross-check
// =============================================================================

func TestCABundle_ContainsValidPEM_B7(t *testing.T) {
	t.Parallel()
	ca := setupTestCA(t)
	bundle, err := ca.CABundle()
	require.NoError(t, err)
	assert.NotEmpty(t, bundle)

	block, _ := pem.Decode(bundle)
	require.NotNil(t, block)
	assert.Equal(t, "CERTIFICATE", block.Type)
	_, err = x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
}

// =============================================================================
// tcg_oids.go — bool-false round-trip on Residency/Fixed extensions
// =============================================================================

// The tcg-cap-* assertions are certificate POLICY identifiers carrying "No
// data" (TCG DevID v1 r12 §8.2). The boolean-valued standalone extensions this
// test covered are gone; the assertions are pinned on issued certificates by
// the certificate policy regression suite in certpolicy_test.go.

// =============================================================================
// types helpers — randomSerial used in tests
// =============================================================================

// b7RandomSerial generates a random serial for test helper usage in this file.
func b7RandomSerial(t *testing.T) *big.Int {
	t.Helper()
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)
	return n
}

// =============================================================================
// Additional targeted gap coverage
// =============================================================================

// TestCAKeyAttributes_StoreTypeMismatch_B7 exercises the store-type mismatch
// branch that is NOT already tested in session1_extensions_test.go under
// TestCAKeyAttributes_WrongStoreType (which may already cover it — but adding
// a dedicated b7 variant for the typed error assertion).
func TestCAKeyAttributes_StoreTypeMismatch_B7(t *testing.T) {
	t.Parallel()
	ca := setupTestCA(t)
	_, err := ca.CAKeyAttributes(types.StoreTPM2)
	assert.ErrorIs(t, err, ErrInvalidStoreType)
}

// TestImportIssuingCAs_HTTPSuccess_DERPayload exercises the DER-download path
// in ImportIssuingCAs using a fresh URL pattern that does not clash with the
// TestImportIssuingCAs_HTTPServerDER test in coverage_gap_test.go.
func TestImportIssuingCAs_DERIssuerChain_B7(t *testing.T) {
	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	issuerTmpl := &x509.Certificate{
		SerialNumber:          b7RandomSerial(t),
		Subject:               pkix.Name{CommonName: "import-aia-issuer-b7"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	issuerDER, err := x509.CreateCertificate(rand.Reader, issuerTmpl, issuerTmpl, &issuerKey.PublicKey, issuerKey)
	require.NoError(t, err)
	issuerCert, err := x509.ParseCertificate(issuerDER)
	require.NoError(t, err)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/pkix-cert")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(issuerDER)
	}))
	defer srv.Close()

	ca := setupTestCAWithObjectStore(t)
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	leafTmpl := &x509.Certificate{
		SerialNumber:          b7RandomSerial(t),
		Subject:               pkix.Name{CommonName: "import-aia-leaf-b7"},
		Issuer:                pkix.Name{CommonName: "import-aia-issuer-b7"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IssuingCertificateURL: []string{srv.URL + "/issuer-b7.crt"},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, issuerCert, &leafKey.PublicKey, issuerKey)
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(leafDER)
	require.NoError(t, err)

	err = ca.ImportIssuingCAs(context.Background(), leaf)
	require.NoError(t, err)
}

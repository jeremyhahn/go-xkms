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

// Package ca coverage boost, second pass: targets low-coverage functions
// remaining after the first pass.  All tests are in-memory, fast, race-free.
package ca

import (
	"context"
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Helpers
// =============================================================================

// softwareKeyAttrs returns the KeyAttributes a leaf issued via IssueCertificate
// uses. The key is stored by the software backend under these attrs; callers
// must pass them when accessing the key from the keyStore.
func softwareKeyAttrs(cn string) *types.KeyAttributes {
	return &types.KeyAttributes{
		CN:           cn,
		KeyAlgorithm: x509.ECDSA,
		StoreType:    types.StoreSoftware,
		KeyType:      types.KeyTypeTLS,
		ECCAttributes: &types.ECCAttributes{
			Curve: elliptic.P256(),
		},
		Hash: crypto.SHA256,
	}
}

// issueCertAndSaveToKeyStore issues a leaf certificate and explicitly saves it
// to the keyStore so that GetTLSCertificate (which reads from the keyStore)
// can find both the key and the certificate.
func issueCertAndSaveToKeyStore(t *testing.T, ca *CA, cn string) {
	t.Helper()
	issued, err := ca.IssueCertificate(context.Background(), &CertificateRequest{
		TenantID: testTenant,
		Subject:  Subject{CommonName: cn},
		SANS:     &SubjectAlternativeNames{DNS: []string{cn}},
		Valid:    365,
	})
	require.NoError(t, err)
	// SaveCert via ImportCertificate so keyStore.GetCert resolves.
	require.NoError(t, ca.ImportCertificate(context.Background(), issued.Certificate))
}

// =============================================================================
// tls_extensions.go — TLSBundleWithCrossSigner happy path (21%)
// =============================================================================

func TestTLSBundleWithCrossSigner_NilXSigner_ReturnsBase(t *testing.T) {
	ca := setupTestCA(t)
	cn := "xsigner-leaf.example.com"
	issueCertAndSaveToKeyStore(t, ca, cn)

	attrs := softwareKeyAttrs(cn)
	// nil xsigner → falls through to TLSBundle directly.
	bundle, err := ca.TLSBundleWithCrossSigner(context.Background(), attrs, nil)
	// Accept both success (raw key export supported) and
	// ErrTLSConfigFailed (opaque key marshal not supported).
	if err != nil {
		assert.ErrorIs(t, err, ErrTLSConfigFailed)
	} else {
		assert.NotEmpty(t, bundle)
	}
}

// =============================================================================
// tls_extensions.go — TLSConfigWithXSigner happy path (12%)
// =============================================================================

func TestTLSConfigWithXSigner_NilXSigner_ReturnsCfg(t *testing.T) {
	ca := setupTestCA(t)
	cn := "xsigner-cfg-leaf.example.com"
	issueCertAndSaveToKeyStore(t, ca, cn)

	attrs := softwareKeyAttrs(cn)
	cfg, err := ca.TLSConfigWithXSigner(context.Background(), attrs, nil)
	require.NoError(t, err)
	assert.NotNil(t, cfg)
}

// =============================================================================
// tls.go — TLSConfigWithOptions server mode (34%)
// =============================================================================

func TestTLSConfigWithOptions_ServerMode_RequireClientCert(t *testing.T) {
	ca := setupTestCA(t)
	cn := "server-mtls.example.com"
	issueCertAndSaveToKeyStore(t, ca, cn)

	attrs := softwareKeyAttrs(cn)
	opts := &TLSConfigOptions{
		IsServer:          true,
		RequireClientCert: true,
	}
	cfg, err := ca.TLSConfigWithOptions(context.Background(), attrs, opts)
	require.NoError(t, err)
	assert.NotNil(t, cfg)
	assert.Equal(t, tls.RequireAndVerifyClientCert, cfg.ClientAuth)
}

func TestTLSConfigWithOptions_ServerMode_NoClientCert(t *testing.T) {
	ca := setupTestCA(t)
	cn := "server-tls.example.com"
	issueCertAndSaveToKeyStore(t, ca, cn)

	attrs := softwareKeyAttrs(cn)
	opts := &TLSConfigOptions{IsServer: true}
	cfg, err := ca.TLSConfigWithOptions(context.Background(), attrs, opts)
	require.NoError(t, err)
	assert.NotNil(t, cfg)
	assert.Equal(t, tls.NoClientCert, cfg.ClientAuth)
}

// =============================================================================
// service_adapter.go — IssueEKCertificateRaw (87% → exercise the happy path)
// =============================================================================

func TestIssueEKCertificateRaw_Success_B2(t *testing.T) {
	// setupTestCA provides a fully initialized CA with real config+keystore.
	ca := setupTestCA(t)

	ekKey := generateTestECDSAKey(t)
	ekPubDER, err := x509.MarshalPKIXPublicKey(&ekKey.PublicKey)
	require.NoError(t, err)

	certDER, err := ca.IssueEKCertificateRaw(context.Background(), "test-ek-raw", "Test Org", ekPubDER, testTenant)
	require.NoError(t, err)
	assert.NotEmpty(t, certDER)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)
	assert.Equal(t, "test-ek-raw", cert.Subject.CommonName)
}

// =============================================================================
// service_adapter.go — IssueAKCertificateRaw (87% → exercise the happy path)
// =============================================================================

func TestIssueAKCertificateRaw_Success_B2(t *testing.T) {
	ca := setupTestCA(t)

	akKey := generateTestECDSAKey(t)
	akPubDER, err := x509.MarshalPKIXPublicKey(&akKey.PublicKey)
	require.NoError(t, err)

	certDER, err := ca.IssueAKCertificateRaw(context.Background(), "test-ak-raw", "Test Org", akPubDER, testTenant)
	require.NoError(t, err)
	assert.NotEmpty(t, certDER)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)
	assert.Equal(t, "test-ak-raw", cert.Subject.CommonName)
}

// =============================================================================
// service_adapter.go — SignTCGCSRIDevIDRaw (0% → error path)
// =============================================================================

func TestSignTCGCSRIDevIDRaw_InvalidCSR(t *testing.T) {
	ca := createTestCAForTCG(t)
	_, _, err := ca.SignTCGCSRIDevIDRaw(context.Background(), "device", "Org", []byte("garbage"), testTenant)
	assert.Error(t, err)
}

// =============================================================================
// service_adapter.go — EnrollDeviceRaw (0% → error path)
// =============================================================================

func TestEnrollDeviceRaw_InvalidCSR(t *testing.T) {
	ca := createTestCAForTCG(t)
	_, _, _, _, _, err := ca.EnrollDeviceRaw(context.Background(), "device", "Org", []byte("garbage"), testTenant)
	assert.Error(t, err)
}

// =============================================================================
// trust_chain.go — CABundleCertPool (71%)
// =============================================================================

func TestCABundleCertPool_NotInitialized(t *testing.T) {
	ca := &CA{}
	_, err := ca.CABundleCertPool()
	assert.Error(t, err)
}

// =============================================================================
// verification.go — IsIssuedBy with AKID (85%)
// =============================================================================

func TestIsIssuedBy_DNMismatch(t *testing.T) {
	// IsIssuedBy returns false when the RawIssuer of the cert does not match
	// the RawSubject of the claimed issuer.
	caKey := generateTestECDSAKey(t)
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "issuer-ca"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		IsCA:         true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	caCert, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)

	// Self-signed leaf → RawIssuer == its own Subject, not caCert's Subject.
	leafKey := generateTestECDSAKey(t)
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "different-issuer"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, leafTemplate, &leafKey.PublicKey, leafKey)
	require.NoError(t, err)
	leafCert, err := x509.ParseCertificate(leafDER)
	require.NoError(t, err)

	assert.False(t, IsIssuedBy(leafCert, caCert))
}

// =============================================================================
// ca_extensions.go — RevokeCert (not initialized path)
// =============================================================================

func TestRevokeCert_NotInitialized_B2(t *testing.T) {
	ca := &CA{}
	cert := &x509.Certificate{SerialNumber: big.NewInt(999)}
	err := ca.RevokeCert(context.Background(), cert, RevokeOptions{})
	assert.ErrorIs(t, err, ErrNotInitialized)
}

// =============================================================================
// ca_extensions.go — DefaultValidityPeriod from caConfig (partial)
// =============================================================================

// =============================================================================
// ca_extensions.go — IsAutoImportingIssuerCAs (66%)
// =============================================================================

func TestIsAutoImportingIssuerCAs_False_NilCAConfig(t *testing.T) {
	ca := &CA{}
	assert.False(t, ca.IsAutoImportingIssuerCAs())
}

// =============================================================================
// ca_extensions.go — PEM (partial)
// =============================================================================

func TestPEM_NilAttrs_B2(t *testing.T) {
	ca := setupTestCA(t)
	_, err := ca.PEM(context.Background(), nil)
	assert.ErrorIs(t, err, ErrInvalidCertificate)
}

// =============================================================================
// ca_extensions.go — DefaultSignatureAlgorithm nil issuing path (85%)
// =============================================================================

// =============================================================================
// ca_extensions.go — DefaultKeyAlgorithm nil issuing (50%)
// =============================================================================

// =============================================================================
// ca.go — Verify (66%)
// =============================================================================

func TestVerify_NotInitialized(t *testing.T) {
	ca := &CA{}
	_, err := ca.Verify(&x509.Certificate{})
	assert.ErrorIs(t, err, ErrNotInitialized)
}

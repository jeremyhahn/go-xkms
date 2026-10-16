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

package ca

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupTestCAWithObjectStore builds on the shared setupTestCA helper by
// attaching an in-memory object store so attestation and cross-signing code
// paths can be exercised.
func setupTestCAWithObjectStore(t *testing.T) *CA {
	t.Helper()
	ca := setupTestCA(t)
	ca.objectStore = qrdbsdk.NewMemoryStorage()
	return ca
}

// makeSelfSignedCert produces a short-lived self-signed certificate used to
// populate the object store for the import / retrieval tests.
func makeSelfSignedCert(t *testing.T, cn string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)
	return cert, key
}

// =============================================================================
// Signer / PrivateKey / PubKey / SignedBlob
// =============================================================================

func TestSigner_ReturnsSigner(t *testing.T) {
	ca := setupTestCA(t)
	signer, err := ca.Signer(context.Background())
	require.NoError(t, err)
	assert.NotNil(t, signer)
	assert.NotNil(t, signer.Public())
}

func TestSigner_NotInitialized(t *testing.T) {
	ca := setupUninitializedCA(t)
	_, err := ca.Signer(context.Background())
	assert.ErrorIs(t, err, ErrNotInitialized)
}

func TestPrivateKey_NilAttributes(t *testing.T) {
	ca := setupTestCA(t)
	_, err := ca.PrivateKey(context.Background(), nil)
	assert.ErrorIs(t, err, ErrInvalidConfig)
}

func TestPubKey_NilAttributes(t *testing.T) {
	ca := setupTestCA(t)
	_, err := ca.PubKey(context.Background(), nil)
	assert.ErrorIs(t, err, ErrInvalidConfig)
}

func TestSignedBlob_ProducesSignature(t *testing.T) {
	ca := setupTestCA(t)
	sig, err := ca.SignedBlob(context.Background(), []byte("payload"))
	require.NoError(t, err)
	assert.NotEmpty(t, sig)
}

func TestSignedBlob_NotInitialized(t *testing.T) {
	ca := setupUninitializedCA(t)
	_, err := ca.SignedBlob(context.Background(), []byte("payload"))
	assert.ErrorIs(t, err, ErrNotInitialized)
}

// =============================================================================
// Issued / Exists / Certificate / CertificatePEM / PEM / ImportCertificate*
// =============================================================================

func TestExists_MatchesAlgorithm(t *testing.T) {
	ca := setupTestCA(t)
	ok, err := ca.Exists(context.Background(), "Test Root CA", x509.ECDSA)
	require.NoError(t, err)
	assert.True(t, ok)
}

func TestExists_WrongAlgorithm(t *testing.T) {
	ca := setupTestCA(t)
	ok, err := ca.Exists(context.Background(), "Test Root CA", x509.RSA)
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestCertificate_FromCache(t *testing.T) {
	ca := setupTestCA(t)
	cert, err := ca.Certificate(context.Background(), &types.KeyAttributes{CN: "Test Root CA"})
	require.NoError(t, err)
	assert.Equal(t, "Test Root CA", cert.Subject.CommonName)
}

func TestCertificate_NotFound(t *testing.T) {
	ca := setupTestCA(t)
	_, err := ca.Certificate(context.Background(), &types.KeyAttributes{CN: "missing"})
	assert.ErrorIs(t, err, ErrCertificateNotFound)
}

func TestCertificatePEM_Roundtrip(t *testing.T) {
	ca := setupTestCA(t)
	out, err := ca.CertificatePEM(context.Background(), "Test Root CA")
	require.NoError(t, err)
	assert.Contains(t, string(out), "BEGIN CERTIFICATE")
}

func TestPEM_IsAliasForCertificatePEM(t *testing.T) {
	ca := setupTestCA(t)
	viaPEM, err := ca.PEM(context.Background(), &types.KeyAttributes{CN: "Test Root CA"})
	require.NoError(t, err)
	viaCertPEM, err := ca.CertificatePEM(context.Background(), "Test Root CA")
	require.NoError(t, err)
	assert.Equal(t, viaCertPEM, viaPEM)
}

func TestImportCertificate_RoundTrip(t *testing.T) {
	ca := setupTestCA(t)
	cert, _ := makeSelfSignedCert(t, "imported.example.com")
	require.NoError(t, ca.ImportCertificate(context.Background(), cert))

	retrieved, err := ca.Certificate(context.Background(), &types.KeyAttributes{CN: "imported.example.com"})
	require.NoError(t, err)
	assert.Equal(t, cert.Raw, retrieved.Raw)
}

func TestImportCertificate_NilRejected(t *testing.T) {
	ca := setupTestCA(t)
	err := ca.ImportCertificate(context.Background(), nil)
	assert.ErrorIs(t, err, ErrInvalidCertificate)
}

func TestImportCertificatePEM_Roundtrip(t *testing.T) {
	ca := setupTestCA(t)
	cert, _ := makeSelfSignedCert(t, "pem-import.example.com")
	pemBytes, err := ca.CertificatePEM(context.Background(), "Test Root CA")
	require.NoError(t, err)
	_ = pemBytes
	err = ca.ImportCertificatePEM(context.Background(), "", nil)
	assert.ErrorIs(t, err, ErrInvalidCertificate)

	// Happy path using a real PEM.
	realPEM := encodeCertAsPEM(t, cert)
	require.NoError(t, ca.ImportCertificatePEM(context.Background(), "pem-import.example.com", realPEM))
}

func encodeCertAsPEM(t *testing.T, cert *x509.Certificate) []byte {
	t.Helper()
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
}

// =============================================================================
// Blob / ImportBlob
// =============================================================================

func TestImportBlob_BlobRoundTrip(t *testing.T) {
	ca := setupTestCAWithObjectStore(t)
	require.NoError(t, ca.ImportBlob([]byte("testkey"), []byte("hello")))

	data, err := ca.Blob([]byte("testkey"))
	require.NoError(t, err)
	assert.Equal(t, []byte("hello"), data)
}

func TestBlob_WithoutObjectStore(t *testing.T) {
	ca := setupTestCA(t)
	_, err := ca.Blob([]byte("k"))
	assert.ErrorIs(t, err, ErrObjectStoreRequired)
}

func TestImportBlob_WithoutObjectStore(t *testing.T) {
	ca := setupTestCA(t)
	err := ca.ImportBlob([]byte("k"), []byte("v"))
	assert.ErrorIs(t, err, ErrObjectStoreRequired)
}

// =============================================================================
// TrustedRoot / TrustedIntermediate
// =============================================================================

func TestTrustedRoot_ReturnsRoot(t *testing.T) {
	ca := setupTestCA(t)
	root, err := ca.TrustedRoot()
	require.NoError(t, err)
	assert.Equal(t, "Test Root CA", root.Subject.CommonName)
}

func TestTrustedRoot_NotInitialized(t *testing.T) {
	ca := setupUninitializedCA(t)
	_, err := ca.TrustedRoot()
	assert.ErrorIs(t, err, ErrNotInitialized)
}

func TestTrustedIntermediate_NotConfigured(t *testing.T) {
	ca := setupTestCA(t) // root-only
	_, err := ca.TrustedIntermediate()
	assert.ErrorIs(t, err, ErrIntermediateNotFound)
}

func TestTrustedIntermediate_Present(t *testing.T) {
	ca := setupTestCAWithRealIntermediate(t)
	inter, err := ca.TrustedIntermediate()
	require.NoError(t, err)
	assert.Equal(t, "Test Intermediate CA", inter.Subject.CommonName)
}

// =============================================================================
// ParseBundle / RootCertificate
// =============================================================================

func TestParseBundle_Empty(t *testing.T) {
	ca := setupTestCA(t)
	_, err := ca.ParseBundle(nil)
	assert.ErrorIs(t, err, ErrInvalidPEM)
}

func TestParseBundle_HappyPath(t *testing.T) {
	ca := setupTestCA(t)
	bundle, err := ca.CABundle()
	require.NoError(t, err)
	certs, err := ca.ParseBundle(bundle)
	require.NoError(t, err)
	assert.NotEmpty(t, certs)
}

func TestRootCertificate_SelfSigned(t *testing.T) {
	ca := setupTestCA(t)
	root, err := ca.TrustedRoot()
	require.NoError(t, err)
	found, err := ca.RootCertificate(root)
	require.NoError(t, err)
	assert.Equal(t, root.Raw, found.Raw)
}

func TestRootCertificate_NilCert(t *testing.T) {
	ca := setupTestCA(t)
	_, err := ca.RootCertificate(nil)
	assert.ErrorIs(t, err, ErrInvalidCertificate)
}

// =============================================================================
// Cross-signing
// =============================================================================

func TestImportXSignedCertificate_RequiresObjectStore(t *testing.T) {
	ca := setupTestCA(t)
	cert, _ := makeSelfSignedCert(t, "foo")
	err := ca.ImportXSignedCertificate("ExternalRoot", cert)
	assert.ErrorIs(t, err, ErrObjectStoreRequired)
}

func TestImportXSignedCertificate_HappyPath(t *testing.T) {
	ca := setupTestCAWithObjectStore(t)
	cert, _ := makeSelfSignedCert(t, "foo")
	require.NoError(t, ca.ImportXSignedCertificate("ExternalRoot", cert))

	fetched, err := ca.XSignedCertificate("ExternalRoot", &types.KeyAttributes{CN: "foo"})
	require.NoError(t, err)
	assert.Equal(t, cert.Raw, fetched.Raw)
}

func TestImportXSignedCertificate_NilCert(t *testing.T) {
	ca := setupTestCAWithObjectStore(t)
	err := ca.ImportXSignedCertificate("ExternalRoot", nil)
	assert.ErrorIs(t, err, ErrInvalidCertificate)
}

func TestCrossSignedPEM_NotFound(t *testing.T) {
	ca := setupTestCAWithObjectStore(t)
	_, err := ca.CrossSignedPEM(&types.KeyAttributes{CN: "missing"})
	assert.ErrorIs(t, err, ErrCertificateNotFound)
}

// =============================================================================
// Attestation
// =============================================================================

func TestImportAttestation_RequiresObjectStore(t *testing.T) {
	ca := setupTestCA(t)
	err := ca.ImportAttestation(context.Background(), &types.KeyAttributes{CN: "ak"}, AttestBlobQuote, []byte("x"))
	assert.ErrorIs(t, err, ErrObjectStoreRequired)
}

func TestImportAttestation_BadType(t *testing.T) {
	ca := setupTestCAWithObjectStore(t)
	err := ca.ImportAttestation(context.Background(), &types.KeyAttributes{CN: "ak"}, "bogus", []byte("x"))
	assert.ErrorIs(t, err, ErrInvalidAttestationBlobType)
}

func TestImportAttestation_Roundtrip(t *testing.T) {
	ca := setupTestCAWithObjectStore(t)
	data := []byte("quoted-data")
	require.NoError(t, ca.ImportAttestationQuote(context.Background(), &types.KeyAttributes{CN: "ak"}, data))
	require.NoError(t, ca.VerifyAttestationQuote(&types.KeyAttributes{CN: "ak"}, data))
}

func TestImportAttestation_VerifyTamperedFails(t *testing.T) {
	ca := setupTestCAWithObjectStore(t)
	require.NoError(t, ca.ImportAttestationQuote(context.Background(), &types.KeyAttributes{CN: "ak"}, []byte("original")))
	err := ca.VerifyAttestationQuote(&types.KeyAttributes{CN: "ak"}, []byte("tampered"))
	assert.ErrorIs(t, err, ErrInvalidSignature)
}

func TestImportAttestationKeyCertificate_Happy(t *testing.T) {
	ca := setupTestCAWithObjectStore(t)
	cert, _ := makeSelfSignedCert(t, "ak-cert")
	require.NoError(t, ca.ImportAttestationKeyCertificate(context.Background(), &types.KeyAttributes{CN: "ak-cert"}, cert.Raw))
}

// =============================================================================
// TLS Extensions
// =============================================================================

func TestTLSBundle_NilAttrs(t *testing.T) {
	ca := setupTestCA(t)
	_, err := ca.TLSBundle(context.Background(), nil)
	assert.ErrorIs(t, err, ErrInvalidTLSOptions)
}

func TestTLSConfigWithXSigner_NilAttrs(t *testing.T) {
	// With attrs=nil, TLSConfigWithXSigner should surface the same
	// validation error as TLSConfig.
	ca := setupTestCA(t)
	_, err := ca.TLSConfigWithXSigner(context.Background(), nil, nil)
	assert.ErrorIs(t, err, ErrInvalidTLSOptions)
}

// =============================================================================
// CAConfig / Default accessors
// =============================================================================

func TestDefaultKeyAlgorithm(t *testing.T) {
	ca := setupTestCA(t)
	// setupTestCA uses default ECDSA config.
	assert.Equal(t, x509.ECDSA, ca.DefaultKeyAlgorithm())
}

func TestDefaultSignatureAlgorithm(t *testing.T) {
	ca := setupTestCA(t)
	assert.NotEqual(t, x509.UnknownSignatureAlgorithm, ca.DefaultSignatureAlgorithm())
}

func TestDefaultValidityPeriod(t *testing.T) {
	ca := setupTestCA(t)
	assert.Positive(t, ca.DefaultValidityPeriod())
}

func TestHash_ECDSAReturnsSHA256(t *testing.T) {
	ca := setupTestCA(t)
	assert.Equal(t, crypto.SHA256, ca.Hash())
}

func TestIsAutoImportingIssuerCAs_DefaultFalse(t *testing.T) {
	ca := setupTestCA(t)
	assert.False(t, ca.IsAutoImportingIssuerCAs())
}

// =============================================================================
// CAKeyAttributes / CASigner
// =============================================================================

func TestCAKeyAttributes_MatchesConfigured(t *testing.T) {
	ca := setupTestCA(t)
	attrs, err := ca.CAKeyAttributes(types.StoreSoftware)
	require.NoError(t, err)
	assert.Equal(t, "Test Root CA", attrs.CN)
}

func TestCAKeyAttributes_WrongStoreType(t *testing.T) {
	ca := setupTestCA(t)
	_, err := ca.CAKeyAttributes(types.StoreType("tpm2"))
	assert.ErrorIs(t, err, ErrInvalidStoreType)
}

func TestCASigner_MatchingAlgorithm(t *testing.T) {
	ca := setupTestCA(t)
	signer, err := ca.CASigner(context.Background(), types.StoreSoftware, x509.ECDSA)
	require.NoError(t, err)
	assert.NotNil(t, signer)
}

func TestCASigner_MismatchedAlgorithm(t *testing.T) {
	ca := setupTestCA(t)
	_, err := ca.CASigner(context.Background(), types.StoreSoftware, x509.RSA)
	assert.ErrorIs(t, err, ErrInvalidKeyAlgorithm)
}

// =============================================================================
// Filtered bundle / RevokeCert
// =============================================================================

func TestCABundleFiltered_NoFilter(t *testing.T) {
	ca := setupTestCA(t)
	bundle, err := ca.CABundleFiltered("", x509.UnknownPublicKeyAlgorithm)
	require.NoError(t, err)
	assert.NotEmpty(t, bundle)
}

func TestCABundleFiltered_AlgorithmFilter(t *testing.T) {
	ca := setupTestCA(t)
	bundle, err := ca.CABundleFiltered("", x509.ECDSA)
	require.NoError(t, err)
	assert.NotEmpty(t, bundle)
}

func TestCABundleFiltered_NoMatch(t *testing.T) {
	ca := setupTestCA(t)
	_, err := ca.CABundleFiltered("", x509.Ed25519)
	assert.ErrorIs(t, err, ErrInvalidCertificateChain)
}

func TestRevokeCert_NilRejected(t *testing.T) {
	ca := setupTestCA(t)
	err := ca.RevokeCert(context.Background(), nil, RevokeOptions{})
	assert.ErrorIs(t, err, ErrInvalidCertificate)
}

func TestRevokeCert_DeleteKeys(t *testing.T) {
	ca := setupTestCA(t)
	issued, err := ca.IssueCertificate(context.Background(), &CertificateRequest{
		Subject: Subject{CommonName: "revoke-me.example.com"},
		Valid:   30,
	})
	require.NoError(t, err)

	err = ca.RevokeCert(context.Background(), issued.Certificate, RevokeOptions{
		Reason:     ReasonKeyCompromise,
		DeleteKeys: true,
	})
	require.NoError(t, err)

	revoked, err := ca.IsRevoked(issued.Certificate.SerialNumber)
	require.NoError(t, err)
	assert.True(t, revoked)
}

func TestRevokeCert_AlreadyRevoked(t *testing.T) {
	ca := setupTestCA(t)
	issued, err := ca.IssueCertificate(context.Background(), &CertificateRequest{
		Subject: Subject{CommonName: "duplicate-revoke.example.com"},
		Valid:   30,
	})
	require.NoError(t, err)

	require.NoError(t, ca.RevokeCert(context.Background(), issued.Certificate, RevokeOptions{}))
	err = ca.RevokeCert(context.Background(), issued.Certificate, RevokeOptions{})
	assert.ErrorIs(t, err, ErrAlreadyRevoked)
}

// =============================================================================
// ImportIssuingCAs / ImportDistributionCRLs no-op paths
// =============================================================================

func TestImportIssuingCAs_NoAIA(t *testing.T) {
	ca := setupTestCA(t)
	cert, _ := makeSelfSignedCert(t, "no-aia.example.com")
	assert.NoError(t, ca.ImportIssuingCAs(context.Background(), cert))
}

func TestImportDistributionCRLs_NoCRLDPs(t *testing.T) {
	ca := setupTestCA(t)
	cert, _ := makeSelfSignedCert(t, "no-crldp.example.com")
	assert.NoError(t, ca.ImportDistributionCRLs(cert))
}

func TestImportDistributionCRLs_NilCert(t *testing.T) {
	ca := setupTestCA(t)
	err := ca.ImportDistributionCRLs(nil)
	assert.ErrorIs(t, err, ErrInvalidCertificate)
}

// =============================================================================
// VerifyTCG_CSR_IDevIDBytes
// =============================================================================

// TestVerifyTCG_CSR_IDevIDBytes_NoTPMRequired proves VerifyTCG_CSR_IDevIDBytes
// no longer requires a TPM (go-xkms#798): the credential challenge is built
// in software via tpm2.NewCredentialChallenge, so a garbage CSR fails at CSR
// unmarshalling, never at a TPM-not-configured check.
func TestVerifyTCG_CSR_IDevIDBytes_NoTPMRequired(t *testing.T) {
	ca := setupTestCA(t)
	_, _, _, err := ca.VerifyTCG_CSR_IDevIDBytes([]byte("packed-csr"), x509.ECDSAWithSHA256)
	assert.NotErrorIs(t, err, ErrTPMNotConfigured)
	assert.ErrorIs(t, err, ErrTCGCSRUnmarshalFailed)
}

// =============================================================================
// Verify (variadic xsigner form)
// =============================================================================

// Session 2.5 collapsed the old VerifyWithXSigner method into the variadic
// Verify(cert, xsigner...) API. The original nil-signer and nil-cert cases
// are preserved here so regressions show up immediately.
func TestVerify_NilXSigner(t *testing.T) {
	ca := setupTestCA(t)
	issued, err := ca.IssueCertificate(context.Background(), &CertificateRequest{
		Subject: Subject{CommonName: "verify-xsigner.example.com"},
		Valid:   30,
	})
	require.NoError(t, err)
	var nilSigner crypto.Signer
	chains, err := ca.Verify(issued.Certificate, nilSigner)
	require.NoError(t, err)
	assert.NotEmpty(t, chains)
}

func TestVerify_NilCertWithXSigner(t *testing.T) {
	ca := setupTestCA(t)
	var nilSigner crypto.Signer
	_, err := ca.Verify(nil, nilSigner)
	assert.ErrorIs(t, err, ErrInvalidCertificate)
}

// TrustedRootCertPoolWithXSigner / TrustedIntermediateCertPoolWithXSigner
// happy path.
func TestTrustedRootCertPoolWithXSigner_NoSigner(t *testing.T) {
	ca := setupTestCA(t)
	issued, err := ca.IssueCertificate(context.Background(), &CertificateRequest{
		Subject: Subject{CommonName: "root-pool-xsigner.example.com"},
		Valid:   30,
	})
	require.NoError(t, err)
	pool, err := ca.TrustedRootCertPoolWithXSigner(issued.Certificate, nil)
	require.NoError(t, err)
	assert.NotNil(t, pool)
}

func TestTrustedIntermediateCertPoolWithXSigner_NoSigner(t *testing.T) {
	ca := setupTestCA(t)
	issued, err := ca.IssueCertificate(context.Background(), &CertificateRequest{
		Subject: Subject{CommonName: "intermediate-pool-xsigner.example.com"},
		Valid:   30,
	})
	require.NoError(t, err)
	pool, err := ca.TrustedIntermediateCertPoolWithXSigner(issued.Certificate, nil)
	require.NoError(t, err)
	assert.NotNil(t, pool)
}

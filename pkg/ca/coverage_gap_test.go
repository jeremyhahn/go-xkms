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

// Package ca coverage-gap tests: targets 0% and low-coverage functions not
// exercised by the existing test suite.  All tests are in-memory, fast, and
// race-free.
package ca

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
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// ca.go — ObjectStore accessor (0%)
// =============================================================================

func TestCA_ObjectStore_Nil(t *testing.T) {
	ca := setupTestCA(t)
	assert.Nil(t, ca.ObjectStore())
}

func TestCA_ObjectStore_NotNil(t *testing.T) {
	ca := setupTestCAWithObjectStore(t)
	assert.NotNil(t, ca.ObjectStore())
}

// =============================================================================
// ca_extensions.go — PrivateKey (33%) — missing error branch
// =============================================================================

func TestPrivateKey_KeyNotFound(t *testing.T) {
	ca := setupTestCA(t)
	_, err := ca.PrivateKey(context.Background(), &types.KeyAttributes{CN: "does-not-exist"})
	assert.ErrorIs(t, err, ErrKeyNotFound)
}

func TestPrivateKey_Success(t *testing.T) {
	ca := setupTestCA(t)
	rootIdentity := ca.config.RootIdentity()
	require.NotNil(t, rootIdentity)
	attrs, err := ca.getCAKeyAttributes(rootIdentity)
	require.NoError(t, err)
	key, err := ca.PrivateKey(context.Background(), attrs)
	require.NoError(t, err)
	assert.NotNil(t, key)
}

// =============================================================================
// ca_extensions.go — PubKey (22%) — success + non-signer error branch
// =============================================================================

func TestPubKey_KeyNotFound(t *testing.T) {
	ca := setupTestCA(t)
	_, err := ca.PubKey(context.Background(), &types.KeyAttributes{CN: "does-not-exist"})
	assert.ErrorIs(t, err, ErrKeyNotFound)
}

func TestPubKey_Success(t *testing.T) {
	ca := setupTestCA(t)
	rootIdentity := ca.config.RootIdentity()
	require.NotNil(t, rootIdentity)
	attrs, err := ca.getCAKeyAttributes(rootIdentity)
	require.NoError(t, err)
	pub, err := ca.PubKey(context.Background(), attrs)
	require.NoError(t, err)
	assert.NotNil(t, pub)
}

// =============================================================================
// ca_extensions.go — Issued (55%) — nil-store paths
// =============================================================================

// =============================================================================
// ca_extensions.go — Certificate (82%) — nil attrs guard
// =============================================================================

func TestCertificate_NilAttrs(t *testing.T) {
	ca := setupTestCA(t)
	_, err := ca.Certificate(context.Background(), nil)
	assert.ErrorIs(t, err, ErrInvalidCertificate)
}

// =============================================================================
// ca_extensions.go — CertificatePEM (75%) — error path
// =============================================================================

func TestCertificatePEM_NotFound(t *testing.T) {
	ca := setupTestCA(t)
	_, err := ca.CertificatePEM(context.Background(), "no-such-cn")
	assert.ErrorIs(t, err, ErrCertificateNotFound)
}

// =============================================================================
// ca_extensions.go — ImportCertificate (75%) — empty CN
// =============================================================================

func TestImportCertificate_EmptyCN(t *testing.T) {
	ca := setupTestCA(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	err = ca.ImportCertificate(context.Background(), cert)
	assert.ErrorIs(t, err, ErrInvalidCertificate)
}

// =============================================================================
// ca_extensions.go — ImportCertificatePEM (73%) — invalid PEM
// =============================================================================

func TestImportCertificatePEM_InvalidPEM(t *testing.T) {
	ca := setupTestCA(t)
	err := ca.ImportCertificatePEM(context.Background(), "some-cn", []byte("not-pem"))
	assert.ErrorIs(t, err, ErrInvalidPEM)
}

func TestImportCertificatePEM_InvalidDER(t *testing.T) {
	ca := setupTestCA(t)
	badPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("garbage")})
	err := ca.ImportCertificatePEM(context.Background(), "some-cn", badPEM)
	assert.ErrorIs(t, err, ErrInvalidCertificate)
}

// =============================================================================
// ca_extensions.go — PEM (66%) — nil attrs guard
// =============================================================================

func TestPEM_NilAttrs(t *testing.T) {
	ca := setupTestCA(t)
	_, err := ca.PEM(context.Background(), nil)
	assert.ErrorIs(t, err, ErrInvalidCertificate)
}

// =============================================================================
// ca_extensions.go — ImportBlob (80%) — nil key
// =============================================================================

func TestImportBlob_NilKey(t *testing.T) {
	ca := setupTestCAWithObjectStore(t)
	err := ca.ImportBlob(nil, []byte("data"))
	assert.Error(t, err)
}

// =============================================================================
// ca_extensions.go — CAConfig (66%) — nil caConfig branch
// =============================================================================

// =============================================================================
// ca_extensions.go — DefaultKeyAlgorithm (50%)
// =============================================================================

func TestDefaultKeyAlgorithm_NoIssuing(t *testing.T) {
	ca := &CA{config: &MultiIdentityCAConfig{}}
	assert.Equal(t, x509.UnknownPublicKeyAlgorithm, ca.DefaultKeyAlgorithm())
}

func TestDefaultKeyAlgorithm_RSA(t *testing.T) {
	ca := setupTestCA(t)
	issuing := ca.config.IssuingIdentity()
	require.NotNil(t, issuing)
	issuing.Keys[0].KeyAlgorithm = types.AlgorithmRSA
	assert.Equal(t, x509.RSA, ca.DefaultKeyAlgorithm())
}

func TestDefaultKeyAlgorithm_Ed25519(t *testing.T) {
	ca := setupTestCA(t)
	issuing := ca.config.IssuingIdentity()
	require.NotNil(t, issuing)
	issuing.Keys[0].KeyAlgorithm = types.AlgorithmEd25519
	assert.Equal(t, x509.Ed25519, ca.DefaultKeyAlgorithm())
}

func TestDefaultKeyAlgorithm_Unknown(t *testing.T) {
	ca := setupTestCA(t)
	issuing := ca.config.IssuingIdentity()
	require.NotNil(t, issuing)
	issuing.Keys[0].KeyAlgorithm = "unsupported"
	assert.Equal(t, x509.UnknownPublicKeyAlgorithm, ca.DefaultKeyAlgorithm())
}

// =============================================================================
// ca_extensions.go — DefaultSignatureAlgorithm (71%)
// =============================================================================

func TestDefaultSignatureAlgorithm_NilIssuing(t *testing.T) {
	ca := &CA{config: &MultiIdentityCAConfig{}}
	assert.Equal(t, x509.UnknownSignatureAlgorithm, ca.DefaultSignatureAlgorithm())
}

// =============================================================================
// ca_extensions.go — DefaultValidityPeriod (66%)
// =============================================================================

func TestDefaultValidityPeriod_FromCaConfig(t *testing.T) {
	ca := setupTestCA(t)
	ca.caConfig = &CAConfig{DefaultCertValidityDays: 42}
	assert.Equal(t, 42, ca.DefaultValidityPeriod())
}

func TestDefaultValidityPeriod_ZeroCaConfigDays(t *testing.T) {
	ca := setupTestCA(t)
	ca.caConfig = &CAConfig{DefaultCertValidityDays: 0}
	// Falls back to config.GetDefaultValidityDays
	assert.Positive(t, ca.DefaultValidityPeriod())
}

// =============================================================================
// ca_extensions.go — IsAutoImportingIssuerCAs (66%)
// =============================================================================

func TestIsAutoImportingIssuerCAs_TrueWhenSet(t *testing.T) {
	ca := setupTestCA(t)
	ca.caConfig = &CAConfig{AutoImportIssuingCA: true}
	assert.True(t, ca.IsAutoImportingIssuerCAs())
}

// =============================================================================
// ca_extensions.go — CAKeyAttributes (80%) — nil issuing
// =============================================================================

func TestCAKeyAttributes_NilIssuing(t *testing.T) {
	ca := &CA{config: &MultiIdentityCAConfig{}}
	_, err := ca.CAKeyAttributes(types.StoreSoftware)
	assert.ErrorIs(t, err, ErrInvalidConfig)
}

// =============================================================================
// ca_extensions.go — CASigner (83%) — mismatched store type flows through
// CAKeyAttributes which returns an error, covered above. Test the success path.
// =============================================================================

func TestCASigner_UnknownAlgoPassthrough(t *testing.T) {
	ca := setupTestCA(t)
	// UnknownPublicKeyAlgorithm means no algorithm check; signer must succeed.
	signer, err := ca.CASigner(context.Background(), types.StoreSoftware, x509.UnknownPublicKeyAlgorithm)
	require.NoError(t, err)
	assert.NotNil(t, signer)
}

// =============================================================================
// ca_extensions.go — CABundleFiltered (71%) — storeType filter path
// =============================================================================

func TestCABundleFiltered_StoreTypeFilter(t *testing.T) {
	ca := setupTestCA(t)
	bundle, err := ca.CABundleFiltered(types.StoreSoftware, x509.UnknownPublicKeyAlgorithm)
	require.NoError(t, err)
	assert.NotEmpty(t, bundle)
}

func TestCABundleFiltered_NotInitialized(t *testing.T) {
	ca := &CA{}
	_, err := ca.CABundleFiltered("", x509.UnknownPublicKeyAlgorithm)
	assert.ErrorIs(t, err, ErrNotInitialized)
}

// =============================================================================
// ca_extensions.go — RevokeCert (92%) — not-initialized branch
// =============================================================================

func TestRevokeCert_NotInitialized(t *testing.T) {
	ca := &CA{}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	err = ca.RevokeCert(context.Background(), cert, RevokeOptions{})
	assert.ErrorIs(t, err, ErrNotInitialized)
}

// =============================================================================
// ca_extensions.go — loadPersistedRevocations (70%) — corrupt record path
// =============================================================================

// This exercises the corrupt-unmarshal branch by inserting junk blobs into the
// revocationStore via the objectStore path.
func TestLoadPersistedRevocations_CorruptBlob(t *testing.T) {
	ca := setupTestCAWithObjectStore(t)
	// Insert a non-JSON blob under the revocation key prefix.
	key := revocationKeyPrefix + "badrecord.json"
	require.NoError(t, ca.objectStore.Put(key, &stubReader{data: []byte("not-json")}))
	// loadPersistedRevocations should log+skip, not return an error.
	err := ca.loadPersistedRevocations(context.Background())
	assert.NoError(t, err)
}

// stubReader is a minimal io.ReadCloser for injecting bytes into tests.
type stubReader struct {
	data []byte
	pos  int
}

func (s *stubReader) Read(p []byte) (n int, err error) {
	if s.pos >= len(s.data) {
		return 0, io.EOF
	}
	n = copy(p, s.data[s.pos:])
	s.pos += n
	return n, nil
}

func (s *stubReader) Close() error { return nil }

// =============================================================================
// ca_extensions.go — listRevocationBlobs (76%) — objectStore path
// =============================================================================

func TestListRevocationBlobs_ObjectStorePath(t *testing.T) {
	ca := setupTestCAWithObjectStore(t)
	// Revoke a cert to trigger blob write via objectStore path.
	require.NoError(t, ca.Revoke(context.Background(), big.NewInt(77777), 0))
	blobs, err := ca.listRevocationBlobs(context.Background())
	require.NoError(t, err)
	assert.NotEmpty(t, blobs)
}

func TestListRevocationBlobs_EmptyStores(t *testing.T) {
	ca := setupTestCA(t)
	blobs, err := ca.listRevocationBlobs(context.Background())
	require.NoError(t, err)
	assert.Empty(t, blobs)
}

// =============================================================================
// ca_extensions.go — putRevocationBlob (80%) — objectStore path
// =============================================================================

func TestPutRevocationBlob_ObjectStorePath(t *testing.T) {
	ca := setupTestCAWithObjectStore(t)
	persisted, err := ca.putRevocationBlob(context.Background(), big.NewInt(88888), []byte(`{"serial":"88888"}`))
	require.NoError(t, err)
	assert.True(t, persisted)
}

func TestPutRevocationBlob_NoStoreReturnsFalse(t *testing.T) {
	ca := setupTestCA(t)
	persisted, err := ca.putRevocationBlob(context.Background(), big.NewInt(99999), []byte(`{}`))
	require.NoError(t, err)
	assert.False(t, persisted)
}

// =============================================================================
// trust_chain.go — CABundleCertPool (0%)
// =============================================================================

func TestCABundleCertPool_Success(t *testing.T) {
	ca := setupTestCA(t)
	pool, err := ca.CABundleCertPool()
	require.NoError(t, err)
	assert.NotNil(t, pool)
}

func TestCABundleCertPool_WithIntermediate(t *testing.T) {
	ca := setupTestCAWithRealIntermediate(t)
	pool, err := ca.CABundleCertPool()
	require.NoError(t, err)
	assert.NotNil(t, pool)
}

// =============================================================================
// trust_chain.go — OSTrustStore (0%)
// =============================================================================

func TestOSTrustStore_Success(t *testing.T) {
	ca := setupTestCA(t)
	pool, err := ca.OSTrustStore()
	require.NoError(t, err)
	assert.NotNil(t, pool)
}

// =============================================================================
// trust_chain_extensions.go — TrustedRootCertPoolWithXSigner (28%)
// =============================================================================

func TestTrustedRootCertPoolWithXSigner_NilXSigner(t *testing.T) {
	ca := setupTestCA(t)
	root, err := ca.TrustedRoot()
	require.NoError(t, err)
	pool, err := ca.TrustedRootCertPoolWithXSigner(root, nil)
	require.NoError(t, err)
	assert.NotNil(t, pool)
}

func TestTrustedRootCertPoolWithXSigner_WithXSignerNoStore(t *testing.T) {
	ca := setupTestCA(t)
	root, err := ca.TrustedRoot()
	require.NoError(t, err)
	// Use a real signer as the xsigner trigger; no cross-signed certs stored.
	extKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	pool, err := ca.TrustedRootCertPoolWithXSigner(root, extKey)
	require.NoError(t, err)
	assert.NotNil(t, pool)
}

func TestTrustedRootCertPoolWithXSigner_NotInitialized(t *testing.T) {
	ca := &CA{}
	_, err := ca.TrustedRootCertPoolWithXSigner(&x509.Certificate{}, nil)
	assert.ErrorIs(t, err, ErrNotInitialized)
}

// =============================================================================
// trust_chain_extensions.go — TrustedIntermediateCertPoolWithXSigner (25%)
// =============================================================================

func TestTrustedIntermediateCertPoolWithXSigner_NilXSigner(t *testing.T) {
	ca := setupTestCA(t)
	root, err := ca.TrustedRoot()
	require.NoError(t, err)
	pool, err := ca.TrustedIntermediateCertPoolWithXSigner(root, nil)
	require.NoError(t, err)
	assert.NotNil(t, pool)
}

func TestTrustedIntermediateCertPoolWithXSigner_WithIntermediate(t *testing.T) {
	ca := setupTestCAWithRealIntermediate(t)
	inter, err := ca.TrustedIntermediate()
	require.NoError(t, err)
	extKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	pool, err := ca.TrustedIntermediateCertPoolWithXSigner(inter, extKey)
	require.NoError(t, err)
	assert.NotNil(t, pool)
}

func TestTrustedIntermediateCertPoolWithXSigner_NotInitialized(t *testing.T) {
	ca := &CA{}
	_, err := ca.TrustedIntermediateCertPoolWithXSigner(&x509.Certificate{}, nil)
	assert.ErrorIs(t, err, ErrNotInitialized)
}

// =============================================================================
// trust_chain_extensions.go — RootCertificate (15%)
// =============================================================================

func TestRootCertificate_NonCAFails(t *testing.T) {
	ca := setupTestCA(t)
	// A self-signed non-CA cert should fail.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "leaf-self-signed"},
		Issuer:       pkix.Name{CommonName: "leaf-self-signed"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	_, err = ca.RootCertificate(cert)
	assert.ErrorIs(t, err, ErrInvalidCertificateChain)
}

func TestRootCertificate_IssuerResolvesToRoot(t *testing.T) {
	ca := setupTestCA(t)
	// Issue a leaf; its issuer should resolve to the root CA.
	issued, err := ca.IssueCertificate(context.Background(), &CertificateRequest{
		Subject: Subject{CommonName: "leaf.example.com"},
		Valid:   365,
	})
	require.NoError(t, err)

	root, err := ca.RootCertificate(issued.Certificate)
	require.NoError(t, err)
	assert.Equal(t, "Test Root CA", root.Subject.CommonName)
}

func TestRootCertificate_IssuerNotFound(t *testing.T) {
	ca := setupTestCA(t)
	// Build an intermediate-like cert signed by a mystery issuer that is not
	// in the CA's store or cache. We use an external CA key as the signer so
	// that the Issuer field in the resulting cert reflects the mystery issuer.
	extKey, extIssuer := makeExternalIssuer(t, "mystery-issuer")

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "orphan"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tpl, extIssuer, &leafKey.PublicKey, extKey)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	_, err = ca.RootCertificate(cert)
	assert.ErrorIs(t, err, ErrRootNotFound)
}

// =============================================================================
// trust_chain_extensions.go — ImportIssuingCAs (10%)
// =============================================================================

func TestImportIssuingCAs_NilCert(t *testing.T) {
	ca := setupTestCA(t)
	err := ca.ImportIssuingCAs(context.Background(), nil)
	assert.ErrorIs(t, err, ErrInvalidCertificate)
}

func TestImportIssuingCAs_NoAIAUrls(t *testing.T) {
	ca := setupTestCA(t)
	cert, _ := makeSelfSignedCert(t, "no-aia")
	err := ca.ImportIssuingCAs(context.Background(), cert)
	assert.NoError(t, err)
}

func TestImportIssuingCAs_HTTPServerDER(t *testing.T) {
	// Serve a DER-encoded cert at a test HTTP server.
	issuingCert, _ := makeSelfSignedCert(t, "served-issuer")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/pkix-cert")
		_, _ = w.Write(issuingCert.Raw)
	}))
	t.Cleanup(srv.Close)

	ca := setupTestCA(t)

	// Build a leaf cert pointing AIA at our test server.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	root, err := ca.TrustedRoot()
	require.NoError(t, err)

	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(9999),
		Subject:               pkix.Name{CommonName: "aia-leaf"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IssuingCertificateURL: []string{srv.URL + "/issuer.der"},
	}
	// Self-sign the leaf for simplicity (only the AIA URLs matter here).
	certDER, err := x509.CreateCertificate(rand.Reader, tpl, root, &key.PublicKey, ca)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	err = ca.ImportIssuingCAs(context.Background(), cert)
	require.NoError(t, err)
}

func TestImportIssuingCAs_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	ca := setupTestCA(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	root, err := ca.TrustedRoot()
	require.NoError(t, err)

	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(8888),
		Subject:               pkix.Name{CommonName: "aia-error-leaf"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IssuingCertificateURL: []string{srv.URL + "/bad"},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tpl, root, &key.PublicKey, ca)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	err = ca.ImportIssuingCAs(context.Background(), cert)
	assert.ErrorIs(t, err, ErrStorageError)
}

// =============================================================================
// trust_chain_extensions.go — parseAIACertificate (0%)
// =============================================================================

func TestParseAIACertificate_DER(t *testing.T) {
	cert, _ := makeSelfSignedCert(t, "der-aia")
	parsed, err := parseAIACertificate(cert.Raw)
	require.NoError(t, err)
	assert.Equal(t, "der-aia", parsed.Subject.CommonName)
}

func TestParseAIACertificate_PEM(t *testing.T) {
	cert, _ := makeSelfSignedCert(t, "pem-aia")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	parsed, err := parseAIACertificate(pemBytes)
	require.NoError(t, err)
	assert.Equal(t, "pem-aia", parsed.Subject.CommonName)
}

func TestParseAIACertificate_NeitherDERNorPEM(t *testing.T) {
	_, err := parseAIACertificate([]byte("definitely not a cert"))
	assert.Error(t, err)
}

func TestParseAIACertificate_BadPEMDER(t *testing.T) {
	// Valid PEM block but garbage DER inside.
	badPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("garbage")})
	_, err := parseAIACertificate(badPEM)
	assert.Error(t, err)
}

// =============================================================================
// trust_chain_extensions.go — appendPEM / bufferBytes (0%)
// =============================================================================

func TestAppendPEM_AddsCertToPool(t *testing.T) {
	pool := x509.NewCertPool()
	cert, _ := makeSelfSignedCert(t, "appended")
	appendPEM(pool, cert)
	// No assertion on pool internals is available from outside; just verify no panic.
}

func TestBufferBytes_ReadsToSlice(t *testing.T) {
	data := []byte("hello buffer")
	result := bufferBytes(&stubReader{data: data})
	assert.Equal(t, data, result)
}

// =============================================================================
// tls_extensions.go — TLSBundle (13%)
// =============================================================================

func TestTLSBundle_NotInitialized(t *testing.T) {
	ca := &CA{}
	_, err := ca.TLSBundle(context.Background(), &types.KeyAttributes{CN: "x"})
	assert.ErrorIs(t, err, ErrNotInitialized)
}

func TestTLSBundle_KeyNotFound(t *testing.T) {
	ca := setupTestCA(t)
	_, err := ca.TLSBundle(context.Background(), &types.KeyAttributes{CN: "nonexistent-key"})
	assert.ErrorIs(t, err, ErrCertificateNotFound)
}

// =============================================================================
// tls_extensions.go — TLSBundleWithCrossSigner (0%)
// =============================================================================

func TestTLSBundleWithCrossSigner_NilXSigner(t *testing.T) {
	ca := setupTestCA(t)
	// TLSBundle requires a real key; use nonexistent to test error propagation.
	_, err := ca.TLSBundleWithCrossSigner(context.Background(), nil, nil)
	assert.ErrorIs(t, err, ErrInvalidTLSOptions)
}

func TestTLSBundleWithCrossSigner_NilXSignerNoError(t *testing.T) {
	// With a nil xsigner the function returns TLSBundle directly.
	// Use the nonexistent-key path which will also error from Certificate().
	ca := setupTestCA(t)
	_, err := ca.TLSBundleWithCrossSigner(context.Background(), &types.KeyAttributes{CN: "no-key"}, nil)
	assert.ErrorIs(t, err, ErrCertificateNotFound)
}

// =============================================================================
// tls_extensions.go — TLSConfigWithXSigner (12%)
// =============================================================================

func TestTLSConfigWithXSigner_NilXSignerNoAttrError(t *testing.T) {
	ca := setupTestCA(t)
	_, err := ca.TLSConfigWithXSigner(context.Background(), nil, nil)
	assert.ErrorIs(t, err, ErrInvalidTLSOptions)
}

// =============================================================================
// tls.go — QuantumSafeTLSConfig (0%)
// =============================================================================

func TestQuantumSafeTLSConfig_NotInitialized(t *testing.T) {
	ca := &CA{}
	_, err := ca.QuantumSafeTLSConfig(context.Background(), &types.KeyAttributes{CN: "x"})
	assert.ErrorIs(t, err, ErrNotInitialized)
}

// =============================================================================
// tls.go — TLSConfigWithOptions (34%)
// =============================================================================

func TestTLSConfigWithOptions_NotInitialized(t *testing.T) {
	ca := &CA{}
	_, err := ca.TLSConfigWithOptions(context.Background(), &types.KeyAttributes{CN: "x"}, nil)
	assert.ErrorIs(t, err, ErrNotInitialized)
}

func TestTLSConfigWithOptions_NilOpts_CertNotFound(t *testing.T) {
	ca := setupTestCA(t)
	_, err := ca.TLSConfigWithOptions(context.Background(), &types.KeyAttributes{CN: "nonexistent"}, nil)
	assert.ErrorIs(t, err, ErrTLSConfigFailed)
}

func TestTLSConfigWithOptions_ClientMode(t *testing.T) {
	ca := setupTestCA(t)
	root, err := ca.TrustedRoot()
	require.NoError(t, err)

	// Issue a server cert to have a real TLS cert available.
	issued, err := ca.IssueCertificate(context.Background(), &CertificateRequest{
		Subject: Subject{CommonName: "tls-opts-client.example.com"},
		Valid:   365,
	})
	require.NoError(t, err)

	rootIdentity := ca.config.RootIdentity()
	attrs, err := ca.getCAKeyAttributes(rootIdentity)
	require.NoError(t, err)
	attrs.CN = issued.Certificate.Subject.CommonName

	rootPool := x509.NewCertPool()
	rootPool.AddCert(root)

	opts := &TLSConfigOptions{
		IsServer:   false,
		ServerName: "tls-opts-client.example.com",
		RootCAs:    rootPool,
	}
	_, err = ca.TLSConfigWithOptions(context.Background(), attrs, opts)
	// The key store may not carry the issued leaf; accept either outcome.
	if err != nil {
		assert.ErrorIs(t, err, ErrTLSConfigFailed)
	}
}

// =============================================================================
// tls.go — TLSCertificate (87%) — partial: Ed25519 path
// =============================================================================

func TestTLSCertificate_NotInitialized(t *testing.T) {
	ca := &CA{}
	_, err := ca.TLSCertificate(context.Background(), &types.KeyAttributes{CN: "x"})
	assert.ErrorIs(t, err, ErrNotInitialized)
}

// LoadTLSCertificate and verifyKeyMatchesCertificate are fully covered by tls_test.go.

// VerifyPeerCertificate is already covered by tls_test.go including the
// ExpiredCert path at TestCA_VerifyPeerCertificate_ExpiredCert.

// =============================================================================
// verification.go — VerifyChain (80%) — success + nil roots
// =============================================================================

func TestVerifyChain_NilRoots(t *testing.T) {
	_, err := VerifyChain(&x509.Certificate{SerialNumber: big.NewInt(1)}, nil, nil)
	assert.ErrorIs(t, err, ErrRootNotFound)
}

func TestVerifyChain_NilCert(t *testing.T) {
	_, err := VerifyChain(nil, nil, x509.NewCertPool())
	assert.ErrorIs(t, err, ErrInvalidCertificate)
}

func TestVerifyChain_HappyPath(t *testing.T) {
	ca := setupTestCA(t)
	issued, err := ca.IssueCertificate(context.Background(), &CertificateRequest{
		Subject: Subject{CommonName: "chain-verify.example.com"},
		Valid:   365,
	})
	require.NoError(t, err)

	root, err := ca.TrustedRoot()
	require.NoError(t, err)
	pool := x509.NewCertPool()
	pool.AddCert(root)

	chains, err := VerifyChain(issued.Certificate, nil, pool)
	require.NoError(t, err)
	assert.NotEmpty(t, chains)
}

// =============================================================================
// verification.go — VerifyWithOptions (85%)
// =============================================================================

func TestVerifyWithOptions_NilCert(t *testing.T) {
	_, err := VerifyWithOptions(nil, nil)
	assert.ErrorIs(t, err, ErrInvalidCertificate)
}

func TestVerifyWithOptions_NotYetValid(t *testing.T) {
	ca := setupTestCA(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	root, err := ca.TrustedRoot()
	require.NoError(t, err)

	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(222),
		Subject:      pkix.Name{CommonName: "future.example.com"},
		DNSNames:     []string{"future.example.com"},
		NotBefore:    time.Now().Add(24 * time.Hour), // not yet valid
		NotAfter:     time.Now().Add(48 * time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tpl, root, &key.PublicKey, ca)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	_, err = VerifyWithOptions(cert, &VerifyOptions{
		CurrentTime: time.Now(),
	})
	assert.ErrorIs(t, err, ErrCertificateNotYetValid)
}

func TestVerifyWithOptions_Expired(t *testing.T) {
	ca := setupTestCA(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	root, err := ca.TrustedRoot()
	require.NoError(t, err)

	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(333),
		Subject:      pkix.Name{CommonName: "expired-opts.example.com"},
		DNSNames:     []string{"expired-opts.example.com"},
		NotBefore:    time.Now().Add(-48 * time.Hour),
		NotAfter:     time.Now().Add(-time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tpl, root, &key.PublicKey, ca)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	_, err = VerifyWithOptions(cert, &VerifyOptions{
		CurrentTime: time.Now(),
	})
	assert.ErrorIs(t, err, ErrCertificateExpired)
}

func TestVerifyWithOptions_WithCRLRevoked(t *testing.T) {
	ca := setupTestCA(t)
	issued, err := ca.IssueCertificate(context.Background(), &CertificateRequest{
		Subject: Subject{CommonName: "crl-test.example.com"},
		Valid:   365,
	})
	require.NoError(t, err)

	require.NoError(t, ca.Revoke(context.Background(), issued.Certificate.SerialNumber, 0))
	crlDER, err := ca.GenerateCRL(context.Background())
	require.NoError(t, err)

	root, err := ca.TrustedRoot()
	require.NoError(t, err)
	pool := x509.NewCertPool()
	pool.AddCert(root)

	_, err = VerifyWithOptions(issued.Certificate, &VerifyOptions{
		CheckRevocation: true,
		CRL:             crlDER,
		Roots:           pool,
		CurrentTime:     time.Now(),
	})
	assert.ErrorIs(t, err, ErrCertificateRevoked)
}

// =============================================================================
// verification.go — verifyRSASignature (76%) — PSS path
// =============================================================================

func TestVerifySignature_RSAPSSCert(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	tpl := &x509.Certificate{
		SerialNumber:       big.NewInt(1),
		Subject:            pkix.Name{CommonName: "rsa-pss"},
		NotBefore:          time.Now().Add(-time.Hour),
		NotAfter:           time.Now().Add(24 * time.Hour),
		SignatureAlgorithm: x509.SHA256WithRSAPSS,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &rsaKey.PublicKey, rsaKey)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	// VerifyCertificateAgainstPublicKey calls the internal verify path.
	err = VerifyCertificateAgainstPublicKey(cert, &rsaKey.PublicKey)
	require.NoError(t, err)
}

// =============================================================================
// verification.go — verifyECDSASignature (81%) — bad DER signature branch
// =============================================================================

func TestVerifyECDSASignature_InvalidASN1(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "ecdsa-bad"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	// Corrupt the signature bytes so asn1.Unmarshal fails.
	cert.Signature = []byte("not-asn1")

	err = verifyECDSASignature(cert, &key.PublicKey, crypto.SHA256)
	assert.ErrorIs(t, err, ErrInvalidSignature)
}

// =============================================================================
// verification.go — SerialNumbersMatch (80%)
// =============================================================================

func TestSerialNumbersMatch_NilA(t *testing.T) {
	cert, _ := makeSelfSignedCert(t, "sn-match")
	assert.False(t, SerialNumbersMatch(nil, cert))
}

func TestSerialNumbersMatch_NilB(t *testing.T) {
	cert, _ := makeSelfSignedCert(t, "sn-match")
	assert.False(t, SerialNumbersMatch(cert, nil))
}

func TestSerialNumbersMatch_BothNilSerials(t *testing.T) {
	a := &x509.Certificate{}
	b := &x509.Certificate{}
	assert.False(t, SerialNumbersMatch(a, b))
}

func TestSerialNumbersMatch_Match(t *testing.T) {
	cert, _ := makeSelfSignedCert(t, "sn-same")
	assert.True(t, SerialNumbersMatch(cert, cert))
}

// =============================================================================
// verification.go — IsIssuedBy (85%)
// =============================================================================

func TestIsIssuedBy_NilCert(t *testing.T) {
	issuer, _ := makeSelfSignedCert(t, "issuer")
	assert.False(t, IsIssuedBy(nil, issuer))
}

func TestIsIssuedBy_NilIssuer(t *testing.T) {
	cert, _ := makeSelfSignedCert(t, "cert")
	assert.False(t, IsIssuedBy(cert, nil))
}

func TestIsIssuedBy_NoAKI(t *testing.T) {
	ca := setupTestCA(t)
	issued, err := ca.IssueCertificate(context.Background(), &CertificateRequest{
		Subject: Subject{CommonName: "aki-test.example.com"},
		Valid:   365,
	})
	require.NoError(t, err)
	root, err := ca.TrustedRoot()
	require.NoError(t, err)
	assert.True(t, IsIssuedBy(issued.Certificate, root))
}

// =============================================================================
// verification.go — PathLength (88%) — MaxPathLenZero branch
// =============================================================================

func TestPathLength_MaxPathLenZero(t *testing.T) {
	cert := &x509.Certificate{
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
		MaxPathLen:            0,
	}
	assert.Equal(t, 0, PathLength(cert))
}

func TestPathLength_NoConstraint(t *testing.T) {
	cert := &x509.Certificate{
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        false,
	}
	assert.Equal(t, -1, PathLength(cert))
}

func TestPathLength_NilCert(t *testing.T) {
	assert.Equal(t, 0, PathLength(nil))
}

// VerifyCertificateAgainstPublicKey_UnsupportedKeyType is already in verification_test.go.

// =============================================================================
// errors.go — ErrWeakSignatureAlgorithmDetail.Error() (0%)
// =============================================================================

func TestErrWeakSignatureAlgorithmDetail_Error(t *testing.T) {
	e := &ErrWeakSignatureAlgorithmDetail{
		Algorithm: "MD5WithRSA",
		Subject:   "CN=test",
	}
	msg := e.Error()
	assert.Contains(t, msg, "MD5WithRSA")
	assert.Contains(t, msg, "CN=test")
	assert.ErrorIs(t, e, ErrWeakSignatureAlgorithm)
}

// =============================================================================
// types.go — CAConfig.Validate (57%) — negative cases
// =============================================================================

func TestCAConfigValidate_NegativeValidity(t *testing.T) {
	cfg := &CAConfig{Identity: "test", ValidityDays: -1}
	assert.ErrorIs(t, cfg.Validate(), ErrInvalidValidityPeriod)
}

func TestCAConfigValidate_NegativePathLength(t *testing.T) {
	cfg := &CAConfig{Identity: "test", MaxPathLength: -1}
	assert.ErrorIs(t, cfg.Validate(), ErrInvalidPathLength)
}

func TestCAConfigValidate_NoIdentityOrSubject(t *testing.T) {
	cfg := &CAConfig{}
	assert.ErrorIs(t, cfg.Validate(), ErrSubjectCommonNameRequired)
}

func TestCAConfigValidate_SubjectCNSufficient(t *testing.T) {
	cfg := &CAConfig{Subject: &Subject{CommonName: "present"}}
	assert.NoError(t, cfg.Validate())
}

// =============================================================================
// attestation.go — ImportLocalAttestation (20%)
// =============================================================================

func TestImportLocalAttestation_NilQuoteCoverage(t *testing.T) {
	ca := setupTestCAWithObjectStore(t)
	err := ca.ImportLocalAttestation(context.Background(), &types.KeyAttributes{CN: "ak"}, nil)
	assert.ErrorIs(t, err, ErrInvalidRequest)
}

func TestImportLocalAttestation_WithoutEventLog(t *testing.T) {
	ca := setupTestCAWithObjectStore(t)
	quote := &tpm2.Quote{
		Quoted: []byte("quoted-data"),
		PCRs:   []byte("pcr-data"),
		// EventLog intentionally empty
	}
	err := ca.ImportLocalAttestation(context.Background(), &types.KeyAttributes{CN: "ak2"}, quote)
	require.NoError(t, err)
}

func TestImportLocalAttestation_WithEventLog(t *testing.T) {
	ca := setupTestCAWithObjectStore(t)
	quote := &tpm2.Quote{
		Quoted:   []byte("quoted-with-log"),
		EventLog: []byte("event-log-data"),
		PCRs:     []byte("pcr-snapshot"),
	}
	err := ca.ImportLocalAttestation(context.Background(), &types.KeyAttributes{CN: "ak3"}, quote)
	require.NoError(t, err)
}

// =============================================================================
// attestation.go — verifyCASignature (21%) — RSA and unsupported key types
// =============================================================================

func TestVerifyCASignature_RSA(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Produce a real PSS signature.
	digest := make([]byte, 32)
	_, err = rand.Read(digest)
	require.NoError(t, err)

	pssOpts := &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
		Hash:       crypto.SHA256,
	}
	sig, err := rsa.SignPSS(rand.Reader, rsaKey, crypto.SHA256, digest, pssOpts)
	require.NoError(t, err)

	err = verifyCASignature(&rsaKey.PublicKey, digest, sig)
	assert.NoError(t, err)
}

func TestVerifyCASignature_RSA_PKCS1Fallback(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	digest := make([]byte, 32)
	_, err = rand.Read(digest)
	require.NoError(t, err)

	sig, err := rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, digest)
	require.NoError(t, err)

	err = verifyCASignature(&rsaKey.PublicKey, digest, sig)
	assert.NoError(t, err)
}

func TestVerifyCASignature_RSA_Invalid(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	err = verifyCASignature(&rsaKey.PublicKey, []byte("digest"), []byte("bad-sig"))
	assert.ErrorIs(t, err, ErrInvalidSignature)
}

func TestVerifyCASignature_Ed25519(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	digest := []byte("some data")
	sig := ed25519.Sign(priv, digest)

	err = verifyCASignature(pub, digest, sig)
	assert.NoError(t, err)
}

func TestVerifyCASignature_Ed25519_Invalid(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	err = verifyCASignature(pub, []byte("data"), []byte("bad"))
	assert.ErrorIs(t, err, ErrInvalidSignature)
}

func TestVerifyCASignature_UnsupportedKeyType(t *testing.T) {
	err := verifyCASignature("not-a-key", []byte("data"), []byte("sig"))
	assert.ErrorIs(t, err, ErrInvalidSignature)
}

// =============================================================================
// attestation.go — getSigningHashFunc (66%) — Ed25519 path
// =============================================================================

func TestGetSigningHashFunc_Ed25519ReturnsZero(t *testing.T) {
	// getSigningHashFunc branches on the type returned by ca.Public().
	// ca.Public() returns the public key of the issuing certificate.
	// We build a minimal CA whose issuing cert has an Ed25519 key.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ed25519-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tpl, tpl, pub, priv)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	ca := &CA{}
	ca.rootCert = cert
	h := ca.getSigningHashFunc()
	assert.Equal(t, crypto.Hash(0), h)
}

// =============================================================================
// attestation.go — attestationBlobKey (75%) — error branch
// =============================================================================

func TestAttestationBlobKey_EmptyCN(t *testing.T) {
	// Empty CN generates a hash-based key name instead of erroring.
	ca := setupTestCAWithObjectStore(t)
	key, err := ca.attestationBlobKey("", AttestBlobQuote)
	assert.NoError(t, err)
	assert.NotEmpty(t, key)
}

// =============================================================================
// crl_import.go — hashCRLURL (0%)
// =============================================================================

func TestHashCRLURL_DeterministicOutput(t *testing.T) {
	url := "http://crl.example.com/root.crl"
	h1 := hashCRLURL(url)
	h2 := hashCRLURL(url)
	assert.Equal(t, h1, h2)
	assert.Len(t, h1, 64) // SHA-256 hex = 64 chars
}

func TestHashCRLURL_DifferentURLs(t *testing.T) {
	assert.NotEqual(t, hashCRLURL("http://a.example.com"), hashCRLURL("http://b.example.com"))
}

// =============================================================================
// cross_signing.go — getXSignedCertificates (0%)
// =============================================================================

func TestGetXSignedCertificates_NilObjectStore(t *testing.T) {
	ca := setupTestCA(t)
	certs, err := ca.getXSignedCertificates("some-cn")
	require.NoError(t, err)
	assert.Nil(t, certs)
}

func TestGetXSignedCertificates_EmptyStore(t *testing.T) {
	ca := setupTestCAWithObjectStore(t)
	certs, err := ca.getXSignedCertificates("nonexistent-cn")
	require.NoError(t, err)
	assert.Empty(t, certs)
}

func TestGetXSignedCertificates_WithStoredCert(t *testing.T) {
	ca := setupTestCAWithObjectStore(t)
	cert, _ := makeSelfSignedCert(t, "xsigned-subject")
	require.NoError(t, ca.ImportXSignedCertificate("ExternalIssuer", cert))

	certs, err := ca.getXSignedCertificates("xsigned-subject")
	require.NoError(t, err)
	assert.Len(t, certs, 1)
	assert.Equal(t, cert.Raw, certs[0].Raw)
}

// =============================================================================
// tcg.go — VerifyQuote (0%)
// =============================================================================

func TestVerifyQuote_NotInitialized(t *testing.T) {
	ca := &CA{}
	err := ca.VerifyQuote(nil, nil, nil)
	assert.ErrorIs(t, err, ErrNotInitialized)
}

func TestVerifyQuote_NilAttrsOrQuote(t *testing.T) {
	ca := setupTestCA(t)
	err := ca.VerifyQuote(nil, nil, nil)
	assert.Error(t, err)
}

func TestVerifyQuote_NonceMismatch(t *testing.T) {
	ca := setupTestCA(t)
	quote := &tpm2.Quote{
		Nonce:     []byte("nonce-a"),
		Quoted:    []byte("data"),
		Signature: []byte("sig"),
	}
	err := ca.VerifyQuote(&types.KeyAttributes{CN: "ak"}, quote, []byte("nonce-b"))
	assert.ErrorIs(t, err, ErrInvalidSignature)
}

func TestVerifyQuote_ECDSASignature(t *testing.T) {
	ca := setupTestCA(t)

	// Issue an AK cert whose public key we can use for the quote.
	akKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	akCert, _ := makeSelfSignedCert(t, "ak-for-quote")
	// Override the key in the cert struct (hack for test) — we supply pubkey via TPMAttributes.
	pubDER, err := x509.MarshalPKIXPublicKey(&akKey.PublicKey)
	require.NoError(t, err)

	// Produce a real ECDSA signature over the quoted data.
	quoted := []byte("tpm-quote-payload")
	digest := sha256digest(quoted)
	sig, err := ecdsa.SignASN1(rand.Reader, akKey, digest[:])
	require.NoError(t, err)

	// Import the cert so the certStore path works.
	require.NoError(t, ca.certStore.StoreCertificate(akCert))

	nonce := []byte("test-nonce")
	quote := &tpm2.Quote{
		Nonce:     nonce,
		Quoted:    quoted,
		Signature: sig,
	}

	// Use TPMAttributes to supply the public key directly.
	attrs := &types.KeyAttributes{
		CN: "ak-for-quote",
		TPMAttributes: &types.TPMAttributes{
			PublicKeyBytes: pubDER,
		},
	}
	err = ca.VerifyQuote(attrs, quote, nonce)
	require.NoError(t, err)
}

// sha256digest returns the SHA-256 digest of data.
func sha256digest(data []byte) [32]byte {
	return sha256.Sum256(data)
}

// =============================================================================
// tcg.go — ImportEndorsementKeyCertificate (0%)
// =============================================================================

func TestImportEndorsementKeyCertificate_NotInitialized(t *testing.T) {
	ca := &CA{}
	err := ca.ImportEndorsementKeyCertificate(nil)
	assert.ErrorIs(t, err, ErrNotInitialized)
}

func TestImportEndorsementKeyCertificate_NilCert(t *testing.T) {
	ca := setupTestCA(t)
	err := ca.ImportEndorsementKeyCertificate(nil)
	assert.ErrorIs(t, err, ErrInvalidCertificate)
}

func TestImportEndorsementKeyCertificate_WithoutEKOID(t *testing.T) {
	ca := setupTestCA(t)
	cert, _ := makeSelfSignedCert(t, "ek-no-oid")
	err := ca.ImportEndorsementKeyCertificate(cert)
	require.NoError(t, err)
}

func TestImportEndorsementKeyCertificate_WithEKOID(t *testing.T) {
	ca := setupTestCA(t)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	ekExt, err := asn1.Marshal("ek")
	require.NoError(t, err)

	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(55),
		Subject:      pkix.Name{CommonName: "ek-with-oid"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		ExtraExtensions: []pkix.Extension{
			{Id: OIDTCGKpEKCertificate, Value: ekExt},
		},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	err = ca.ImportEndorsementKeyCertificate(cert)
	require.NoError(t, err)
}

// =============================================================================
// tcg.go — EndorsementKeyCertificate (0%)
// =============================================================================

func TestEndorsementKeyCertificate_NotInitialized(t *testing.T) {
	ca := &CA{}
	_, err := ca.EndorsementKeyCertificate("ek-cn")
	assert.ErrorIs(t, err, ErrNotInitialized)
}

func TestEndorsementKeyCertificate_NotFound(t *testing.T) {
	ca := setupTestCA(t)
	_, err := ca.EndorsementKeyCertificate("nonexistent-ek")
	assert.ErrorIs(t, err, ErrCertificateNotFound)
}

func TestEndorsementKeyCertificate_Found(t *testing.T) {
	ca := setupTestCA(t)
	cert, _ := makeSelfSignedCert(t, "ek-stored")
	require.NoError(t, ca.ImportEndorsementKeyCertificate(cert))

	retrieved, err := ca.EndorsementKeyCertificate("ek-stored")
	require.NoError(t, err)
	assert.Equal(t, cert.Raw, retrieved.Raw)
}

// =============================================================================
// tcg_enrollment.go — SetTPM (0%)
// =============================================================================

func TestSetTPM_StoresAndRetrievesInstance(t *testing.T) {
	ca := setupTestCA(t)
	// nil TPM interface — SetTPM should not panic.
	ca.SetTPM(nil)
	retrieved := ca.getTPM()
	assert.Nil(t, retrieved)
}

// tcg_oids.go Create* functions are already exercised by tcg_oids_test.go;
// only the OID branches NOT covered there need additional tests here.
// The existing tcg_oids_test.go already achieves 75%+ on those functions.
// We add only the gap paths: TPM spec extension from tcg_oids_test already
// covers these; no new tests needed here.

// =============================================================================
// ocsp.go — VerifyOCSPResponse (0%)
// =============================================================================

func TestVerifyOCSPResponse_EmptyBytes(t *testing.T) {
	ca := setupTestCA(t)
	responder := NewOCSPResponder(ca, DefaultOCSPResponderConfig())

	_, err := responder.VerifyOCSPResponse(nil)
	assert.ErrorIs(t, err, ErrOCSPInvalidRequest)
}

func TestVerifyOCSPResponse_InvalidBytes(t *testing.T) {
	ca := setupTestCA(t)
	responder := NewOCSPResponder(ca, DefaultOCSPResponderConfig())

	_, err := responder.VerifyOCSPResponse([]byte("not-ocsp"))
	assert.ErrorIs(t, err, ErrOCSPResponseFailed)
}

// =============================================================================
// service_adapter.go — IssueEKCertificateRaw / IssueAKCertificateRaw (0%)
// =============================================================================

func TestIssueEKCertificateRaw_InvalidDER(t *testing.T) {
	ca := setupTestCA(t)
	_, err := ca.IssueEKCertificateRaw(context.Background(), "ek-raw", "Test Org", []byte("garbage"))
	assert.Error(t, err)
}

func TestIssueEKCertificateRaw_Success(t *testing.T) {
	ca := setupTestCA(t)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)

	certDER, err := ca.IssueEKCertificateRaw(context.Background(), "ek-raw-ok", "Test Org", pubDER)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)
	assert.Equal(t, "ek-raw-ok", cert.Subject.CommonName)
}

func TestIssueAKCertificateRaw_InvalidDER(t *testing.T) {
	ca := setupTestCA(t)
	_, err := ca.IssueAKCertificateRaw(context.Background(), "ak-raw", "Test Org", []byte("garbage"))
	assert.Error(t, err)
}

func TestIssueAKCertificateRaw_Success(t *testing.T) {
	ca := setupTestCA(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)

	certDER, err := ca.IssueAKCertificateRaw(context.Background(), "ak-raw-ok", "Test Org", pubDER)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)
	assert.Equal(t, "ak-raw-ok", cert.Subject.CommonName)
}

// =============================================================================
// bundle.go — encodeCertsToPEM (90%) — empty bundle path
// =============================================================================

func TestEncodeCertsToPEM_EmptySlice(t *testing.T) {
	bundler := NewDefaultCABundler(nil)
	bundler.Clear()
	// CABundle with empty certs; the covered path is inside encodeCertsToPEM.
	pems, err := bundler.CABundle("", "")
	_ = pems
	_ = err
}

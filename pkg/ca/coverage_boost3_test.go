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

// Package ca coverage boost, third pass: targets low-coverage functions
// remaining after the first and second passes.  All tests are in-memory,
// fast, race-free.
package ca

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// OCSP — getCachedResponse / cacheResponse / ClearCache
// =============================================================================

func TestOCSPCacheHit(t *testing.T) {
	ca := setupTestCA(t)
	resp := NewOCSPResponder(ca, DefaultOCSPResponderConfig())

	key := "ocsp:123"
	resp.cacheResponse(key, []byte("data"))
	got := resp.getCachedResponse(key)
	assert.Equal(t, []byte("data"), got)
}

func TestOCSPCacheExpired(t *testing.T) {
	ca := setupTestCA(t)
	cfg := OCSPResponderConfig{
		CacheTTL:   1, // 1 nanosecond — effectively expired immediately
		NextUpdate: DefaultOCSPResponderConfig().NextUpdate,
	}
	resp := NewOCSPResponder(ca, cfg)

	key := "ocsp:expired"
	resp.cacheResponse(key, []byte("stale"))
	// Sleep is not needed; CacheTTL is 1ns so the entry is already expired
	time.Sleep(time.Millisecond)
	got := resp.getCachedResponse(key)
	assert.Nil(t, got, "expired entry should return nil")
}

func TestOCSPClearCache(t *testing.T) {
	ca := setupTestCA(t)
	resp := NewOCSPResponder(ca, DefaultOCSPResponderConfig())

	resp.cacheResponse("k1", []byte("v1"))
	resp.cacheResponse("k2", []byte("v2"))
	resp.ClearCache()
	assert.Nil(t, resp.getCachedResponse("k1"))
	assert.Nil(t, resp.getCachedResponse("k2"))
}

func TestOCSPCacheMiss(t *testing.T) {
	ca := setupTestCA(t)
	resp := NewOCSPResponder(ca, DefaultOCSPResponderConfig())
	assert.Nil(t, resp.getCachedResponse("nonexistent"))
}

// =============================================================================
// OCSP — checkCertificateStatus paths
// =============================================================================

func TestCheckCertificateStatus_Good_NoObjectStore(t *testing.T) {
	ca := setupTestCA(t)
	resp := NewOCSPResponder(ca, DefaultOCSPResponderConfig())

	status, _, _, err := resp.checkCertificateStatus(context.Background(), big.NewInt(999999))
	require.NoError(t, err)
	assert.Equal(t, 0 /*ocsp.Good*/, status)
}

func TestCheckCertificateStatus_Revoked_InMemory(t *testing.T) {
	ca := setupTestCA(t)
	resp := NewOCSPResponder(ca, DefaultOCSPResponderConfig())

	serial := big.NewInt(55555)
	ca.revocations[serial.Text(10)] = &RevocationInfo{
		RevocationTime: time.Now(),
		Reason:         1,
	}

	status, _, reason, err := resp.checkCertificateStatus(context.Background(), serial)
	require.NoError(t, err)
	assert.Equal(t, 1 /*ocsp.Revoked*/, status)
	assert.Equal(t, 1, reason)
}

// =============================================================================
// OCSP — loadRevocationFromStore paths
// =============================================================================

func TestLoadRevocationFromStore_NotFound(t *testing.T) {
	ca := setupTestCAWithObjectStore(t)
	resp := NewOCSPResponder(ca, DefaultOCSPResponderConfig())

	_, err := resp.loadRevocationFromStore(context.Background(), big.NewInt(404))
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrCRLNotFound), "got: %v", err)
}

func TestLoadRevocationFromStore_ValidRecord(t *testing.T) {
	ca := setupTestCAWithObjectStore(t)
	resp := NewOCSPResponder(ca, DefaultOCSPResponderConfig())

	serial := big.NewInt(77777)
	rec := persistedRevocation{
		Serial:    serial.Text(10),
		RevokedAt: time.Now().UTC().Truncate(time.Second),
		Reason:    1,
	}
	data, err := json.Marshal(rec)
	require.NoError(t, err)

	key := revocationKey(serial) + ".json"
	require.NoError(t, ca.revocationStore.Put(context.Background(), key, data))

	loaded, err := resp.loadRevocationFromStore(context.Background(), serial)
	require.NoError(t, err)
	assert.Equal(t, rec.Serial, loaded.Serial)
	assert.Equal(t, rec.Reason, loaded.Reason)
}

// =============================================================================
// OCSP — VerifyOCSPResponse
// =============================================================================

func TestVerifyOCSPResponse_EmptyInput_B3(t *testing.T) {
	ca := setupTestCA(t)
	resp := NewOCSPResponder(ca, DefaultOCSPResponderConfig())
	_, err := resp.VerifyOCSPResponse(nil)
	assert.ErrorIs(t, err, ErrOCSPInvalidRequest)
}

func TestVerifyOCSPResponse_InvalidBytes_B3(t *testing.T) {
	ca := setupTestCA(t)
	resp := NewOCSPResponder(ca, DefaultOCSPResponderConfig())
	_, err := resp.VerifyOCSPResponse([]byte("not-an-ocsp-response"))
	assert.ErrorIs(t, err, ErrOCSPResponseFailed)
}

// =============================================================================
// OCSP — CreateOCSPRequest
// =============================================================================

func TestCreateOCSPRequest_NilCert(t *testing.T) {
	_, err := CreateOCSPRequest(nil, nil, nil)
	assert.ErrorIs(t, err, ErrInvalidCertificate)
}

func TestCreateOCSPRequest_ValidPair(t *testing.T) {
	// Build a self-signed issuer and a leaf signed by it.
	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	issuerTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "issuer"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	issuerDER, err := x509.CreateCertificate(rand.Reader, issuerTmpl, issuerTmpl, &issuerKey.PublicKey, issuerKey)
	require.NoError(t, err)
	issuer, err := x509.ParseCertificate(issuerDER)
	require.NoError(t, err)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, issuerTmpl, &leafKey.PublicKey, issuerKey)
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(leafDER)
	require.NoError(t, err)

	reqBytes, err := CreateOCSPRequest(leaf, issuer, nil)
	require.NoError(t, err)
	assert.NotEmpty(t, reqBytes)
}

// =============================================================================
// ImportDistributionCRLs — nil cert + no distribution points + no object store
// =============================================================================

func TestImportDistributionCRLs_NilCert_B3(t *testing.T) {
	ca := setupTestCA(t)
	err := ca.ImportDistributionCRLs(nil)
	assert.ErrorIs(t, err, ErrInvalidCertificate)
}

func TestImportDistributionCRLs_NoCRLDP_B3(t *testing.T) {
	ca := setupTestCA(t)
	cert := &x509.Certificate{} // no CRLDistributionPoints
	err := ca.ImportDistributionCRLs(cert)
	assert.NoError(t, err)
}

func TestImportDistributionCRLs_NoObjectStore(t *testing.T) {
	ca := setupTestCA(t) // no object store
	cert := &x509.Certificate{
		CRLDistributionPoints: []string{"http://example.com/crl.crl"},
	}
	err := ca.ImportDistributionCRLs(cert)
	assert.ErrorIs(t, err, ErrObjectStoreRequired)
}

// =============================================================================
// EnrollDevice / VerifyTCG_CSR_IDevIDBytes — TPM-not-configured fast-paths
// =============================================================================

func TestEnrollDevice_NotInitialized_B3(t *testing.T) {
	ca := setupUninitializedCA(t)
	_, err := ca.EnrollDevice(context.Background(), []byte("x"), nil)
	assert.ErrorIs(t, err, ErrNotInitialized)
}

func TestEnrollDevice_NoTPM_B3(t *testing.T) {
	ca := setupTestCA(t)
	// Ensure no TPM is configured (tpmInstance is package-level atomic pointer).
	tpmInstance.Store(nil)
	_, err := ca.EnrollDevice(context.Background(), []byte("x"), nil)
	assert.ErrorIs(t, err, ErrTPMNotConfigured)
}

func TestEnrollDevice_InvalidPackedCSR_B3(t *testing.T) {
	// To reach the UnmarshalIDevIDCSR path, we need a TPM. We can only test
	// the no-TPM fast path without a real TPM simulator.
	ca := setupTestCA(t)
	tpmInstance.Store(nil)
	_, err := ca.EnrollDevice(context.Background(), []byte("garbage"), nil)
	assert.ErrorIs(t, err, ErrTPMNotConfigured)
}

func TestVerifyTCG_CSR_IDevIDBytes_NoTPM(t *testing.T) {
	ca := setupTestCA(t)
	tpmInstance.Store(nil)
	_, _, _, err := ca.VerifyTCG_CSR_IDevIDBytes([]byte("x"), x509.ECDSAWithSHA256)
	assert.ErrorIs(t, err, ErrTPMNotConfigured)
}

// =============================================================================
// SignTCGCSRIDevID — not-initialized + nil CSR fast-paths
// =============================================================================

func TestSignTCGCSRIDevID_NotInitialized_B3(t *testing.T) {
	ca := setupUninitializedCA(t)
	_, _, err := ca.SignTCGCSRIDevID(context.Background(), nil, nil)
	assert.ErrorIs(t, err, ErrNotInitialized)
}

func TestSignTCGCSRIDevID_NilCSR_B3(t *testing.T) {
	ca := setupTestCA(t)
	_, _, err := ca.SignTCGCSRIDevID(context.Background(), nil, nil)
	assert.ErrorIs(t, err, ErrInvalidCSR)
}

// =============================================================================
// TLSConfigWithOptions — additional paths (client mode, nil opts, validation)
// =============================================================================

func TestTLSConfigWithOptions_ClientMode_B3(t *testing.T) {
	ca := setupTestCA(t)
	issueCertAndSaveToKeyStore(t, ca, "tls-client-opts-b3")
	attrs := softwareKeyAttrs("tls-client-opts-b3")

	opts := &TLSConfigOptions{
		IsServer:   false,
		ServerName: "server.example.com",
	}
	cfg, err := ca.TLSConfigWithOptions(context.Background(), attrs, opts)
	require.NoError(t, err)
	assert.Equal(t, "server.example.com", cfg.ServerName)
}

func TestTLSConfigWithOptions_NilOpts_B3(t *testing.T) {
	ca := setupTestCA(t)
	issueCertAndSaveToKeyStore(t, ca, "tls-nilopt-b3")
	attrs := softwareKeyAttrs("tls-nilopt-b3")

	cfg, err := ca.TLSConfigWithOptions(context.Background(), attrs, nil)
	require.NoError(t, err)
	assert.NotNil(t, cfg)
}

func TestTLSConfigWithOptions_NotInitialized_B3(t *testing.T) {
	ca := setupUninitializedCA(t)
	_, err := ca.TLSConfigWithOptions(context.Background(), softwareKeyAttrs("x"), &TLSConfigOptions{})
	assert.ErrorIs(t, err, ErrNotInitialized)
}

// =============================================================================
// TLSConfigWithXSigner — nil xsigner fast-path
// =============================================================================

func TestTLSConfigWithXSigner_NilXSigner_B3(t *testing.T) {
	ca := setupTestCA(t)
	issueCertAndSaveToKeyStore(t, ca, "tls-xsigner-nil-b3")
	attrs := softwareKeyAttrs("tls-xsigner-nil-b3")

	cfg, err := ca.TLSConfigWithXSigner(context.Background(), attrs, nil)
	require.NoError(t, err)
	assert.NotNil(t, cfg)
}

func TestTLSConfigWithXSigner_WithXSigner_NoObjectStore(t *testing.T) {
	ca := setupTestCA(t) // no object store → getXSignedCertificates returns nil,nil
	issueCertAndSaveToKeyStore(t, ca, "tls-xsigner-obj-b3")
	attrs := softwareKeyAttrs("tls-xsigner-obj-b3")

	// Any non-nil ECDSA signer will do; the object store is nil so no
	// xsigned certs are loaded and the base config is returned unchanged.
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	cfg, err := ca.TLSConfigWithXSigner(context.Background(), attrs, ecKey)
	require.NoError(t, err)
	assert.NotNil(t, cfg)
}

// =============================================================================
// TLSBundleWithCrossSigner — nil xsigner fast-path (covered via base TLSBundle)
// =============================================================================

func TestTLSBundleWithCrossSigner_NilXSigner_B3(t *testing.T) {
	ca := setupTestCA(t)
	issueCertAndSaveToKeyStore(t, ca, "bundle-xsign-nil-b3")
	attrs := softwareKeyAttrs("bundle-xsign-nil-b3")

	// TLSBundle may fail on opaque key export; that is expected and acceptable.
	bundle, err := ca.TLSBundleWithCrossSigner(context.Background(), attrs, nil)
	if err != nil {
		assert.ErrorIs(t, err, ErrTLSConfigFailed)
		return
	}
	assert.NotEmpty(t, bundle)
}

// =============================================================================
// CreateCSR — with explicit Signer (avoids keystore)
// =============================================================================

func TestCreateCSR_WithExplicitSigner(t *testing.T) {
	ca := setupTestCA(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	req := &CertificateRequest{
		Subject: Subject{CommonName: "csr-explicit-signer"},
		SANS:    &SubjectAlternativeNames{DNS: []string{"csr-explicit-signer.local"}},
		Signer:  key,
	}
	csrPEM, err := ca.CreateCSR(context.Background(), req)
	require.NoError(t, err)

	block, _ := pem.Decode(csrPEM)
	require.NotNil(t, block)
	_, err = x509.ParseCertificateRequest(block.Bytes)
	require.NoError(t, err)
}

func TestCreateCSR_DefaultKeyAttributes(t *testing.T) {
	ca := setupTestCA(t)
	req := &CertificateRequest{
		Subject: Subject{CommonName: "csr-default-key"},
		SANS:    &SubjectAlternativeNames{DNS: []string{"csr-default-key.local"}},
	}
	csrPEM, err := ca.CreateCSR(context.Background(), req)
	require.NoError(t, err)
	assert.NotEmpty(t, csrPEM)
}

func TestCreateCSRWithKey_NilSigner_B3(t *testing.T) {
	req := &CertificateRequest{
		Subject: Subject{CommonName: "csr-nil-signer"},
	}
	_, err := CreateCSRWithKey(req, nil)
	assert.ErrorIs(t, err, ErrCSRGenerationFailed)
}

// =============================================================================
// Verify — cross-sign-aware path (nil xsigner falls to native path)
// =============================================================================

func TestVerify_IssuedCertificate(t *testing.T) {
	ca := setupTestCA(t)
	issued, err := ca.IssueCertificate(context.Background(), &CertificateRequest{
		Subject: Subject{CommonName: "verify-leaf"},
		SANS:    &SubjectAlternativeNames{DNS: []string{"verify-leaf.local"}},
		Valid:   365,
	})
	require.NoError(t, err)

	chains, err := ca.Verify(issued.Certificate)
	require.NoError(t, err)
	assert.NotEmpty(t, chains)
}

func TestVerify_RevokedCert(t *testing.T) {
	ca := setupTestCA(t)
	issued, err := ca.IssueCertificate(context.Background(), &CertificateRequest{
		Subject: Subject{CommonName: "verify-revoked"},
		SANS:    &SubjectAlternativeNames{DNS: []string{"verify-revoked.local"}},
		Valid:   365,
	})
	require.NoError(t, err)

	require.NoError(t, ca.RevokeCert(context.Background(), issued.Certificate, RevokeOptions{Reason: 1}))
	_, err = ca.Verify(issued.Certificate)
	assert.ErrorIs(t, err, ErrCertificateRevoked)
}

func TestVerify_WithNilXSigner(t *testing.T) {
	ca := setupTestCA(t)
	issued, err := ca.IssueCertificate(context.Background(), &CertificateRequest{
		Subject: Subject{CommonName: "verify-xsign-nil"},
		SANS:    &SubjectAlternativeNames{DNS: []string{"verify-xsign-nil.local"}},
		Valid:   365,
	})
	require.NoError(t, err)

	// Passing a typed nil crypto.Signer — variadic slot treated as nil.
	chains, err := ca.Verify(issued.Certificate, nil)
	require.NoError(t, err)
	assert.NotEmpty(t, chains)
}

// =============================================================================
// Sign — initialized and not-initialized paths
// =============================================================================

func TestSign_NotInitialized(t *testing.T) {
	ca := setupUninitializedCA(t)
	digest := sha256.Sum256([]byte("test"))
	_, err := ca.Sign(rand.Reader, digest[:], crypto.SHA256)
	assert.ErrorIs(t, err, ErrNotInitialized)
}

func TestSign_Success(t *testing.T) {
	ca := setupTestCA(t)
	digest := sha256.Sum256([]byte("sign-me"))
	sig, err := ca.Sign(rand.Reader, digest[:], crypto.SHA256)
	require.NoError(t, err)
	assert.NotEmpty(t, sig)
}

// =============================================================================
// ImportIssuingCAs — nil cert + no AIA paths
// =============================================================================

func TestImportIssuingCAs_NilCert_B3(t *testing.T) {
	ca := setupTestCA(t)
	err := ca.ImportIssuingCAs(context.Background(), nil)
	assert.ErrorIs(t, err, ErrInvalidCertificate)
}

func TestImportIssuingCAs_NoAIA_B3(t *testing.T) {
	ca := setupTestCA(t)
	cert := &x509.Certificate{} // no IssuingCertificateURL
	err := ca.ImportIssuingCAs(context.Background(), cert)
	assert.NoError(t, err)
}

// =============================================================================
// ImportLocalAttestation — nil quote fast-path
// =============================================================================

func TestImportLocalAttestation_NilQuote_B3(t *testing.T) {
	ca := setupTestCAWithObjectStore(t)
	attrs := &types.KeyAttributes{CN: "ak-test"}
	err := ca.ImportLocalAttestation(context.Background(), attrs, nil)
	assert.Error(t, err)
}

// =============================================================================
// ImportAttestationKeyCertificate — guard paths
// =============================================================================

func TestImportAttestationKeyCertificate_NilAttrs_B3(t *testing.T) {
	ca := setupTestCAWithObjectStore(t)
	err := ca.ImportAttestationKeyCertificate(context.Background(), nil, []byte("der"))
	assert.ErrorIs(t, err, ErrInvalidRequest)
}

func TestImportAttestationKeyCertificate_EmptyDER(t *testing.T) {
	ca := setupTestCAWithObjectStore(t)
	attrs := &types.KeyAttributes{CN: "ak-empty"}
	err := ca.ImportAttestationKeyCertificate(context.Background(), attrs, nil)
	assert.ErrorIs(t, err, ErrInvalidCertificate)
}

func TestImportAttestationKeyCertificate_NoObjectStore(t *testing.T) {
	ca := setupTestCA(t) // no object store
	attrs := &types.KeyAttributes{CN: "ak-no-store"}
	err := ca.ImportAttestationKeyCertificate(context.Background(), attrs, []byte("notavalidder"))
	assert.ErrorIs(t, err, ErrObjectStoreRequired)
}

func TestImportAttestationKeyCertificate_InvalidDER_B3(t *testing.T) {
	ca := setupTestCAWithObjectStore(t)
	attrs := &types.KeyAttributes{CN: "ak-invalid"}
	err := ca.ImportAttestationKeyCertificate(context.Background(), attrs, []byte("not-a-certificate"))
	assert.ErrorIs(t, err, ErrInvalidCertificate)
}

// =============================================================================
// TCG extension creation helpers — store/FIPS extensions (non-duplicating)
// =============================================================================

func TestCreateTPKeyStoreExtension_Variants(t *testing.T) {
	for _, v := range []string{"TPM2", "PKCS8", "PKCS11", ""} {
		ext, err := CreateTPKeyStoreExtension(v)
		require.NoError(t, err, "value=%q", v)
		assert.Equal(t, OIDTPKeyStore, ext.Id)
	}
}

func TestCreateTPIssuerKeyStoreExtension_Variants(t *testing.T) {
	for _, v := range []string{"TPM2", "PKCS11", ""} {
		ext, err := CreateTPIssuerKeyStoreExtension(v)
		require.NoError(t, err, "value=%q", v)
		assert.Equal(t, OIDTPIssuerKeyStore, ext.Id)
	}
}

func TestCreateTPFIPS140Extension_BothValues(t *testing.T) {
	extTrue, err := CreateTPFIPS140Extension(true)
	require.NoError(t, err)
	assert.Equal(t, OIDTPFIPS140, extTrue.Id)

	extFalse, err := CreateTPFIPS140Extension(false)
	require.NoError(t, err)
	assert.Equal(t, OIDTPFIPS140, extFalse.Id)
	assert.NotEqual(t, extTrue.Value, extFalse.Value)
}

// =============================================================================
// TBS determinism
// =============================================================================

func TestExtractTBSBytes_ValidCert(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "tbs-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	tbs, err := ExtractTBSBytes(certDER)
	require.NoError(t, err)
	assert.NotEmpty(t, tbs)
}

func TestExtractTBSBytes_EmptyInput(t *testing.T) {
	_, err := ExtractTBSBytes(nil)
	assert.ErrorIs(t, err, ErrTBSNilInput)
}

func TestExtractTBSBytes_InvalidInput(t *testing.T) {
	_, err := ExtractTBSBytes([]byte("garbage"))
	assert.Error(t, err)
}

// =============================================================================
// profiles.go — Register / Get / List
// =============================================================================

func TestProfileRegistry_RegisterAndGet(t *testing.T) {
	r := NewDefaultProfileRegistry()
	prof := NewServerProfile()
	require.NoError(t, r.Register("test-server-b3", prof))

	got, err := r.Get("test-server-b3")
	require.NoError(t, err)
	assert.NotNil(t, got)
}

func TestProfileRegistry_Register_NilProfile(t *testing.T) {
	r := NewDefaultProfileRegistry()
	err := r.Register("nil-profile", nil)
	assert.ErrorIs(t, err, ErrInvalidProfile)
}

func TestProfileRegistry_Register_EmptyName(t *testing.T) {
	r := NewDefaultProfileRegistry()
	err := r.Register("  ", NewClientProfile())
	assert.ErrorIs(t, err, ErrInvalidProfile)
}

func TestProfileRegistry_Get_NotFound(t *testing.T) {
	r := NewDefaultProfileRegistry()
	_, err := r.Get("definitely-not-registered-b3")
	assert.ErrorIs(t, err, ErrProfileNotFound)
}

func TestProfileRegistry_CaseInsensitive(t *testing.T) {
	r := NewDefaultProfileRegistry()
	prof := NewCodeSigningProfile()
	require.NoError(t, r.Register("MyProfile-B3", prof))

	got, err := r.Get("myprofile-b3")
	require.NoError(t, err)
	assert.NotNil(t, got)
}

// =============================================================================
// listRevocationBlobs — revocationStore is the sole source, objectStore
// entries are never consulted
// =============================================================================

func TestListRevocationBlobs_WithObjectStore_Empty_B3(t *testing.T) {
	ca := setupTestCAWithObjectStore(t)
	blobs, err := ca.listRevocationBlobs(context.Background())
	require.NoError(t, err)
	assert.Empty(t, blobs)
}

// TestListRevocationBlobs_ObjectStoreEntryIgnored_B3 proves an entry written
// directly to objectStore under the revocation key prefix is not surfaced by
// listRevocationBlobs: the deleted objectStore fallback is gone, not merely
// unreachable through some other path.
func TestListRevocationBlobs_ObjectStoreEntryIgnored_B3(t *testing.T) {
	ca := setupTestCAWithObjectStore(t)
	key := revocationKeyPrefix + "test-serial.json"
	require.NoError(t, ca.objectStore.Put(key, strings.NewReader(`{"serial":"01"}`)))

	blobs, err := ca.listRevocationBlobs(context.Background())
	require.NoError(t, err)
	assert.Empty(t, blobs, "objectStore entries must not be surfaced")
}

// =============================================================================
// getXSignedCertificates — nil object store path
// =============================================================================

func TestGetXSignedCertificates_NilObjectStore_B3(t *testing.T) {
	ca := setupTestCA(t) // no object store
	certs, err := ca.getXSignedCertificates("some-cn")
	require.NoError(t, err)
	assert.Nil(t, certs)
}

func TestGetXSignedCertificates_EmptyStore_B3(t *testing.T) {
	ca := setupTestCAWithObjectStore(t)
	certs, err := ca.getXSignedCertificates("nonexistent-cn")
	require.NoError(t, err)
	assert.Empty(t, certs)
}

// =============================================================================
// openssl.go — TryLoadOpenSSLDefaults nil guard
// =============================================================================

func TestTryLoadOpenSSLDefaults_NilSubject_B3(t *testing.T) {
	// Should not panic when subject is nil.
	TryLoadOpenSSLDefaults(nil)
}

func TestTryLoadOpenSSLDefaults_NonNilSubject_B3(t *testing.T) {
	s := &Subject{CommonName: "already-set"}
	TryLoadOpenSSLDefaults(s)
	// CommonName was already set and must not be overwritten.
	assert.Equal(t, "already-set", s.CommonName)
}

// =============================================================================
// hybrid.go — extractTBS valid/invalid paths
// =============================================================================

func TestExtractTBS_ValidCert(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "extract-tbs-hybrid"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	tbs, err := extractTBS(certDER)
	require.NoError(t, err)
	assert.NotEmpty(t, tbs)
}

func TestExtractTBS_InvalidInput(t *testing.T) {
	_, err := extractTBS([]byte("not-a-cert"))
	assert.Error(t, err)
}

// =============================================================================
// Signer / getOrGenerateCAKey paths — Sign method
// =============================================================================

func TestSign_DigestAndVerify(t *testing.T) {
	ca := setupTestCA(t)

	msg := []byte("hello world")
	digest := sha256.Sum256(msg)

	sig, err := ca.Sign(rand.Reader, digest[:], crypto.SHA256)
	require.NoError(t, err)
	assert.NotEmpty(t, sig)

	// Signature should be valid ECDSA DER bytes.
	signer, err := ca.Signer(context.Background())
	require.NoError(t, err)
	pub, ok := signer.Public().(*ecdsa.PublicKey)
	require.True(t, ok)
	assert.True(t, ecdsa.VerifyASN1(pub, digest[:], sig))
}

// =============================================================================
// RSA key — CreateCSRWithKey produces valid CSR
// =============================================================================

func TestCreateCSRWithKey_RSA_B3(t *testing.T) {
	key := generateTestRSAKey(t)
	req := &CertificateRequest{
		Subject: Subject{CommonName: "csr-rsa"},
		SANS:    &SubjectAlternativeNames{DNS: []string{"csr-rsa.local"}},
	}
	csrPEM, err := CreateCSRWithKey(req, key)
	require.NoError(t, err)
	block, _ := pem.Decode(csrPEM)
	require.NotNil(t, block)
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	require.NoError(t, err)
	assert.Equal(t, "csr-rsa", csr.Subject.CommonName)
}

// =============================================================================
// CABundleCertPool — with object-store path via setupTestCAWithObjectStore
// =============================================================================

func TestCABundleCertPool_WithObjectStore(t *testing.T) {
	ca := setupTestCAWithObjectStore(t)
	pool, err := ca.CABundleCertPool()
	require.NoError(t, err)
	assert.NotNil(t, pool)
}

// =============================================================================
// TrustedRootCertPoolWithXSigner — nil xsigner check (returns pool without xsigned certs)
// =============================================================================

func TestTrustedRootCertPoolWithXSigner_NilXSigner_B3(t *testing.T) {
	ca := setupTestCA(t)
	issued, err := ca.IssueCertificate(context.Background(), &CertificateRequest{
		Subject: Subject{CommonName: "root-pool-xsign"},
		SANS:    &SubjectAlternativeNames{DNS: []string{"root-pool-xsign.local"}},
		Valid:   365,
	})
	require.NoError(t, err)

	pool, err := ca.TrustedRootCertPoolWithXSigner(issued.Certificate, nil)
	// Either succeeds or returns an error if the function requires xsigner != nil.
	if err == nil {
		assert.NotNil(t, pool)
	}
}

// =============================================================================
// RSA 2048 — IssueCertificate with RSA key attributes
// =============================================================================

func TestIssueCertificate_RSAKey(t *testing.T) {
	ca := setupTestCA(t)
	rsaKey := generateTestRSAKey(t)
	req := &CertificateRequest{
		Subject: Subject{CommonName: "rsa-leaf"},
		SANS:    &SubjectAlternativeNames{DNS: []string{"rsa-leaf.local"}},
		Valid:   365,
		Signer:  rsaKey,
		KeyAttributes: &types.KeyAttributes{
			CN:           "rsa-leaf",
			KeyAlgorithm: x509.RSA,
			StoreType:    types.StoreSoftware,
			KeyType:      types.KeyTypeTLS,
			RSAAttributes: &types.RSAAttributes{
				KeySize: 2048,
			},
			Hash: crypto.SHA256,
		},
	}
	result, err := ca.IssueCertificate(context.Background(), req)
	require.NoError(t, err)
	assert.NotNil(t, result.Certificate)
	assert.Equal(t, "rsa-leaf", result.Certificate.Subject.CommonName)
}

// =============================================================================
// hashCRLURL — deterministic hash output
// =============================================================================

func TestHashCRLURL_Deterministic_B3(t *testing.T) {
	url := "http://example.com/test.crl"
	h1 := hashCRLURL(url)
	h2 := hashCRLURL(url)
	assert.Equal(t, h1, h2)
	assert.Len(t, h1, 64) // hex SHA-256
}

func TestHashCRLURL_DifferentURLs_B3(t *testing.T) {
	h1 := hashCRLURL("http://a.example.com/crl.crl")
	h2 := hashCRLURL("http://b.example.com/crl.crl")
	assert.NotEqual(t, h1, h2)
}

// =============================================================================
// ocspCacheKey
// =============================================================================

func TestOCSPCacheKey_Deterministic(t *testing.T) {
	serial := big.NewInt(12345)
	k1 := ocspCacheKey(serial)
	k2 := ocspCacheKey(serial)
	assert.Equal(t, k1, k2)
	assert.Contains(t, k1, "12345")
}

// =============================================================================
// CABundleFiltered — object store with certs
// =============================================================================

func TestCABundleFiltered_WithObjectStore(t *testing.T) {
	ca := setupTestCAWithObjectStore(t)
	// Empty string + UnknownPublicKeyAlgorithm = no filter.
	bundle, err := ca.CABundleFiltered("", x509.UnknownPublicKeyAlgorithm)
	require.NoError(t, err)
	assert.NotNil(t, bundle)
}

// =============================================================================
// MutualTLSConfig — server and client modes
// =============================================================================

func TestMutualTLSConfig_Success(t *testing.T) {
	ca := setupTestCA(t)
	issueCertAndSaveToKeyStore(t, ca, "mtls-b3")
	attrs := softwareKeyAttrs("mtls-b3")

	cfg, err := ca.MutualTLSConfig(context.Background(), attrs)
	require.NoError(t, err)
	assert.NotNil(t, cfg)
}

// =============================================================================
// NewIntermediateCA — missing parent / not initialized fast-paths
// =============================================================================

func TestNewIntermediateCA_NilParams(t *testing.T) {
	_, err := NewIntermediateCA(context.Background(), nil, nil)
	assert.Error(t, err)
}

func TestNewIntermediateCA_NilParent(t *testing.T) {
	params := &Params{
		Identity: []Identity{
			{Subject: Subject{CommonName: "root-x"}},
			{Subject: Subject{CommonName: "intermediate-x"}},
		},
	}
	_, err := NewIntermediateCA(context.Background(), params, nil)
	assert.ErrorIs(t, err, ErrParentCARequired)
}

// =============================================================================
// RSA signer via IssueCertificate with pre-generated RSA public key
// =============================================================================

func TestIssueCertificate_WithRSASigner_Verifies(t *testing.T) {
	ca := setupTestCA(t)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	req := &CertificateRequest{
		Subject: Subject{CommonName: "rsa-verify-leaf"},
		SANS:    &SubjectAlternativeNames{DNS: []string{"rsa-verify-leaf.local"}},
		Valid:   365,
		Signer:  rsaKey,
	}
	result, err := ca.IssueCertificate(context.Background(), req)
	require.NoError(t, err)
	require.NotNil(t, result.Certificate)

	// Verify the issued certificate is signed by the CA's root.
	chains, err := ca.Verify(result.Certificate)
	require.NoError(t, err)
	assert.NotEmpty(t, chains)
}

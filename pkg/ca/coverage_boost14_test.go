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

// Package ca coverage boost, fourteenth pass: targets remaining uncovered
// functions identified after boost13. All tests are in-memory, fast,
// race-detector clean.
package ca

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// ca.go — Params.Validate + New: CAConfig.Validate() error path (lines 173, 397)
// =============================================================================

// TestParamsValidate_InvalidCAConfig_B14 exercises the CAConfig.Validate()
// error path inside Params.Validate() (ca.go line 173) AND the propagation
// through New() (ca.go line 397).
func TestParamsValidate_InvalidCAConfig_B14(t *testing.T) {
	t.Parallel()
	backend, cs := newB9Backend(t)
	// ValidityDays = -1 causes CAConfig.Validate() to fail.
	params := &Params{
		Config: &CAConfig{
			Identity:     "bad-validity-b14",
			ValidityDays: -1,
		},
		KeyAttributes: softwareKeyAttrs("bad-validity-b14"),
		KeyStore:      backend,
		CertStore:     cs,
	}
	err := params.Validate()
	assert.ErrorIs(t, err, ErrInvalidConfig)

	// Also verify New() propagates the error (line 397).
	_, err = New(params)
	assert.ErrorIs(t, err, ErrInvalidConfig)
}

// =============================================================================
// ca.go — NewFromMultiIdentityConfig: Config.Validate() error path (line 484)
// =============================================================================

// TestNewFromMultiIdentityConfig_InvalidConfig_B14 exercises the
// Config.Validate() error path in NewFromMultiIdentityConfig (line 484) by
// passing a MultiIdentityCAConfig with no identities.
func TestNewFromMultiIdentityConfig_InvalidConfig_B14(t *testing.T) {
	t.Parallel()
	backend, cs := newB9Backend(t)
	mp := &MultiIdentityParams{
		// Empty MultiIdentityCAConfig has no identities — Validate() fails.
		Config:    &MultiIdentityCAConfig{},
		KeyStore:  backend,
		CertStore: cs,
	}
	_, err := NewFromMultiIdentityConfig(mp)
	assert.Error(t, err)
}

// =============================================================================
// ca.go — SignCSR: x509.ParseCertificateRequest error path (line 1244)
// =============================================================================

// TestSignCSR_InvalidDERInBlock_B14 exercises the ParseCertificateRequest
// error path in SignCSR (ca.go line 1244) by presenting a PEM block of the
// correct type but with invalid DER content.
func TestSignCSR_InvalidDERInBlock_B14(t *testing.T) {
	t.Parallel()
	ca := setupTestCA(t)

	// "YWJj" = base64("abc") — valid PEM encoding but not valid DER for a CSR.
	const invalidCSR = "-----BEGIN CERTIFICATE REQUEST-----\nYWJj\n-----END CERTIFICATE REQUEST-----\n"
	_, err := ca.SignCSR(context.Background(), []byte(invalidCSR), nil)
	assert.ErrorIs(t, err, ErrInvalidCSR)
}

// =============================================================================
// OCSP: VerifyOCSPResponse success path (ocsp.go line 331)
// =============================================================================

// TestOCSPResponder_VerifyOCSPResponse_Success_B14 exercises the success
// return path of VerifyOCSPResponse (ocsp.go line 331) by obtaining a valid
// OCSP response from HandleRequest.
func TestOCSPResponder_VerifyOCSPResponse_Success_B14(t *testing.T) {
	t.Parallel()
	ca := setupTestCA(t)
	responder := NewOCSPResponder(ca, DefaultOCSPResponderConfig())

	issued, err := ca.IssueCertificate(context.Background(), &CertificateRequest{
		Subject: Subject{CommonName: "ocsp-verify-b14"},
		Valid:   365,
	})
	require.NoError(t, err)

	rootCert, err := ca.CACertificate()
	require.NoError(t, err)

	reqBytes, err := CreateOCSPRequest(issued.Certificate, rootCert, nil)
	require.NoError(t, err)

	respBytes, err := responder.HandleRequest(context.Background(), reqBytes)
	require.NoError(t, err)

	// VerifyOCSPResponse success path (line 331).
	resp, err := responder.VerifyOCSPResponse(respBytes)
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

// =============================================================================
// OCSP: cache hit path (ocsp.go line 159)
// =============================================================================

// TestOCSPResponder_CacheHit_B14 exercises the cached-response return in
// createResponse (ocsp.go line 159) by calling HandleRequest twice for the
// same certificate serial.
func TestOCSPResponder_CacheHit_B14(t *testing.T) {
	t.Parallel()
	ca := setupTestCA(t)
	responder := NewOCSPResponder(ca, DefaultOCSPResponderConfig())

	issued, err := ca.IssueCertificate(context.Background(), &CertificateRequest{
		Subject: Subject{CommonName: "ocsp-cache-hit-b14"},
		Valid:   365,
	})
	require.NoError(t, err)

	rootCert, err := ca.CACertificate()
	require.NoError(t, err)

	reqBytes, err := CreateOCSPRequest(issued.Certificate, rootCert, nil)
	require.NoError(t, err)

	// First call populates the cache.
	first, err := responder.HandleRequest(context.Background(), reqBytes)
	require.NoError(t, err)
	require.NotEmpty(t, first)

	// Second call hits the cache (line 159).
	second, err := responder.HandleRequest(context.Background(), reqBytes)
	require.NoError(t, err)
	assert.Equal(t, first, second, "cache hit must return identical response bytes")
}

// =============================================================================
// OCSP: HasIntermediate branch in createResponse (ocsp.go line 168)
// =============================================================================

// TestOCSPResponder_IntermediateCA_B14 exercises the HasIntermediate branch
// in createResponse (ocsp.go line 168) by using a CA that has a real
// intermediate certificate.
func TestOCSPResponder_IntermediateCA_B14(t *testing.T) {
	t.Parallel()
	ca := setupTestCAWithRealIntermediate(t)
	responder := NewOCSPResponder(ca, DefaultOCSPResponderConfig())

	issued, err := ca.IssueCertificate(context.Background(), &CertificateRequest{
		Subject: Subject{CommonName: "ocsp-intermediate-b14"},
		Valid:   365,
	})
	require.NoError(t, err)

	issuerCert := ca.intermediateCert
	require.NotNil(t, issuerCert)

	reqBytes, err := CreateOCSPRequest(issued.Certificate, issuerCert, nil)
	require.NoError(t, err)

	respBytes, err := responder.HandleRequest(context.Background(), reqBytes)
	require.NoError(t, err)
	assert.NotEmpty(t, respBytes)
}

// =============================================================================
// trust_chain.go — OSTrustStore (lines 125-128)
// =============================================================================

// TestOSTrustStore_B14 exercises OSTrustStore. On Linux the OS trust store is
// available; either result path is valid as long as the call is exercised.
func TestOSTrustStore_B14(t *testing.T) {
	t.Parallel()
	ca := setupTestCA(t)
	pool, err := ca.OSTrustStore()
	if err != nil {
		assert.Nil(t, pool)
	} else {
		assert.NotNil(t, pool)
	}
}

// =============================================================================
// cross_signing.go — XSignedRootCertificate nil cert (line 91)
// =============================================================================

// TestXSignedRootCertificate_NilCert_B14 exercises the nil-cert error path
// (cross_signing.go line 91) in XSignedRootCertificate.
func TestXSignedRootCertificate_NilCert_B14(t *testing.T) {
	t.Parallel()
	ca := setupTestCAWithObjectStore(t)
	_, err := ca.XSignedRootCertificate("some-issuer-b14", nil)
	assert.ErrorIs(t, err, ErrInvalidCertificate)
}

// =============================================================================
// cross_signing.go — XSignedIntermediateCertificates nil/empty paths (117, 120)
// =============================================================================

// TestXSignedIntermediateCertificates_EmptyIssuerCN_B14 exercises the
// empty-issuerCN error path (line 117) in XSignedIntermediateCertificates.
func TestXSignedIntermediateCertificates_EmptyIssuerCN_B14(t *testing.T) {
	t.Parallel()
	ca := setupTestCAWithObjectStore(t)
	leaf, _ := b13MakeRawCert(t, "leaf-b14-cross", nil, nil, false)
	_, err := ca.XSignedIntermediateCertificates("", leaf)
	assert.ErrorIs(t, err, ErrInvalidConfig)
}

// TestXSignedIntermediateCertificates_NilCert_B14 exercises the nil-cert
// error path (line 120) in XSignedIntermediateCertificates.
func TestXSignedIntermediateCertificates_NilCert_B14(t *testing.T) {
	t.Parallel()
	ca := setupTestCAWithObjectStore(t)
	_, err := ca.XSignedIntermediateCertificates("some-issuer-b14", nil)
	assert.ErrorIs(t, err, ErrInvalidCertificate)
}

// =============================================================================
// cross_signing.go — CrossSignedPEM nil attrs and no objectStore (lines 171, 174)
// =============================================================================

// TestCrossSignedPEM_NilAttrs_B14 exercises the nil-attrs / empty-CN error
// path (cross_signing.go line 171) in CrossSignedPEM.
func TestCrossSignedPEM_NilAttrs_B14(t *testing.T) {
	t.Parallel()
	ca := setupTestCAWithObjectStore(t)
	_, err := ca.CrossSignedPEM(nil)
	assert.Error(t, err)
}

// TestCrossSignedPEM_NoObjectStore_B14 exercises the no-objectStore error
// path (cross_signing.go line 173-174) in CrossSignedPEM.
func TestCrossSignedPEM_NoObjectStore_B14(t *testing.T) {
	t.Parallel()
	ca := setupTestCA(t)
	attrs := softwareKeyAttrs("cross-no-store-b14")
	_, err := ca.CrossSignedPEM(attrs)
	assert.ErrorIs(t, err, ErrObjectStoreRequired)
}

// =============================================================================
// constructors.go — NewCA: NewIntermediateCA error path (line 399)
// =============================================================================

// TestNewCA_IntermediateError_B14 exercises the NewIntermediateCA error return
// path in NewCA (constructors.go line 399) by providing two identities where
// the intermediate has an empty common name.
func TestNewCA_IntermediateError_B14(t *testing.T) {
	t.Parallel()
	backend, cs := newB9Backend(t)

	params := &Params{
		Identity: []Identity{
			{
				Subject: Subject{CommonName: "NewCA Root B14", Organization: "Test"},
				Valid:   10,
				Keys:    DefaultKeyConfig(),
			},
			{
				// Empty CN triggers intermediateID.Validate() error.
				Subject: Subject{CommonName: ""},
				Valid:   10,
				Keys:    DefaultKeyConfig(),
			},
		},
		KeyStore:  backend,
		CertStore: cs,
		SerialGen: NewSerialGenerator(NewMemoryStorage()),
	}
	_, _, err := NewCA(context.Background(), params)
	assert.ErrorIs(t, err, ErrInvalidConfig)
}

// =============================================================================
// ca_extensions.go — Certificate: intermediateCert match path (line 194)
// =============================================================================

// TestCertificate_IntermediateMatch_B14 exercises the intermediateCert branch
// in Certificate (ca_extensions.go line 194) by querying the intermediate CA
// certificate via its common name.
func TestCertificate_IntermediateMatch_B14(t *testing.T) {
	t.Parallel()
	ca := setupTestCAWithRealIntermediate(t)
	require.NotNil(t, ca.intermediateCert)

	attrs := &types.KeyAttributes{
		CN:           ca.intermediateCert.Subject.CommonName,
		KeyAlgorithm: x509.ECDSA,
		StoreType:    types.StoreSoftware,
		KeyType:      types.KeyTypeCA,
	}
	cert, err := ca.Certificate(context.Background(), attrs)
	require.NoError(t, err)
	assert.Equal(t, ca.intermediateCert.Subject.CommonName, cert.Subject.CommonName)
}

// =============================================================================
// ca_extensions.go — Issued: keyStore path when certStore is nil (line 146)
// =============================================================================

// TestIssued_KeyStorePath_B14 exercises the keyStore lookup branch in Issued
// (ca_extensions.go line 146) by constructing a minimal CA with no certStore
// so only the keyStore branch is taken.
func TestIssued_KeyStorePath_B14(t *testing.T) {
	t.Parallel()
	// Issue a cert using a full CA so the key/cert are stored in the keyStore.
	fullCA := setupTestCA(t)
	const cn = "issued-keystore-only-b14"
	issueCertAndSaveToKeyStore(t, fullCA, cn)

	// Build a minimal CA with the same keyStore but no certStore.
	// This forces the Issued() call to skip the certStore path and use keyStore.
	caNoCS := &CA{
		keyStore:    fullCA.keyStore,
		certStore:   nil,
		revocations: make(map[string]*RevocationInfo),
	}
	caNoCS.initialized.Store(true)

	found, err := caNoCS.Issued(context.Background(), cn)
	require.NoError(t, err)
	assert.True(t, found)
}

// =============================================================================
// ca_extensions.go — CAKeyAttributes: storeType mismatch (line 453)
// =============================================================================

// TestCAKeyAttributes_StoreTypeMismatch_B14 exercises the storeType mismatch
// error path in CAKeyAttributes (ca_extensions.go line 453) by requesting a
// store type that differs from the CA's configured type.
func TestCAKeyAttributes_StoreTypeMismatch_B14(t *testing.T) {
	t.Parallel()
	ca := setupTestCA(t)
	// The CA is configured as StoreSoftware. Requesting StoreTPM2 forces mismatch.
	_, err := ca.CAKeyAttributes(types.StoreTPM2)
	assert.ErrorIs(t, err, ErrInvalidStoreType)
}

// =============================================================================
// profiles.go — baseProfile.Apply: nil template (line 180)
// =============================================================================

// TestBaseProfileApply_NilTemplate_B14 exercises the nil-template error path
// in baseProfile.Apply (profiles.go line 180) via the server profile.
func TestBaseProfileApply_NilTemplate_B14(t *testing.T) {
	t.Parallel()
	ca := setupTestCA(t)
	serverProfile, err := ca.profiles.Get("server")
	require.NoError(t, err)
	require.NotNil(t, serverProfile, "server profile must be registered")
	err = serverProfile.Apply(nil, &CertificateRequest{
		Subject: Subject{CommonName: "nil-template-b14"},
	})
	assert.ErrorIs(t, err, ErrInvalidProfile)
}

// =============================================================================
// tls.go — verifyKeyMatchesCertificate: Ed25519 key + non-Ed25519 cert (line 870)
// =============================================================================

// TestVerifyKeyMatchesCertificate_Ed25519ECDSAMismatch_B14 exercises the
// Ed25519 key / non-Ed25519 cert mismatch path (tls.go line 870) by pairing
// an Ed25519 private key with an ECDSA certificate.
func TestVerifyKeyMatchesCertificate_Ed25519ECDSAMismatch_B14(t *testing.T) {
	t.Parallel()

	// Generate an Ed25519 private key.
	_, ed25519Key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	// Build an ECDSA certificate whose public key is *ecdsa.PublicKey.
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "ecdsa-cert-b14"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &ecKey.PublicKey, ecKey)
	require.NoError(t, err)
	ecCert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	// verifyKeyMatchesCertificate is unexported but accessible from the same package.
	// ed25519Key is ed25519.PrivateKey; cert has *ecdsa.PublicKey → mismatch at line 870.
	err = verifyKeyMatchesCertificate(ed25519Key, ecCert)
	assert.ErrorIs(t, err, ErrKeyCertMismatch)
}

// =============================================================================
// quantum.go — verifyMLDSASignature: UnmarshalBinary error paths (326, 333, 340)
// and default algorithm branch (line 345)
// =============================================================================

// TestVerifyMLDSASignature_BadPublicKeyBytes_B14 exercises the UnmarshalBinary
// error paths (lines 326, 333, 340) in verifyMLDSASignature by passing garbage
// bytes for the public key across all three ML-DSA variants.
func TestVerifyMLDSASignature_BadPublicKeyBytes_B14(t *testing.T) {
	t.Parallel()

	badPub := []byte("not-a-valid-ml-dsa-public-key-b14")
	msg := []byte("message")
	sig := []byte("signature")

	for _, tc := range []struct {
		algo string
		line string
	}{
		{"ML-DSA-44", "line 326"},
		{"ML-DSA-65", "line 333"},
		{"ML-DSA-87", "line 340"},
	} {
		tc := tc
		t.Run(tc.algo, func(t *testing.T) {
			t.Parallel()
			ok, err := verifyMLDSASignature(tc.algo, badPub, msg, sig)
			assert.False(t, ok, "%s: expected false for bad public key bytes", tc.line)
			assert.Error(t, err, "%s: expected error for bad public key bytes", tc.line)
		})
	}
}

// TestVerifyMLDSASignature_UnknownAlgorithm_B14 exercises the default case
// (line 345) in verifyMLDSASignature by passing an unknown algorithm string.
func TestVerifyMLDSASignature_UnknownAlgorithm_B14(t *testing.T) {
	t.Parallel()
	ok, err := verifyMLDSASignature("ML-DSA-UNKNOWN-B14", []byte("pub"), []byte("msg"), []byte("sig"))
	assert.False(t, ok)
	assert.Error(t, err)
}

// =============================================================================
// quantum.go — oidToQuantumAlgorithm: unknown OID error return (line 317)
// =============================================================================

// TestOIDToQuantumAlgorithm_UnknownOID_B14 exercises the error return in
// oidToQuantumAlgorithm (quantum.go line 317) by passing an OID not registered
// for any ML-DSA variant.
func TestOIDToQuantumAlgorithm_UnknownOID_B14(t *testing.T) {
	t.Parallel()
	unknownOID := asn1.ObjectIdentifier{1, 2, 3, 4}
	_, err := oidToQuantumAlgorithm(unknownOID)
	assert.Error(t, err)
}

// =============================================================================
// quantum.go — quantumAlgorithmOID: unknown algorithm error return (line 305)
// =============================================================================

// TestQuantumAlgorithmOID_UnknownAlgo_B14 exercises the error return in
// quantumAlgorithmOID (quantum.go line 305) by passing an unrecognized string.
func TestQuantumAlgorithmOID_UnknownAlgo_B14(t *testing.T) {
	t.Parallel()
	_, err := quantumAlgorithmOID("UNKNOWN-ALGO-B14")
	assert.Error(t, err)
}

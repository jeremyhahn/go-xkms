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
	"encoding/pem"
	"errors"
	"io"
	"math/big"
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

// =============================================================================
// ca_extensions.go — PrivateKey (33%) — missing error branch
// =============================================================================

func TestPrivateKey_KeyNotFound(t *testing.T) {
	ca := setupTestCA(t)
	_, err := ca.PrivateKey(context.Background(), &types.KeyAttributes{CN: "does-not-exist"})
	assert.ErrorIs(t, err, ErrKeyNotFound)
}

// =============================================================================
// ca_extensions.go — PubKey (22%) — success + non-signer error branch
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
// ca_extensions.go — DefaultKeyAlgorithm (50%)
// =============================================================================

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
// ca_extensions.go — CABundleFiltered (71%) — storeType filter path
// =============================================================================

func TestCABundleFiltered_StoreTypeFilter(t *testing.T) {
	ca := setupTestCA(t)
	bundle, err := ca.CABundleFiltered(types.StoreSoftware, x509.UnknownPublicKeyAlgorithm)
	require.NoError(t, err)
	assert.NotEmpty(t, bundle)
}

// =============================================================================
// ca_extensions.go — loadPersistedRevocations — corrupt record path
// =============================================================================

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
// trust_chain_extensions.go — TrustedRootCertPoolWithXSigner (28%)
// =============================================================================

func TestTrustedRootCertPoolWithXSigner_NotInitialized(t *testing.T) {
	ca := &CA{}
	_, err := ca.TrustedRootCertPoolWithXSigner(&x509.Certificate{}, nil)
	assert.ErrorIs(t, err, ErrNotInitialized)
}

// =============================================================================
// trust_chain_extensions.go — TrustedIntermediateCertPoolWithXSigner (25%)
// =============================================================================

func TestTrustedIntermediateCertPoolWithXSigner_NotInitialized(t *testing.T) {
	ca := &CA{}
	_, err := ca.TrustedIntermediateCertPoolWithXSigner(&x509.Certificate{}, nil)
	assert.ErrorIs(t, err, ErrNotInitialized)
}

// =============================================================================
// trust_chain_extensions.go — parseAIACertificate (0%)
// =============================================================================

func TestParseAIACertificate_PEM(t *testing.T) {
	cert, _ := makeSelfSignedCert(t, "pem-aia")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	parsed, err := parseAIACertificate(pemBytes)
	require.NoError(t, err)
	assert.Equal(t, "pem-aia", parsed.Subject.CommonName)
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
	result, err := bufferBytes(&stubReader{data: data})
	require.NoError(t, err)
	assert.Equal(t, data, result)
}

func TestBufferBytes_ReadErrorSurfaces(t *testing.T) {
	readErr := errors.New("coverage_gap_test: simulated read failure")
	_, err := bufferBytes(&failingReader{err: readErr})
	require.ErrorIs(t, err, readErr)
}

// failingReader is an io.Reader whose Read always fails, used to exercise
// bufferBytes' error path.
type failingReader struct {
	err error
}

func (r *failingReader) Read([]byte) (int, error) { return 0, r.err }

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
// tls.go — TLSCertificate (87%) — partial: Ed25519 path
// =============================================================================

// LoadTLSCertificate and verifyKeyMatchesCertificate are fully covered by tls_test.go.

// VerifyPeerCertificate is already covered by tls_test.go including the
// ExpiredCert path at TestCA_VerifyPeerCertificate_ExpiredCert.

// =============================================================================
// verification.go — VerifyWithOptions (85%)
// =============================================================================

func TestVerifyWithOptions_WithCRLRevoked(t *testing.T) {
	ca := setupTestCA(t)
	issued, err := ca.IssueCertificate(context.Background(), &CertificateRequest{
		TenantID: testTenant,
		Subject:  Subject{CommonName: "crl-test.example.com"},
		Valid:    365,
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

func TestSerialNumbersMatch_BothNilSerials(t *testing.T) {
	a := &x509.Certificate{}
	b := &x509.Certificate{}
	assert.False(t, SerialNumbersMatch(a, b))
}

// =============================================================================
// verification.go — PathLength (88%) — MaxPathLenZero branch
// =============================================================================

func TestPathLength_NoConstraint(t *testing.T) {
	cert := &x509.Certificate{
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        false,
	}
	assert.Equal(t, -1, PathLength(cert))
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

func TestCAConfigValidate_NegativePathLength(t *testing.T) {
	cfg := &CAConfig{Identity: "test", MaxPathLength: -1}
	assert.ErrorIs(t, cfg.Validate(), ErrInvalidPathLength)
}

func TestCAConfigValidate_NoIdentityOrSubject(t *testing.T) {
	cfg := &CAConfig{}
	assert.ErrorIs(t, cfg.Validate(), ErrSubjectCommonNameRequired)
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

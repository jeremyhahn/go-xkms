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

// Session 2.5 extension tests:
//   - multi-tenant SignCSR (Signer + IssuerCert on SignOptions)
//   - RevokeCert persistence (with and without object store)
//   - IssuingIdentity accessor
//   - OCSP responder behaviour
//   - VerifyTBSDeterminism behaviour
//   - Verify variadic xsigner behaviour
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
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ocsp"
)

// =============================================================================
// Shared Test Helpers
// =============================================================================

// makeExternalIssuer creates an external CA-capable keypair and a
// self-signed issuer certificate suitable for use as SignOptions.IssuerCert
// / SignOptions.Signer in the multi-tenant signing tests.
func makeExternalIssuer(t *testing.T, cn string) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(42),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-1 * time.Minute),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		SubjectKeyId:          []byte{0xDE, 0xAD, 0xBE, 0xEF},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)
	return key, cert
}

// makeLeafCSR generates a fresh leaf keypair and returns its PEM-encoded CSR
// along with the subject CN.
func makeLeafCSR(t *testing.T, cn string) ([]byte, crypto.Signer) {
	t.Helper()
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	csrTemplate := &x509.CertificateRequest{
		Subject:            pkix.Name{CommonName: cn},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, leafKey)
	require.NoError(t, err)
	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	})
	return csrPEM, leafKey
}

// =============================================================================
// 2.5.a — SignCSR multi-tenant signing path
// =============================================================================

// The multi-tenant code path routes signing through an externally supplied
// crypto.Signer + x509.Certificate pair. The issued certificate's Issuer
// subject must reflect the external issuer, not the native CA.
func TestSignCSR_MultiTenantSigner(t *testing.T) {
	ca := setupTestCA(t)
	extKey, extIssuer := makeExternalIssuer(t, "External Tenant CA")
	csrPEM, _ := makeLeafCSR(t, "tenant-leaf.example.com")

	cert, err := ca.SignCSR(context.Background(), csrPEM, &SignOptions{
		TenantID:   testTenant,
		Signer:     extKey,
		IssuerCert: extIssuer,
		Profile:    "",
	})
	require.NoError(t, err)
	require.NotNil(t, cert)

	// Issuer should be the external CA, not Test Root CA.
	assert.Equal(t, "External Tenant CA", cert.Issuer.CommonName,
		"multi-tenant path must record the external issuer in the cert")
	assert.NotEqual(t, "Test Root CA", cert.Issuer.CommonName,
		"multi-tenant path must NOT record the native CA as issuer")

	// Signature must validate against the external public key.
	assert.NoError(t, cert.CheckSignatureFrom(extIssuer),
		"issued cert must verify against the external issuer")
}

// Signer set without IssuerCert is a configuration error — the CA cannot
// compute an AuthorityKeyIdentifier or populate the Issuer subject, so the
// request is rejected up-front rather than producing a malformed cert.
func TestSignCSR_MultiTenantSignerWithoutIssuerCert(t *testing.T) {
	ca := setupTestCA(t)
	extKey, _ := makeExternalIssuer(t, "External Tenant CA")
	csrPEM, _ := makeLeafCSR(t, "tenant-leaf.example.com")

	_, err := ca.SignCSR(context.Background(), csrPEM, &SignOptions{
		TenantID:   testTenant,
		Signer:     extKey,
		IssuerCert: nil,
	})
	assert.ErrorIs(t, err, ErrInvalidIssuer,
		"Signer without IssuerCert must return ErrInvalidIssuer")
}

// The native path (opts.Signer == nil) must keep producing certs signed by
// the CA's own key — a regression here would silently break every non
// multi-tenant consumer.
func TestSignCSR_NativePathStillWorks(t *testing.T) {
	ca := setupTestCA(t)
	csrPEM, _ := makeLeafCSR(t, "native-leaf.example.com")

	cert, err := ca.SignCSR(context.Background(), csrPEM, &SignOptions{TenantID: testTenant})
	require.NoError(t, err)
	require.NotNil(t, cert)
	assert.Equal(t, "Test Root CA", cert.Issuer.CommonName,
		"native path must sign with the CA's own key and subject")
}

// =============================================================================
// 2.5.b — RevokeCert persistence
// =============================================================================

// RevokeCert writes a revocation record to the object store when one is
// configured; a fresh CA pointed at the same object store + certstore must
// see the revocation after Load().
func TestRevokeCert_PersistsToObjectStore(t *testing.T) {
	ca := setupTestCAWithObjectStore(t)

	issued, err := ca.IssueCertificate(context.Background(), &CertificateRequest{
		TenantID: testTenant,
		Subject:  Subject{CommonName: "persisted-revoke.example.com"},
		Valid:    30,
	})
	require.NoError(t, err)

	err = ca.RevokeCert(context.Background(), issued.Certificate, RevokeOptions{Reason: 1})
	require.NoError(t, err)

	// The record should be queryable via IsRevoked immediately.
	revoked, err := ca.IsRevoked(issued.Certificate.SerialNumber)
	require.NoError(t, err)
	assert.True(t, revoked, "RevokeCert must update the in-memory map")

	// Simulate a fresh CA by clearing the map and re-running loadPersistedRevocations.
	ca.revocationsMutex.Lock()
	ca.revocations = make(map[string]*RevocationInfo)
	ca.revocationsMutex.Unlock()

	err = ca.loadPersistedRevocations(context.Background())
	require.NoError(t, err, "loadPersistedRevocations must succeed")

	revoked, err = ca.IsRevoked(issued.Certificate.SerialNumber)
	require.NoError(t, err)
	assert.True(t, revoked,
		"revocation must be restored from the object store after map reset")
}

// Without an object store, RevokeCert still records revocations in memory so
// IsRevoked and GenerateCRL see them — the only observable difference is that
// a fresh process would not rediscover them (and a slog warning is emitted).
func TestRevokeCert_NoObjectStore(t *testing.T) {
	ca := setupTestCA(t) // no objectStore attached
	require.Nil(t, ca.objectStore,
		"precondition: setupTestCA must not wire an objectStore")

	issued, err := ca.IssueCertificate(context.Background(), &CertificateRequest{
		TenantID: testTenant,
		Subject:  Subject{CommonName: "no-store-revoke.example.com"},
		Valid:    30,
	})
	require.NoError(t, err)

	err = ca.RevokeCert(context.Background(), issued.Certificate, RevokeOptions{Reason: 0})
	require.NoError(t, err,
		"RevokeCert must succeed even without an object store")

	revoked, err := ca.IsRevoked(issued.Certificate.SerialNumber)
	require.NoError(t, err)
	assert.True(t, revoked, "in-memory revocation must be visible")
}

// Revoke (the serial-based API) shares recordRevocation with RevokeCert, so
// a persisted Revoke record must also be rediscovered on reload.
func TestRevoke_PersistsToObjectStore(t *testing.T) {
	ca := setupTestCAWithObjectStore(t)

	serial := big.NewInt(12345)
	err := ca.Revoke(context.Background(), serial, 4)
	require.NoError(t, err)

	ca.revocationsMutex.Lock()
	ca.revocations = make(map[string]*RevocationInfo)
	ca.revocationsMutex.Unlock()

	err = ca.loadPersistedRevocations(context.Background())
	require.NoError(t, err)

	revoked, err := ca.IsRevoked(serial)
	require.NoError(t, err)
	assert.True(t, revoked, "Revoke(serial) must persist + reload")
}

// A double-revoke on the same serial must still return ErrAlreadyRevoked
// even when the first revocation was persisted to the object store.
func TestRevokeCert_DoubleRevokeWithPersistence(t *testing.T) {
	ca := setupTestCAWithObjectStore(t)

	issued, err := ca.IssueCertificate(context.Background(), &CertificateRequest{
		TenantID: testTenant,
		Subject:  Subject{CommonName: "double-revoke.example.com"},
		Valid:    30,
	})
	require.NoError(t, err)

	err = ca.RevokeCert(context.Background(), issued.Certificate, RevokeOptions{Reason: 1})
	require.NoError(t, err)

	err = ca.RevokeCert(context.Background(), issued.Certificate, RevokeOptions{Reason: 1})
	assert.ErrorIs(t, err, ErrAlreadyRevoked,
		"second RevokeCert must return ErrAlreadyRevoked")
}

// =============================================================================
// 2.5.c — IssuingIdentity accessor
// =============================================================================

// IssuingIdentity returns a value-copy of the Identity this CA signs with.
// The returned Identity must carry the configured Keys slice so the admin
// service can walk it when building status payloads.
func TestIssuingIdentity_ReturnsConfiguredIdentity(t *testing.T) {
	ca := setupTestCA(t)
	identity := ca.IssuingIdentity()

	assert.Equal(t, "Test Root CA", identity.Subject.CommonName,
		"IssuingIdentity must return the configured issuing identity")
	assert.NotEmpty(t, identity.Keys,
		"IssuingIdentity must surface the Keys slice for status reporting")
}

// A CA with an unconfigured issuing identity must return a zero-value
// Identity rather than panicking, so callers can safely access fields.
func TestIssuingIdentity_ZeroValueWhenUnset(t *testing.T) {
	// A bare CA with no config exercises the nil guard. Using a freshly
	// constructed CA struct (not via New) lets us set config directly.
	ca := &CA{config: &MultiIdentityCAConfig{}}
	identity := ca.IssuingIdentity()
	assert.Empty(t, identity.Subject.CommonName,
		"unset issuing identity must return a zero-value Identity")
}

// =============================================================================
// 2.5.d — OCSP Responder
// =============================================================================

func TestOCSPResponder_GoodStatus(t *testing.T) {
	ca := setupTestCAWithObjectStore(t)
	responder := NewOCSPResponder(ca, OCSPResponderConfig{})
	require.NotNil(t, responder)

	issued, err := ca.IssueCertificate(context.Background(), &CertificateRequest{
		TenantID: testTenant,
		Subject:  Subject{CommonName: "ocsp-good.example.com"},
		Valid:    30,
	})
	require.NoError(t, err)

	rootCert, err := ca.CACertificate()
	require.NoError(t, err)

	reqBytes, err := CreateOCSPRequest(issued.Certificate, rootCert, nil)
	require.NoError(t, err)

	respBytes, err := responder.HandleRequest(context.Background(), reqBytes)
	require.NoError(t, err)
	require.NotEmpty(t, respBytes)

	resp, err := ocsp.ParseResponse(respBytes, nil)
	require.NoError(t, err)
	assert.Equal(t, ocsp.Good, resp.Status,
		"un-revoked certificate must produce GOOD status")
}

func TestOCSPResponder_RevokedStatus(t *testing.T) {
	ca := setupTestCAWithObjectStore(t)
	responder := NewOCSPResponder(ca, OCSPResponderConfig{})

	issued, err := ca.IssueCertificate(context.Background(), &CertificateRequest{
		TenantID: testTenant,
		Subject:  Subject{CommonName: "ocsp-revoked.example.com"},
		Valid:    30,
	})
	require.NoError(t, err)

	err = ca.RevokeCert(context.Background(), issued.Certificate, RevokeOptions{Reason: 1})
	require.NoError(t, err)

	rootCert, err := ca.CACertificate()
	require.NoError(t, err)

	reqBytes, err := CreateOCSPRequest(issued.Certificate, rootCert, nil)
	require.NoError(t, err)

	respBytes, err := responder.HandleRequest(context.Background(), reqBytes)
	require.NoError(t, err)
	resp, err := ocsp.ParseResponse(respBytes, nil)
	require.NoError(t, err)
	assert.Equal(t, ocsp.Revoked, resp.Status,
		"revoked certificate must produce REVOKED status")
	assert.Equal(t, 1, resp.RevocationReason)
}

func TestOCSPResponder_InvalidRequest(t *testing.T) {
	ca := setupTestCAWithObjectStore(t)
	responder := NewOCSPResponder(ca, OCSPResponderConfig{})

	_, err := responder.HandleRequest(context.Background(), nil)
	assert.ErrorIs(t, err, ErrOCSPInvalidRequest,
		"nil request must return ErrOCSPInvalidRequest")

	_, err = responder.HandleRequest(context.Background(), []byte{0x00, 0x01, 0x02})
	assert.ErrorIs(t, err, ErrOCSPRequestParseFailed,
		"garbage request must return ErrOCSPRequestParseFailed")
}

func TestOCSPResponder_DefaultConfig(t *testing.T) {
	cfg := DefaultOCSPResponderConfig()
	assert.Equal(t, 1*time.Hour, cfg.CacheTTL)
	assert.Equal(t, 7*24*time.Hour, cfg.NextUpdate)
}

func TestOCSPResponder_ClearCache(t *testing.T) {
	ca := setupTestCAWithObjectStore(t)
	responder := NewOCSPResponder(ca, OCSPResponderConfig{})

	// Populate the cache via a GOOD lookup.
	issued, err := ca.IssueCertificate(context.Background(), &CertificateRequest{
		TenantID: testTenant,
		Subject:  Subject{CommonName: "ocsp-cache.example.com"},
		Valid:    30,
	})
	require.NoError(t, err)
	rootCert, err := ca.CACertificate()
	require.NoError(t, err)
	reqBytes, err := CreateOCSPRequest(issued.Certificate, rootCert, nil)
	require.NoError(t, err)
	_, err = responder.HandleRequest(context.Background(), reqBytes)
	require.NoError(t, err)

	responder.cacheMu.RLock()
	cachedBefore := len(responder.cache)
	responder.cacheMu.RUnlock()
	require.Greater(t, cachedBefore, 0, "precondition: cache must be populated")

	responder.ClearCache()

	responder.cacheMu.RLock()
	cachedAfter := len(responder.cache)
	responder.cacheMu.RUnlock()
	assert.Zero(t, cachedAfter, "ClearCache must drop every entry")
}

// =============================================================================
// 2.5.e — VerifyTBSDeterminism
// =============================================================================

// Identical DER bytes must yield a successful determinism check.
func TestVerifyTBSDeterminism_Matching(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "tbs-match"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	err = VerifyTBSDeterminism(certDER, certDER)
	assert.NoError(t, err, "identical DER bytes must verify as deterministic")
}

// Empty inputs are rejected before any parsing happens.
func TestVerifyTBSDeterminism_EmptyInputs(t *testing.T) {
	err := VerifyTBSDeterminism(nil, nil)
	assert.ErrorIs(t, err, ErrTBSNilInput)

	err = VerifyTBSDeterminism([]byte{0x30, 0x03}, nil)
	assert.ErrorIs(t, err, ErrTBSNilInput)

	err = VerifyTBSDeterminism(nil, []byte{0x30, 0x03})
	assert.ErrorIs(t, err, ErrTBSNilInput)
}

// Two different certificates must produce different TBS bytes.
func TestVerifyTBSDeterminism_Mismatch(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template1 := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "tbs-first"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	cert1DER, err := x509.CreateCertificate(rand.Reader, template1, template1, &key.PublicKey, key)
	require.NoError(t, err)

	template2 := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "tbs-second"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	cert2DER, err := x509.CreateCertificate(rand.Reader, template2, template2, &key.PublicKey, key)
	require.NoError(t, err)

	err = VerifyTBSDeterminism(cert1DER, cert2DER)
	assert.ErrorIs(t, err, ErrTBSDeterminismFailure)
}

// Malformed DER (valid outer SEQUENCE but truncated inner TBS) must return
// a malformed-TBS error rather than treating missing bytes as a match.
func TestVerifyTBSDeterminism_MalformedInput(t *testing.T) {
	// A 1-byte malformed input cannot be a SEQUENCE.
	malformed := []byte{0x30, 0x01, 0xFF}
	err := VerifyTBSDeterminism(malformed, malformed)
	assert.Error(t, err)
	assert.True(t,
		errors.Is(err, ErrMalformedCertificate) ||
			errors.Is(err, ErrMalformedTBSCertificate) ||
			errors.Is(err, ErrEmptyTBSCertificate),
		"malformed DER must surface a tbs-level error; got %v", err)
}

// =============================================================================
// 2.5.f — Verify variadic xsigner collapse
// =============================================================================

// Verify(cert) — the classic form — must continue to work with no xsigner
// argument. This is the path every non cross-signing caller takes.
func TestVerify_NoXSigner(t *testing.T) {
	ca := setupTestCA(t)
	issued, err := ca.IssueCertificate(context.Background(), &CertificateRequest{
		TenantID: testTenant,
		Subject:  Subject{CommonName: "verify-plain.example.com"},
		Valid:    30,
	})
	require.NoError(t, err)

	chains, err := ca.Verify(issued.Certificate)
	require.NoError(t, err)
	assert.NotEmpty(t, chains,
		"Verify with no xsigner must produce the native trust chain")
}

// Verify(cert, nil) is the common conditional-xsigner shape — it must
// behave exactly like Verify(cert). Having to special-case nil at every
// call site is exactly what Session 2.5 collapsed away.
func TestVerify_ExplicitNilXSigner(t *testing.T) {
	ca := setupTestCA(t)
	issued, err := ca.IssueCertificate(context.Background(), &CertificateRequest{
		TenantID: testTenant,
		Subject:  Subject{CommonName: "verify-nil-xsigner.example.com"},
		Valid:    30,
	})
	require.NoError(t, err)

	var nilSigner crypto.Signer
	chains, err := ca.Verify(issued.Certificate, nilSigner)
	require.NoError(t, err)
	assert.NotEmpty(t, chains,
		"Verify(cert, nil) must behave like Verify(cert)")
}

// Revocation checks must run regardless of whether an xsigner is provided;
// a revoked cert cannot be "rescued" by routing through the cross-sign path.
func TestVerify_RevokedCertWithXSigner(t *testing.T) {
	ca := setupTestCAWithObjectStore(t)
	issued, err := ca.IssueCertificate(context.Background(), &CertificateRequest{
		TenantID: testTenant,
		Subject:  Subject{CommonName: "verify-revoked.example.com"},
		Valid:    30,
	})
	require.NoError(t, err)

	err = ca.RevokeCert(context.Background(), issued.Certificate, RevokeOptions{Reason: 1})
	require.NoError(t, err)

	extKey, _ := makeExternalIssuer(t, "XSigner CA")
	_, err = ca.Verify(issued.Certificate, extKey)
	assert.ErrorIs(t, err, ErrCertificateRevoked,
		"revocation must short-circuit Verify even on the xsigner path")
}

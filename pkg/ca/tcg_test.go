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
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/certstore"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2"
)

// =============================================================================
// Test Helpers
// =============================================================================

// mockCertStoreForTCG implements certstore.CertStore for testing TCG operations.
// Thread-safe: uses sync.RWMutex to protect concurrent map access.
type mockCertStoreForTCG struct {
	mu         sync.RWMutex
	certs      map[string]*x509.Certificate
	chains     map[string][]*x509.Certificate
	crls       map[string]*x509.RevocationList
	storeError error
}

func newMockCertStoreForTCG() *mockCertStoreForTCG {
	return &mockCertStoreForTCG{
		certs:  make(map[string]*x509.Certificate),
		chains: make(map[string][]*x509.Certificate),
		crls:   make(map[string]*x509.RevocationList),
	}
}

func (m *mockCertStoreForTCG) StoreCertificate(cert *x509.Certificate) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.storeError != nil {
		return m.storeError
	}
	// Mirrors certstore.CertificateKey: a certificate with an empty Subject
	// (the WebAuthn §8.3.1 profile LAK certificate, go-xkms#715) is keyed by
	// its SPKI SHA-256 thumbprint rather than colliding on the empty string.
	m.certs[certstore.CertificateKey(cert)] = cert
	return nil
}

func (m *mockCertStoreForTCG) GetCertificate(cn string) (*x509.Certificate, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if cert, ok := m.certs[cn]; ok {
		return cert, nil
	}
	return nil, errors.New("certificate not found")
}

func (m *mockCertStoreForTCG) DeleteCertificate(string) error { return nil }

func (m *mockCertStoreForTCG) ListCertificates() ([]*x509.Certificate, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	certs := make([]*x509.Certificate, 0, len(m.certs))
	for _, cert := range m.certs {
		certs = append(certs, cert)
	}
	return certs, nil
}

func (m *mockCertStoreForTCG) StoreCertificateChain(chain []*x509.Certificate) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(chain) > 0 {
		m.chains[chain[0].Subject.CommonName] = chain
	}
	return nil
}

func (m *mockCertStoreForTCG) GetCertificateChain(cn string) ([]*x509.Certificate, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if chain, ok := m.chains[cn]; ok {
		return chain, nil
	}
	return nil, errors.New("chain not found")
}

func (m *mockCertStoreForTCG) StoreCRL(crl *x509.RevocationList) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.crls[crl.Issuer.CommonName] = crl
	return nil
}

func (m *mockCertStoreForTCG) GetCRL(issuer string) (*x509.RevocationList, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if crl, ok := m.crls[issuer]; ok {
		return crl, nil
	}
	return nil, errors.New("crl not found")
}

func (m *mockCertStoreForTCG) VerifyCertificate(*x509.Certificate, *x509.CertPool) error {
	return nil
}

func (m *mockCertStoreForTCG) IsRevoked(*x509.Certificate) (bool, error) {
	return false, nil
}

func (m *mockCertStoreForTCG) Close() error { return nil }

// createTestCAForTCG creates a minimal CA for TCG tests with external signer support.
func createTestCAForTCG(t *testing.T) *CA {
	t.Helper()
	ca := &CA{
		serialGen:   NewSerialGenerator(NewMemoryStorage()),
		certStore:   newMockCertStoreForTCG(),
		revocations: make(map[string]*RevocationInfo),
	}
	ca.initialized.Store(true)
	return ca
}

// createUninitializedTestCA creates a CA that is not initialized.
func createUninitializedTestCA(t *testing.T) *CA {
	t.Helper()
	ca := &CA{
		serialGen:   NewSerialGenerator(NewMemoryStorage()),
		certStore:   newMockCertStoreForTCG(),
		revocations: make(map[string]*RevocationInfo),
	}
	return ca
}

// createSelfSignedCACert creates a self-signed CA cert for use as IssuerCert in tests.
func createSelfSignedCACert(t *testing.T, key crypto.Signer) *x509.Certificate {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Test TCG CA",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatalf("failed to create CA cert: %v", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse CA cert: %v", err)
	}
	return cert
}

// createTestCertRequest creates a CertificateRequest with external signer for testing.
func createTestCertRequest(t *testing.T, signer crypto.Signer, issuerCert *x509.Certificate) *CertificateRequest {
	t.Helper()
	return &CertificateRequest{
		Subject: Subject{
			CommonName:   "Test Device EK",
			Organization: "Test Org",
			Country:      "US",
		},
		Signer:     signer,
		IssuerCert: issuerCert,
	}
}

// hasExtensionOID checks if a certificate contains an extension with the given OID.
func hasExtensionOID(cert *x509.Certificate, oid asn1.ObjectIdentifier) bool {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oid) {
			return true
		}
	}
	return false
}

// hasEKUOID checks whether a certificate's standard ExtKeyUsage extension
// (RFC 5280 section 4.2.1.12) carries the given OID among its
// UnknownExtKeyUsage values. tcg-kp-EKCertificate and tcg-kp-AIKCertificate
// are Extended Key Usage purposes, so a conformant certificate -- and any
// relying party's EKU check, including go-webauthn's "tpm" attestation format
// verifier -- looks for them here, not as a standalone extension under the
// OID's own Id.
func hasEKUOID(cert *x509.Certificate, oid asn1.ObjectIdentifier) bool {
	for _, eku := range cert.UnknownExtKeyUsage {
		if eku.Equal(oid) {
			return true
		}
	}
	return false
}

// =============================================================================
// IssueEKCertificate Tests
// =============================================================================

func TestIssueEKCertificate_ExternalSigner_ECDSA(t *testing.T) {
	ca := createTestCAForTCG(t)
	signerKey := generateTestECDSAKey(t)
	issuerCert := createSelfSignedCACert(t, signerKey)

	// Generate EK key pair (RSA is typical for EKs, but ECDSA also valid)
	ekKey := generateTestECDSAKey(t)

	request := createTestCertRequest(t, signerKey, issuerCert)
	request.Subject.CommonName = "Test EK Certificate"

	cert, err := ca.IssueEKCertificate(context.Background(), request, ekKey.Public())
	if err != nil {
		t.Fatalf("IssueEKCertificate() returned unexpected error: %v", err)
	}

	// Verify subject matches request
	if cert.Subject.CommonName != "Test EK Certificate" {
		t.Errorf("Subject.CommonName = %q, want %q", cert.Subject.CommonName, "Test EK Certificate")
	}
	if len(cert.Subject.Organization) == 0 || cert.Subject.Organization[0] != "Test Org" {
		t.Errorf("Subject.Organization = %v, want [Test Org]", cert.Subject.Organization)
	}

	// Verify KeyUsage is KeyEncipherment per TCG EK profile
	if cert.KeyUsage != x509.KeyUsageKeyEncipherment {
		t.Errorf("KeyUsage = %v, want KeyUsageKeyEncipherment (%v)", cert.KeyUsage, x509.KeyUsageKeyEncipherment)
	}

	// Verify ExtKeyUsage includes ClientAuth and ServerAuth
	if len(cert.ExtKeyUsage) != 2 {
		t.Fatalf("len(ExtKeyUsage) = %d, want 2", len(cert.ExtKeyUsage))
	}
	foundClientAuth := false
	foundServerAuth := false
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageClientAuth {
			foundClientAuth = true
		}
		if eku == x509.ExtKeyUsageServerAuth {
			foundServerAuth = true
		}
	}
	if !foundClientAuth {
		t.Error("ExtKeyUsage missing ClientAuth")
	}
	if !foundServerAuth {
		t.Error("ExtKeyUsage missing ServerAuth")
	}

	// Verify NotAfter is TCG indefinite validity (99991231235959Z)
	if !cert.NotAfter.Equal(tcgNotAfter) {
		t.Errorf("NotAfter = %v, want %v", cert.NotAfter, tcgNotAfter)
	}

	// Verify TCG EK Certificate extended key usage is present
	if !hasEKUOID(cert, OIDTCGKpEKCertificate) {
		t.Error("certificate missing TCG EK Certificate extended key usage (OIDTCGKpEKCertificate)")
	}

	// Verify certificate is not a CA
	if cert.IsCA {
		t.Error("EK certificate should not be a CA")
	}

	// Verify certificate was stored in certStore
	stored, err := ca.certStore.GetCertificate("Test EK Certificate")
	if err != nil {
		t.Fatalf("certificate was not stored in certStore: %v", err)
	}
	if stored.SerialNumber.Cmp(cert.SerialNumber) != 0 {
		t.Error("stored certificate serial does not match returned certificate")
	}
}

func TestIssueEKCertificate_ExternalSigner_RSA(t *testing.T) {
	ca := createTestCAForTCG(t)
	signerKey := generateTestRSAKey(t)
	issuerCert := createSelfSignedCACert(t, signerKey)

	ekKey := generateTestRSAKey(t)

	request := createTestCertRequest(t, signerKey, issuerCert)
	request.Subject.CommonName = "RSA EK Certificate"

	cert, err := ca.IssueEKCertificate(context.Background(), request, ekKey.Public())
	if err != nil {
		t.Fatalf("IssueEKCertificate() with RSA signer returned unexpected error: %v", err)
	}

	if cert.Subject.CommonName != "RSA EK Certificate" {
		t.Errorf("Subject.CommonName = %q, want %q", cert.Subject.CommonName, "RSA EK Certificate")
	}

	// Verify RSA signature algorithm
	if cert.SignatureAlgorithm != x509.SHA256WithRSA {
		t.Errorf("SignatureAlgorithm = %v, want SHA256WithRSA", cert.SignatureAlgorithm)
	}

	// Verify public key is RSA
	if _, ok := cert.PublicKey.(*rsa.PublicKey); !ok {
		t.Errorf("PublicKey type = %T, want *rsa.PublicKey", cert.PublicKey)
	}
}

func TestIssueEKCertificate_WithExtensions(t *testing.T) {
	ca := createTestCAForTCG(t)
	signerKey := generateTestECDSAKey(t)
	issuerCert := createSelfSignedCACert(t, signerKey)

	ekKey := generateTestECDSAKey(t)

	request := createTestCertRequest(t, signerKey, issuerCert)
	request.Subject.CommonName = "EK With Extensions"
	request.ProdModel = "TPM-Model-X"
	request.ProdSerial = "SN-12345"
	request.PermanentID = "device-001"

	cert, err := ca.IssueEKCertificate(context.Background(), request, ekKey.Public())
	if err != nil {
		t.Fatalf("IssueEKCertificate() with extensions returned unexpected error: %v", err)
	}

	// The device's model is a platform attribute, not the TPM's own model.
	if !hasExtensionOID(cert, OIDTCGAttributePlatformModel) {
		t.Error("certificate missing platform model extension")
	}
	if hasExtensionOID(cert, OIDTCGAttributeTPMModel) {
		t.Error("the product model must not be written under tcg-at-tpmModel")
	}
	if hasExtensionOID(cert, OIDTCGAttributeTPMVersion) {
		t.Error("the product serial must not be written under tcg-at-tpmVersion")
	}

	// TCG DevID v1 r12 §8.1 puts the device's serial number in the subject.
	if cert.Subject.SerialNumber != "SN-12345" {
		t.Errorf("Subject.SerialNumber = %q, want %q", cert.Subject.SerialNumber, "SN-12345")
	}

	// The permanent identifier is an RFC 4043 otherName inside subjectAltName,
	// not a standalone extension under the otherName's own OID.
	if hasExtensionOID(cert, OIDPermanentIdentifier) {
		t.Error("permanentIdentifier must not be a standalone extension")
	}
	if !hasExtensionOID(cert, asn1.ObjectIdentifier{2, 5, 29, 17}) {
		t.Error("certificate missing the subjectAltName carrying the permanent identifier")
	}

	// Verify TPM Specification extension is present
	if !hasExtensionOID(cert, OIDTCGAttributeTPMSpecification) {
		t.Error("certificate missing TPM Specification extension")
	}

	// Verify TP KeyStore extension is present
	if !hasExtensionOID(cert, OIDTPKeyStore) {
		t.Error("certificate missing TP KeyStore extension")
	}

	// Verify TP Issuer KeyStore extension is present (issuerKeyStoreType = "external")
	if !hasExtensionOID(cert, OIDTPIssuerKeyStore) {
		t.Error("certificate missing TP Issuer KeyStore extension")
	}
}

func TestIssueEKCertificate_WithSANs(t *testing.T) {
	ca := createTestCAForTCG(t)
	signerKey := generateTestECDSAKey(t)
	issuerCert := createSelfSignedCACert(t, signerKey)

	ekKey := generateTestECDSAKey(t)

	request := createTestCertRequest(t, signerKey, issuerCert)
	request.Subject.CommonName = "EK With SANs"
	request.SANS = &SubjectAlternativeNames{
		DNS:   []string{"device.example.com", "ek.example.com"},
		IPs:   []string{"192.168.1.100", "10.0.0.1"},
		Email: []string{"admin@example.com"},
		URIs:  []string{"urn:example:device:001"},
	}

	cert, err := ca.IssueEKCertificate(context.Background(), request, ekKey.Public())
	if err != nil {
		t.Fatalf("IssueEKCertificate() with SANs returned unexpected error: %v", err)
	}

	// Verify DNS SANs
	if len(cert.DNSNames) != 2 {
		t.Fatalf("len(DNSNames) = %d, want 2", len(cert.DNSNames))
	}
	if cert.DNSNames[0] != "device.example.com" {
		t.Errorf("DNSNames[0] = %q, want %q", cert.DNSNames[0], "device.example.com")
	}
	if cert.DNSNames[1] != "ek.example.com" {
		t.Errorf("DNSNames[1] = %q, want %q", cert.DNSNames[1], "ek.example.com")
	}

	// Verify IP SANs
	if len(cert.IPAddresses) != 2 {
		t.Fatalf("len(IPAddresses) = %d, want 2", len(cert.IPAddresses))
	}
	expectedIP1 := net.ParseIP("192.168.1.100")
	expectedIP2 := net.ParseIP("10.0.0.1")
	if !cert.IPAddresses[0].Equal(expectedIP1) {
		t.Errorf("IPAddresses[0] = %v, want %v", cert.IPAddresses[0], expectedIP1)
	}
	if !cert.IPAddresses[1].Equal(expectedIP2) {
		t.Errorf("IPAddresses[1] = %v, want %v", cert.IPAddresses[1], expectedIP2)
	}

	// Verify Email SANs
	if len(cert.EmailAddresses) != 1 || cert.EmailAddresses[0] != "admin@example.com" {
		t.Errorf("EmailAddresses = %v, want [admin@example.com]", cert.EmailAddresses)
	}

	// Verify URI SANs
	if len(cert.URIs) != 1 || cert.URIs[0].String() != "urn:example:device:001" {
		t.Errorf("URIs = %v, want [urn:example:device:001]", cert.URIs)
	}
}

func TestIssueEKCertificate_NotInitialized(t *testing.T) {
	ca := createUninitializedTestCA(t)

	signerKey := generateTestECDSAKey(t)
	issuerCert := createSelfSignedCACert(t, signerKey)
	ekKey := generateTestECDSAKey(t)

	request := createTestCertRequest(t, signerKey, issuerCert)

	_, err := ca.IssueEKCertificate(context.Background(), request, ekKey.Public())
	if !errors.Is(err, ErrNotInitialized) {
		t.Errorf("IssueEKCertificate() error = %v, want %v", err, ErrNotInitialized)
	}
}

func TestIssueEKCertificate_NilPublicKey(t *testing.T) {
	ca := createTestCAForTCG(t)

	signerKey := generateTestECDSAKey(t)
	issuerCert := createSelfSignedCACert(t, signerKey)

	request := createTestCertRequest(t, signerKey, issuerCert)

	_, err := ca.IssueEKCertificate(context.Background(), request, nil)
	if !errors.Is(err, ErrTCGInvalidPublicKey) {
		t.Errorf("IssueEKCertificate(nil pubkey) error = %v, want %v", err, ErrTCGInvalidPublicKey)
	}
}

func TestIssueEKCertificate_UnsupportedKeyType(t *testing.T) {
	ca := createTestCAForTCG(t)

	signerKey := generateTestECDSAKey(t)
	issuerCert := createSelfSignedCACert(t, signerKey)

	// Ed25519 is not supported for EK certificates (only RSA and ECDSA)
	ed25519Key := generateTestEd25519Key(t)

	request := createTestCertRequest(t, signerKey, issuerCert)

	_, err := ca.IssueEKCertificate(context.Background(), request, ed25519Key.Public())
	if !errors.Is(err, ErrTCGInvalidPublicKey) {
		t.Errorf("IssueEKCertificate(Ed25519) error = %v, want %v", err, ErrTCGInvalidPublicKey)
	}
}

func TestIssueEKCertificate_SignerWithoutIssuerCert(t *testing.T) {
	ca := createTestCAForTCG(t)

	signerKey := generateTestECDSAKey(t)
	ekKey := generateTestECDSAKey(t)

	// Set signer but no issuer cert
	request := &CertificateRequest{
		Subject: Subject{CommonName: "EK Missing Issuer"},
		Signer:  signerKey,
		// IssuerCert intentionally omitted
	}

	_, err := ca.IssueEKCertificate(context.Background(), request, ekKey.Public())
	if !errors.Is(err, ErrTCGInvalidIssuer) {
		t.Errorf("IssueEKCertificate(signer without issuerCert) error = %v, want %v", err, ErrTCGInvalidIssuer)
	}
}

func TestIssueEKCertificate_CertStoreError(t *testing.T) {
	ca := createTestCAForTCG(t)
	store := ca.certStore.(*mockCertStoreForTCG)
	store.storeError = errors.New("storage unavailable")

	signerKey := generateTestECDSAKey(t)
	issuerCert := createSelfSignedCACert(t, signerKey)
	ekKey := generateTestECDSAKey(t)

	request := createTestCertRequest(t, signerKey, issuerCert)
	request.Subject.CommonName = "EK Store Fail"

	_, err := ca.IssueEKCertificate(context.Background(), request, ekKey.Public())
	if !errors.Is(err, ErrStorageError) {
		t.Errorf("IssueEKCertificate() with storage error = %v, want wrapping %v", err, ErrStorageError)
	}
}

func TestIssueEKCertificate_ECDSASigner_RSAPublicKey(t *testing.T) {
	ca := createTestCAForTCG(t)
	signerKey := generateTestECDSAKey(t)
	issuerCert := createSelfSignedCACert(t, signerKey)

	// Use RSA as the EK key with ECDSA CA signer (cross-algorithm)
	ekKey := generateTestRSAKey(t)

	request := createTestCertRequest(t, signerKey, issuerCert)
	request.Subject.CommonName = "Cross-Algorithm EK"

	cert, err := ca.IssueEKCertificate(context.Background(), request, ekKey.Public())
	if err != nil {
		t.Fatalf("IssueEKCertificate() with cross-algorithm returned unexpected error: %v", err)
	}

	// Verify the EK public key is RSA while signature is ECDSA
	if _, ok := cert.PublicKey.(*rsa.PublicKey); !ok {
		t.Errorf("PublicKey type = %T, want *rsa.PublicKey", cert.PublicKey)
	}
	if cert.SignatureAlgorithm != x509.ECDSAWithSHA256 {
		t.Errorf("SignatureAlgorithm = %v, want ECDSAWithSHA256", cert.SignatureAlgorithm)
	}
}

func TestIssueEKCertificate_NoExtensionFields(t *testing.T) {
	ca := createTestCAForTCG(t)
	signerKey := generateTestECDSAKey(t)
	issuerCert := createSelfSignedCACert(t, signerKey)

	ekKey := generateTestECDSAKey(t)

	// Request with no ProdModel, ProdSerial, or PermanentID
	request := createTestCertRequest(t, signerKey, issuerCert)
	request.Subject.CommonName = "Minimal EK"

	cert, err := ca.IssueEKCertificate(context.Background(), request, ekKey.Public())
	if err != nil {
		t.Fatalf("IssueEKCertificate() returned unexpected error: %v", err)
	}

	// Should still have the core TCG EK certificate extended key usage
	if !hasEKUOID(cert, OIDTCGKpEKCertificate) {
		t.Error("certificate missing TCG EK Certificate extended key usage")
	}

	// Should NOT have model/version/permanentID extensions
	if hasExtensionOID(cert, OIDTCGAttributeTPMModel) {
		t.Error("certificate should not have TPM Model extension when ProdModel is empty")
	}
	if hasExtensionOID(cert, OIDTCGAttributeTPMVersion) {
		t.Error("certificate should not have TPM Version extension when ProdSerial is empty")
	}
	if hasExtensionOID(cert, OIDPermanentIdentifier) {
		t.Error("certificate should not have Permanent Identifier extension when PermanentID is empty")
	}
}

// =============================================================================
// IssueAKCertificate Tests
// =============================================================================

func TestIssueAKCertificate_ExternalSigner_ECDSA(t *testing.T) {
	ca := createTestCAForTCG(t)
	signerKey := generateTestECDSAKey(t)
	issuerCert := createSelfSignedCACert(t, signerKey)

	akKey := generateTestECDSAKey(t)

	request := createTestCertRequest(t, signerKey, issuerCert)
	request.Subject.CommonName = "Test AK Certificate"

	cert, err := ca.IssueAKCertificate(context.Background(), request, akKey.Public())
	if err != nil {
		t.Fatalf("IssueAKCertificate() returned unexpected error: %v", err)
	}

	// Verify subject
	if cert.Subject.CommonName != "Test AK Certificate" {
		t.Errorf("Subject.CommonName = %q, want %q", cert.Subject.CommonName, "Test AK Certificate")
	}

	// Verify KeyUsage is DigitalSignature per TCG spec
	if cert.KeyUsage != x509.KeyUsageDigitalSignature {
		t.Errorf("KeyUsage = %v, want KeyUsageDigitalSignature (%v)", cert.KeyUsage, x509.KeyUsageDigitalSignature)
	}

	// Verify TCG AIK Certificate extended key usage is present
	if !hasEKUOID(cert, OIDTCGKpAIKCertificate) {
		t.Error("certificate missing TCG AIK Certificate extended key usage (OIDTCGKpAIKCertificate)")
	}

	// Verify policy OIDs (TCGVerifiedTPMResidencyPolicy, TCGVerifiedTPMFixedPolicy)
	// TCG DevID v1 r12 §8.2: an attestation key asserts residency and
	// restricted; verifiedTPMFixed "MUST NOT be combined" with restricted.
	if len(cert.Policies) < 2 {
		t.Fatalf("len(Policies) = %d, want >= 2", len(cert.Policies))
	}
	foundResidency := false
	foundRestricted := false
	for _, policy := range cert.Policies {
		if policy.Equal(TCGVerifiedTPMResidencyPolicy) {
			foundResidency = true
		}
		if policy.Equal(TCGVerifiedTPMRestrictedPolicy) {
			foundRestricted = true
		}
		if policy.Equal(TCGVerifiedTPMFixedPolicy) {
			t.Error("verifiedTPMFixed must not be combined with verifiedTPMRestricted")
		}
	}
	if !foundResidency {
		t.Error("certificate missing TCGVerifiedTPMResidencyPolicy in Policies")
	}
	if !foundRestricted {
		t.Error("certificate missing TCGVerifiedTPMRestrictedPolicy in Policies")
	}

	// Verify NotAfter is TCG indefinite validity
	if !cert.NotAfter.Equal(tcgNotAfter) {
		t.Errorf("NotAfter = %v, want %v", cert.NotAfter, tcgNotAfter)
	}

	// Verify certificate is not a CA
	if cert.IsCA {
		t.Error("AK certificate should not be a CA")
	}

	// Verify certificate was stored
	stored, err := ca.certStore.GetCertificate("Test AK Certificate")
	if err != nil {
		t.Fatalf("AK certificate was not stored: %v", err)
	}
	if stored.SerialNumber.Cmp(cert.SerialNumber) != 0 {
		t.Error("stored certificate serial does not match returned certificate")
	}
}

func TestIssueAKCertificate_ExternalSigner_Ed25519(t *testing.T) {
	ca := createTestCAForTCG(t)

	// Use Ed25519 signer as the CA signer
	ed25519Key := generateTestEd25519Key(t)
	issuerCert := createSelfSignedCACert(t, ed25519Key)

	// AK key is also Ed25519 (valid for AK per the switch in IssueAKCertificate)
	akEd25519Key := generateTestEd25519Key(t)

	request := &CertificateRequest{
		Subject: Subject{
			CommonName:   "Ed25519 AK Certificate",
			Organization: "Test Org",
		},
		Signer:     ed25519Key,
		IssuerCert: issuerCert,
	}

	cert, err := ca.IssueAKCertificate(context.Background(), request, akEd25519Key.Public())
	if err != nil {
		t.Fatalf("IssueAKCertificate() with Ed25519 returned unexpected error: %v", err)
	}

	// Verify the public key is Ed25519
	if _, ok := cert.PublicKey.(ed25519.PublicKey); !ok {
		t.Errorf("PublicKey type = %T, want ed25519.PublicKey", cert.PublicKey)
	}

	// Verify signature algorithm is PureEd25519
	if cert.SignatureAlgorithm != x509.PureEd25519 {
		t.Errorf("SignatureAlgorithm = %v, want PureEd25519", cert.SignatureAlgorithm)
	}

	// Verify AIK extended key usage is present
	if !hasEKUOID(cert, OIDTCGKpAIKCertificate) {
		t.Error("certificate missing TCG AIK Certificate extended key usage")
	}
}

func TestIssueAKCertificate_ExternalSigner_RSA(t *testing.T) {
	ca := createTestCAForTCG(t)
	signerKey := generateTestRSAKey(t)
	issuerCert := createSelfSignedCACert(t, signerKey)

	akKey := generateTestRSAKey(t)

	request := createTestCertRequest(t, signerKey, issuerCert)
	request.Subject.CommonName = "RSA AK Certificate"

	cert, err := ca.IssueAKCertificate(context.Background(), request, akKey.Public())
	if err != nil {
		t.Fatalf("IssueAKCertificate() with RSA returned unexpected error: %v", err)
	}

	if _, ok := cert.PublicKey.(*rsa.PublicKey); !ok {
		t.Errorf("PublicKey type = %T, want *rsa.PublicKey", cert.PublicKey)
	}
}

func TestIssueAKCertificate_NotInitialized(t *testing.T) {
	ca := createUninitializedTestCA(t)

	signerKey := generateTestECDSAKey(t)
	issuerCert := createSelfSignedCACert(t, signerKey)
	akKey := generateTestECDSAKey(t)

	request := createTestCertRequest(t, signerKey, issuerCert)

	_, err := ca.IssueAKCertificate(context.Background(), request, akKey.Public())
	if !errors.Is(err, ErrNotInitialized) {
		t.Errorf("IssueAKCertificate() error = %v, want %v", err, ErrNotInitialized)
	}
}

func TestIssueAKCertificate_NilPublicKey(t *testing.T) {
	ca := createTestCAForTCG(t)
	signerKey := generateTestECDSAKey(t)
	issuerCert := createSelfSignedCACert(t, signerKey)

	request := createTestCertRequest(t, signerKey, issuerCert)

	_, err := ca.IssueAKCertificate(context.Background(), request, nil)
	if !errors.Is(err, ErrTCGInvalidPublicKey) {
		t.Errorf("IssueAKCertificate(nil pubkey) error = %v, want %v", err, ErrTCGInvalidPublicKey)
	}
}

func TestIssueAKCertificate_UnsupportedKeyType(t *testing.T) {
	ca := createTestCAForTCG(t)
	signerKey := generateTestECDSAKey(t)
	issuerCert := createSelfSignedCACert(t, signerKey)

	request := createTestCertRequest(t, signerKey, issuerCert)

	// Use a type that is not RSA, ECDSA, or Ed25519
	type unsupportedKey struct{}
	var badKey unsupportedKey

	_, err := ca.IssueAKCertificate(context.Background(), request, badKey)
	if !errors.Is(err, ErrTCGInvalidPublicKey) {
		t.Errorf("IssueAKCertificate(unsupported key type) error = %v, want %v", err, ErrTCGInvalidPublicKey)
	}
}

func TestIssueAKCertificate_SignerWithoutIssuerCert(t *testing.T) {
	ca := createTestCAForTCG(t)

	signerKey := generateTestECDSAKey(t)
	akKey := generateTestECDSAKey(t)

	request := &CertificateRequest{
		Subject: Subject{CommonName: "AK Missing Issuer"},
		Signer:  signerKey,
		// IssuerCert intentionally omitted
	}

	_, err := ca.IssueAKCertificate(context.Background(), request, akKey.Public())
	if !errors.Is(err, ErrTCGInvalidIssuer) {
		t.Errorf("IssueAKCertificate(signer without issuerCert) error = %v, want %v", err, ErrTCGInvalidIssuer)
	}
}

func TestIssueAKCertificate_WithSANs(t *testing.T) {
	ca := createTestCAForTCG(t)
	signerKey := generateTestECDSAKey(t)
	issuerCert := createSelfSignedCACert(t, signerKey)

	akKey := generateTestECDSAKey(t)

	request := createTestCertRequest(t, signerKey, issuerCert)
	request.Subject.CommonName = "AK With SANs"
	request.SANS = &SubjectAlternativeNames{
		DNS: []string{"ak.device.example.com"},
		IPs: []string{"10.0.0.42"},
	}

	cert, err := ca.IssueAKCertificate(context.Background(), request, akKey.Public())
	if err != nil {
		t.Fatalf("IssueAKCertificate() with SANs returned unexpected error: %v", err)
	}

	if len(cert.DNSNames) != 1 || cert.DNSNames[0] != "ak.device.example.com" {
		t.Errorf("DNSNames = %v, want [ak.device.example.com]", cert.DNSNames)
	}
	if len(cert.IPAddresses) != 1 || !cert.IPAddresses[0].Equal(net.ParseIP("10.0.0.42")) {
		t.Errorf("IPAddresses = %v, want [10.0.0.42]", cert.IPAddresses)
	}
}

func TestIssueAKCertificate_CertStoreError(t *testing.T) {
	ca := createTestCAForTCG(t)
	store := ca.certStore.(*mockCertStoreForTCG)
	store.storeError = errors.New("storage unavailable")

	signerKey := generateTestECDSAKey(t)
	issuerCert := createSelfSignedCACert(t, signerKey)
	akKey := generateTestECDSAKey(t)

	request := createTestCertRequest(t, signerKey, issuerCert)
	request.Subject.CommonName = "AK Store Fail"

	_, err := ca.IssueAKCertificate(context.Background(), request, akKey.Public())
	if !errors.Is(err, ErrStorageError) {
		t.Errorf("IssueAKCertificate() with storage error = %v, want wrapping %v", err, ErrStorageError)
	}
}

// =============================================================================
// SignTCGCSRIDevID Tests
// =============================================================================

func TestSignTCGCSRIDevID_NilCSR(t *testing.T) {
	ca := createTestCAForTCG(t)

	request := &CertificateRequest{
		Subject: Subject{CommonName: "Device"},
	}

	_, _, err := ca.SignTCGCSRIDevID(context.Background(), nil, request)
	if !errors.Is(err, ErrInvalidCSR) {
		t.Errorf("SignTCGCSRIDevID(nil) error = %v, want %v", err, ErrInvalidCSR)
	}
}

func TestSignTCGCSRIDevID_NotInitialized(t *testing.T) {
	ca := createUninitializedTestCA(t)

	csr := &tpm2.TCG_CSR_IDEVID{}
	request := &CertificateRequest{
		Subject: Subject{CommonName: "Device"},
	}

	_, _, err := ca.SignTCGCSRIDevID(context.Background(), csr, request)
	if !errors.Is(err, ErrNotInitialized) {
		t.Errorf("SignTCGCSRIDevID() error = %v, want %v", err, ErrNotInitialized)
	}
}

func TestSignTCGCSRIDevID_InvalidCSR(t *testing.T) {
	ca := createTestCAForTCG(t)

	signerKey := generateTestECDSAKey(t)
	issuerCert := createSelfSignedCACert(t, signerKey)

	// Empty CSR with no valid content will fail verification
	csr := &tpm2.TCG_CSR_IDEVID{}

	request := &CertificateRequest{
		Subject:    Subject{CommonName: "Device"},
		Signer:     signerKey,
		IssuerCert: issuerCert,
	}

	_, _, err := ca.SignTCGCSRIDevID(context.Background(), csr, request)
	if !errors.Is(err, ErrTCGCSRVerificationFailed) {
		t.Errorf("SignTCGCSRIDevID(empty CSR) error = %v, want %v", err, ErrTCGCSRVerificationFailed)
	}
}

func TestSignTCGCSRIDevID_SignerWithoutIssuerCert(t *testing.T) {
	ca := createTestCAForTCG(t)

	signerKey := generateTestECDSAKey(t)

	// This will fail at CSR verification stage before reaching resolveTCGSigner,
	// because the empty CSR fails verification. We verify the signer-without-cert
	// path through the resolveTCGSigner tests below.
	csr := &tpm2.TCG_CSR_IDEVID{}

	request := &CertificateRequest{
		Subject: Subject{CommonName: "Device"},
		Signer:  signerKey,
		// IssuerCert omitted
	}

	_, _, err := ca.SignTCGCSRIDevID(context.Background(), csr, request)
	// Expect CSR verification to fail first since the CSR is empty
	if err == nil {
		t.Error("SignTCGCSRIDevID() should have returned an error for empty CSR with signer but no issuer cert")
	}
}

// =============================================================================
// resolveTCGSigner Tests
// =============================================================================

func TestResolveTCGSigner_ExternalSigner(t *testing.T) {
	ca := createTestCAForTCG(t)
	signerKey := generateTestECDSAKey(t)
	issuerCert := createSelfSignedCACert(t, signerKey)

	request := &CertificateRequest{
		Subject:    Subject{CommonName: "Test"},
		Signer:     signerKey,
		IssuerCert: issuerCert,
	}

	signer, cert, keystoreType, err := ca.resolveTCGSigner(context.Background(), request)
	if err != nil {
		t.Fatalf("resolveTCGSigner() returned unexpected error: %v", err)
	}

	if signer == nil {
		t.Fatal("resolveTCGSigner() returned nil signer")
	}

	// Verify the signer's public key matches the input
	ecdsaPub, ok := signer.Public().(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("signer public key type = %T, want *ecdsa.PublicKey", signer.Public())
	}
	if !ecdsaPub.Equal(signerKey.Public()) {
		t.Error("signer public key does not match input key")
	}

	// Verify the returned certificate is the issuer cert
	if cert != issuerCert {
		t.Error("returned certificate is not the provided issuer cert")
	}

	// Verify issuer keystore type is "external"
	if keystoreType != "external" {
		t.Errorf("keystoreType = %q, want %q", keystoreType, "external")
	}
}

func TestResolveTCGSigner_SignerWithoutCert(t *testing.T) {
	ca := createTestCAForTCG(t)
	signerKey := generateTestECDSAKey(t)

	request := &CertificateRequest{
		Subject: Subject{CommonName: "Test"},
		Signer:  signerKey,
		// IssuerCert omitted
	}

	_, _, _, err := ca.resolveTCGSigner(context.Background(), request)
	if !errors.Is(err, ErrTCGInvalidIssuer) {
		t.Errorf("resolveTCGSigner(signer without cert) error = %v, want %v", err, ErrTCGInvalidIssuer)
	}
}

func TestResolveTCGSigner_NoSignerNoConfig(t *testing.T) {
	// CA with no internal signer configuration will fail on internal path
	ca := createTestCAForTCG(t)

	request := &CertificateRequest{
		Subject: Subject{CommonName: "Test"},
		// No Signer, no IssuerCert
	}

	_, _, _, err := ca.resolveTCGSigner(context.Background(), request)
	// No internal signer configured, should fail trying to get issuing certificate
	if err == nil {
		t.Error("resolveTCGSigner() should return error when no signer and no internal config")
	}
}

func TestResolveTCGSigner_RSASigner(t *testing.T) {
	ca := createTestCAForTCG(t)
	signerKey := generateTestRSAKey(t)
	issuerCert := createSelfSignedCACert(t, signerKey)

	request := &CertificateRequest{
		Subject:    Subject{CommonName: "Test"},
		Signer:     signerKey,
		IssuerCert: issuerCert,
	}

	signer, cert, keystoreType, err := ca.resolveTCGSigner(context.Background(), request)
	if err != nil {
		t.Fatalf("resolveTCGSigner() with RSA returned unexpected error: %v", err)
	}

	if signer == nil {
		t.Fatal("resolveTCGSigner() returned nil signer")
	}
	if cert == nil {
		t.Fatal("resolveTCGSigner() returned nil certificate")
	}
	if keystoreType != "external" {
		t.Errorf("keystoreType = %q, want %q", keystoreType, "external")
	}
}

// =============================================================================
// Subject Alternative Name Merging (Issuer.Template)
// =============================================================================
//
// Subject alternative names supplied through CertificateSpec.SANS are merged
// onto the template by the canonical issuer. These tests cover that merge for
// the TCG paths, which are the ones that pass SANS in the CA's configuration
// representation rather than as parsed values.

// templateWithSANs builds a template through the canonical issuer carrying
// only the supplied subject alternative names.
func templateWithSANs(t *testing.T, spec *CertificateSpec) *x509.Certificate {
	t.Helper()
	key := generateTestECDSAKey(t)
	spec.Serial = big.NewInt(1)
	spec.Profile = NewTCGDeviceIdentityProfile()
	template, err := (&Issuer{Signer: key}).Template(spec)
	if err != nil {
		t.Fatalf("Template() error = %v", err)
	}
	return template
}

func TestIssuerTemplate_MergesSANs(t *testing.T) {
	template := templateWithSANs(t, &CertificateSpec{
		SANS: &SubjectAlternativeNames{
			DNS:   []string{"foo.example.com", "bar.example.com"},
			IPs:   []string{"10.0.0.1", "192.168.1.1"},
			Email: []string{"test@example.com", "admin@example.com"},
			URIs:  []string{"https://example.com/device", "urn:uuid:12345"},
		},
	})

	if len(template.DNSNames) != 2 || template.DNSNames[0] != "foo.example.com" {
		t.Errorf("DNSNames = %v, want the two configured names in order", template.DNSNames)
	}
	if len(template.IPAddresses) != 2 || template.IPAddresses[0].String() != "10.0.0.1" {
		t.Errorf("IPAddresses = %v, want the two configured addresses in order", template.IPAddresses)
	}
	if len(template.EmailAddresses) != 2 || template.EmailAddresses[1] != "admin@example.com" {
		t.Errorf("EmailAddresses = %v, want the two configured addresses in order", template.EmailAddresses)
	}
	if len(template.URIs) != 2 {
		t.Fatalf("len(URIs) = %d, want 2", len(template.URIs))
	}
	if template.URIs[0].String() != "https://example.com/device" {
		t.Errorf("URIs[0] = %q, want https://example.com/device", template.URIs[0].String())
	}
	if template.URIs[1].String() != "urn:uuid:12345" {
		t.Errorf("URIs[1] = %q, want urn:uuid:12345", template.URIs[1].String())
	}
}

func TestIssuerTemplate_NilSANsLeavesNamesUntouched(t *testing.T) {
	template := templateWithSANs(t, &CertificateSpec{
		DNSNames: []string{"existing.example.com"},
	})

	if len(template.DNSNames) != 1 || template.DNSNames[0] != "existing.example.com" {
		t.Errorf("DNSNames = %v, should be unchanged when no SANS are supplied", template.DNSNames)
	}
}

func TestIssuerTemplate_EmptySANsAddNothing(t *testing.T) {
	template := templateWithSANs(t, &CertificateSpec{
		SANS: &SubjectAlternativeNames{},
	})

	if len(template.DNSNames) != 0 {
		t.Errorf("DNSNames should be empty, got %v", template.DNSNames)
	}
	if len(template.IPAddresses) != 0 {
		t.Errorf("IPAddresses should be empty, got %v", template.IPAddresses)
	}
	if len(template.EmailAddresses) != 0 {
		t.Errorf("EmailAddresses should be empty, got %v", template.EmailAddresses)
	}
	if len(template.URIs) != 0 {
		t.Errorf("URIs should be empty, got %v", template.URIs)
	}
}

func TestIssuerTemplate_SANsAppendToExistingNames(t *testing.T) {
	template := templateWithSANs(t, &CertificateSpec{
		DNSNames:       []string{"existing.example.com"},
		EmailAddresses: []string{"existing@example.com"},
		SANS: &SubjectAlternativeNames{
			DNS:   []string{"new.example.com"},
			Email: []string{"new@example.com"},
		},
	})

	if len(template.DNSNames) != 2 {
		t.Fatalf("len(DNSNames) = %d, want 2", len(template.DNSNames))
	}
	if template.DNSNames[0] != "existing.example.com" {
		t.Errorf("DNSNames[0] = %q, want existing.example.com", template.DNSNames[0])
	}
	if template.DNSNames[1] != "new.example.com" {
		t.Errorf("DNSNames[1] = %q, want new.example.com", template.DNSNames[1])
	}
	if len(template.EmailAddresses) != 2 {
		t.Fatalf("len(EmailAddresses) = %d, want 2", len(template.EmailAddresses))
	}
}

// =============================================================================
// buildIAKExtensions / buildIDevIDExtensions Tests
// =============================================================================
//
// These cover only what the two builders still own. The TCG DevID v1 r12 §8.1
// subjectAltName and the §8.2 certificate policies are asserted on the ISSUED
// certificate in tcg_conformance_test.go, which is where a reader can see what
// a relying party actually receives.

func TestBuildIAKExtensions(t *testing.T) {
	unpacked := &tpm2.UNPACKED_TCG_CSR_IDEVID{
		CsrContents: tpm2.UNPACKED_TCG_IDEVID_CONTENT{
			ProdModel:  []byte("TestTPM-2000"),
			ProdSerial: []byte("SERIAL-XYZ-789"),
			AttestPub:  []byte{0x01, 0x02, 0x03},
		},
	}

	extensions, err := buildIAKExtensions(unpacked, "TPM2")
	if err != nil {
		t.Fatalf("buildIAKExtensions: %v", err)
	}

	extMap := make(map[string]pkix.Extension)
	for _, ext := range extensions {
		extMap[ext.Id.String()] = ext
	}

	// The tcg-kp-AIKCertificate marker is not a standalone extension here: it
	// is an Extended Key Usage purpose that the tcg-iak profile's
	// UnknownExtKeyUsage applies at the certificate template level
	// (NewTCGInitialAttestationKeyProfile / tcgAIKCertificateExtKeyUsage), not
	// something buildIAKExtensions itself produces.
	if _, ok := extMap[OIDTCGKpAIKCertificate.String()]; ok {
		t.Error("AIK Certificate marker must not be a standalone extension")
	}
	if _, ok := extMap[OIDTCGAttributePlatformModel.String()]; !ok {
		t.Error("missing platform model extension")
	}
	if _, ok := extMap[OIDTPKeyStore.String()]; !ok {
		t.Error("missing TP KeyStore extension")
	}
	if _, ok := extMap[OIDTPIssuerKeyStore.String()]; !ok {
		t.Error("missing TP Issuer KeyStore extension")
	}

	// The device's model is not the TPM's model, and the device's serial number
	// is not the TPM's firmware version.
	if _, ok := extMap[OIDTCGAttributeTPMModel.String()]; ok {
		t.Error("the product model must not be written under tcg-at-tpmModel")
	}
	if _, ok := extMap[OIDTCGAttributeTPMVersion.String()]; ok {
		t.Error("the product serial must not be written under tcg-at-tpmVersion")
	}

	// TCG DevID v1 r12 §8.2: the tcg-cap-* assertions are certificate policy
	// identifiers carrying "No data", never standalone extensions.
	if _, ok := extMap[OIDTCGVerifiedTPMResidency.String()]; ok {
		t.Error("verifiedTPMResidency must not be a standalone extension")
	}
	if _, ok := extMap[OIDTCGVerifiedTPMFixed.String()]; ok {
		t.Error("verifiedTPMFixed must not be a standalone extension")
	}
}

func TestBuildIAKExtensions_EmptyProdFields(t *testing.T) {
	unpacked := &tpm2.UNPACKED_TCG_CSR_IDEVID{
		CsrContents: tpm2.UNPACKED_TCG_IDEVID_CONTENT{},
	}

	extensions, err := buildIAKExtensions(unpacked, "")
	if err != nil {
		t.Fatalf("buildIAKExtensions: %v", err)
	}

	extMap := make(map[string]pkix.Extension)
	for _, ext := range extensions {
		extMap[ext.Id.String()] = ext
	}

	if _, ok := extMap[OIDTCGKpAIKCertificate.String()]; ok {
		t.Error("AIK Certificate marker must not be a standalone extension, even with empty prod fields")
	}
	if _, ok := extMap[OIDTCGAttributePlatformModel.String()]; ok {
		t.Error("should not have a platform model extension when ProdModel is empty")
	}
	if _, ok := extMap[OIDTPIssuerKeyStore.String()]; ok {
		t.Error("should not have TP Issuer KeyStore extension when issuerKeyStoreType is empty")
	}
}

func TestBuildIDevIDExtensions(t *testing.T) {
	unpacked := &tpm2.UNPACKED_TCG_CSR_IDEVID{
		CsrContents: tpm2.UNPACKED_TCG_IDEVID_CONTENT{
			ProdModel:  []byte("DeviceModel-100"),
			ProdSerial: []byte("DEV-SERIAL-001"),
		},
	}

	extensions, err := buildIDevIDExtensions(unpacked, "PKCS11")
	if err != nil {
		t.Fatalf("buildIDevIDExtensions: %v", err)
	}

	extMap := make(map[string]pkix.Extension)
	for _, ext := range extensions {
		extMap[ext.Id.String()] = ext
	}

	if _, ok := extMap[OIDTCGKpAIKCertificate.String()]; ok {
		t.Error("IDevID extensions should not include AIK Certificate marker")
	}
	if _, ok := extMap[OIDTCGAttributePlatformModel.String()]; !ok {
		t.Error("missing platform model extension")
	}
	if _, ok := extMap[OIDTPKeyStore.String()]; !ok {
		t.Error("missing TP KeyStore extension")
	}
	if _, ok := extMap[OIDTPIssuerKeyStore.String()]; !ok {
		t.Error("missing TP Issuer KeyStore extension")
	}

	// The permanent identifier is a subjectAltName otherName derived from the
	// endorsement key, not a standalone extension holding model and serial.
	if _, ok := extMap[OIDPermanentIdentifier.String()]; ok {
		t.Error("permanentIdentifier must not be a standalone extension")
	}
}

func TestBuildIDevIDExtensions_NoIssuerKeyStoreType(t *testing.T) {
	unpacked := &tpm2.UNPACKED_TCG_CSR_IDEVID{
		CsrContents: tpm2.UNPACKED_TCG_IDEVID_CONTENT{
			ProdModel:  []byte("Model"),
			ProdSerial: []byte("Serial"),
		},
	}

	extensions, err := buildIDevIDExtensions(unpacked, "")
	if err != nil {
		t.Fatalf("buildIDevIDExtensions: %v", err)
	}

	for _, ext := range extensions {
		if ext.Id.Equal(OIDTPIssuerKeyStore) {
			t.Error("should not include TP Issuer KeyStore extension when issuerKeyStoreType is empty")
		}
	}
}

// =============================================================================
// Concurrent Access Tests
// =============================================================================

func TestIssueEKCertificate_ConcurrentAccess(t *testing.T) {
	ca := createTestCAForTCG(t)
	signerKey := generateTestECDSAKey(t)
	issuerCert := createSelfSignedCACert(t, signerKey)

	const numGoroutines = 10
	errCh := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(idx int) {
			ekKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				errCh <- err
				return
			}
			request := &CertificateRequest{
				Subject: Subject{
					CommonName: "Concurrent EK " + big.NewInt(int64(idx)).String(),
				},
				Signer:     signerKey,
				IssuerCert: issuerCert,
			}
			_, err = ca.IssueEKCertificate(context.Background(), request, ekKey.Public())
			errCh <- err
		}(i)
	}

	for i := 0; i < numGoroutines; i++ {
		if err := <-errCh; err != nil {
			t.Errorf("concurrent IssueEKCertificate() goroutine error: %v", err)
		}
	}
}

func TestIssueAKCertificate_ConcurrentAccess(t *testing.T) {
	ca := createTestCAForTCG(t)
	signerKey := generateTestECDSAKey(t)
	issuerCert := createSelfSignedCACert(t, signerKey)

	const numGoroutines = 10
	errCh := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(idx int) {
			akKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				errCh <- err
				return
			}
			request := &CertificateRequest{
				Subject: Subject{
					CommonName: "Concurrent AK " + big.NewInt(int64(idx)).String(),
				},
				Signer:     signerKey,
				IssuerCert: issuerCert,
			}
			_, err = ca.IssueAKCertificate(context.Background(), request, akKey.Public())
			errCh <- err
		}(i)
	}

	for i := 0; i < numGoroutines; i++ {
		if err := <-errCh; err != nil {
			t.Errorf("concurrent IssueAKCertificate() goroutine error: %v", err)
		}
	}
}

// =============================================================================
// Serial Number Uniqueness Tests
// =============================================================================

func TestIssueEKAndAKCertificates_UniqueSerials(t *testing.T) {
	ca := createTestCAForTCG(t)
	signerKey := generateTestECDSAKey(t)
	issuerCert := createSelfSignedCACert(t, signerKey)

	serials := make(map[string]bool)

	// Issue multiple EK and AK certificates and verify unique serial numbers
	for i := 0; i < 5; i++ {
		ekKey := generateTestECDSAKey(t)
		request := &CertificateRequest{
			Subject: Subject{
				CommonName: "EK-" + big.NewInt(int64(i)).String(),
			},
			Signer:     signerKey,
			IssuerCert: issuerCert,
		}

		cert, err := ca.IssueEKCertificate(context.Background(), request, ekKey.Public())
		if err != nil {
			t.Fatalf("IssueEKCertificate() iteration %d returned error: %v", i, err)
		}

		serialStr := cert.SerialNumber.String()
		if serials[serialStr] {
			t.Errorf("duplicate serial number detected: %s", serialStr)
		}
		serials[serialStr] = true
	}

	for i := 0; i < 5; i++ {
		akKey := generateTestECDSAKey(t)
		request := &CertificateRequest{
			Subject: Subject{
				CommonName: "AK-" + big.NewInt(int64(i)).String(),
			},
			Signer:     signerKey,
			IssuerCert: issuerCert,
		}

		cert, err := ca.IssueAKCertificate(context.Background(), request, akKey.Public())
		if err != nil {
			t.Fatalf("IssueAKCertificate() iteration %d returned error: %v", i, err)
		}

		serialStr := cert.SerialNumber.String()
		if serials[serialStr] {
			t.Errorf("duplicate serial number detected: %s", serialStr)
		}
		serials[serialStr] = true
	}
}

// =============================================================================
// NotBefore Clock Skew Tests
// =============================================================================

func TestIssueEKCertificate_NotBeforeBackdated(t *testing.T) {
	ca := createTestCAForTCG(t)
	signerKey := generateTestECDSAKey(t)
	issuerCert := createSelfSignedCACert(t, signerKey)
	ekKey := generateTestECDSAKey(t)

	before := time.Now()
	request := createTestCertRequest(t, signerKey, issuerCert)
	request.Subject.CommonName = "Backdated EK"

	cert, err := ca.IssueEKCertificate(context.Background(), request, ekKey.Public())
	if err != nil {
		t.Fatalf("IssueEKCertificate() returned unexpected error: %v", err)
	}

	// NotBefore should be backdated by ~1 minute
	expectedNotBefore := before.Add(-1 * time.Minute)
	if cert.NotBefore.After(expectedNotBefore.Add(5 * time.Second)) {
		t.Errorf("NotBefore = %v, expected to be backdated by ~1 minute from %v", cert.NotBefore, before)
	}
	if cert.NotBefore.After(before) {
		t.Errorf("NotBefore = %v, should be before current time %v", cert.NotBefore, before)
	}
}

func TestIssueAKCertificate_NotBeforeBackdated(t *testing.T) {
	ca := createTestCAForTCG(t)
	signerKey := generateTestECDSAKey(t)
	issuerCert := createSelfSignedCACert(t, signerKey)
	akKey := generateTestECDSAKey(t)

	before := time.Now()
	request := createTestCertRequest(t, signerKey, issuerCert)
	request.Subject.CommonName = "Backdated AK"

	cert, err := ca.IssueAKCertificate(context.Background(), request, akKey.Public())
	if err != nil {
		t.Fatalf("IssueAKCertificate() returned unexpected error: %v", err)
	}

	expectedNotBefore := before.Add(-1 * time.Minute)
	if cert.NotBefore.After(expectedNotBefore.Add(5 * time.Second)) {
		t.Errorf("NotBefore = %v, expected to be backdated by ~1 minute from %v", cert.NotBefore, before)
	}
}

// =============================================================================
// TCG-specific Extension Value Verification Tests
// =============================================================================

func TestIssueEKCertificate_TPMSpecificationExtension(t *testing.T) {
	ca := createTestCAForTCG(t)
	signerKey := generateTestECDSAKey(t)
	issuerCert := createSelfSignedCACert(t, signerKey)
	ekKey := generateTestECDSAKey(t)

	request := createTestCertRequest(t, signerKey, issuerCert)
	request.Subject.CommonName = "EK Spec Test"

	cert, err := ca.IssueEKCertificate(context.Background(), request, ekKey.Public())
	if err != nil {
		t.Fatalf("IssueEKCertificate() returned unexpected error: %v", err)
	}

	// Find and parse the TPM Specification extension
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(OIDTCGAttributeTPMSpecification) {
			spec, err := ParseTPMSpecificationExtension(ext.Value)
			if err != nil {
				t.Fatalf("failed to parse TPM Specification extension: %v", err)
			}
			if spec.Family != "2.0" {
				t.Errorf("TPM Specification Family = %q, want %q", spec.Family, "2.0")
			}
			return
		}
	}
	t.Error("TPM Specification extension not found")
}

func TestIssueEKCertificate_IssuerFieldsMatchSigningCert(t *testing.T) {
	ca := createTestCAForTCG(t)
	signerKey := generateTestECDSAKey(t)
	issuerCert := createSelfSignedCACert(t, signerKey)
	ekKey := generateTestECDSAKey(t)

	request := createTestCertRequest(t, signerKey, issuerCert)
	request.Subject.CommonName = "EK Issuer Check"

	cert, err := ca.IssueEKCertificate(context.Background(), request, ekKey.Public())
	if err != nil {
		t.Fatalf("IssueEKCertificate() returned unexpected error: %v", err)
	}

	// Verify issuer matches the signing certificate's subject
	if cert.Issuer.CommonName != issuerCert.Subject.CommonName {
		t.Errorf("Issuer.CommonName = %q, want %q", cert.Issuer.CommonName, issuerCert.Subject.CommonName)
	}
}

// =============================================================================
// ECDSA Curve Variants
// =============================================================================

func TestIssueEKCertificate_ECDSA_P384(t *testing.T) {
	ca := createTestCAForTCG(t)

	// Use P-384 signer
	signerKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate P-384 key: %v", err)
	}
	issuerCert := createSelfSignedCACert(t, signerKey)

	ekKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate P-384 EK key: %v", err)
	}

	request := createTestCertRequest(t, signerKey, issuerCert)
	request.Subject.CommonName = "P384 EK"

	cert, err := ca.IssueEKCertificate(context.Background(), request, ekKey.Public())
	if err != nil {
		t.Fatalf("IssueEKCertificate() with P-384 returned unexpected error: %v", err)
	}

	if cert.SignatureAlgorithm != x509.ECDSAWithSHA384 {
		t.Errorf("SignatureAlgorithm = %v, want ECDSAWithSHA384", cert.SignatureAlgorithm)
	}
}

// TestIssueEKCertificate_ManufacturerReadableByDevIDEnrollment is the
// regression for an endorse-01 EK certificate whose manufacturer code no DevID
// enrollment could read: it was written as a bare extension under the
// attribute's own OID, so SignTCGCSRIDevID refused every TPM endorsed here with
// ErrTCGEKManufacturerUnknown. The code must round-trip through the reader the
// DevID path uses, with no override supplied.
func TestIssueEKCertificate_ManufacturerReadableByDevIDEnrollment(t *testing.T) {
	ca := createTestCAForTCG(t)
	signerKey := generateTestECDSAKey(t)
	issuerCert := createSelfSignedCACert(t, signerKey)
	ekKey := generateTestECDSAKey(t)

	const manufacturer = "id:49465800"
	request := createTestCertRequest(t, signerKey, issuerCert)
	request.Subject.CommonName = "lab-node-5-ek"
	request.PermanentID = "device-001"
	request.TPMManufacturer = manufacturer

	cert, err := ca.IssueEKCertificate(context.Background(), request, ekKey.Public())
	if err != nil {
		t.Fatalf("IssueEKCertificate() returned unexpected error: %v", err)
	}

	if hasExtensionOID(cert, OIDTCGAttributeTPMManufacturer) {
		t.Error("tcg-at-tpmManufacturer must not be a standalone extension")
	}
	got, err := TCGTPMManufacturer(cert)
	if err != nil {
		t.Fatalf("TCGTPMManufacturer() = %v, want the issued code", err)
	}
	if got != manufacturer {
		t.Errorf("TCGTPMManufacturer() = %q, want %q", got, manufacturer)
	}

	identity, err := TCGDeviceIdentityFromEKCertificate(cert, "")
	if err != nil {
		t.Fatalf("TCGDeviceIdentityFromEKCertificate() with no override = %v", err)
	}
	if !strings.HasPrefix(identity.HardwareSerialNumber, manufacturer+":") {
		t.Errorf("HardwareSerialNumber = %q, want the %q prefix", identity.HardwareSerialNumber, manufacturer)
	}
	if _, ok := parsedOtherNames(t, cert)[OIDPermanentIdentifier.String()]; !ok {
		t.Error("the permanent identifier must share the subjectAltName with the manufacturer")
	}
}

// TestIssueEKCertificate_RefusesMalformedManufacturer covers the error path:
// a code that is not in the tcg-at-tpmManufacturer form would identify no TPM,
// so no certificate is issued.
func TestIssueEKCertificate_RefusesMalformedManufacturer(t *testing.T) {
	ca := createTestCAForTCG(t)
	signerKey := generateTestECDSAKey(t)
	issuerCert := createSelfSignedCACert(t, signerKey)
	ekKey := generateTestECDSAKey(t)

	request := createTestCertRequest(t, signerKey, issuerCert)
	request.Subject.CommonName = "bad-manufacturer-ek"
	request.TPMManufacturer = "Infineon"

	cert, err := ca.IssueEKCertificate(context.Background(), request, ekKey.Public())
	if !errors.Is(err, ErrTCGInvalidManufacturerCode) {
		t.Fatalf("IssueEKCertificate() error = %v, want %v", err, ErrTCGInvalidManufacturerCode)
	}
	if cert != nil {
		t.Error("no certificate may be issued for a malformed manufacturer code")
	}
}

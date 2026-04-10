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
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"
)

// =============================================================================
// Test Certificate Generation Helpers
// =============================================================================

// generateRootCert creates a self-signed root CA certificate for testing.
func generateRootCert(t *testing.T, key interface{}, subject string) *x509.Certificate {
	t.Helper()

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("Failed to generate serial number: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   subject,
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	var pubKey interface{}
	switch k := key.(type) {
	case *rsa.PrivateKey:
		pubKey = &k.PublicKey
	case *ecdsa.PrivateKey:
		pubKey = &k.PublicKey
	case ed25519.PrivateKey:
		pubKey = k.Public()
	default:
		t.Fatalf("Unsupported key type: %T", key)
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, pubKey, key)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	return cert
}

// generateIntermediateCertWithParent creates an intermediate CA certificate signed by a parent.
func generateIntermediateCertWithParent(t *testing.T, key interface{}, subject string, parent *x509.Certificate, parentKey interface{}, pathLen int) *x509.Certificate {
	t.Helper()

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("Failed to generate serial number: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   subject,
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	if pathLen >= 0 {
		template.MaxPathLen = pathLen
		template.MaxPathLenZero = (pathLen == 0)
	}

	var pubKey interface{}
	switch k := key.(type) {
	case *rsa.PrivateKey:
		pubKey = &k.PublicKey
	case *ecdsa.PrivateKey:
		pubKey = &k.PublicKey
	case ed25519.PrivateKey:
		pubKey = k.Public()
	default:
		t.Fatalf("Unsupported key type: %T", key)
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, parent, pubKey, parentKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	return cert
}

// generateLeafCert creates a non-CA (leaf) certificate for testing.
func generateLeafCert(t *testing.T, key interface{}, subject string, parent *x509.Certificate, parentKey interface{}) *x509.Certificate {
	t.Helper()

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("Failed to generate serial number: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   subject,
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	var pubKey interface{}
	switch k := key.(type) {
	case *rsa.PrivateKey:
		pubKey = &k.PublicKey
	case *ecdsa.PrivateKey:
		pubKey = &k.PublicKey
	case ed25519.PrivateKey:
		pubKey = k.Public()
	default:
		t.Fatalf("Unsupported key type: %T", key)
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, parent, pubKey, parentKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	return cert
}

// mockCertificateProvider implements CertificateProvider for testing.
type mockCertificateProvider struct {
	cert      *x509.Certificate
	storeType string
}

func (m *mockCertificateProvider) Certificate() *x509.Certificate {
	return m.cert
}

func (m *mockCertificateProvider) StoreType() string {
	return m.storeType
}

// =============================================================================
// SimpleCertificate Tests
// =============================================================================

func TestSimpleCertificate_NewSimpleCertificate_WithValidCert(t *testing.T) {
	t.Parallel()

	key := generateTestRSAKey(t)
	cert := generateRootCert(t, key, "Test Root CA")

	sc := NewSimpleCertificate(cert, StoreTypeSoftware)

	if sc == nil {
		t.Fatal("NewSimpleCertificate returned nil")
	}

	if sc.Certificate() != cert {
		t.Error("Certificate() did not return the expected certificate")
	}

	if sc.StoreType() != StoreTypeSoftware {
		t.Errorf("StoreType(): expected %q, got %q", StoreTypeSoftware, sc.StoreType())
	}
}

func TestSimpleCertificate_NewSimpleCertificate_WithDifferentStoreTypes(t *testing.T) {
	t.Parallel()

	key := generateTestRSAKey(t)
	cert := generateRootCert(t, key, "Test Root CA")

	tests := []struct {
		name      string
		storeType string
	}{
		{"software", StoreTypeSoftware},
		{"tpm2", StoreTypeTPM2},
		{"pkcs11", StoreTypePKCS11},
		{"empty", StoreTypeAll},
		{"custom", "custom-store"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sc := NewSimpleCertificate(cert, tc.storeType)

			if sc.StoreType() != tc.storeType {
				t.Errorf("StoreType(): expected %q, got %q", tc.storeType, sc.StoreType())
			}
		})
	}
}

func TestSimpleCertificate_Certificate_ReturnsCorrectCert(t *testing.T) {
	t.Parallel()

	key := generateTestECDSAKey(t)
	cert := generateRootCert(t, key, "ECDSA Root CA")

	sc := NewSimpleCertificate(cert, StoreTypeTPM2)

	result := sc.Certificate()
	if result != cert {
		t.Error("Certificate() did not return the expected certificate")
	}

	if result.Subject.CommonName != "ECDSA Root CA" {
		t.Errorf("Certificate CommonName: expected %q, got %q", "ECDSA Root CA", result.Subject.CommonName)
	}
}

func TestSimpleCertificate_StoreType_ReturnsCorrectType(t *testing.T) {
	t.Parallel()

	key := generateTestRSAKey(t)
	cert := generateRootCert(t, key, "Test CA")

	sc := NewSimpleCertificate(cert, StoreTypePKCS11)

	if sc.StoreType() != StoreTypePKCS11 {
		t.Errorf("StoreType(): expected %q, got %q", StoreTypePKCS11, sc.StoreType())
	}
}

func TestSimpleCertificate_WithNilCert(t *testing.T) {
	t.Parallel()

	sc := NewSimpleCertificate(nil, StoreTypeSoftware)

	if sc == nil {
		t.Fatal("NewSimpleCertificate returned nil")
	}

	if sc.Certificate() != nil {
		t.Error("Certificate() should return nil for nil certificate input")
	}

	if sc.StoreType() != StoreTypeSoftware {
		t.Errorf("StoreType(): expected %q, got %q", StoreTypeSoftware, sc.StoreType())
	}
}

// =============================================================================
// DefaultCABundler Constructor Tests
// =============================================================================

func TestNewDefaultCABundler_WithValidCerts(t *testing.T) {
	t.Parallel()

	key1 := generateTestRSAKey(t)
	key2 := generateTestRSAKey(t)
	cert1 := generateRootCert(t, key1, "Root CA 1")
	cert2 := generateRootCert(t, key2, "Root CA 2")

	bundler := NewDefaultCABundler([]*x509.Certificate{cert1, cert2})

	if bundler == nil {
		t.Fatal("NewDefaultCABundler returned nil")
	}

	if bundler.Count() != 2 {
		t.Errorf("Count(): expected 2, got %d", bundler.Count())
	}
}

func TestNewDefaultCABundler_WithNilCertsFiltered(t *testing.T) {
	t.Parallel()

	key := generateTestRSAKey(t)
	cert := generateRootCert(t, key, "Root CA")

	bundler := NewDefaultCABundler([]*x509.Certificate{cert, nil, nil})

	if bundler.Count() != 1 {
		t.Errorf("Count(): expected 1 (nil certs filtered), got %d", bundler.Count())
	}
}

func TestNewDefaultCABundler_WithEmptySlice(t *testing.T) {
	t.Parallel()

	bundler := NewDefaultCABundler([]*x509.Certificate{})

	if bundler == nil {
		t.Fatal("NewDefaultCABundler returned nil")
	}

	if bundler.Count() != 0 {
		t.Errorf("Count(): expected 0, got %d", bundler.Count())
	}
}

func TestNewDefaultCABundler_WithAllNilCerts(t *testing.T) {
	t.Parallel()

	bundler := NewDefaultCABundler([]*x509.Certificate{nil, nil, nil})

	if bundler.Count() != 0 {
		t.Errorf("Count(): expected 0 (all nil certs), got %d", bundler.Count())
	}
}

func TestNewDefaultCABundlerWithProviders_WithValidProviders(t *testing.T) {
	t.Parallel()

	key1 := generateTestRSAKey(t)
	key2 := generateTestECDSAKey(t)
	cert1 := generateRootCert(t, key1, "RSA Root")
	cert2 := generateRootCert(t, key2, "ECDSA Root")

	providers := []CertificateProvider{
		&mockCertificateProvider{cert: cert1, storeType: StoreTypeSoftware},
		&mockCertificateProvider{cert: cert2, storeType: StoreTypeTPM2},
	}

	bundler := NewDefaultCABundlerWithProviders(providers)

	if bundler == nil {
		t.Fatal("NewDefaultCABundlerWithProviders returned nil")
	}

	if bundler.Count() != 2 {
		t.Errorf("Count(): expected 2, got %d", bundler.Count())
	}
}

func TestNewDefaultCABundlerWithProviders_WithNilProvidersFiltered(t *testing.T) {
	t.Parallel()

	key := generateTestRSAKey(t)
	cert := generateRootCert(t, key, "Root CA")

	providers := []CertificateProvider{
		&mockCertificateProvider{cert: cert, storeType: StoreTypeSoftware},
		nil,
		&mockCertificateProvider{cert: nil, storeType: StoreTypeTPM2},
	}

	bundler := NewDefaultCABundlerWithProviders(providers)

	if bundler.Count() != 1 {
		t.Errorf("Count(): expected 1 (nil providers filtered), got %d", bundler.Count())
	}
}

func TestNewDefaultCABundlerWithProviders_WithEmptySlice(t *testing.T) {
	t.Parallel()

	bundler := NewDefaultCABundlerWithProviders([]CertificateProvider{})

	if bundler == nil {
		t.Fatal("NewDefaultCABundlerWithProviders returned nil")
	}

	if bundler.Count() != 0 {
		t.Errorf("Count(): expected 0, got %d", bundler.Count())
	}
}

// =============================================================================
// Algorithm Filter Tests
// =============================================================================

func TestIsRSACertificate_WithRSACert(t *testing.T) {
	t.Parallel()

	key := generateTestRSAKey(t)
	cert := generateRootCert(t, key, "RSA Root CA")

	if !isRSACertificate(cert) {
		t.Error("isRSACertificate() should return true for RSA certificate")
	}
}

func TestIsRSACertificate_WithNonRSACert(t *testing.T) {
	t.Parallel()

	key := generateTestECDSAKey(t)
	cert := generateRootCert(t, key, "ECDSA Root CA")

	if isRSACertificate(cert) {
		t.Error("isRSACertificate() should return false for ECDSA certificate")
	}
}

func TestIsRSACertificate_WithEd25519Cert(t *testing.T) {
	t.Parallel()

	key := generateTestEd25519Key(t)
	cert := generateRootCert(t, key, "Ed25519 Root CA")

	if isRSACertificate(cert) {
		t.Error("isRSACertificate() should return false for Ed25519 certificate")
	}
}

func TestIsECDSACertificate_WithECDSACert(t *testing.T) {
	t.Parallel()

	key := generateTestECDSAKey(t)
	cert := generateRootCert(t, key, "ECDSA Root CA")

	if !isECDSACertificate(cert) {
		t.Error("isECDSACertificate() should return true for ECDSA certificate")
	}
}

func TestIsECDSACertificate_WithNonECDSACert(t *testing.T) {
	t.Parallel()

	key := generateTestRSAKey(t)
	cert := generateRootCert(t, key, "RSA Root CA")

	if isECDSACertificate(cert) {
		t.Error("isECDSACertificate() should return false for RSA certificate")
	}
}

func TestIsEd25519Certificate_WithEd25519Cert(t *testing.T) {
	t.Parallel()

	key := generateTestEd25519Key(t)
	cert := generateRootCert(t, key, "Ed25519 Root CA")

	if !isEd25519Certificate(cert) {
		t.Error("isEd25519Certificate() should return true for Ed25519 certificate")
	}
}

func TestIsEd25519Certificate_WithNonEd25519Cert(t *testing.T) {
	t.Parallel()

	key := generateTestRSAKey(t)
	cert := generateRootCert(t, key, "RSA Root CA")

	if isEd25519Certificate(cert) {
		t.Error("isEd25519Certificate() should return false for RSA certificate")
	}
}

func TestMatchAllAlgorithms_ReturnsTrue(t *testing.T) {
	t.Parallel()

	rsaKey := generateTestRSAKey(t)
	ecdsaKey := generateTestECDSAKey(t)
	ed25519Key := generateTestEd25519Key(t)

	rsaCert := generateRootCert(t, rsaKey, "RSA CA")
	ecdsaCert := generateRootCert(t, ecdsaKey, "ECDSA CA")
	ed25519Cert := generateRootCert(t, ed25519Key, "Ed25519 CA")

	if !matchAllAlgorithms(rsaCert) {
		t.Error("matchAllAlgorithms() should return true for RSA certificate")
	}

	if !matchAllAlgorithms(ecdsaCert) {
		t.Error("matchAllAlgorithms() should return true for ECDSA certificate")
	}

	if !matchAllAlgorithms(ed25519Cert) {
		t.Error("matchAllAlgorithms() should return true for Ed25519 certificate")
	}
}

// =============================================================================
// CABundle Tests
// =============================================================================

func TestCABundle_ReturnsPEMEncodedBundle(t *testing.T) {
	t.Parallel()

	key := generateTestRSAKey(t)
	cert := generateRootCert(t, key, "Root CA")

	bundler := NewDefaultCABundler([]*x509.Certificate{cert})

	pemData, err := bundler.CABundle(StoreTypeAll, AlgorithmAll)
	if err != nil {
		t.Fatalf("CABundle() error: %v", err)
	}

	if len(pemData) == 0 {
		t.Error("CABundle() returned empty data")
	}

	block, _ := pem.Decode(pemData)
	if block == nil {
		t.Fatal("Failed to decode PEM block")
	}

	if block.Type != "CERTIFICATE" {
		t.Errorf("PEM block type: expected %q, got %q", "CERTIFICATE", block.Type)
	}

	parsedCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse certificate from PEM: %v", err)
	}

	if parsedCert.Subject.CommonName != "Root CA" {
		t.Errorf("Certificate CommonName: expected %q, got %q", "Root CA", parsedCert.Subject.CommonName)
	}
}

func TestCABundle_FiltersByAlgorithm(t *testing.T) {
	t.Parallel()

	rsaKey := generateTestRSAKey(t)
	ecdsaKey := generateTestECDSAKey(t)
	ed25519Key := generateTestEd25519Key(t)

	rsaCert := generateRootCert(t, rsaKey, "RSA Root")
	ecdsaCert := generateRootCert(t, ecdsaKey, "ECDSA Root")
	ed25519Cert := generateRootCert(t, ed25519Key, "Ed25519 Root")

	bundler := NewDefaultCABundler([]*x509.Certificate{rsaCert, ecdsaCert, ed25519Cert})

	tests := []struct {
		name          string
		algorithm     string
		expectedCount int
		expectedSubj  string
	}{
		{"RSA filter", AlgorithmRSA, 1, "RSA Root"},
		{"ECDSA filter", AlgorithmECDSA, 1, "ECDSA Root"},
		{"Ed25519 filter", AlgorithmEd25519, 1, "Ed25519 Root"},
		{"All algorithms", AlgorithmAll, 3, ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			certs, err := bundler.CABundleCerts(StoreTypeAll, tc.algorithm)
			if err != nil {
				t.Fatalf("CABundleCerts() error: %v", err)
			}

			if len(certs) != tc.expectedCount {
				t.Errorf("Certificate count: expected %d, got %d", tc.expectedCount, len(certs))
			}

			if tc.expectedSubj != "" && certs[0].Subject.CommonName != tc.expectedSubj {
				t.Errorf("Certificate subject: expected %q, got %q", tc.expectedSubj, certs[0].Subject.CommonName)
			}
		})
	}
}

func TestCABundle_ReturnsErrNoCACertificates_ForEmptyBundler(t *testing.T) {
	t.Parallel()

	bundler := NewDefaultCABundler([]*x509.Certificate{})

	_, err := bundler.CABundle(StoreTypeAll, AlgorithmAll)

	if !errors.Is(err, ErrNoCACertificates) {
		t.Errorf("CABundle() error: expected ErrNoCACertificates, got %v", err)
	}
}

func TestCABundle_ReturnsErrNoCertificatesMatch_WhenNoMatch(t *testing.T) {
	t.Parallel()

	rsaKey := generateTestRSAKey(t)
	rsaCert := generateRootCert(t, rsaKey, "RSA Root")

	bundler := NewDefaultCABundler([]*x509.Certificate{rsaCert})

	_, err := bundler.CABundle(StoreTypeAll, AlgorithmECDSA)

	if !errors.Is(err, ErrNoCertificatesMatch) {
		t.Errorf("CABundle() error: expected ErrNoCertificatesMatch, got %v", err)
	}
}

func TestCABundle_ReturnsErrNoCertificatesMatch_ForUnknownAlgorithm(t *testing.T) {
	t.Parallel()

	rsaKey := generateTestRSAKey(t)
	rsaCert := generateRootCert(t, rsaKey, "RSA Root")

	bundler := NewDefaultCABundler([]*x509.Certificate{rsaCert})

	_, err := bundler.CABundle(StoreTypeAll, "UNKNOWN_ALG")

	if !errors.Is(err, ErrNoCertificatesMatch) {
		t.Errorf("CABundle() error: expected ErrNoCertificatesMatch, got %v", err)
	}
}

// =============================================================================
// CABundleCerts Tests
// =============================================================================

func TestCABundleCerts_ReturnsCertsInCorrectOrder(t *testing.T) {
	t.Parallel()

	rootKey := generateTestRSAKey(t)
	intermediateKey := generateTestRSAKey(t)

	rootCert := generateRootCert(t, rootKey, "Root CA")
	intermediateCert := generateIntermediateCertWithParent(t, intermediateKey, "Intermediate CA", rootCert, rootKey, 0)

	bundler := NewDefaultCABundler([]*x509.Certificate{rootCert, intermediateCert})

	certs, err := bundler.CABundleCerts(StoreTypeAll, AlgorithmAll)
	if err != nil {
		t.Fatalf("CABundleCerts() error: %v", err)
	}

	if len(certs) != 2 {
		t.Fatalf("Certificate count: expected 2, got %d", len(certs))
	}

	// Intermediate should come before root
	if certs[0].Subject.CommonName != "Intermediate CA" {
		t.Errorf("First cert: expected %q, got %q", "Intermediate CA", certs[0].Subject.CommonName)
	}

	if certs[1].Subject.CommonName != "Root CA" {
		t.Errorf("Second cert: expected %q, got %q", "Root CA", certs[1].Subject.CommonName)
	}
}

func TestCABundleCerts_FiltersByStoreType(t *testing.T) {
	t.Parallel()

	key1 := generateTestRSAKey(t)
	key2 := generateTestRSAKey(t)
	softwareCert := generateRootCert(t, key1, "Software Root")
	tpm2Cert := generateRootCert(t, key2, "TPM2 Root")

	providers := []CertificateProvider{
		&mockCertificateProvider{cert: softwareCert, storeType: StoreTypeSoftware},
		&mockCertificateProvider{cert: tpm2Cert, storeType: StoreTypeTPM2},
	}

	bundler := NewDefaultCABundlerWithProviders(providers)

	tests := []struct {
		name          string
		storeType     string
		expectedCount int
		expectedSubj  string
	}{
		{"software filter", StoreTypeSoftware, 1, "Software Root"},
		{"tpm2 filter", StoreTypeTPM2, 1, "TPM2 Root"},
		{"all stores", StoreTypeAll, 2, ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			certs, err := bundler.CABundleCerts(tc.storeType, AlgorithmAll)
			if err != nil {
				t.Fatalf("CABundleCerts() error: %v", err)
			}

			if len(certs) != tc.expectedCount {
				t.Errorf("Certificate count: expected %d, got %d", tc.expectedCount, len(certs))
			}

			if tc.expectedSubj != "" && certs[0].Subject.CommonName != tc.expectedSubj {
				t.Errorf("Certificate subject: expected %q, got %q", tc.expectedSubj, certs[0].Subject.CommonName)
			}
		})
	}
}

func TestCABundleCerts_FiltersByAlgorithm(t *testing.T) {
	t.Parallel()

	rsaKey := generateTestRSAKey(t)
	ecdsaKey := generateTestECDSAKey(t)
	rsaCert := generateRootCert(t, rsaKey, "RSA Root")
	ecdsaCert := generateRootCert(t, ecdsaKey, "ECDSA Root")

	bundler := NewDefaultCABundler([]*x509.Certificate{rsaCert, ecdsaCert})

	certs, err := bundler.CABundleCerts(StoreTypeAll, AlgorithmECDSA)
	if err != nil {
		t.Fatalf("CABundleCerts() error: %v", err)
	}

	if len(certs) != 1 {
		t.Errorf("Certificate count: expected 1, got %d", len(certs))
	}

	if certs[0].Subject.CommonName != "ECDSA Root" {
		t.Errorf("Certificate subject: expected %q, got %q", "ECDSA Root", certs[0].Subject.CommonName)
	}
}

func TestCABundleCerts_CombinedStoreTypeAndAlgorithmFilter(t *testing.T) {
	t.Parallel()

	rsaKey := generateTestRSAKey(t)
	ecdsaKey := generateTestECDSAKey(t)
	rsaSoftwareCert := generateRootCert(t, rsaKey, "RSA Software Root")
	ecdsaTpm2Cert := generateRootCert(t, ecdsaKey, "ECDSA TPM2 Root")

	providers := []CertificateProvider{
		&mockCertificateProvider{cert: rsaSoftwareCert, storeType: StoreTypeSoftware},
		&mockCertificateProvider{cert: ecdsaTpm2Cert, storeType: StoreTypeTPM2},
	}

	bundler := NewDefaultCABundlerWithProviders(providers)

	// Filter by TPM2 store and ECDSA algorithm
	certs, err := bundler.CABundleCerts(StoreTypeTPM2, AlgorithmECDSA)
	if err != nil {
		t.Fatalf("CABundleCerts() error: %v", err)
	}

	if len(certs) != 1 {
		t.Errorf("Certificate count: expected 1, got %d", len(certs))
	}

	if certs[0].Subject.CommonName != "ECDSA TPM2 Root" {
		t.Errorf("Certificate subject: expected %q, got %q", "ECDSA TPM2 Root", certs[0].Subject.CommonName)
	}
}

func TestCABundleCerts_CaseInsensitiveAlgorithmMatching(t *testing.T) {
	t.Parallel()

	rsaKey := generateTestRSAKey(t)
	rsaCert := generateRootCert(t, rsaKey, "RSA Root")

	bundler := NewDefaultCABundler([]*x509.Certificate{rsaCert})

	tests := []struct {
		name      string
		algorithm string
	}{
		{"lowercase", "rsa"},
		{"uppercase", "RSA"},
		{"mixed case", "RsA"},
		{"with spaces", "  RSA  "},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			certs, err := bundler.CABundleCerts(StoreTypeAll, tc.algorithm)
			if err != nil {
				t.Fatalf("CABundleCerts() error: %v", err)
			}

			if len(certs) != 1 {
				t.Errorf("Certificate count: expected 1, got %d", len(certs))
			}
		})
	}
}

func TestCABundleCerts_ReturnsErrNoCACertificates(t *testing.T) {
	t.Parallel()

	bundler := NewDefaultCABundler([]*x509.Certificate{})

	_, err := bundler.CABundleCerts(StoreTypeAll, AlgorithmAll)

	if !errors.Is(err, ErrNoCACertificates) {
		t.Errorf("CABundleCerts() error: expected ErrNoCACertificates, got %v", err)
	}
}

func TestCABundleCerts_ReturnsErrNoCertificatesMatch(t *testing.T) {
	t.Parallel()

	ecdsaKey := generateTestECDSAKey(t)
	ecdsaCert := generateRootCert(t, ecdsaKey, "ECDSA Root")

	bundler := NewDefaultCABundler([]*x509.Certificate{ecdsaCert})

	_, err := bundler.CABundleCerts(StoreTypeAll, AlgorithmRSA)

	if !errors.Is(err, ErrNoCertificatesMatch) {
		t.Errorf("CABundleCerts() error: expected ErrNoCertificatesMatch, got %v", err)
	}
}

// =============================================================================
// sortCertificatesForBundle Tests
// =============================================================================

func TestSortCertificatesForBundle_SelfSignedLast(t *testing.T) {
	t.Parallel()

	rootKey := generateTestRSAKey(t)
	intermediateKey := generateTestRSAKey(t)

	rootCert := generateRootCert(t, rootKey, "Root CA")
	intermediateCert := generateIntermediateCertWithParent(t, intermediateKey, "Intermediate CA", rootCert, rootKey, 0)

	// Input with root first
	certs := []*x509.Certificate{rootCert, intermediateCert}

	sorted := sortCertificatesForBundle(certs)

	if sorted[0].Subject.CommonName != "Intermediate CA" {
		t.Errorf("First cert: expected intermediate, got %q", sorted[0].Subject.CommonName)
	}

	if sorted[1].Subject.CommonName != "Root CA" {
		t.Errorf("Second cert: expected root, got %q", sorted[1].Subject.CommonName)
	}
}

func TestSortCertificatesForBundle_IntermediatesSortedByPathLength(t *testing.T) {
	t.Parallel()

	rootKey := generateTestRSAKey(t)
	rootCert := generateRootCert(t, rootKey, "Root CA")

	key0 := generateTestRSAKey(t)
	key1 := generateTestRSAKey(t)
	key2 := generateTestRSAKey(t)

	// Create intermediates with different path lengths
	intermediate0 := generateIntermediateCertWithParent(t, key0, "Intermediate PathLen 0", rootCert, rootKey, 0)
	intermediate1 := generateIntermediateCertWithParent(t, key1, "Intermediate PathLen 1", rootCert, rootKey, 1)
	intermediate2 := generateIntermediateCertWithParent(t, key2, "Intermediate PathLen 2", rootCert, rootKey, 2)

	certs := []*x509.Certificate{intermediate0, intermediate2, intermediate1}

	sorted := sortCertificatesForBundle(certs)

	// Higher path length should come first (closer to leaf)
	if sorted[0].MaxPathLen != 2 {
		t.Errorf("First cert MaxPathLen: expected 2, got %d", sorted[0].MaxPathLen)
	}

	if sorted[1].MaxPathLen != 1 {
		t.Errorf("Second cert MaxPathLen: expected 1, got %d", sorted[1].MaxPathLen)
	}

	if sorted[2].MaxPathLen != 0 {
		t.Errorf("Third cert MaxPathLen: expected 0, got %d", sorted[2].MaxPathLen)
	}
}

func TestSortCertificatesForBundle_DeterministicOrderBySubject(t *testing.T) {
	t.Parallel()

	rootKey := generateTestRSAKey(t)
	rootCert := generateRootCert(t, rootKey, "Root CA")

	keyA := generateTestRSAKey(t)
	keyB := generateTestRSAKey(t)
	keyC := generateTestRSAKey(t)

	// Create certs with same path length but different subjects
	certA := generateIntermediateCertWithParent(t, keyA, "A Intermediate", rootCert, rootKey, 1)
	certB := generateIntermediateCertWithParent(t, keyB, "B Intermediate", rootCert, rootKey, 1)
	certC := generateIntermediateCertWithParent(t, keyC, "C Intermediate", rootCert, rootKey, 1)

	certs := []*x509.Certificate{certC, certA, certB}

	sorted := sortCertificatesForBundle(certs)

	// Should be sorted alphabetically by subject
	if sorted[0].Subject.CommonName != "A Intermediate" {
		t.Errorf("First cert: expected 'A Intermediate', got %q", sorted[0].Subject.CommonName)
	}

	if sorted[1].Subject.CommonName != "B Intermediate" {
		t.Errorf("Second cert: expected 'B Intermediate', got %q", sorted[1].Subject.CommonName)
	}

	if sorted[2].Subject.CommonName != "C Intermediate" {
		t.Errorf("Third cert: expected 'C Intermediate', got %q", sorted[2].Subject.CommonName)
	}
}

func TestSortCertificatesForBundle_SingleCert(t *testing.T) {
	t.Parallel()

	key := generateTestRSAKey(t)
	cert := generateRootCert(t, key, "Root CA")

	certs := []*x509.Certificate{cert}

	sorted := sortCertificatesForBundle(certs)

	if len(sorted) != 1 {
		t.Errorf("Length: expected 1, got %d", len(sorted))
	}

	if sorted[0].Subject.CommonName != "Root CA" {
		t.Errorf("Certificate subject: expected 'Root CA', got %q", sorted[0].Subject.CommonName)
	}
}

func TestSortCertificatesForBundle_EmptySlice(t *testing.T) {
	t.Parallel()

	certs := []*x509.Certificate{}

	sorted := sortCertificatesForBundle(certs)

	if len(sorted) != 0 {
		t.Errorf("Length: expected 0, got %d", len(sorted))
	}
}

func TestSortCertificatesForBundle_DoesNotModifyInput(t *testing.T) {
	t.Parallel()

	rootKey := generateTestRSAKey(t)
	intermediateKey := generateTestRSAKey(t)

	rootCert := generateRootCert(t, rootKey, "Root CA")
	intermediateCert := generateIntermediateCertWithParent(t, intermediateKey, "Intermediate CA", rootCert, rootKey, 0)

	original := []*x509.Certificate{rootCert, intermediateCert}
	originalFirst := original[0]

	sorted := sortCertificatesForBundle(original)

	if original[0] != originalFirst {
		t.Error("sortCertificatesForBundle modified the input slice")
	}

	if sorted[0] == original[0] {
		// Sorted should have different order
		if sorted[0].Subject.CommonName == rootCert.Subject.CommonName {
			t.Error("Sorted slice has same order as input (intermediate should be first)")
		}
	}
}

// =============================================================================
// isSelfSigned Tests
// =============================================================================

func TestIsSelfSigned_WithSelfSignedCert(t *testing.T) {
	t.Parallel()

	key := generateTestRSAKey(t)
	cert := generateRootCert(t, key, "Self-Signed Root CA")

	if !isSelfSigned(cert) {
		t.Error("isSelfSigned() should return true for self-signed certificate")
	}
}

func TestIsSelfSigned_WithNonSelfSignedCert(t *testing.T) {
	t.Parallel()

	rootKey := generateTestRSAKey(t)
	intermediateKey := generateTestRSAKey(t)

	rootCert := generateRootCert(t, rootKey, "Root CA")
	intermediateCert := generateIntermediateCertWithParent(t, intermediateKey, "Intermediate CA", rootCert, rootKey, 0)

	if isSelfSigned(intermediateCert) {
		t.Error("isSelfSigned() should return false for non-self-signed certificate")
	}
}

// =============================================================================
// getEffectivePathLen Tests
// =============================================================================

func TestGetEffectivePathLen_NonCA(t *testing.T) {
	t.Parallel()

	rootKey := generateTestRSAKey(t)
	leafKey := generateTestRSAKey(t)

	rootCert := generateRootCert(t, rootKey, "Root CA")
	leafCert := generateLeafCert(t, leafKey, "Leaf Cert", rootCert, rootKey)

	pathLen := getEffectivePathLen(leafCert)

	if pathLen != -2 {
		t.Errorf("getEffectivePathLen() for non-CA: expected -2, got %d", pathLen)
	}
}

func TestGetEffectivePathLen_MaxPathLenZero(t *testing.T) {
	t.Parallel()

	rootKey := generateTestRSAKey(t)
	intermediateKey := generateTestRSAKey(t)

	rootCert := generateRootCert(t, rootKey, "Root CA")
	cert := generateIntermediateCertWithParent(t, intermediateKey, "Intermediate CA", rootCert, rootKey, 0)

	pathLen := getEffectivePathLen(cert)

	if pathLen != 0 {
		t.Errorf("getEffectivePathLen() for MaxPathLenZero: expected 0, got %d", pathLen)
	}
}

func TestGetEffectivePathLen_PositiveMaxPathLen(t *testing.T) {
	t.Parallel()

	rootKey := generateTestRSAKey(t)
	intermediateKey := generateTestRSAKey(t)

	rootCert := generateRootCert(t, rootKey, "Root CA")
	cert := generateIntermediateCertWithParent(t, intermediateKey, "Intermediate CA", rootCert, rootKey, 3)

	pathLen := getEffectivePathLen(cert)

	if pathLen != 3 {
		t.Errorf("getEffectivePathLen() for MaxPathLen=3: expected 3, got %d", pathLen)
	}
}

func TestGetEffectivePathLen_NoConstraint(t *testing.T) {
	t.Parallel()

	key := generateTestRSAKey(t)
	// Root CA without explicit path length
	cert := generateRootCert(t, key, "Root CA")

	pathLen := getEffectivePathLen(cert)

	if pathLen != -1 {
		t.Errorf("getEffectivePathLen() for no constraint: expected -1, got %d", pathLen)
	}
}

// =============================================================================
// encodeCertsToPEM Tests
// =============================================================================

func TestEncodeCertsToPEM_SingleCert(t *testing.T) {
	t.Parallel()

	key := generateTestRSAKey(t)
	cert := generateRootCert(t, key, "Root CA")

	pemData, err := encodeCertsToPEM([]*x509.Certificate{cert})
	if err != nil {
		t.Fatalf("encodeCertsToPEM() error: %v", err)
	}

	if len(pemData) == 0 {
		t.Error("encodeCertsToPEM() returned empty data")
	}

	block, _ := pem.Decode(pemData)
	if block == nil {
		t.Fatal("Failed to decode PEM block")
	}

	if block.Type != "CERTIFICATE" {
		t.Errorf("PEM block type: expected %q, got %q", "CERTIFICATE", block.Type)
	}
}

func TestEncodeCertsToPEM_MultipleCerts(t *testing.T) {
	t.Parallel()

	key1 := generateTestRSAKey(t)
	key2 := generateTestRSAKey(t)
	cert1 := generateRootCert(t, key1, "Root CA 1")
	cert2 := generateRootCert(t, key2, "Root CA 2")

	pemData, err := encodeCertsToPEM([]*x509.Certificate{cert1, cert2})
	if err != nil {
		t.Fatalf("encodeCertsToPEM() error: %v", err)
	}

	// Decode both certificates
	var certs []*x509.Certificate
	rest := pemData

	for len(rest) > 0 {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}

		parsedCert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatalf("Failed to parse certificate: %v", err)
		}
		certs = append(certs, parsedCert)
	}

	if len(certs) != 2 {
		t.Errorf("Certificate count: expected 2, got %d", len(certs))
	}
}

func TestEncodeCertsToPEM_SkipsNilCerts(t *testing.T) {
	t.Parallel()

	key := generateTestRSAKey(t)
	cert := generateRootCert(t, key, "Root CA")

	pemData, err := encodeCertsToPEM([]*x509.Certificate{cert, nil, nil})
	if err != nil {
		t.Fatalf("encodeCertsToPEM() error: %v", err)
	}

	// Should only have one certificate
	var count int
	rest := pemData

	for len(rest) > 0 {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		count++
	}

	if count != 1 {
		t.Errorf("Certificate count: expected 1 (nil certs skipped), got %d", count)
	}
}

func TestEncodeCertsToPEM_EmptyInput(t *testing.T) {
	t.Parallel()

	_, err := encodeCertsToPEM([]*x509.Certificate{})

	if !errors.Is(err, ErrNoCACertificates) {
		t.Errorf("encodeCertsToPEM() error: expected ErrNoCACertificates, got %v", err)
	}
}

func TestEncodeCertsToPEM_AllNilCerts(t *testing.T) {
	t.Parallel()

	_, err := encodeCertsToPEM([]*x509.Certificate{nil, nil, nil})

	if !errors.Is(err, ErrNoCACertificates) {
		t.Errorf("encodeCertsToPEM() error: expected ErrNoCACertificates, got %v", err)
	}
}

func TestEncodeCertsToPEM_VerifyPEMFormat(t *testing.T) {
	t.Parallel()

	key := generateTestRSAKey(t)
	cert := generateRootCert(t, key, "Root CA")

	pemData, err := encodeCertsToPEM([]*x509.Certificate{cert})
	if err != nil {
		t.Fatalf("encodeCertsToPEM() error: %v", err)
	}

	// Check for PEM header
	if !bytes.Contains(pemData, []byte("-----BEGIN CERTIFICATE-----")) {
		t.Error("PEM data missing BEGIN header")
	}

	// Check for PEM footer
	if !bytes.Contains(pemData, []byte("-----END CERTIFICATE-----")) {
		t.Error("PEM data missing END header")
	}
}

// =============================================================================
// AddCertificate Tests
// =============================================================================

func TestAddCertificate_WithValidCert(t *testing.T) {
	t.Parallel()

	bundler := NewDefaultCABundler([]*x509.Certificate{})

	key := generateTestRSAKey(t)
	cert := generateRootCert(t, key, "Root CA")

	err := bundler.AddCertificate(cert, StoreTypeSoftware)
	if err != nil {
		t.Fatalf("AddCertificate() error: %v", err)
	}

	if bundler.Count() != 1 {
		t.Errorf("Count(): expected 1, got %d", bundler.Count())
	}
}

func TestAddCertificate_ReturnsErrNilCertificate(t *testing.T) {
	t.Parallel()

	bundler := NewDefaultCABundler([]*x509.Certificate{})

	err := bundler.AddCertificate(nil, StoreTypeSoftware)

	if !errors.Is(err, ErrNilCertificate) {
		t.Errorf("AddCertificate() error: expected ErrNilCertificate, got %v", err)
	}

	if bundler.Count() != 0 {
		t.Errorf("Count(): expected 0 (nil cert not added), got %d", bundler.Count())
	}
}

func TestAddCertificate_MultipleAdds(t *testing.T) {
	t.Parallel()

	bundler := NewDefaultCABundler([]*x509.Certificate{})

	key1 := generateTestRSAKey(t)
	key2 := generateTestECDSAKey(t)
	cert1 := generateRootCert(t, key1, "RSA Root")
	cert2 := generateRootCert(t, key2, "ECDSA Root")

	if err := bundler.AddCertificate(cert1, StoreTypeSoftware); err != nil {
		t.Fatalf("AddCertificate() error: %v", err)
	}

	if err := bundler.AddCertificate(cert2, StoreTypeTPM2); err != nil {
		t.Fatalf("AddCertificate() error: %v", err)
	}

	if bundler.Count() != 2 {
		t.Errorf("Count(): expected 2, got %d", bundler.Count())
	}
}

// =============================================================================
// AddProvider Tests
// =============================================================================

func TestAddProvider_WithValidProvider(t *testing.T) {
	t.Parallel()

	bundler := NewDefaultCABundler([]*x509.Certificate{})

	key := generateTestRSAKey(t)
	cert := generateRootCert(t, key, "Root CA")
	provider := &mockCertificateProvider{cert: cert, storeType: StoreTypeTPM2}

	err := bundler.AddProvider(provider)
	if err != nil {
		t.Fatalf("AddProvider() error: %v", err)
	}

	if bundler.Count() != 1 {
		t.Errorf("Count(): expected 1, got %d", bundler.Count())
	}
}

func TestAddProvider_ReturnsErrNilCertificate_ForNilProvider(t *testing.T) {
	t.Parallel()

	bundler := NewDefaultCABundler([]*x509.Certificate{})

	err := bundler.AddProvider(nil)

	if !errors.Is(err, ErrNilCertificate) {
		t.Errorf("AddProvider() error: expected ErrNilCertificate, got %v", err)
	}

	if bundler.Count() != 0 {
		t.Errorf("Count(): expected 0 (nil provider not added), got %d", bundler.Count())
	}
}

func TestAddProvider_ReturnsErrNilCertificate_ForProviderWithNilCert(t *testing.T) {
	t.Parallel()

	bundler := NewDefaultCABundler([]*x509.Certificate{})
	provider := &mockCertificateProvider{cert: nil, storeType: StoreTypeSoftware}

	err := bundler.AddProvider(provider)

	if !errors.Is(err, ErrNilCertificate) {
		t.Errorf("AddProvider() error: expected ErrNilCertificate, got %v", err)
	}

	if bundler.Count() != 0 {
		t.Errorf("Count(): expected 0 (provider with nil cert not added), got %d", bundler.Count())
	}
}

// =============================================================================
// Count Tests
// =============================================================================

func TestCount_ReturnsCorrectNumber(t *testing.T) {
	t.Parallel()

	key1 := generateTestRSAKey(t)
	key2 := generateTestRSAKey(t)
	key3 := generateTestRSAKey(t)
	cert1 := generateRootCert(t, key1, "Root 1")
	cert2 := generateRootCert(t, key2, "Root 2")
	cert3 := generateRootCert(t, key3, "Root 3")

	bundler := NewDefaultCABundler([]*x509.Certificate{cert1, cert2, cert3})

	if bundler.Count() != 3 {
		t.Errorf("Count(): expected 3, got %d", bundler.Count())
	}
}

func TestCount_ReturnsZeroForEmptyBundler(t *testing.T) {
	t.Parallel()

	bundler := NewDefaultCABundler([]*x509.Certificate{})

	if bundler.Count() != 0 {
		t.Errorf("Count(): expected 0, got %d", bundler.Count())
	}
}

func TestCount_UpdatesAfterAddCertificate(t *testing.T) {
	t.Parallel()

	bundler := NewDefaultCABundler([]*x509.Certificate{})

	if bundler.Count() != 0 {
		t.Errorf("Initial count: expected 0, got %d", bundler.Count())
	}

	key := generateTestRSAKey(t)
	cert := generateRootCert(t, key, "Root CA")

	if err := bundler.AddCertificate(cert, StoreTypeSoftware); err != nil {
		t.Fatalf("AddCertificate() error: %v", err)
	}

	if bundler.Count() != 1 {
		t.Errorf("Count after add: expected 1, got %d", bundler.Count())
	}
}

// =============================================================================
// Clear Tests
// =============================================================================

func TestClear_RemovesAllCerts(t *testing.T) {
	t.Parallel()

	key1 := generateTestRSAKey(t)
	key2 := generateTestRSAKey(t)
	cert1 := generateRootCert(t, key1, "Root 1")
	cert2 := generateRootCert(t, key2, "Root 2")

	bundler := NewDefaultCABundler([]*x509.Certificate{cert1, cert2})

	if bundler.Count() != 2 {
		t.Fatalf("Initial count: expected 2, got %d", bundler.Count())
	}

	bundler.Clear()

	if bundler.Count() != 0 {
		t.Errorf("Count after clear: expected 0, got %d", bundler.Count())
	}
}

func TestClear_EmptyBundlerNoOp(t *testing.T) {
	t.Parallel()

	bundler := NewDefaultCABundler([]*x509.Certificate{})

	bundler.Clear()

	if bundler.Count() != 0 {
		t.Errorf("Count after clear on empty: expected 0, got %d", bundler.Count())
	}
}

func TestClear_AllowsNewAddsAfterClear(t *testing.T) {
	t.Parallel()

	key := generateTestRSAKey(t)
	cert := generateRootCert(t, key, "Root CA")

	bundler := NewDefaultCABundler([]*x509.Certificate{cert})
	bundler.Clear()

	newCert := generateRootCert(t, key, "New Root CA")
	if err := bundler.AddCertificate(newCert, StoreTypeSoftware); err != nil {
		t.Fatalf("AddCertificate() error: %v", err)
	}

	if bundler.Count() != 1 {
		t.Errorf("Count after add: expected 1, got %d", bundler.Count())
	}
}

// =============================================================================
// Integration Tests
// =============================================================================

func TestCABundle_CompleteChainOrdering(t *testing.T) {
	t.Parallel()

	// Generate a complete certificate chain
	rootKey := generateTestRSAKey(t)
	intermediateKey := generateTestRSAKey(t)
	subIntermediateKey := generateTestRSAKey(t)

	rootCert := generateRootCert(t, rootKey, "Root CA")
	intermediateCert := generateIntermediateCertWithParent(t, intermediateKey, "Intermediate CA", rootCert, rootKey, 1)
	subIntermediateCert := generateIntermediateCertWithParent(t, subIntermediateKey, "Sub-Intermediate CA", intermediateCert, intermediateKey, 0)

	// Add in random order
	bundler := NewDefaultCABundler([]*x509.Certificate{rootCert, subIntermediateCert, intermediateCert})

	certs, err := bundler.CABundleCerts(StoreTypeAll, AlgorithmAll)
	if err != nil {
		t.Fatalf("CABundleCerts() error: %v", err)
	}

	if len(certs) != 3 {
		t.Fatalf("Certificate count: expected 3, got %d", len(certs))
	}

	// Verify ordering: intermediates first (by path length desc), then root
	// Intermediate (pathLen=1), Sub-Intermediate (pathLen=0), Root (self-signed)
	if isSelfSigned(certs[0]) {
		t.Error("First cert should not be root (self-signed)")
	}

	if !isSelfSigned(certs[2]) {
		t.Error("Last cert should be root (self-signed)")
	}
}

func TestCABundle_MixedAlgorithmsAndStoreTypes(t *testing.T) {
	t.Parallel()

	rsaKey := generateTestRSAKey(t)
	ecdsaKey := generateTestECDSAKey(t)
	ed25519Key := generateTestEd25519Key(t)

	rsaSoftware := generateRootCert(t, rsaKey, "RSA Software Root")
	ecdsaTpm2 := generateRootCert(t, ecdsaKey, "ECDSA TPM2 Root")
	ed25519Pkcs11 := generateRootCert(t, ed25519Key, "Ed25519 PKCS11 Root")

	providers := []CertificateProvider{
		&mockCertificateProvider{cert: rsaSoftware, storeType: StoreTypeSoftware},
		&mockCertificateProvider{cert: ecdsaTpm2, storeType: StoreTypeTPM2},
		&mockCertificateProvider{cert: ed25519Pkcs11, storeType: StoreTypePKCS11},
	}

	bundler := NewDefaultCABundlerWithProviders(providers)

	// Test various filter combinations
	tests := []struct {
		name          string
		storeType     string
		algorithm     string
		expectedCount int
	}{
		{"all", StoreTypeAll, AlgorithmAll, 3},
		{"software only", StoreTypeSoftware, AlgorithmAll, 1},
		{"tpm2 only", StoreTypeTPM2, AlgorithmAll, 1},
		{"pkcs11 only", StoreTypePKCS11, AlgorithmAll, 1},
		{"rsa only", StoreTypeAll, AlgorithmRSA, 1},
		{"ecdsa only", StoreTypeAll, AlgorithmECDSA, 1},
		{"ed25519 only", StoreTypeAll, AlgorithmEd25519, 1},
		{"software + rsa", StoreTypeSoftware, AlgorithmRSA, 1},
		{"tpm2 + ecdsa", StoreTypeTPM2, AlgorithmECDSA, 1},
		{"pkcs11 + ed25519", StoreTypePKCS11, AlgorithmEd25519, 1},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			certs, err := bundler.CABundleCerts(tc.storeType, tc.algorithm)
			if err != nil {
				t.Fatalf("CABundleCerts() error: %v", err)
			}

			if len(certs) != tc.expectedCount {
				t.Errorf("Certificate count: expected %d, got %d", tc.expectedCount, len(certs))
			}
		})
	}
}

func TestCABundle_PEMBundleRoundTrip(t *testing.T) {
	t.Parallel()

	key1 := generateTestRSAKey(t)
	key2 := generateTestECDSAKey(t)
	cert1 := generateRootCert(t, key1, "RSA Root")
	cert2 := generateRootCert(t, key2, "ECDSA Root")

	bundler := NewDefaultCABundler([]*x509.Certificate{cert1, cert2})

	pemData, err := bundler.CABundle(StoreTypeAll, AlgorithmAll)
	if err != nil {
		t.Fatalf("CABundle() error: %v", err)
	}

	// Parse PEM bundle back to certificates
	var parsedCerts []*x509.Certificate
	rest := pemData

	for len(rest) > 0 {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}

		parsedCert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatalf("Failed to parse certificate: %v", err)
		}
		parsedCerts = append(parsedCerts, parsedCert)
	}

	if len(parsedCerts) != 2 {
		t.Errorf("Parsed certificate count: expected 2, got %d", len(parsedCerts))
	}

	// Verify subjects match (order may differ due to sorting)
	subjects := make(map[string]bool)
	for _, cert := range parsedCerts {
		subjects[cert.Subject.CommonName] = true
	}

	if !subjects["RSA Root"] {
		t.Error("Missing RSA Root certificate in parsed bundle")
	}

	if !subjects["ECDSA Root"] {
		t.Error("Missing ECDSA Root certificate in parsed bundle")
	}
}

// =============================================================================
// Error Scenarios Tests
// =============================================================================

func TestCABundle_StoreTypeFilterNoMatch(t *testing.T) {
	t.Parallel()

	key := generateTestRSAKey(t)
	cert := generateRootCert(t, key, "Root CA")

	provider := &mockCertificateProvider{cert: cert, storeType: StoreTypeSoftware}
	bundler := NewDefaultCABundlerWithProviders([]CertificateProvider{provider})

	_, err := bundler.CABundleCerts(StoreTypeTPM2, AlgorithmAll)

	if !errors.Is(err, ErrNoCertificatesMatch) {
		t.Errorf("CABundleCerts() error: expected ErrNoCertificatesMatch, got %v", err)
	}
}

func TestCABundle_CombinedFilterNoMatch(t *testing.T) {
	t.Parallel()

	rsaKey := generateTestRSAKey(t)
	rsaCert := generateRootCert(t, rsaKey, "RSA Root")

	provider := &mockCertificateProvider{cert: rsaCert, storeType: StoreTypeSoftware}
	bundler := NewDefaultCABundlerWithProviders([]CertificateProvider{provider})

	// Request ECDSA from software store - but we only have RSA
	_, err := bundler.CABundleCerts(StoreTypeSoftware, AlgorithmECDSA)

	if !errors.Is(err, ErrNoCertificatesMatch) {
		t.Errorf("CABundleCerts() error: expected ErrNoCertificatesMatch, got %v", err)
	}
}

// =============================================================================
// Interface Compliance Tests
// =============================================================================

func TestDefaultCABundler_ImplementsCABundler(t *testing.T) {
	t.Parallel()

	var _ CABundler = (*DefaultCABundler)(nil)
}

func TestSimpleCertificate_ImplementsCertificateProvider(t *testing.T) {
	t.Parallel()

	var _ CertificateProvider = (*SimpleCertificate)(nil)
}

func TestMockCertificateProvider_ImplementsCertificateProvider(t *testing.T) {
	t.Parallel()

	var _ CertificateProvider = (*mockCertificateProvider)(nil)
}

// =============================================================================
// Edge Cases Tests
// =============================================================================

func TestCABundle_WhitespaceInStoreType(t *testing.T) {
	t.Parallel()

	key := generateTestRSAKey(t)
	cert := generateRootCert(t, key, "Root CA")

	provider := &mockCertificateProvider{cert: cert, storeType: StoreTypeSoftware}
	bundler := NewDefaultCABundlerWithProviders([]CertificateProvider{provider})

	// Should handle whitespace in store type filter
	certs, err := bundler.CABundleCerts("  software  ", AlgorithmAll)
	if err != nil {
		t.Fatalf("CABundleCerts() error: %v", err)
	}

	if len(certs) != 1 {
		t.Errorf("Certificate count: expected 1, got %d", len(certs))
	}
}

func TestCABundle_CaseInsensitiveStoreType(t *testing.T) {
	t.Parallel()

	key := generateTestRSAKey(t)
	cert := generateRootCert(t, key, "Root CA")

	provider := &mockCertificateProvider{cert: cert, storeType: "SOFTWARE"}
	bundler := NewDefaultCABundlerWithProviders([]CertificateProvider{provider})

	// Should match case-insensitively
	certs, err := bundler.CABundleCerts("software", AlgorithmAll)
	if err != nil {
		t.Fatalf("CABundleCerts() error: %v", err)
	}

	if len(certs) != 1 {
		t.Errorf("Certificate count: expected 1, got %d", len(certs))
	}
}

func TestCABundle_EmptyStoreTypeMatchesAll(t *testing.T) {
	t.Parallel()

	key := generateTestRSAKey(t)
	cert := generateRootCert(t, key, "Root CA")

	// Provider with empty store type should match any filter
	provider := &mockCertificateProvider{cert: cert, storeType: ""}
	bundler := NewDefaultCABundlerWithProviders([]CertificateProvider{provider})

	tests := []string{StoreTypeSoftware, StoreTypeTPM2, StoreTypePKCS11, StoreTypeAll}

	for _, storeType := range tests {
		t.Run(storeType, func(t *testing.T) {
			certs, err := bundler.CABundleCerts(storeType, AlgorithmAll)
			if err != nil {
				t.Fatalf("CABundleCerts() error: %v", err)
			}

			if len(certs) != 1 {
				t.Errorf("Certificate count: expected 1, got %d", len(certs))
			}
		})
	}
}

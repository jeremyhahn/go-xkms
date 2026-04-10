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
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"testing"
)

// =============================================================================
// Test Key Generation Helpers
// =============================================================================

// csrTestECDSAKey generates an in-memory ECDSA key for testing.
func csrTestECDSAKey(t *testing.T, curve elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}
	return key
}

// csrTestRSAKey generates an in-memory RSA key for testing.
func csrTestRSAKey(t *testing.T, bits int) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}
	return key
}

// csrTestEd25519Key generates an in-memory Ed25519 key for testing.
func csrTestEd25519Key(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key: %v", err)
	}
	return priv
}

// =============================================================================
// CreateCSRWithKey Tests
// =============================================================================

func TestCreateCSRWithKey_ECDSA_P256(t *testing.T) {
	key := csrTestECDSAKey(t, elliptic.P256())
	request := &CertificateRequest{
		Subject: Subject{
			CommonName:   "test.example.com",
			Organization: "Test Org",
			Country:      "US",
		},
	}

	csrPEM, err := CreateCSRWithKey(request, key)
	if err != nil {
		t.Fatalf("CreateCSRWithKey failed: %v", err)
	}

	// Verify PEM format
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		t.Fatal("Failed to decode PEM")
	}
	if block.Type != "CERTIFICATE REQUEST" {
		t.Errorf("PEM type = %q, want %q", block.Type, "CERTIFICATE REQUEST")
	}

	// Parse and validate the CSR
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse CSR: %v", err)
	}

	if err := csr.CheckSignature(); err != nil {
		t.Errorf("CSR signature verification failed: %v", err)
	}

	if csr.Subject.CommonName != "test.example.com" {
		t.Errorf("CommonName = %q, want %q", csr.Subject.CommonName, "test.example.com")
	}

	if csr.SignatureAlgorithm != x509.ECDSAWithSHA256 {
		t.Errorf("SignatureAlgorithm = %v, want %v", csr.SignatureAlgorithm, x509.ECDSAWithSHA256)
	}
}

func TestCreateCSRWithKey_ECDSA_P384(t *testing.T) {
	key := csrTestECDSAKey(t, elliptic.P384())
	request := &CertificateRequest{
		Subject: Subject{CommonName: "p384.example.com"},
	}

	csrPEM, err := CreateCSRWithKey(request, key)
	if err != nil {
		t.Fatalf("CreateCSRWithKey failed: %v", err)
	}

	block, _ := pem.Decode(csrPEM)
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse CSR: %v", err)
	}

	if csr.SignatureAlgorithm != x509.ECDSAWithSHA384 {
		t.Errorf("SignatureAlgorithm = %v, want %v", csr.SignatureAlgorithm, x509.ECDSAWithSHA384)
	}
}

func TestCreateCSRWithKey_ECDSA_P521(t *testing.T) {
	key := csrTestECDSAKey(t, elliptic.P521())
	request := &CertificateRequest{
		Subject: Subject{CommonName: "p521.example.com"},
	}

	csrPEM, err := CreateCSRWithKey(request, key)
	if err != nil {
		t.Fatalf("CreateCSRWithKey failed: %v", err)
	}

	block, _ := pem.Decode(csrPEM)
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse CSR: %v", err)
	}

	if csr.SignatureAlgorithm != x509.ECDSAWithSHA512 {
		t.Errorf("SignatureAlgorithm = %v, want %v", csr.SignatureAlgorithm, x509.ECDSAWithSHA512)
	}
}

func TestCreateCSRWithKey_RSA(t *testing.T) {
	key := csrTestRSAKey(t, 2048)
	request := &CertificateRequest{
		Subject: Subject{
			CommonName:   "rsa.example.com",
			Organization: "RSA Test Org",
		},
	}

	csrPEM, err := CreateCSRWithKey(request, key)
	if err != nil {
		t.Fatalf("CreateCSRWithKey failed: %v", err)
	}

	block, _ := pem.Decode(csrPEM)
	if block == nil {
		t.Fatal("Failed to decode PEM")
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse CSR: %v", err)
	}

	if err := csr.CheckSignature(); err != nil {
		t.Errorf("CSR signature verification failed: %v", err)
	}

	if csr.Subject.CommonName != "rsa.example.com" {
		t.Errorf("CommonName = %q, want %q", csr.Subject.CommonName, "rsa.example.com")
	}

	if csr.SignatureAlgorithm != x509.SHA256WithRSA {
		t.Errorf("SignatureAlgorithm = %v, want %v", csr.SignatureAlgorithm, x509.SHA256WithRSA)
	}
}

func TestCreateCSRWithKey_Ed25519(t *testing.T) {
	key := csrTestEd25519Key(t)
	request := &CertificateRequest{
		Subject: Subject{
			CommonName:   "ed25519.example.com",
			Organization: "Ed25519 Test Org",
		},
	}

	csrPEM, err := CreateCSRWithKey(request, key)
	if err != nil {
		t.Fatalf("CreateCSRWithKey failed: %v", err)
	}

	block, _ := pem.Decode(csrPEM)
	if block == nil {
		t.Fatal("Failed to decode PEM")
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse CSR: %v", err)
	}

	if err := csr.CheckSignature(); err != nil {
		t.Errorf("CSR signature verification failed: %v", err)
	}

	if csr.Subject.CommonName != "ed25519.example.com" {
		t.Errorf("CommonName = %q, want %q", csr.Subject.CommonName, "ed25519.example.com")
	}

	if csr.SignatureAlgorithm != x509.PureEd25519 {
		t.Errorf("SignatureAlgorithm = %v, want %v", csr.SignatureAlgorithm, x509.PureEd25519)
	}
}

func TestCreateCSRWithKey_NilSigner(t *testing.T) {
	request := &CertificateRequest{
		Subject: Subject{CommonName: "test.example.com"},
	}

	_, err := CreateCSRWithKey(request, nil)
	if err == nil {
		t.Fatal("Expected error for nil signer, got nil")
	}

	if !errors.Is(err, ErrCSRGenerationFailed) {
		t.Errorf("Expected ErrCSRGenerationFailed, got %v", err)
	}
}

func TestCreateCSRWithKey_NilRequest(t *testing.T) {
	key := csrTestECDSAKey(t, elliptic.P256())

	_, err := CreateCSRWithKey(nil, key)
	if err == nil {
		t.Fatal("Expected error for nil request, got nil")
	}

	if !errors.Is(err, ErrInvalidCSR) {
		t.Errorf("Expected ErrInvalidCSR, got %v", err)
	}
}

func TestCreateCSRWithKey_MissingCommonName(t *testing.T) {
	key := csrTestECDSAKey(t, elliptic.P256())
	request := &CertificateRequest{
		Subject: Subject{
			Organization: "Test Org",
			// CommonName is intentionally empty
		},
	}

	_, err := CreateCSRWithKey(request, key)
	if err == nil {
		t.Fatal("Expected error for missing CommonName, got nil")
	}

	if !errors.Is(err, ErrSubjectCommonNameRequired) {
		t.Errorf("Expected ErrSubjectCommonNameRequired, got %v", err)
	}
}

// =============================================================================
// buildCSRTemplate Tests
// =============================================================================

func TestBuildCSRTemplate_FullSubject(t *testing.T) {
	request := &CertificateRequest{
		Subject: Subject{
			CommonName:         "test.example.com",
			Organization:       "Test Organization",
			OrganizationalUnit: "Engineering",
			Country:            "US",
			Province:           "California",
			Locality:           "San Francisco",
			Address:            "123 Test St",
			PostalCode:         "94102",
		},
	}

	template, err := buildCSRTemplate(request)
	if err != nil {
		t.Fatalf("buildCSRTemplate failed: %v", err)
	}

	if template.Subject.CommonName != "test.example.com" {
		t.Errorf("CommonName = %q, want %q", template.Subject.CommonName, "test.example.com")
	}
	if len(template.Subject.Organization) == 0 || template.Subject.Organization[0] != "Test Organization" {
		t.Errorf("Organization = %v, want [Test Organization]", template.Subject.Organization)
	}
	if len(template.Subject.OrganizationalUnit) == 0 || template.Subject.OrganizationalUnit[0] != "Engineering" {
		t.Errorf("OrganizationalUnit = %v, want [Engineering]", template.Subject.OrganizationalUnit)
	}
	if len(template.Subject.Country) == 0 || template.Subject.Country[0] != "US" {
		t.Errorf("Country = %v, want [US]", template.Subject.Country)
	}
	if len(template.Subject.Province) == 0 || template.Subject.Province[0] != "California" {
		t.Errorf("Province = %v, want [California]", template.Subject.Province)
	}
	if len(template.Subject.Locality) == 0 || template.Subject.Locality[0] != "San Francisco" {
		t.Errorf("Locality = %v, want [San Francisco]", template.Subject.Locality)
	}
	if len(template.Subject.StreetAddress) == 0 || template.Subject.StreetAddress[0] != "123 Test St" {
		t.Errorf("StreetAddress = %v, want [123 Test St]", template.Subject.StreetAddress)
	}
	if len(template.Subject.PostalCode) == 0 || template.Subject.PostalCode[0] != "94102" {
		t.Errorf("PostalCode = %v, want [94102]", template.Subject.PostalCode)
	}
}

func TestBuildCSRTemplate_MinimalSubject(t *testing.T) {
	request := &CertificateRequest{
		Subject: Subject{
			CommonName: "minimal.example.com",
		},
	}

	template, err := buildCSRTemplate(request)
	if err != nil {
		t.Fatalf("buildCSRTemplate failed: %v", err)
	}

	if template.Subject.CommonName != "minimal.example.com" {
		t.Errorf("CommonName = %q, want %q", template.Subject.CommonName, "minimal.example.com")
	}
	if len(template.Subject.Organization) != 0 {
		t.Errorf("Organization = %v, want empty", template.Subject.Organization)
	}
}

func TestBuildCSRTemplate_WithDNSSANs(t *testing.T) {
	request := &CertificateRequest{
		Subject: Subject{CommonName: "test.example.com"},
		SANS: &SubjectAlternativeNames{
			DNS: []string{"test.example.com", "www.example.com", "api.example.com"},
		},
	}

	template, err := buildCSRTemplate(request)
	if err != nil {
		t.Fatalf("buildCSRTemplate failed: %v", err)
	}

	if len(template.DNSNames) != 3 {
		t.Fatalf("DNSNames length = %d, want 3", len(template.DNSNames))
	}
	expectedDNS := map[string]bool{
		"test.example.com": true,
		"www.example.com":  true,
		"api.example.com":  true,
	}
	for _, dns := range template.DNSNames {
		if !expectedDNS[dns] {
			t.Errorf("Unexpected DNS name: %s", dns)
		}
	}
}

func TestBuildCSRTemplate_WithIPSANs(t *testing.T) {
	request := &CertificateRequest{
		Subject: Subject{CommonName: "test.example.com"},
		SANS: &SubjectAlternativeNames{
			IPs: []string{"192.168.1.100", "10.0.0.1", "::1", "2001:db8::1"},
		},
	}

	template, err := buildCSRTemplate(request)
	if err != nil {
		t.Fatalf("buildCSRTemplate failed: %v", err)
	}

	if len(template.IPAddresses) != 4 {
		t.Fatalf("IPAddresses length = %d, want 4", len(template.IPAddresses))
	}

	expectedIPs := map[string]bool{
		"192.168.1.100": true,
		"10.0.0.1":      true,
		"::1":           true,
		"2001:db8::1":   true,
	}
	for _, ip := range template.IPAddresses {
		if !expectedIPs[ip.String()] {
			t.Errorf("Unexpected IP: %s", ip.String())
		}
	}
}

func TestBuildCSRTemplate_WithEmailSANs(t *testing.T) {
	request := &CertificateRequest{
		Subject: Subject{CommonName: "user@example.com"},
		SANS: &SubjectAlternativeNames{
			Email: []string{"user@example.com", "admin@example.com"},
		},
	}

	template, err := buildCSRTemplate(request)
	if err != nil {
		t.Fatalf("buildCSRTemplate failed: %v", err)
	}

	if len(template.EmailAddresses) != 2 {
		t.Fatalf("EmailAddresses length = %d, want 2", len(template.EmailAddresses))
	}
	expectedEmails := map[string]bool{
		"user@example.com":  true,
		"admin@example.com": true,
	}
	for _, email := range template.EmailAddresses {
		if !expectedEmails[email] {
			t.Errorf("Unexpected email: %s", email)
		}
	}
}

func TestBuildCSRTemplate_WithURISANs(t *testing.T) {
	request := &CertificateRequest{
		Subject: Subject{CommonName: "service.example.com"},
		SANS: &SubjectAlternativeNames{
			URIs: []string{"https://example.com", "spiffe://cluster.local/ns/default/sa/service"},
		},
	}

	template, err := buildCSRTemplate(request)
	if err != nil {
		t.Fatalf("buildCSRTemplate failed: %v", err)
	}

	if len(template.URIs) != 2 {
		t.Fatalf("URIs length = %d, want 2", len(template.URIs))
	}
	expectedURIs := map[string]bool{
		"https://example.com":                          true,
		"spiffe://cluster.local/ns/default/sa/service": true,
	}
	for _, uri := range template.URIs {
		if !expectedURIs[uri.String()] {
			t.Errorf("Unexpected URI: %s", uri.String())
		}
	}
}

func TestBuildCSRTemplate_WithAllSANTypes(t *testing.T) {
	request := &CertificateRequest{
		Subject: Subject{CommonName: "full.example.com"},
		SANS: &SubjectAlternativeNames{
			DNS:   []string{"full.example.com", "www.example.com"},
			IPs:   []string{"192.168.1.1", "10.0.0.1"},
			Email: []string{"admin@example.com"},
			URIs:  []string{"https://example.com/api"},
		},
	}

	template, err := buildCSRTemplate(request)
	if err != nil {
		t.Fatalf("buildCSRTemplate failed: %v", err)
	}

	if len(template.DNSNames) != 2 {
		t.Errorf("DNSNames length = %d, want 2", len(template.DNSNames))
	}
	if len(template.IPAddresses) != 2 {
		t.Errorf("IPAddresses length = %d, want 2", len(template.IPAddresses))
	}
	if len(template.EmailAddresses) != 1 {
		t.Errorf("EmailAddresses length = %d, want 1", len(template.EmailAddresses))
	}
	if len(template.URIs) != 1 {
		t.Errorf("URIs length = %d, want 1", len(template.URIs))
	}
}

func TestBuildCSRTemplate_NilSANs(t *testing.T) {
	request := &CertificateRequest{
		Subject: Subject{CommonName: "nosans.example.com"},
		SANS:    nil,
	}

	template, err := buildCSRTemplate(request)
	if err != nil {
		t.Fatalf("buildCSRTemplate failed: %v", err)
	}

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

// =============================================================================
// addSANsExtension Tests
// =============================================================================

func TestAddSANsExtension_NilSANs(t *testing.T) {
	template := &x509.CertificateRequest{}
	err := addSANsExtension(template, nil)
	if err != nil {
		t.Errorf("addSANsExtension with nil SANs should not error: %v", err)
	}
}

func TestAddSANsExtension_EmptySANs(t *testing.T) {
	template := &x509.CertificateRequest{}
	sans := &SubjectAlternativeNames{}
	err := addSANsExtension(template, sans)
	if err != nil {
		t.Errorf("addSANsExtension with empty SANs should not error: %v", err)
	}
}

func TestAddSANsExtension_InvalidIP(t *testing.T) {
	template := &x509.CertificateRequest{}
	sans := &SubjectAlternativeNames{
		IPs: []string{"not-an-ip", "192.168.1.1", "also-invalid"},
	}

	err := addSANsExtension(template, sans)
	if err != nil {
		t.Fatalf("addSANsExtension failed: %v", err)
	}

	// Should only have the valid IP
	if len(template.IPAddresses) != 1 {
		t.Errorf("IPAddresses length = %d, want 1 (valid only)", len(template.IPAddresses))
	}
}

func TestAddSANsExtension_InvalidURI(t *testing.T) {
	template := &x509.CertificateRequest{}
	sans := &SubjectAlternativeNames{
		URIs: []string{
			"https://valid.example.com",
			"no-scheme-uri",     // missing scheme
			"://malformed",      // malformed
			"ftp://another.com", // valid
		},
	}

	err := addSANsExtension(template, sans)
	if err != nil {
		t.Fatalf("addSANsExtension failed: %v", err)
	}

	// Should have 2 valid URIs (https and ftp)
	if len(template.URIs) != 2 {
		t.Errorf("URIs length = %d, want 2 (valid only)", len(template.URIs))
	}
}

func TestAddSANsExtension_HardwareModuleName(t *testing.T) {
	template := &x509.CertificateRequest{}
	sans := &SubjectAlternativeNames{
		DNS: []string{"device.example.com"},
		HardwareModuleName: &HardwareModuleInfo{
			HWType:         asn1.ObjectIdentifier{2, 23, 133, 1}, // TCG Platform
			HWSerialNumber: "TPM1234567890",
		},
	}

	err := addSANsExtension(template, sans)
	if err != nil {
		t.Fatalf("addSANsExtension failed: %v", err)
	}

	// Verify DNS was added
	if len(template.DNSNames) != 1 {
		t.Errorf("DNSNames length = %d, want 1", len(template.DNSNames))
	}

	// Verify hardware module extension was added
	if len(template.ExtraExtensions) != 1 {
		t.Fatalf("ExtraExtensions length = %d, want 1", len(template.ExtraExtensions))
	}

	ext := template.ExtraExtensions[0]
	expectedOID := asn1.ObjectIdentifier{2, 5, 29, 17} // subjectAltName
	if !ext.Id.Equal(expectedOID) {
		t.Errorf("Extension OID = %v, want %v", ext.Id, expectedOID)
	}
	if ext.Critical {
		t.Error("SAN extension should not be critical")
	}
}

// =============================================================================
// getSignatureAlgorithm Tests
// =============================================================================

func TestGetSignatureAlgorithm_ECDSA_P256(t *testing.T) {
	key := csrTestECDSAKey(t, elliptic.P256())
	alg, err := getSignatureAlgorithm(key.Public())
	if err != nil {
		t.Fatalf("getSignatureAlgorithm failed: %v", err)
	}
	if alg != x509.ECDSAWithSHA256 {
		t.Errorf("Algorithm = %v, want %v", alg, x509.ECDSAWithSHA256)
	}
}

func TestGetSignatureAlgorithm_ECDSA_P384(t *testing.T) {
	key := csrTestECDSAKey(t, elliptic.P384())
	alg, err := getSignatureAlgorithm(key.Public())
	if err != nil {
		t.Fatalf("getSignatureAlgorithm failed: %v", err)
	}
	if alg != x509.ECDSAWithSHA384 {
		t.Errorf("Algorithm = %v, want %v", alg, x509.ECDSAWithSHA384)
	}
}

func TestGetSignatureAlgorithm_ECDSA_P521(t *testing.T) {
	key := csrTestECDSAKey(t, elliptic.P521())
	alg, err := getSignatureAlgorithm(key.Public())
	if err != nil {
		t.Fatalf("getSignatureAlgorithm failed: %v", err)
	}
	if alg != x509.ECDSAWithSHA512 {
		t.Errorf("Algorithm = %v, want %v", alg, x509.ECDSAWithSHA512)
	}
}

func TestGetSignatureAlgorithm_ECDSA_P224(t *testing.T) {
	key := csrTestECDSAKey(t, elliptic.P224())
	alg, err := getSignatureAlgorithm(key.Public())
	if err != nil {
		t.Fatalf("getSignatureAlgorithm failed: %v", err)
	}
	// P-224 should use SHA256 (224-bit and 256-bit use SHA256)
	if alg != x509.ECDSAWithSHA256 {
		t.Errorf("Algorithm = %v, want %v", alg, x509.ECDSAWithSHA256)
	}
}

func TestGetSignatureAlgorithm_RSA(t *testing.T) {
	key := csrTestRSAKey(t, 2048)
	alg, err := getSignatureAlgorithm(key.Public())
	if err != nil {
		t.Fatalf("getSignatureAlgorithm failed: %v", err)
	}
	if alg != x509.SHA256WithRSA {
		t.Errorf("Algorithm = %v, want %v", alg, x509.SHA256WithRSA)
	}
}

func TestGetSignatureAlgorithm_Ed25519(t *testing.T) {
	key := csrTestEd25519Key(t)
	alg, err := getSignatureAlgorithm(key.Public())
	if err != nil {
		t.Fatalf("getSignatureAlgorithm failed: %v", err)
	}
	if alg != x509.PureEd25519 {
		t.Errorf("Algorithm = %v, want %v", alg, x509.PureEd25519)
	}
}

func TestGetSignatureAlgorithm_UnsupportedKeyType(t *testing.T) {
	// Test with an unsupported key type (string as a stand-in)
	_, err := getSignatureAlgorithm("unsupported-key-type")
	if err == nil {
		t.Fatal("Expected error for unsupported key type, got nil")
	}
	if !errors.Is(err, ErrInvalidKeyAlgorithm) {
		t.Errorf("Expected ErrInvalidKeyAlgorithm, got %v", err)
	}
}

// =============================================================================
// getECDSASignatureAlgorithm Tests
// =============================================================================

func TestGetECDSASignatureAlgorithm_NilCurve(t *testing.T) {
	_, err := getECDSASignatureAlgorithm(nil)
	if err == nil {
		t.Fatal("Expected error for nil curve, got nil")
	}
	if !errors.Is(err, ErrInvalidKeyAlgorithm) {
		t.Errorf("Expected ErrInvalidKeyAlgorithm, got %v", err)
	}
}

func TestGetECDSASignatureAlgorithm_AllCurves(t *testing.T) {
	tests := []struct {
		name     string
		curve    elliptic.Curve
		expected x509.SignatureAlgorithm
	}{
		{"P-224", elliptic.P224(), x509.ECDSAWithSHA256},
		{"P-256", elliptic.P256(), x509.ECDSAWithSHA256},
		{"P-384", elliptic.P384(), x509.ECDSAWithSHA384},
		{"P-521", elliptic.P521(), x509.ECDSAWithSHA512},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			alg, err := getECDSASignatureAlgorithm(tt.curve)
			if err != nil {
				t.Fatalf("getECDSASignatureAlgorithm failed: %v", err)
			}
			if alg != tt.expected {
				t.Errorf("Algorithm = %v, want %v", alg, tt.expected)
			}
		})
	}
}

// =============================================================================
// encodeCSRToPEM Tests
// =============================================================================

func TestEncodeCSRToPEM_ValidDER(t *testing.T) {
	// Create a valid CSR to get DER bytes
	key := csrTestECDSAKey(t, elliptic.P256())
	request := &CertificateRequest{
		Subject: Subject{CommonName: "test.example.com"},
	}

	template, _ := buildCSRTemplate(request)
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		t.Fatalf("Failed to create CSR: %v", err)
	}

	pemData := encodeCSRToPEM(csrDER)

	// Verify PEM encoding
	block, _ := pem.Decode(pemData)
	if block == nil {
		t.Fatal("Failed to decode PEM")
	}
	if block.Type != "CERTIFICATE REQUEST" {
		t.Errorf("PEM type = %q, want %q", block.Type, "CERTIFICATE REQUEST")
	}

	// Verify DER bytes match
	if string(block.Bytes) != string(csrDER) {
		t.Error("PEM bytes do not match original DER bytes")
	}
}

func TestEncodeCSRToPEM_EmptyDER(t *testing.T) {
	pemData := encodeCSRToPEM([]byte{})
	block, _ := pem.Decode(pemData)
	if block == nil {
		t.Fatal("Failed to decode PEM for empty DER")
	}
	if block.Type != "CERTIFICATE REQUEST" {
		t.Errorf("PEM type = %q, want %q", block.Type, "CERTIFICATE REQUEST")
	}
	if len(block.Bytes) != 0 {
		t.Errorf("PEM bytes length = %d, want 0", len(block.Bytes))
	}
}

// =============================================================================
// validateCSRRequest Tests
// =============================================================================

func TestValidateCSRRequest_Valid(t *testing.T) {
	request := &CertificateRequest{
		Subject: Subject{CommonName: "valid.example.com"},
	}
	err := validateCSRRequest(request)
	if err != nil {
		t.Errorf("validateCSRRequest failed for valid request: %v", err)
	}
}

func TestValidateCSRRequest_NilRequest(t *testing.T) {
	err := validateCSRRequest(nil)
	if err == nil {
		t.Fatal("Expected error for nil request, got nil")
	}
	if !errors.Is(err, ErrInvalidCSR) {
		t.Errorf("Expected ErrInvalidCSR, got %v", err)
	}
}

func TestValidateCSRRequest_EmptyCommonName(t *testing.T) {
	request := &CertificateRequest{
		Subject: Subject{
			Organization: "Test Org",
		},
	}
	err := validateCSRRequest(request)
	if err == nil {
		t.Fatal("Expected error for empty CommonName, got nil")
	}
	if !errors.Is(err, ErrSubjectCommonNameRequired) {
		t.Errorf("Expected ErrSubjectCommonNameRequired, got %v", err)
	}
}

// =============================================================================
// Full CSR Generation Flow Tests
// =============================================================================

func TestCreateCSRWithKey_FullFlow_ECDSA(t *testing.T) {
	key := csrTestECDSAKey(t, elliptic.P256())
	request := &CertificateRequest{
		Subject: Subject{
			CommonName:         "fullflow.example.com",
			Organization:       "Full Flow Org",
			OrganizationalUnit: "Engineering",
			Country:            "US",
			Province:           "California",
			Locality:           "San Francisco",
		},
		SANS: &SubjectAlternativeNames{
			DNS:   []string{"fullflow.example.com", "www.fullflow.example.com"},
			IPs:   []string{"192.168.1.100", "10.0.0.1"},
			Email: []string{"admin@fullflow.example.com"},
			URIs:  []string{"https://fullflow.example.com/api"},
		},
	}

	csrPEM, err := CreateCSRWithKey(request, key)
	if err != nil {
		t.Fatalf("CreateCSRWithKey failed: %v", err)
	}

	// Parse and validate
	block, _ := pem.Decode(csrPEM)
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse CSR: %v", err)
	}

	// Verify signature
	if err := csr.CheckSignature(); err != nil {
		t.Errorf("CSR signature verification failed: %v", err)
	}

	// Verify subject
	if csr.Subject.CommonName != "fullflow.example.com" {
		t.Errorf("CommonName = %q, want %q", csr.Subject.CommonName, "fullflow.example.com")
	}

	// Verify SANs
	if len(csr.DNSNames) != 2 {
		t.Errorf("DNSNames length = %d, want 2", len(csr.DNSNames))
	}
	if len(csr.IPAddresses) != 2 {
		t.Errorf("IPAddresses length = %d, want 2", len(csr.IPAddresses))
	}
	if len(csr.EmailAddresses) != 1 {
		t.Errorf("EmailAddresses length = %d, want 1", len(csr.EmailAddresses))
	}
	if len(csr.URIs) != 1 {
		t.Errorf("URIs length = %d, want 1", len(csr.URIs))
	}
}

func TestCreateCSRWithKey_FullFlow_RSA(t *testing.T) {
	key := csrTestRSAKey(t, 2048)
	request := &CertificateRequest{
		Subject: Subject{
			CommonName:   "rsaflow.example.com",
			Organization: "RSA Flow Org",
		},
		SANS: &SubjectAlternativeNames{
			DNS: []string{"rsaflow.example.com"},
		},
	}

	csrPEM, err := CreateCSRWithKey(request, key)
	if err != nil {
		t.Fatalf("CreateCSRWithKey failed: %v", err)
	}

	block, _ := pem.Decode(csrPEM)
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse CSR: %v", err)
	}

	if err := csr.CheckSignature(); err != nil {
		t.Errorf("CSR signature verification failed: %v", err)
	}

	if csr.SignatureAlgorithm != x509.SHA256WithRSA {
		t.Errorf("SignatureAlgorithm = %v, want %v", csr.SignatureAlgorithm, x509.SHA256WithRSA)
	}
}

func TestCreateCSRWithKey_FullFlow_Ed25519(t *testing.T) {
	key := csrTestEd25519Key(t)
	request := &CertificateRequest{
		Subject: Subject{
			CommonName:   "ed25519flow.example.com",
			Organization: "Ed25519 Flow Org",
		},
		SANS: &SubjectAlternativeNames{
			DNS: []string{"ed25519flow.example.com"},
		},
	}

	csrPEM, err := CreateCSRWithKey(request, key)
	if err != nil {
		t.Fatalf("CreateCSRWithKey failed: %v", err)
	}

	block, _ := pem.Decode(csrPEM)
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse CSR: %v", err)
	}

	if err := csr.CheckSignature(); err != nil {
		t.Errorf("CSR signature verification failed: %v", err)
	}

	if csr.SignatureAlgorithm != x509.PureEd25519 {
		t.Errorf("SignatureAlgorithm = %v, want %v", csr.SignatureAlgorithm, x509.PureEd25519)
	}
}

// =============================================================================
// Table-Driven Tests for Multiple Key Types
// =============================================================================

func TestCreateCSRWithKey_TableDriven(t *testing.T) {
	tests := []struct {
		name           string
		signerFunc     func(t *testing.T) crypto.Signer
		expectedSigAlg x509.SignatureAlgorithm
		subject        Subject
		sans           *SubjectAlternativeNames
	}{
		{
			name:           "ECDSA P-256 with DNS SANs",
			signerFunc:     func(t *testing.T) crypto.Signer { return csrTestECDSAKey(t, elliptic.P256()) },
			expectedSigAlg: x509.ECDSAWithSHA256,
			subject:        Subject{CommonName: "p256.example.com"},
			sans:           &SubjectAlternativeNames{DNS: []string{"p256.example.com"}},
		},
		{
			name:           "ECDSA P-384 with IP SANs",
			signerFunc:     func(t *testing.T) crypto.Signer { return csrTestECDSAKey(t, elliptic.P384()) },
			expectedSigAlg: x509.ECDSAWithSHA384,
			subject:        Subject{CommonName: "p384.example.com"},
			sans:           &SubjectAlternativeNames{IPs: []string{"10.0.0.1"}},
		},
		{
			name:           "ECDSA P-521 with Email SANs",
			signerFunc:     func(t *testing.T) crypto.Signer { return csrTestECDSAKey(t, elliptic.P521()) },
			expectedSigAlg: x509.ECDSAWithSHA512,
			subject:        Subject{CommonName: "p521.example.com"},
			sans:           &SubjectAlternativeNames{Email: []string{"user@p521.example.com"}},
		},
		{
			name:           "RSA 2048 with URI SANs",
			signerFunc:     func(t *testing.T) crypto.Signer { return csrTestRSAKey(t, 2048) },
			expectedSigAlg: x509.SHA256WithRSA,
			subject:        Subject{CommonName: "rsa.example.com"},
			sans:           &SubjectAlternativeNames{URIs: []string{"https://rsa.example.com"}},
		},
		{
			name:           "Ed25519 with mixed SANs",
			signerFunc:     func(t *testing.T) crypto.Signer { return csrTestEd25519Key(t) },
			expectedSigAlg: x509.PureEd25519,
			subject:        Subject{CommonName: "ed25519.example.com"},
			sans: &SubjectAlternativeNames{
				DNS:   []string{"ed25519.example.com"},
				IPs:   []string{"192.168.1.1"},
				Email: []string{"admin@ed25519.example.com"},
			},
		},
		{
			name:           "ECDSA P-256 without SANs",
			signerFunc:     func(t *testing.T) crypto.Signer { return csrTestECDSAKey(t, elliptic.P256()) },
			expectedSigAlg: x509.ECDSAWithSHA256,
			subject:        Subject{CommonName: "nosans.example.com"},
			sans:           nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signer := tt.signerFunc(t)
			request := &CertificateRequest{
				Subject: tt.subject,
				SANS:    tt.sans,
			}

			csrPEM, err := CreateCSRWithKey(request, signer)
			if err != nil {
				t.Fatalf("CreateCSRWithKey failed: %v", err)
			}

			block, _ := pem.Decode(csrPEM)
			if block == nil {
				t.Fatal("Failed to decode PEM")
			}

			csr, err := x509.ParseCertificateRequest(block.Bytes)
			if err != nil {
				t.Fatalf("Failed to parse CSR: %v", err)
			}

			if err := csr.CheckSignature(); err != nil {
				t.Errorf("CSR signature verification failed: %v", err)
			}

			if csr.SignatureAlgorithm != tt.expectedSigAlg {
				t.Errorf("SignatureAlgorithm = %v, want %v", csr.SignatureAlgorithm, tt.expectedSigAlg)
			}

			if csr.Subject.CommonName != tt.subject.CommonName {
				t.Errorf("CommonName = %q, want %q", csr.Subject.CommonName, tt.subject.CommonName)
			}

			if tt.sans != nil {
				if len(tt.sans.DNS) > 0 && len(csr.DNSNames) != len(tt.sans.DNS) {
					t.Errorf("DNSNames length = %d, want %d", len(csr.DNSNames), len(tt.sans.DNS))
				}
				if len(tt.sans.IPs) > 0 && len(csr.IPAddresses) != len(tt.sans.IPs) {
					t.Errorf("IPAddresses length = %d, want %d", len(csr.IPAddresses), len(tt.sans.IPs))
				}
				if len(tt.sans.Email) > 0 && len(csr.EmailAddresses) != len(tt.sans.Email) {
					t.Errorf("EmailAddresses length = %d, want %d", len(csr.EmailAddresses), len(tt.sans.Email))
				}
			}
		})
	}
}

// =============================================================================
// Error Handling Tests
// =============================================================================

func TestCreateCSRWithKey_ErrorHandling(t *testing.T) {
	tests := []struct {
		name        string
		request     *CertificateRequest
		signer      crypto.Signer
		expectError error
	}{
		{
			name:        "nil request",
			request:     nil,
			signer:      csrTestECDSAKey(t, elliptic.P256()),
			expectError: ErrInvalidCSR,
		},
		{
			name: "nil signer",
			request: &CertificateRequest{
				Subject: Subject{CommonName: "test.example.com"},
			},
			signer:      nil,
			expectError: ErrCSRGenerationFailed,
		},
		{
			name: "empty common name",
			request: &CertificateRequest{
				Subject: Subject{Organization: "Test Org"},
			},
			signer:      csrTestECDSAKey(t, elliptic.P256()),
			expectError: ErrSubjectCommonNameRequired,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := CreateCSRWithKey(tt.request, tt.signer)
			if err == nil {
				t.Fatal("Expected error, got nil")
			}
			if !errors.Is(err, tt.expectError) {
				t.Errorf("Error = %v, want %v", err, tt.expectError)
			}
		})
	}
}

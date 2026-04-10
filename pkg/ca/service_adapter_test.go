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
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/backend/software"
	"github.com/jeremyhahn/go-xkms/pkg/certstore"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// =============================================================================
// Test Helpers
// =============================================================================

// setupTestCA creates a fully initialized CA backed by in-memory storage.
// The CA uses the default ECDSA P-256 configuration and is ready for signing
// and certificate issuance operations.
func setupTestCA(t *testing.T) *CA {
	t.Helper()

	// Create in-memory storage for keys
	keyStorage := storage.NewMemory()

	// Create software backend with in-memory storage
	swBackend, err := software.NewBackend(&software.Config{
		KeyStorage: keyStorage,
	})
	if err != nil {
		t.Fatalf("Failed to create software backend: %v", err)
	}

	// Create in-memory certificate storage
	certStorage := storage.NewMemory()

	// Create xkms Backend composing key provider + cert storage
	backend, err := xkms.New(&xkms.BackendConfig{
		Backend:     swBackend,
		CertStorage: certStorage,
	})
	if err != nil {
		t.Fatalf("Failed to create xkms backend: %v", err)
	}

	// Create in-memory cert adapter for the certstore
	certAdapterStorage := storage.NewMemory()
	certAdapter := storage.NewCertAdapter(certAdapterStorage)

	cs, err := certstore.New(&certstore.Config{
		CertStorage: certAdapter,
	})
	if err != nil {
		t.Fatalf("Failed to create certstore: %v", err)
	}

	// Build CA config with default root CA
	config := DefaultMultiIdentityCAConfig()
	config.Identity[0].Subject.CommonName = "Test Root CA"
	config.Identity[0].Subject.Organization = "Test Organization"

	// Set the KeyType to "CA" -- required by KeyAttributes.Validate()
	config.Identity[0].Keys[0].KeyType = "CA"

	// Create CA
	caIface, err := NewFromMultiIdentityConfig(&MultiIdentityParams{
		Config:    config,
		KeyStore:  backend,
		CertStore: cs,
	})
	if err != nil {
		t.Fatalf("Failed to create CA: %v", err)
	}

	// Initialize the CA (generates root certificate)
	if err := caIface.Init(); err != nil {
		t.Fatalf("Failed to initialize CA: %v", err)
	}

	// Return the concrete *CA type for testing unexported adapter methods
	concreteCA, ok := caIface.(*CA)
	if !ok {
		t.Fatalf("Expected *CA type, got %T", caIface)
	}

	return concreteCA
}

// setupUninitializedCA creates a CA that has NOT been initialized.
// Useful for testing error paths that require ErrNotInitialized.
func setupUninitializedCA(t *testing.T) *CA {
	t.Helper()

	keyStorage := storage.NewMemory()
	swBackend, err := software.NewBackend(&software.Config{
		KeyStorage: keyStorage,
	})
	if err != nil {
		t.Fatalf("Failed to create software backend: %v", err)
	}

	certStorage := storage.NewMemory()
	backend, err := xkms.New(&xkms.BackendConfig{
		Backend:     swBackend,
		CertStorage: certStorage,
	})
	if err != nil {
		t.Fatalf("Failed to create xkms backend: %v", err)
	}

	certAdapterStorage := storage.NewMemory()
	certAdapter := storage.NewCertAdapter(certAdapterStorage)
	cs, err := certstore.New(&certstore.Config{
		CertStorage: certAdapter,
	})
	if err != nil {
		t.Fatalf("Failed to create certstore: %v", err)
	}

	config := DefaultMultiIdentityCAConfig()
	config.Identity[0].Subject.CommonName = "Uninitialized Root CA"
	config.Identity[0].Keys[0].KeyType = "CA"

	caIface, err := NewFromMultiIdentityConfig(&MultiIdentityParams{
		Config:    config,
		KeyStore:  backend,
		CertStore: cs,
	})
	if err != nil {
		t.Fatalf("Failed to create CA: %v", err)
	}

	concreteCA, ok := caIface.(*CA)
	if !ok {
		t.Fatalf("Expected *CA type, got %T", caIface)
	}

	return concreteCA
}

// generateTestCSRPEM creates a valid PEM-encoded CSR using a freshly generated
// ECDSA P-256 key pair. The CSR contains the specified common name.
func generateTestCSRPEM(t *testing.T, commonName string) []byte {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	template := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: commonName},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		t.Fatalf("Failed to create CSR: %v", err)
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	})
}

// =============================================================================
// parseSANStrings Tests
// =============================================================================

func TestParseSANStrings_DNSPrefix(t *testing.T) {
	sans := parseSANStrings([]string{"DNS:example.com"})

	if sans == nil {
		t.Fatal("parseSANStrings returned nil")
	}
	if len(sans.DNS) != 1 {
		t.Fatalf("DNS length = %d, want 1", len(sans.DNS))
	}
	if sans.DNS[0] != "example.com" {
		t.Errorf("DNS[0] = %q, want %q", sans.DNS[0], "example.com")
	}
	if len(sans.IPs) != 0 {
		t.Errorf("IPs should be empty, got %v", sans.IPs)
	}
	if len(sans.Email) != 0 {
		t.Errorf("Email should be empty, got %v", sans.Email)
	}
	if len(sans.URIs) != 0 {
		t.Errorf("URIs should be empty, got %v", sans.URIs)
	}
}

func TestParseSANStrings_IPPrefix(t *testing.T) {
	sans := parseSANStrings([]string{"IP:1.2.3.4"})

	if sans == nil {
		t.Fatal("parseSANStrings returned nil")
	}
	if len(sans.IPs) != 1 {
		t.Fatalf("IPs length = %d, want 1", len(sans.IPs))
	}
	if sans.IPs[0] != "1.2.3.4" {
		t.Errorf("IPs[0] = %q, want %q", sans.IPs[0], "1.2.3.4")
	}
	if len(sans.DNS) != 0 {
		t.Errorf("DNS should be empty, got %v", sans.DNS)
	}
}

func TestParseSANStrings_EmailPrefix(t *testing.T) {
	sans := parseSANStrings([]string{"Email:user@example.com"})

	if sans == nil {
		t.Fatal("parseSANStrings returned nil")
	}
	if len(sans.Email) != 1 {
		t.Fatalf("Email length = %d, want 1", len(sans.Email))
	}
	if sans.Email[0] != "user@example.com" {
		t.Errorf("Email[0] = %q, want %q", sans.Email[0], "user@example.com")
	}
	if len(sans.DNS) != 0 {
		t.Errorf("DNS should be empty, got %v", sans.DNS)
	}
}

func TestParseSANStrings_URIPrefix(t *testing.T) {
	sans := parseSANStrings([]string{"URI:https://example.com"})

	if sans == nil {
		t.Fatal("parseSANStrings returned nil")
	}
	if len(sans.URIs) != 1 {
		t.Fatalf("URIs length = %d, want 1", len(sans.URIs))
	}
	if sans.URIs[0] != "https://example.com" {
		t.Errorf("URIs[0] = %q, want %q", sans.URIs[0], "https://example.com")
	}
	if len(sans.DNS) != 0 {
		t.Errorf("DNS should be empty, got %v", sans.DNS)
	}
}

func TestParseSANStrings_NoPrefixDNS(t *testing.T) {
	// A bare hostname without any prefix should be classified as DNS
	// because it does not parse as a valid IP address.
	sans := parseSANStrings([]string{"example.com"})

	if sans == nil {
		t.Fatal("parseSANStrings returned nil")
	}
	if len(sans.DNS) != 1 {
		t.Fatalf("DNS length = %d, want 1", len(sans.DNS))
	}
	if sans.DNS[0] != "example.com" {
		t.Errorf("DNS[0] = %q, want %q", sans.DNS[0], "example.com")
	}
	if len(sans.IPs) != 0 {
		t.Errorf("IPs should be empty for non-IP input, got %v", sans.IPs)
	}
}

func TestParseSANStrings_NoPrefixIP(t *testing.T) {
	// A bare IP address without any prefix should be classified as IP
	// because net.ParseIP succeeds.
	sans := parseSANStrings([]string{"192.168.1.1"})

	if sans == nil {
		t.Fatal("parseSANStrings returned nil")
	}
	if len(sans.IPs) != 1 {
		t.Fatalf("IPs length = %d, want 1", len(sans.IPs))
	}
	if sans.IPs[0] != "192.168.1.1" {
		t.Errorf("IPs[0] = %q, want %q", sans.IPs[0], "192.168.1.1")
	}
	if len(sans.DNS) != 0 {
		t.Errorf("DNS should be empty for IP input, got %v", sans.DNS)
	}
}

func TestParseSANStrings_Mixed(t *testing.T) {
	sans := parseSANStrings([]string{
		"DNS:web.example.com",
		"IP:10.0.0.1",
		"Email:admin@example.com",
		"URI:https://api.example.com",
		"other.example.com",   // no prefix, not an IP -> DNS
		"172.16.0.1",          // no prefix, valid IP -> IP
		"DNS:api.example.com", // second DNS entry
	})

	if sans == nil {
		t.Fatal("parseSANStrings returned nil")
	}

	// DNS: "web.example.com" + "other.example.com" + "api.example.com" = 3
	if len(sans.DNS) != 3 {
		t.Errorf("DNS length = %d, want 3, got %v", len(sans.DNS), sans.DNS)
	}

	// IPs: "10.0.0.1" + "172.16.0.1" = 2
	if len(sans.IPs) != 2 {
		t.Errorf("IPs length = %d, want 2, got %v", len(sans.IPs), sans.IPs)
	}

	// Email: "admin@example.com" = 1
	if len(sans.Email) != 1 {
		t.Errorf("Email length = %d, want 1, got %v", len(sans.Email), sans.Email)
	}

	// URIs: "https://api.example.com" = 1
	if len(sans.URIs) != 1 {
		t.Errorf("URIs length = %d, want 1, got %v", len(sans.URIs), sans.URIs)
	}
}

func TestParseSANStrings_Empty(t *testing.T) {
	sans := parseSANStrings([]string{})

	if sans == nil {
		t.Fatal("parseSANStrings returned nil for empty slice")
	}
	if len(sans.DNS) != 0 {
		t.Errorf("DNS should be empty, got %v", sans.DNS)
	}
	if len(sans.IPs) != 0 {
		t.Errorf("IPs should be empty, got %v", sans.IPs)
	}
	if len(sans.Email) != 0 {
		t.Errorf("Email should be empty, got %v", sans.Email)
	}
	if len(sans.URIs) != 0 {
		t.Errorf("URIs should be empty, got %v", sans.URIs)
	}
}

func TestParseSANStrings_IPv6NoPrefixClassifiedAsIP(t *testing.T) {
	sans := parseSANStrings([]string{"::1"})

	if sans == nil {
		t.Fatal("parseSANStrings returned nil")
	}
	if len(sans.IPs) != 1 {
		t.Fatalf("IPs length = %d, want 1", len(sans.IPs))
	}
	if sans.IPs[0] != "::1" {
		t.Errorf("IPs[0] = %q, want %q", sans.IPs[0], "::1")
	}
	if len(sans.DNS) != 0 {
		t.Errorf("DNS should be empty for IPv6 input, got %v", sans.DNS)
	}
}

func TestParseSANStrings_CaseSensitivePrefixes(t *testing.T) {
	// Prefixes are case-sensitive: "dns:" should NOT match "DNS:" prefix,
	// so "dns:example.com" falls through to default (not an IP) -> DNS
	sans := parseSANStrings([]string{"dns:example.com"})

	if sans == nil {
		t.Fatal("parseSANStrings returned nil")
	}
	// "dns:example.com" does not match HasPrefix("DNS:"), so it goes to default.
	// net.ParseIP("dns:example.com") returns nil, so it becomes a DNS entry.
	if len(sans.DNS) != 1 {
		t.Fatalf("DNS length = %d, want 1", len(sans.DNS))
	}
	if sans.DNS[0] != "dns:example.com" {
		t.Errorf("DNS[0] = %q, want %q", sans.DNS[0], "dns:example.com")
	}
}

// =============================================================================
// SignCSRRaw Tests
// =============================================================================

func TestSignCSRRaw_Defaults(t *testing.T) {
	testCA := setupTestCA(t)
	csrPEM := generateTestCSRPEM(t, "defaults.example.com")

	// profile="" and validityDays=0 should delegate to SignCSR with nil opts
	cert, err := testCA.SignCSRRaw(csrPEM, "", 0)
	if err != nil {
		t.Fatalf("SignCSRRaw with defaults failed: %v", err)
	}

	if cert == nil {
		t.Fatal("SignCSRRaw returned nil certificate")
	}

	if cert.Subject.CommonName != "defaults.example.com" {
		t.Errorf("CommonName = %q, want %q", cert.Subject.CommonName, "defaults.example.com")
	}

	// Verify the issuer is the test CA
	if cert.Issuer.CommonName != "Test Root CA" {
		t.Errorf("Issuer CN = %q, want %q", cert.Issuer.CommonName, "Test Root CA")
	}

	// Verify the certificate is not a CA certificate
	if cert.IsCA {
		t.Error("Issued certificate should not be a CA certificate")
	}
}

func TestSignCSRRaw_WithProfile(t *testing.T) {
	testCA := setupTestCA(t)
	csrPEM := generateTestCSRPEM(t, "profiled.example.com")

	// Use profile="server" and validityDays=365
	cert, err := testCA.SignCSRRaw(csrPEM, "server", 365)
	if err != nil {
		t.Fatalf("SignCSRRaw with profile failed: %v", err)
	}

	if cert == nil {
		t.Fatal("SignCSRRaw returned nil certificate")
	}

	if cert.Subject.CommonName != "profiled.example.com" {
		t.Errorf("CommonName = %q, want %q", cert.Subject.CommonName, "profiled.example.com")
	}

	// The server profile should include ServerAuth extended key usage
	hasServerAuth := false
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageServerAuth {
			hasServerAuth = true
			break
		}
	}
	if !hasServerAuth {
		t.Error("Server profile certificate should include ExtKeyUsageServerAuth")
	}
}

func TestSignCSRRaw_InvalidCSR(t *testing.T) {
	testCA := setupTestCA(t)

	// Pass garbage bytes that are not a valid PEM-encoded CSR
	_, err := testCA.SignCSRRaw([]byte("this is not a valid CSR"), "", 0)
	if err == nil {
		t.Fatal("Expected error for invalid CSR, got nil")
	}

	if !errors.Is(err, ErrInvalidCSR) {
		t.Errorf("Expected ErrInvalidCSR, got: %v", err)
	}
}

func TestSignCSRRaw_NotInitialized(t *testing.T) {
	uninitCA := setupUninitializedCA(t)
	csrPEM := generateTestCSRPEM(t, "uninit.example.com")

	_, err := uninitCA.SignCSRRaw(csrPEM, "", 0)
	if err == nil {
		t.Fatal("Expected error for uninitialized CA, got nil")
	}

	if !errors.Is(err, ErrNotInitialized) {
		t.Errorf("Expected ErrNotInitialized, got: %v", err)
	}
}

func TestSignCSRRaw_ProfileOnlyNoValidityDays(t *testing.T) {
	testCA := setupTestCA(t)
	csrPEM := generateTestCSRPEM(t, "profile-only.example.com")

	// Profile set but validityDays=0: should still create opts with profile
	cert, err := testCA.SignCSRRaw(csrPEM, "client", 0)
	if err != nil {
		t.Fatalf("SignCSRRaw with profile only failed: %v", err)
	}

	if cert == nil {
		t.Fatal("SignCSRRaw returned nil certificate")
	}

	// Client profile should include ClientAuth extended key usage
	hasClientAuth := false
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageClientAuth {
			hasClientAuth = true
			break
		}
	}
	if !hasClientAuth {
		t.Error("Client profile certificate should include ExtKeyUsageClientAuth")
	}
}

func TestSignCSRRaw_ValidityDaysOnlyNoProfile(t *testing.T) {
	testCA := setupTestCA(t)
	csrPEM := generateTestCSRPEM(t, "validity-only.example.com")

	// validityDays>0 but no profile: should create opts with validity only
	cert, err := testCA.SignCSRRaw(csrPEM, "", 30)
	if err != nil {
		t.Fatalf("SignCSRRaw with validity only failed: %v", err)
	}

	if cert == nil {
		t.Fatal("SignCSRRaw returned nil certificate")
	}

	if cert.Subject.CommonName != "validity-only.example.com" {
		t.Errorf("CommonName = %q, want %q", cert.Subject.CommonName, "validity-only.example.com")
	}
}

func TestSignCSRRaw_WrongPEMType(t *testing.T) {
	testCA := setupTestCA(t)

	// Create a PEM block with CERTIFICATE type instead of CERTIFICATE REQUEST
	wrongPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: []byte("fake certificate data"),
	})

	_, err := testCA.SignCSRRaw(wrongPEM, "", 0)
	if err == nil {
		t.Fatal("Expected error for wrong PEM type, got nil")
	}

	if !errors.Is(err, ErrInvalidCSR) {
		t.Errorf("Expected ErrInvalidCSR, got: %v", err)
	}
}

// =============================================================================
// IssueCertificateRaw Tests
// =============================================================================

func TestIssueCertificateRaw_Success(t *testing.T) {
	testCA := setupTestCA(t)

	certPEM, chainPEM, _, serialHex, err := testCA.IssueCertificateRaw(
		"server.example.com", "Test Org", nil, 365, "", "",
	)
	if err != nil {
		t.Fatalf("IssueCertificateRaw failed: %v", err)
	}

	// Verify certificate PEM is non-empty and valid
	if len(certPEM) == 0 {
		t.Fatal("certPEM is empty")
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("Failed to decode certificate PEM")
	}
	if block.Type != "CERTIFICATE" {
		t.Errorf("PEM type = %q, want %q", block.Type, "CERTIFICATE")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	if cert.Subject.CommonName != "server.example.com" {
		t.Errorf("CommonName = %q, want %q", cert.Subject.CommonName, "server.example.com")
	}

	// Verify chain PEM is present (the CA bundle)
	if len(chainPEM) == 0 {
		t.Fatal("chainPEM is empty")
	}

	// Verify serial hex is non-empty
	if serialHex == "" {
		t.Fatal("serialHex is empty")
	}
}

func TestIssueCertificateRaw_WithSANs(t *testing.T) {
	testCA := setupTestCA(t)

	sans := []string{"DNS:example.com", "IP:1.2.3.4"}

	certPEM, _, _, _, err := testCA.IssueCertificateRaw(
		"san-cert.example.com", "Test Org", sans, 365, "", "",
	)
	if err != nil {
		t.Fatalf("IssueCertificateRaw with SANs failed: %v", err)
	}

	if len(certPEM) == 0 {
		t.Fatal("certPEM is empty")
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("Failed to decode certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	// Verify DNS SANs were applied
	foundDNS := false
	for _, dns := range cert.DNSNames {
		if dns == "example.com" {
			foundDNS = true
			break
		}
	}
	if !foundDNS {
		t.Errorf("Expected DNS SAN 'example.com' not found in %v", cert.DNSNames)
	}

	// Verify IP SANs were applied
	foundIP := false
	for _, ip := range cert.IPAddresses {
		if ip.String() == "1.2.3.4" {
			foundIP = true
			break
		}
	}
	if !foundIP {
		t.Errorf("Expected IP SAN '1.2.3.4' not found in %v", cert.IPAddresses)
	}
}

func TestIssueCertificateRaw_EmptyCommonName(t *testing.T) {
	testCA := setupTestCA(t)

	_, _, _, _, err := testCA.IssueCertificateRaw(
		"", "Test Org", nil, 365, "", "",
	)
	if err == nil {
		t.Fatal("Expected error for empty common name, got nil")
	}

	if !errors.Is(err, ErrSubjectCommonNameRequired) {
		t.Errorf("Expected ErrSubjectCommonNameRequired, got: %v", err)
	}
}

func TestIssueCertificateRaw_NotInitialized(t *testing.T) {
	uninitCA := setupUninitializedCA(t)

	_, _, _, _, err := uninitCA.IssueCertificateRaw(
		"uninit.example.com", "Test Org", nil, 365, "", "",
	)
	if err == nil {
		t.Fatal("Expected error for uninitialized CA, got nil")
	}

	if !errors.Is(err, ErrNotInitialized) {
		t.Errorf("Expected ErrNotInitialized, got: %v", err)
	}
}

func TestIssueCertificateRaw_WithAllSANTypes(t *testing.T) {
	testCA := setupTestCA(t)

	sans := []string{
		"DNS:web.example.com",
		"DNS:api.example.com",
		"IP:10.0.0.1",
		"IP:192.168.1.1",
		"Email:admin@example.com",
		"URI:https://example.com/api",
	}

	certPEM, _, _, _, err := testCA.IssueCertificateRaw(
		"all-sans.example.com", "Test Org", sans, 365, "", "",
	)
	if err != nil {
		t.Fatalf("IssueCertificateRaw with all SAN types failed: %v", err)
	}

	block, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	// Verify DNS SANs
	if len(cert.DNSNames) < 2 {
		t.Errorf("Expected at least 2 DNS SANs, got %d: %v", len(cert.DNSNames), cert.DNSNames)
	}

	// Verify IP SANs
	if len(cert.IPAddresses) < 2 {
		t.Errorf("Expected at least 2 IP SANs, got %d", len(cert.IPAddresses))
	}

	// Verify Email SANs
	if len(cert.EmailAddresses) < 1 {
		t.Errorf("Expected at least 1 Email SAN, got %d", len(cert.EmailAddresses))
	}

	// Verify URI SANs
	if len(cert.URIs) < 1 {
		t.Errorf("Expected at least 1 URI SAN, got %d", len(cert.URIs))
	}
}

func TestIssueCertificateRaw_NilSANs(t *testing.T) {
	testCA := setupTestCA(t)

	certPEM, _, _, serialHex, err := testCA.IssueCertificateRaw(
		"no-sans.example.com", "Test Org", nil, 365, "", "",
	)
	if err != nil {
		t.Fatalf("IssueCertificateRaw with nil SANs failed: %v", err)
	}

	if len(certPEM) == 0 {
		t.Fatal("certPEM is empty")
	}
	if serialHex == "" {
		t.Fatal("serialHex is empty")
	}
}

func TestIssueCertificateRaw_EmptySANs(t *testing.T) {
	testCA := setupTestCA(t)

	certPEM, _, _, _, err := testCA.IssueCertificateRaw(
		"empty-sans.example.com", "Test Org", []string{}, 365, "", "",
	)
	if err != nil {
		t.Fatalf("IssueCertificateRaw with empty SANs failed: %v", err)
	}

	if len(certPEM) == 0 {
		t.Fatal("certPEM is empty")
	}
}

func TestIssueCertificateRaw_DuplicateCommonName(t *testing.T) {
	testCA := setupTestCA(t)

	// Issue first certificate
	_, _, _, _, err := testCA.IssueCertificateRaw(
		"duplicate.example.com", "Test Org", nil, 365, "", "",
	)
	if err != nil {
		t.Fatalf("First IssueCertificateRaw failed: %v", err)
	}

	// Attempt to issue a second certificate with the same CN
	_, _, _, _, err = testCA.IssueCertificateRaw(
		"duplicate.example.com", "Test Org", nil, 365, "", "",
	)
	if err == nil {
		t.Fatal("Expected error for duplicate common name, got nil")
	}

	if !errors.Is(err, ErrCertificateAlreadyExists) {
		t.Errorf("Expected ErrCertificateAlreadyExists, got: %v", err)
	}
}

func TestIssueCertificateRaw_WithServerProfile(t *testing.T) {
	testCA := setupTestCA(t)

	certPEM, _, _, _, err := testCA.IssueCertificateRaw(
		"profiled-server.example.com", "Test Org", nil, 365, "server", "",
	)
	if err != nil {
		t.Fatalf("IssueCertificateRaw with server profile failed: %v", err)
	}

	block, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	// Server profile should include ServerAuth
	hasServerAuth := false
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageServerAuth {
			hasServerAuth = true
			break
		}
	}
	if !hasServerAuth {
		t.Error("Server profile certificate should include ExtKeyUsageServerAuth")
	}
}

// =============================================================================
// GetCACertificatePEM Tests
// =============================================================================

func TestGetCACertificatePEM_Success(t *testing.T) {
	testCA := setupTestCA(t)

	pemData, err := testCA.GetCACertificatePEM()
	if err != nil {
		t.Fatalf("GetCACertificatePEM failed: %v", err)
	}

	if len(pemData) == 0 {
		t.Fatal("GetCACertificatePEM returned empty PEM data")
	}

	// Verify it starts with the PEM header
	if !bytes.HasPrefix(pemData, []byte("-----BEGIN CERTIFICATE-----")) {
		t.Errorf("PEM data does not start with expected header, starts with: %q",
			string(pemData[:min(len(pemData), 40)]))
	}

	// Verify we can decode the PEM
	block, _ := pem.Decode(pemData)
	if block == nil {
		t.Fatal("Failed to decode PEM data")
	}
	if block.Type != "CERTIFICATE" {
		t.Errorf("PEM type = %q, want %q", block.Type, "CERTIFICATE")
	}

	// Verify we can parse the certificate
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse certificate from PEM: %v", err)
	}

	// Verify it is the CA certificate
	if cert.Subject.CommonName != "Test Root CA" {
		t.Errorf("CA CN = %q, want %q", cert.Subject.CommonName, "Test Root CA")
	}

	if !cert.IsCA {
		t.Error("CA certificate should have IsCA=true")
	}
}

func TestGetCACertificatePEM_NotInitialized(t *testing.T) {
	uninitCA := setupUninitializedCA(t)

	_, err := uninitCA.GetCACertificatePEM()
	if err == nil {
		t.Fatal("Expected error for uninitialized CA, got nil")
	}

	if !errors.Is(err, ErrNotInitialized) {
		t.Errorf("Expected ErrNotInitialized, got: %v", err)
	}
}

func TestGetCACertificatePEM_ContainsValidDER(t *testing.T) {
	testCA := setupTestCA(t)

	pemData, err := testCA.GetCACertificatePEM()
	if err != nil {
		t.Fatalf("GetCACertificatePEM failed: %v", err)
	}

	// Parse the PEM and verify DER content matches the CA certificate
	block, _ := pem.Decode(pemData)
	if block == nil {
		t.Fatal("Failed to decode PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	// Get the CA certificate directly and compare
	caCert, err := testCA.CACertificate()
	if err != nil {
		t.Fatalf("CACertificate failed: %v", err)
	}

	if !bytes.Equal(cert.Raw, caCert.Raw) {
		t.Error("PEM certificate DER does not match CA certificate DER")
	}
}

func TestGetCACertificatePEM_PEMEndsWithNewline(t *testing.T) {
	testCA := setupTestCA(t)

	pemData, err := testCA.GetCACertificatePEM()
	if err != nil {
		t.Fatalf("GetCACertificatePEM failed: %v", err)
	}

	// PEM encoding should end with "-----END CERTIFICATE-----\n"
	if !strings.HasSuffix(string(pemData), "-----END CERTIFICATE-----\n") {
		t.Errorf("PEM data does not end with expected footer, ends with: %q",
			string(pemData[max(0, len(pemData)-40):]))
	}
}

// =============================================================================
// parseSANStrings Table-Driven Tests
// =============================================================================

func TestParseSANStrings_TableDriven(t *testing.T) {
	tests := []struct {
		name          string
		input         []string
		expectedDNS   int
		expectedIPs   int
		expectedEmail int
		expectedURIs  int
	}{
		{
			name:          "single DNS prefix",
			input:         []string{"DNS:test.com"},
			expectedDNS:   1,
			expectedIPs:   0,
			expectedEmail: 0,
			expectedURIs:  0,
		},
		{
			name:          "single IP prefix",
			input:         []string{"IP:10.0.0.1"},
			expectedDNS:   0,
			expectedIPs:   1,
			expectedEmail: 0,
			expectedURIs:  0,
		},
		{
			name:          "single Email prefix",
			input:         []string{"Email:test@test.com"},
			expectedDNS:   0,
			expectedIPs:   0,
			expectedEmail: 1,
			expectedURIs:  0,
		},
		{
			name:          "single URI prefix",
			input:         []string{"URI:spiffe://cluster.local/ns/default"},
			expectedDNS:   0,
			expectedIPs:   0,
			expectedEmail: 0,
			expectedURIs:  1,
		},
		{
			name:          "bare hostname goes to DNS",
			input:         []string{"myhost.local"},
			expectedDNS:   1,
			expectedIPs:   0,
			expectedEmail: 0,
			expectedURIs:  0,
		},
		{
			name:          "bare IPv4 goes to IPs",
			input:         []string{"127.0.0.1"},
			expectedDNS:   0,
			expectedIPs:   1,
			expectedEmail: 0,
			expectedURIs:  0,
		},
		{
			name:          "bare IPv6 goes to IPs",
			input:         []string{"::1"},
			expectedDNS:   0,
			expectedIPs:   1,
			expectedEmail: 0,
			expectedURIs:  0,
		},
		{
			name:          "multiple of each type",
			input:         []string{"DNS:a.com", "DNS:b.com", "IP:1.1.1.1", "IP:2.2.2.2", "Email:a@a.com", "Email:b@b.com", "URI:https://a.com", "URI:https://b.com"},
			expectedDNS:   2,
			expectedIPs:   2,
			expectedEmail: 2,
			expectedURIs:  2,
		},
		{
			name:          "empty input",
			input:         []string{},
			expectedDNS:   0,
			expectedIPs:   0,
			expectedEmail: 0,
			expectedURIs:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseSANStrings(tt.input)
			if result == nil {
				t.Fatal("parseSANStrings returned nil")
			}
			if len(result.DNS) != tt.expectedDNS {
				t.Errorf("DNS count = %d, want %d", len(result.DNS), tt.expectedDNS)
			}
			if len(result.IPs) != tt.expectedIPs {
				t.Errorf("IPs count = %d, want %d", len(result.IPs), tt.expectedIPs)
			}
			if len(result.Email) != tt.expectedEmail {
				t.Errorf("Email count = %d, want %d", len(result.Email), tt.expectedEmail)
			}
			if len(result.URIs) != tt.expectedURIs {
				t.Errorf("URIs count = %d, want %d", len(result.URIs), tt.expectedURIs)
			}
		})
	}
}

// =============================================================================
// Integration: SignCSRRaw -> Verify round trip
// =============================================================================

func TestSignCSRRaw_VerifyIssuedCert(t *testing.T) {
	testCA := setupTestCA(t)
	csrPEM := generateTestCSRPEM(t, "verify-roundtrip.example.com")

	cert, err := testCA.SignCSRRaw(csrPEM, "", 0)
	if err != nil {
		t.Fatalf("SignCSRRaw failed: %v", err)
	}

	// Verify the issued cert against the CA trust chain
	chains, err := testCA.Verify(cert)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	if len(chains) == 0 {
		t.Fatal("Verify returned no certificate chains")
	}

	// The chain should include the issued cert and the root CA
	if len(chains[0]) < 2 {
		t.Errorf("Expected chain length >= 2, got %d", len(chains[0]))
	}
}

// =============================================================================
// Integration: IssueCertificateRaw -> parse and verify
// =============================================================================

func TestIssueCertificateRaw_FullRoundTrip(t *testing.T) {
	testCA := setupTestCA(t)

	certPEM, chainPEM, _, serialHex, err := testCA.IssueCertificateRaw(
		"roundtrip.example.com", "RoundTrip Org",
		[]string{"DNS:roundtrip.example.com", "IP:10.10.10.10"},
		180, "", "",
	)
	if err != nil {
		t.Fatalf("IssueCertificateRaw failed: %v", err)
	}

	// Parse the issued certificate
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("Failed to decode cert PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	// Verify CN
	if cert.Subject.CommonName != "roundtrip.example.com" {
		t.Errorf("CN = %q, want %q", cert.Subject.CommonName, "roundtrip.example.com")
	}

	// Verify serial hex matches
	if serialHex == "" {
		t.Fatal("serialHex is empty")
	}
	actualSerialHex := cert.SerialNumber.Text(16)
	if actualSerialHex != serialHex {
		t.Errorf("Serial hex = %q, want %q", actualSerialHex, serialHex)
	}

	// Verify chain PEM contains at least one certificate
	chainBlock, _ := pem.Decode(chainPEM)
	if chainBlock == nil {
		t.Fatal("Failed to decode chain PEM")
	}
	if chainBlock.Type != "CERTIFICATE" {
		t.Errorf("Chain PEM type = %q, want %q", chainBlock.Type, "CERTIFICATE")
	}

	// Verify the issued certificate against the CA
	chains, err := testCA.Verify(cert)
	if err != nil {
		t.Fatalf("Verify issued certificate failed: %v", err)
	}
	if len(chains) == 0 {
		t.Fatal("Verify returned empty chains")
	}
}

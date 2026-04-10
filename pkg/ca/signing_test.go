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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"net/url"
	"strings"
	"testing"
)

// =============================================================================
// ParseCSR Tests
// =============================================================================

func TestParseCSR_ValidCSR(t *testing.T) {
	// Generate a test CSR
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	request := &CertificateRequest{
		Subject: Subject{
			CommonName:   "parse.example.com",
			Organization: "Parse Test Org",
			Country:      "US",
		},
		SANS: &SubjectAlternativeNames{
			DNS: []string{"parse.example.com", "www.parse.example.com"},
			IPs: []string{"192.168.1.100"},
		},
	}

	csrPEM, err := CreateCSRWithKey(request, key)
	if err != nil {
		t.Fatalf("Failed to create CSR: %v", err)
	}

	// Test ParseCSR
	csr, err := ParseCSR(csrPEM)
	if err != nil {
		t.Fatalf("ParseCSR failed: %v", err)
	}

	if csr.Subject.CommonName != "parse.example.com" {
		t.Errorf("CommonName = %q, want %q", csr.Subject.CommonName, "parse.example.com")
	}

	if len(csr.DNSNames) != 2 {
		t.Errorf("DNSNames length = %d, want 2", len(csr.DNSNames))
	}

	if len(csr.IPAddresses) != 1 {
		t.Errorf("IPAddresses length = %d, want 1", len(csr.IPAddresses))
	}
}

func TestParseCSR_ValidCSRNewType(t *testing.T) {
	// Generate a test CSR and modify the PEM type
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	subject := Subject{CommonName: "newtype.example.com"}
	template := &x509.CertificateRequest{
		Subject: subject.ToPkixName(),
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		t.Fatalf("Failed to create CSR: %v", err)
	}

	// Encode with alternate PEM type
	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "NEW CERTIFICATE REQUEST",
		Bytes: csrDER,
	})

	csr, err := ParseCSR(csrPEM)
	if err != nil {
		t.Fatalf("ParseCSR with NEW CERTIFICATE REQUEST type failed: %v", err)
	}

	if csr.Subject.CommonName != "newtype.example.com" {
		t.Errorf("CommonName = %q, want %q", csr.Subject.CommonName, "newtype.example.com")
	}
}

func TestParseCSR_EmptyInput(t *testing.T) {
	_, err := ParseCSR([]byte{})
	if err == nil {
		t.Fatal("Expected error for empty input, got nil")
	}

	var pemErr *PEMDecodeError
	if !errors.As(err, &pemErr) {
		t.Errorf("Expected PEMDecodeError, got %T", err)
	}
}

func TestParseCSR_NilInput(t *testing.T) {
	_, err := ParseCSR(nil)
	if err == nil {
		t.Fatal("Expected error for nil input, got nil")
	}

	var pemErr *PEMDecodeError
	if !errors.As(err, &pemErr) {
		t.Errorf("Expected PEMDecodeError, got %T", err)
	}
}

func TestParseCSR_InvalidPEM(t *testing.T) {
	invalidPEM := []byte("not valid PEM data at all")
	_, err := ParseCSR(invalidPEM)
	if err == nil {
		t.Fatal("Expected error for invalid PEM, got nil")
	}

	var pemErr *PEMDecodeError
	if !errors.As(err, &pemErr) {
		t.Errorf("Expected PEMDecodeError, got %T", err)
	}
}

func TestParseCSR_WrongPEMType(t *testing.T) {
	// Create a PEM block with wrong type
	wrongTypePEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: []byte("fake data"),
	})

	_, err := ParseCSR(wrongTypePEM)
	if err == nil {
		t.Fatal("Expected error for wrong PEM type, got nil")
	}

	var pemErr *PEMDecodeError
	if !errors.As(err, &pemErr) {
		t.Errorf("Expected PEMDecodeError, got %T", err)
	}

	if !strings.Contains(err.Error(), "PRIVATE KEY") {
		t.Errorf("Error should mention invalid type, got: %v", err)
	}
}

func TestParseCSR_InvalidDER(t *testing.T) {
	// Create a PEM block with correct type but invalid DER content
	invalidDERPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: []byte("this is not valid DER"),
	})

	_, err := ParseCSR(invalidDERPEM)
	if err == nil {
		t.Fatal("Expected error for invalid DER, got nil")
	}

	var parseErr *CSRParseError
	if !errors.As(err, &parseErr) {
		t.Errorf("Expected CSRParseError, got %T", err)
	}
}

func TestParseCSR_InvalidSignature(t *testing.T) {
	// Generate a valid CSR and then corrupt the signature
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	corruptSubject := Subject{CommonName: "corrupt.example.com"}
	template := &x509.CertificateRequest{
		Subject: corruptSubject.ToPkixName(),
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		t.Fatalf("Failed to create CSR: %v", err)
	}

	// Corrupt the signature (last few bytes of DER)
	if len(csrDER) > 10 {
		csrDER[len(csrDER)-5] ^= 0xFF // flip some bits
		csrDER[len(csrDER)-3] ^= 0xFF
	}

	corruptPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	})

	_, err = ParseCSR(corruptPEM)
	if err == nil {
		t.Fatal("Expected error for corrupted signature, got nil")
	}

	var sigErr *CSRSignatureError
	if !errors.As(err, &sigErr) {
		// Some corruptions may cause parse errors instead of signature errors
		var parseErr *CSRParseError
		if !errors.As(err, &parseErr) {
			t.Errorf("Expected CSRSignatureError or CSRParseError, got %T: %v", err, err)
		}
	}
}

// =============================================================================
// ParseSANsFromCSR Tests
// =============================================================================

func TestParseSANsFromCSR_AllSANTypes(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	request := &CertificateRequest{
		Subject: Subject{CommonName: "sans.example.com"},
		SANS: &SubjectAlternativeNames{
			DNS:   []string{"sans.example.com", "www.sans.example.com"},
			IPs:   []string{"192.168.1.1", "10.0.0.1"},
			Email: []string{"admin@sans.example.com", "user@sans.example.com"},
			URIs:  []string{"https://sans.example.com/api", "spiffe://cluster/ns/svc"},
		},
	}

	csrPEM, err := CreateCSRWithKey(request, key)
	if err != nil {
		t.Fatalf("Failed to create CSR: %v", err)
	}

	csr, err := ParseCSR(csrPEM)
	if err != nil {
		t.Fatalf("Failed to parse CSR: %v", err)
	}

	sans := ParseSANsFromCSR(csr)
	if sans == nil {
		t.Fatal("ParseSANsFromCSR returned nil")
	}

	// Verify DNS names
	if len(sans.DNS) != 2 {
		t.Errorf("DNS length = %d, want 2", len(sans.DNS))
	}
	expectedDNS := map[string]bool{"sans.example.com": true, "www.sans.example.com": true}
	for _, dns := range sans.DNS {
		if !expectedDNS[dns] {
			t.Errorf("Unexpected DNS name: %s", dns)
		}
	}

	// Verify IPs
	if len(sans.IPs) != 2 {
		t.Errorf("IPs length = %d, want 2", len(sans.IPs))
	}
	expectedIPs := map[string]bool{"192.168.1.1": true, "10.0.0.1": true}
	for _, ip := range sans.IPs {
		if !expectedIPs[ip] {
			t.Errorf("Unexpected IP: %s", ip)
		}
	}

	// Verify Email
	if len(sans.Email) != 2 {
		t.Errorf("Email length = %d, want 2", len(sans.Email))
	}
	expectedEmail := map[string]bool{"admin@sans.example.com": true, "user@sans.example.com": true}
	for _, email := range sans.Email {
		if !expectedEmail[email] {
			t.Errorf("Unexpected email: %s", email)
		}
	}

	// Verify URIs
	if len(sans.URIs) != 2 {
		t.Errorf("URIs length = %d, want 2", len(sans.URIs))
	}
	expectedURIs := map[string]bool{
		"https://sans.example.com/api": true,
		"spiffe://cluster/ns/svc":      true,
	}
	for _, uri := range sans.URIs {
		if !expectedURIs[uri] {
			t.Errorf("Unexpected URI: %s", uri)
		}
	}
}

func TestParseSANsFromCSR_DNSOnly(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	request := &CertificateRequest{
		Subject: Subject{CommonName: "dns.example.com"},
		SANS: &SubjectAlternativeNames{
			DNS: []string{"dns.example.com"},
		},
	}

	csrPEM, err := CreateCSRWithKey(request, key)
	if err != nil {
		t.Fatalf("Failed to create CSR: %v", err)
	}

	csr, err := ParseCSR(csrPEM)
	if err != nil {
		t.Fatalf("Failed to parse CSR: %v", err)
	}

	sans := ParseSANsFromCSR(csr)
	if sans == nil {
		t.Fatal("ParseSANsFromCSR returned nil")
	}

	if len(sans.DNS) != 1 {
		t.Errorf("DNS length = %d, want 1", len(sans.DNS))
	}
	if len(sans.IPs) != 0 {
		t.Errorf("IPs length = %d, want 0", len(sans.IPs))
	}
	if len(sans.Email) != 0 {
		t.Errorf("Email length = %d, want 0", len(sans.Email))
	}
	if len(sans.URIs) != 0 {
		t.Errorf("URIs length = %d, want 0", len(sans.URIs))
	}
}

func TestParseSANsFromCSR_NilCSR(t *testing.T) {
	sans := ParseSANsFromCSR(nil)
	if sans != nil {
		t.Errorf("ParseSANsFromCSR(nil) = %v, want nil", sans)
	}
}

func TestParseSANsFromCSR_NoSANs(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	request := &CertificateRequest{
		Subject: Subject{CommonName: "nosans.example.com"},
		SANS:    nil, // No SANs
	}

	csrPEM, err := CreateCSRWithKey(request, key)
	if err != nil {
		t.Fatalf("Failed to create CSR: %v", err)
	}

	csr, err := ParseCSR(csrPEM)
	if err != nil {
		t.Fatalf("Failed to parse CSR: %v", err)
	}

	sans := ParseSANsFromCSR(csr)
	if sans != nil {
		t.Errorf("ParseSANsFromCSR for CSR without SANs = %v, want nil", sans)
	}
}

// =============================================================================
// MergeSANs Tests
// =============================================================================

func TestMergeSANs_BothNil(t *testing.T) {
	result := MergeSANs(nil, nil)
	if result != nil {
		t.Errorf("MergeSANs(nil, nil) = %v, want nil", result)
	}
}

func TestMergeSANs_BaseNil(t *testing.T) {
	additional := &SubjectAlternativeNames{
		DNS:   []string{"add.example.com"},
		IPs:   []string{"10.0.0.1"},
		Email: []string{"add@example.com"},
		URIs:  []string{"https://add.example.com"},
	}

	result := MergeSANs(nil, additional)
	if result == nil {
		t.Fatal("MergeSANs(nil, additional) returned nil")
	}

	if len(result.DNS) != 1 || result.DNS[0] != "add.example.com" {
		t.Errorf("DNS = %v, want [add.example.com]", result.DNS)
	}
	if len(result.IPs) != 1 || result.IPs[0] != "10.0.0.1" {
		t.Errorf("IPs = %v, want [10.0.0.1]", result.IPs)
	}
	if len(result.Email) != 1 || result.Email[0] != "add@example.com" {
		t.Errorf("Email = %v, want [add@example.com]", result.Email)
	}
	if len(result.URIs) != 1 || result.URIs[0] != "https://add.example.com" {
		t.Errorf("URIs = %v, want [https://add.example.com]", result.URIs)
	}
}

func TestMergeSANs_AdditionalNil(t *testing.T) {
	base := &SubjectAlternativeNames{
		DNS:   []string{"base.example.com"},
		IPs:   []string{"192.168.1.1"},
		Email: []string{"base@example.com"},
		URIs:  []string{"https://base.example.com"},
	}

	result := MergeSANs(base, nil)
	if result == nil {
		t.Fatal("MergeSANs(base, nil) returned nil")
	}

	if len(result.DNS) != 1 || result.DNS[0] != "base.example.com" {
		t.Errorf("DNS = %v, want [base.example.com]", result.DNS)
	}
	if len(result.IPs) != 1 || result.IPs[0] != "192.168.1.1" {
		t.Errorf("IPs = %v, want [192.168.1.1]", result.IPs)
	}
	if len(result.Email) != 1 || result.Email[0] != "base@example.com" {
		t.Errorf("Email = %v, want [base@example.com]", result.Email)
	}
	if len(result.URIs) != 1 || result.URIs[0] != "https://base.example.com" {
		t.Errorf("URIs = %v, want [https://base.example.com]", result.URIs)
	}
}

func TestMergeSANs_Merge(t *testing.T) {
	base := &SubjectAlternativeNames{
		DNS:   []string{"base.example.com"},
		IPs:   []string{"192.168.1.1"},
		Email: []string{"base@example.com"},
		URIs:  []string{"https://base.example.com"},
	}

	additional := &SubjectAlternativeNames{
		DNS:   []string{"add.example.com", "extra.example.com"},
		IPs:   []string{"10.0.0.1"},
		Email: []string{"add@example.com"},
		URIs:  []string{"https://add.example.com"},
	}

	result := MergeSANs(base, additional)
	if result == nil {
		t.Fatal("MergeSANs returned nil")
	}

	// Verify merged DNS (3 unique entries)
	if len(result.DNS) != 3 {
		t.Errorf("DNS length = %d, want 3", len(result.DNS))
	}

	// Verify merged IPs (2 unique entries)
	if len(result.IPs) != 2 {
		t.Errorf("IPs length = %d, want 2", len(result.IPs))
	}

	// Verify merged Email (2 unique entries)
	if len(result.Email) != 2 {
		t.Errorf("Email length = %d, want 2", len(result.Email))
	}

	// Verify merged URIs (2 unique entries)
	if len(result.URIs) != 2 {
		t.Errorf("URIs length = %d, want 2", len(result.URIs))
	}
}

func TestMergeSANs_Deduplication(t *testing.T) {
	base := &SubjectAlternativeNames{
		DNS:   []string{"dup.example.com", "unique-base.example.com"},
		IPs:   []string{"192.168.1.1", "10.0.0.1"},
		Email: []string{"dup@example.com"},
		URIs:  []string{"https://dup.example.com"},
	}

	additional := &SubjectAlternativeNames{
		DNS:   []string{"dup.example.com", "unique-add.example.com"}, // dup.example.com is a duplicate
		IPs:   []string{"192.168.1.1", "172.16.0.1"},                 // 192.168.1.1 is a duplicate
		Email: []string{"dup@example.com", "unique@example.com"},     // dup@example.com is a duplicate
		URIs:  []string{"https://dup.example.com", "https://unique.example.com"},
	}

	result := MergeSANs(base, additional)
	if result == nil {
		t.Fatal("MergeSANs returned nil")
	}

	// DNS: 3 unique (dup.example.com, unique-base.example.com, unique-add.example.com)
	if len(result.DNS) != 3 {
		t.Errorf("DNS length = %d, want 3 (deduplicated)", len(result.DNS))
	}

	// IPs: 3 unique (192.168.1.1, 10.0.0.1, 172.16.0.1)
	if len(result.IPs) != 3 {
		t.Errorf("IPs length = %d, want 3 (deduplicated)", len(result.IPs))
	}

	// Email: 2 unique (dup@example.com, unique@example.com)
	if len(result.Email) != 2 {
		t.Errorf("Email length = %d, want 2 (deduplicated)", len(result.Email))
	}

	// URIs: 2 unique (https://dup.example.com, https://unique.example.com)
	if len(result.URIs) != 2 {
		t.Errorf("URIs length = %d, want 2 (deduplicated)", len(result.URIs))
	}
}

func TestMergeSANs_HardwareModuleName(t *testing.T) {
	baseHW := &HardwareModuleInfo{
		HWType:         asn1.ObjectIdentifier{2, 23, 133, 1},
		HWSerialNumber: "BASE123",
	}
	additionalHW := &HardwareModuleInfo{
		HWType:         asn1.ObjectIdentifier{2, 23, 133, 2},
		HWSerialNumber: "ADD456",
	}

	tests := []struct {
		name           string
		baseHW         *HardwareModuleInfo
		additionalHW   *HardwareModuleInfo
		expectedSerial string
	}{
		{
			name:           "additional takes precedence",
			baseHW:         baseHW,
			additionalHW:   additionalHW,
			expectedSerial: "ADD456",
		},
		{
			name:           "base when additional is nil",
			baseHW:         baseHW,
			additionalHW:   nil,
			expectedSerial: "BASE123",
		},
		{
			name:           "additional when base is nil",
			baseHW:         nil,
			additionalHW:   additionalHW,
			expectedSerial: "ADD456",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			base := &SubjectAlternativeNames{
				DNS:                []string{"base.example.com"},
				HardwareModuleName: tt.baseHW,
			}
			additional := &SubjectAlternativeNames{
				DNS:                []string{"add.example.com"},
				HardwareModuleName: tt.additionalHW,
			}

			result := MergeSANs(base, additional)
			if result == nil {
				t.Fatal("MergeSANs returned nil")
			}

			if result.HardwareModuleName == nil {
				t.Fatal("HardwareModuleName should not be nil")
			}

			if result.HardwareModuleName.HWSerialNumber != tt.expectedSerial {
				t.Errorf("HWSerialNumber = %q, want %q", result.HardwareModuleName.HWSerialNumber, tt.expectedSerial)
			}
		})
	}
}

func TestMergeSANs_EmptySANs(t *testing.T) {
	base := &SubjectAlternativeNames{}
	additional := &SubjectAlternativeNames{}

	result := MergeSANs(base, additional)
	if result != nil {
		t.Errorf("MergeSANs with empty SANs = %v, want nil", result)
	}
}

// =============================================================================
// ApplySANsToTemplate Tests
// =============================================================================

func TestApplySANsToTemplate_AllSANTypes(t *testing.T) {
	template := &x509.Certificate{}
	sans := &SubjectAlternativeNames{
		DNS:   []string{"apply.example.com", "www.apply.example.com"},
		IPs:   []string{"192.168.1.1", "10.0.0.1", "::1"},
		Email: []string{"admin@apply.example.com"},
		URIs:  []string{"https://apply.example.com", "spiffe://cluster/ns/svc"},
	}

	err := ApplySANsToTemplate(template, sans)
	if err != nil {
		t.Fatalf("ApplySANsToTemplate failed: %v", err)
	}

	// Verify DNS
	if len(template.DNSNames) != 2 {
		t.Errorf("DNSNames length = %d, want 2", len(template.DNSNames))
	}

	// Verify IPs
	if len(template.IPAddresses) != 3 {
		t.Errorf("IPAddresses length = %d, want 3", len(template.IPAddresses))
	}

	// Verify Email
	if len(template.EmailAddresses) != 1 {
		t.Errorf("EmailAddresses length = %d, want 1", len(template.EmailAddresses))
	}

	// Verify URIs
	if len(template.URIs) != 2 {
		t.Errorf("URIs length = %d, want 2", len(template.URIs))
	}
}

func TestApplySANsToTemplate_NilTemplate(t *testing.T) {
	sans := &SubjectAlternativeNames{
		DNS: []string{"test.example.com"},
	}

	err := ApplySANsToTemplate(nil, sans)
	if err != nil {
		t.Errorf("ApplySANsToTemplate with nil template should not error: %v", err)
	}
}

func TestApplySANsToTemplate_NilSANs(t *testing.T) {
	template := &x509.Certificate{}

	err := ApplySANsToTemplate(template, nil)
	if err != nil {
		t.Errorf("ApplySANsToTemplate with nil SANs should not error: %v", err)
	}

	if len(template.DNSNames) != 0 {
		t.Errorf("DNSNames should be empty, got %v", template.DNSNames)
	}
}

func TestApplySANsToTemplate_InvalidIPs(t *testing.T) {
	template := &x509.Certificate{}
	sans := &SubjectAlternativeNames{
		IPs: []string{"192.168.1.1", "not-an-ip", "10.0.0.1", "also-invalid"},
	}

	err := ApplySANsToTemplate(template, sans)
	if err != nil {
		t.Fatalf("ApplySANsToTemplate failed: %v", err)
	}

	// Should only have 2 valid IPs
	if len(template.IPAddresses) != 2 {
		t.Errorf("IPAddresses length = %d, want 2 (valid only)", len(template.IPAddresses))
	}
}

func TestApplySANsToTemplate_InvalidURIs(t *testing.T) {
	template := &x509.Certificate{}
	sans := &SubjectAlternativeNames{
		URIs: []string{
			"https://valid.example.com",
			"no-scheme",                 // invalid - no scheme
			"://malformed",              // invalid - malformed
			"ftp://another.example.com", // valid
		},
	}

	err := ApplySANsToTemplate(template, sans)
	if err != nil {
		t.Fatalf("ApplySANsToTemplate failed: %v", err)
	}

	// Should only have 2 valid URIs
	if len(template.URIs) != 2 {
		t.Errorf("URIs length = %d, want 2 (valid only)", len(template.URIs))
	}
}

func TestApplySANsToTemplate_EmptySANs(t *testing.T) {
	template := &x509.Certificate{}
	sans := &SubjectAlternativeNames{}

	err := ApplySANsToTemplate(template, sans)
	if err != nil {
		t.Fatalf("ApplySANsToTemplate failed: %v", err)
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
// DefaultServerKeyUsage Tests
// =============================================================================

func TestDefaultServerKeyUsage(t *testing.T) {
	keyUsage := DefaultServerKeyUsage()

	// Server certs need DigitalSignature and KeyEncipherment
	expectedUsage := x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment

	if keyUsage != expectedUsage {
		t.Errorf("DefaultServerKeyUsage() = %v, want %v", keyUsage, expectedUsage)
	}

	// Verify individual bits
	if keyUsage&x509.KeyUsageDigitalSignature == 0 {
		t.Error("DefaultServerKeyUsage should include DigitalSignature")
	}
	if keyUsage&x509.KeyUsageKeyEncipherment == 0 {
		t.Error("DefaultServerKeyUsage should include KeyEncipherment")
	}
}

func TestDefaultServerKeyUsage_NotCertSign(t *testing.T) {
	keyUsage := DefaultServerKeyUsage()

	// Server certs should NOT have cert signing capability
	if keyUsage&x509.KeyUsageCertSign != 0 {
		t.Error("DefaultServerKeyUsage should NOT include CertSign")
	}
	if keyUsage&x509.KeyUsageCRLSign != 0 {
		t.Error("DefaultServerKeyUsage should NOT include CRLSign")
	}
}

// =============================================================================
// DefaultClientKeyUsage Tests
// =============================================================================

func TestDefaultClientKeyUsage(t *testing.T) {
	keyUsage := DefaultClientKeyUsage()

	// Client certs need DigitalSignature
	expectedUsage := x509.KeyUsageDigitalSignature

	if keyUsage != expectedUsage {
		t.Errorf("DefaultClientKeyUsage() = %v, want %v", keyUsage, expectedUsage)
	}

	// Verify individual bits
	if keyUsage&x509.KeyUsageDigitalSignature == 0 {
		t.Error("DefaultClientKeyUsage should include DigitalSignature")
	}
}

func TestDefaultClientKeyUsage_NotKeyEncipherment(t *testing.T) {
	keyUsage := DefaultClientKeyUsage()

	// Client certs typically don't need KeyEncipherment
	if keyUsage&x509.KeyUsageKeyEncipherment != 0 {
		t.Error("DefaultClientKeyUsage should NOT include KeyEncipherment")
	}
}

// =============================================================================
// DefaultServerExtKeyUsage Tests
// =============================================================================

func TestDefaultServerExtKeyUsage(t *testing.T) {
	extKeyUsage := DefaultServerExtKeyUsage()

	if len(extKeyUsage) != 1 {
		t.Fatalf("DefaultServerExtKeyUsage() length = %d, want 1", len(extKeyUsage))
	}

	if extKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		t.Errorf("DefaultServerExtKeyUsage()[0] = %v, want %v", extKeyUsage[0], x509.ExtKeyUsageServerAuth)
	}
}

// =============================================================================
// DefaultClientExtKeyUsage Tests
// =============================================================================

func TestDefaultClientExtKeyUsage(t *testing.T) {
	extKeyUsage := DefaultClientExtKeyUsage()

	if len(extKeyUsage) != 1 {
		t.Fatalf("DefaultClientExtKeyUsage() length = %d, want 1", len(extKeyUsage))
	}

	if extKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Errorf("DefaultClientExtKeyUsage()[0] = %v, want %v", extKeyUsage[0], x509.ExtKeyUsageClientAuth)
	}
}

// =============================================================================
// DefaultServerClientExtKeyUsage Tests
// =============================================================================

func TestDefaultServerClientExtKeyUsage(t *testing.T) {
	extKeyUsage := DefaultServerClientExtKeyUsage()

	if len(extKeyUsage) != 2 {
		t.Fatalf("DefaultServerClientExtKeyUsage() length = %d, want 2", len(extKeyUsage))
	}

	hasServerAuth := false
	hasClientAuth := false
	for _, usage := range extKeyUsage {
		if usage == x509.ExtKeyUsageServerAuth {
			hasServerAuth = true
		}
		if usage == x509.ExtKeyUsageClientAuth {
			hasClientAuth = true
		}
	}

	if !hasServerAuth {
		t.Error("DefaultServerClientExtKeyUsage should include ServerAuth")
	}
	if !hasClientAuth {
		t.Error("DefaultServerClientExtKeyUsage should include ClientAuth")
	}
}

// =============================================================================
// IsValidCSRPEM Tests
// =============================================================================

func TestIsValidCSRPEM_Valid(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	request := &CertificateRequest{
		Subject: Subject{CommonName: "valid.example.com"},
	}

	csrPEM, err := CreateCSRWithKey(request, key)
	if err != nil {
		t.Fatalf("Failed to create CSR: %v", err)
	}

	if !IsValidCSRPEM(csrPEM) {
		t.Error("IsValidCSRPEM returned false for valid CSR PEM")
	}
}

func TestIsValidCSRPEM_ValidNewType(t *testing.T) {
	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "NEW CERTIFICATE REQUEST",
		Bytes: []byte("fake data"),
	})

	if !IsValidCSRPEM(pemData) {
		t.Error("IsValidCSRPEM returned false for NEW CERTIFICATE REQUEST type")
	}
}

func TestIsValidCSRPEM_Empty(t *testing.T) {
	if IsValidCSRPEM([]byte{}) {
		t.Error("IsValidCSRPEM returned true for empty input")
	}
}

func TestIsValidCSRPEM_Nil(t *testing.T) {
	if IsValidCSRPEM(nil) {
		t.Error("IsValidCSRPEM returned true for nil input")
	}
}

func TestIsValidCSRPEM_InvalidPEM(t *testing.T) {
	if IsValidCSRPEM([]byte("not valid PEM")) {
		t.Error("IsValidCSRPEM returned true for invalid PEM")
	}
}

func TestIsValidCSRPEM_WrongType(t *testing.T) {
	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: []byte("fake data"),
	})

	if IsValidCSRPEM(pemData) {
		t.Error("IsValidCSRPEM returned true for wrong PEM type")
	}
}

func TestIsValidCSRPEM_PrivateKeyType(t *testing.T) {
	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: []byte("fake data"),
	})

	if IsValidCSRPEM(pemData) {
		t.Error("IsValidCSRPEM returned true for PRIVATE KEY type")
	}
}

// =============================================================================
// Error Type Tests
// =============================================================================

func TestPEMDecodeError_Error(t *testing.T) {
	err := &PEMDecodeError{Reason: "test reason"}
	expected := "ca: pem decode failed: test reason"
	if err.Error() != expected {
		t.Errorf("Error() = %q, want %q", err.Error(), expected)
	}
}

func TestCSRParseError_Error(t *testing.T) {
	underlying := errors.New("underlying error")
	err := &CSRParseError{Err: underlying}
	expected := "ca: csr parse failed: underlying error"
	if err.Error() != expected {
		t.Errorf("Error() = %q, want %q", err.Error(), expected)
	}
}

func TestCSRParseError_Unwrap(t *testing.T) {
	underlying := errors.New("underlying error")
	err := &CSRParseError{Err: underlying}
	if err.Unwrap() != underlying {
		t.Errorf("Unwrap() = %v, want %v", err.Unwrap(), underlying)
	}
}

func TestCSRSignatureError_Error(t *testing.T) {
	underlying := errors.New("signature error")
	err := &CSRSignatureError{Err: underlying}
	expected := "ca: csr signature verification failed: signature error"
	if err.Error() != expected {
		t.Errorf("Error() = %q, want %q", err.Error(), expected)
	}
}

func TestCSRSignatureError_Unwrap(t *testing.T) {
	underlying := errors.New("signature error")
	err := &CSRSignatureError{Err: underlying}
	if err.Unwrap() != underlying {
		t.Errorf("Unwrap() = %v, want %v", err.Unwrap(), underlying)
	}
}

func TestCSRSigningError_Error(t *testing.T) {
	underlying := errors.New("underlying error")

	tests := []struct {
		name     string
		err      *CSRSigningError
		expected string
	}{
		{
			name:     "without details",
			err:      &CSRSigningError{Op: "sign", Err: underlying},
			expected: "ca: sign failed: underlying error",
		},
		{
			name:     "with details",
			err:      &CSRSigningError{Op: "sign", Err: underlying, Details: "extra info"},
			expected: "ca: sign failed: extra info: underlying error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err.Error() != tt.expected {
				t.Errorf("Error() = %q, want %q", tt.err.Error(), tt.expected)
			}
		})
	}
}

func TestCSRSigningError_Unwrap(t *testing.T) {
	underlying := errors.New("underlying error")
	err := &CSRSigningError{Op: "sign", Err: underlying}
	if err.Unwrap() != underlying {
		t.Errorf("Unwrap() = %v, want %v", err.Unwrap(), underlying)
	}
}

func TestCertificateCreationError_Error(t *testing.T) {
	underlying := errors.New("creation error")
	err := &CertificateCreationError{Err: underlying}
	expected := "ca: certificate creation failed: creation error"
	if err.Error() != expected {
		t.Errorf("Error() = %q, want %q", err.Error(), expected)
	}
}

func TestCertificateCreationError_Unwrap(t *testing.T) {
	underlying := errors.New("creation error")
	err := &CertificateCreationError{Err: underlying}
	if err.Unwrap() != underlying {
		t.Errorf("Unwrap() = %v, want %v", err.Unwrap(), underlying)
	}
}

func TestCertificateStoreError_Error(t *testing.T) {
	underlying := errors.New("store error")
	err := &CertificateStoreError{Op: "save", Err: underlying}
	expected := "ca: certificate store save failed: store error"
	if err.Error() != expected {
		t.Errorf("Error() = %q, want %q", err.Error(), expected)
	}
}

func TestCertificateStoreError_Unwrap(t *testing.T) {
	underlying := errors.New("store error")
	err := &CertificateStoreError{Op: "save", Err: underlying}
	if err.Unwrap() != underlying {
		t.Errorf("Unwrap() = %v, want %v", err.Unwrap(), underlying)
	}
}

// =============================================================================
// Integration Tests (Full CSR -> Parse -> Extract SANs flow)
// =============================================================================

func TestFullCSRParseFlow(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	originalSANs := &SubjectAlternativeNames{
		DNS:   []string{"full.example.com", "www.full.example.com", "api.full.example.com"},
		IPs:   []string{"192.168.1.1", "10.0.0.1", "::1"},
		Email: []string{"admin@full.example.com", "support@full.example.com"},
		URIs:  []string{"https://full.example.com/api", "spiffe://cluster.local/ns/prod"},
	}

	request := &CertificateRequest{
		Subject: Subject{
			CommonName:         "full.example.com",
			Organization:       "Full Test Org",
			OrganizationalUnit: "Engineering",
			Country:            "US",
			Province:           "California",
			Locality:           "San Francisco",
		},
		SANS: originalSANs,
	}

	// Step 1: Create CSR
	csrPEM, err := CreateCSRWithKey(request, key)
	if err != nil {
		t.Fatalf("CreateCSRWithKey failed: %v", err)
	}

	// Step 2: Validate PEM
	if !IsValidCSRPEM(csrPEM) {
		t.Error("IsValidCSRPEM returned false for valid CSR")
	}

	// Step 3: Parse CSR
	csr, err := ParseCSR(csrPEM)
	if err != nil {
		t.Fatalf("ParseCSR failed: %v", err)
	}

	// Step 4: Extract SANs
	extractedSANs := ParseSANsFromCSR(csr)
	if extractedSANs == nil {
		t.Fatal("ParseSANsFromCSR returned nil")
	}

	// Step 5: Verify all SANs were preserved
	if len(extractedSANs.DNS) != len(originalSANs.DNS) {
		t.Errorf("DNS count = %d, want %d", len(extractedSANs.DNS), len(originalSANs.DNS))
	}
	if len(extractedSANs.IPs) != len(originalSANs.IPs) {
		t.Errorf("IPs count = %d, want %d", len(extractedSANs.IPs), len(originalSANs.IPs))
	}
	if len(extractedSANs.Email) != len(originalSANs.Email) {
		t.Errorf("Email count = %d, want %d", len(extractedSANs.Email), len(originalSANs.Email))
	}
	if len(extractedSANs.URIs) != len(originalSANs.URIs) {
		t.Errorf("URIs count = %d, want %d", len(extractedSANs.URIs), len(originalSANs.URIs))
	}

	// Step 6: Apply to new certificate template
	certTemplate := &x509.Certificate{}
	err = ApplySANsToTemplate(certTemplate, extractedSANs)
	if err != nil {
		t.Fatalf("ApplySANsToTemplate failed: %v", err)
	}

	// Step 7: Verify template has SANs
	if len(certTemplate.DNSNames) != len(originalSANs.DNS) {
		t.Errorf("Template DNS count = %d, want %d", len(certTemplate.DNSNames), len(originalSANs.DNS))
	}
	if len(certTemplate.IPAddresses) != len(originalSANs.IPs) {
		t.Errorf("Template IPs count = %d, want %d", len(certTemplate.IPAddresses), len(originalSANs.IPs))
	}
	if len(certTemplate.EmailAddresses) != len(originalSANs.Email) {
		t.Errorf("Template Email count = %d, want %d", len(certTemplate.EmailAddresses), len(originalSANs.Email))
	}
	if len(certTemplate.URIs) != len(originalSANs.URIs) {
		t.Errorf("Template URIs count = %d, want %d", len(certTemplate.URIs), len(originalSANs.URIs))
	}
}

// =============================================================================
// Table-Driven Tests
// =============================================================================

func TestIsValidCSRPEM_TableDriven(t *testing.T) {
	tests := []struct {
		name     string
		input    func() []byte
		expected bool
	}{
		{
			name: "valid CSR PEM",
			input: func() []byte {
				return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: []byte("test")})
			},
			expected: true,
		},
		{
			name: "valid NEW CERTIFICATE REQUEST",
			input: func() []byte {
				return pem.EncodeToMemory(&pem.Block{Type: "NEW CERTIFICATE REQUEST", Bytes: []byte("test")})
			},
			expected: true,
		},
		{
			name:     "CERTIFICATE type",
			input:    func() []byte { return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("test")}) },
			expected: false,
		},
		{
			name:     "PRIVATE KEY type",
			input:    func() []byte { return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("test")}) },
			expected: false,
		},
		{
			name:     "PUBLIC KEY type",
			input:    func() []byte { return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("test")}) },
			expected: false,
		},
		{
			name:     "empty input",
			input:    func() []byte { return []byte{} },
			expected: false,
		},
		{
			name:     "nil input",
			input:    func() []byte { return nil },
			expected: false,
		},
		{
			name:     "garbage input",
			input:    func() []byte { return []byte("not pem data") },
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsValidCSRPEM(tt.input())
			if result != tt.expected {
				t.Errorf("IsValidCSRPEM() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestApplySANsToTemplate_URISchemes(t *testing.T) {
	tests := []struct {
		name          string
		uris          []string
		expectedCount int
	}{
		{
			name:          "https URIs",
			uris:          []string{"https://example.com", "https://api.example.com"},
			expectedCount: 2,
		},
		{
			name:          "http URIs",
			uris:          []string{"http://example.com"},
			expectedCount: 1,
		},
		{
			name:          "spiffe URIs",
			uris:          []string{"spiffe://cluster.local/ns/default/sa/service"},
			expectedCount: 1,
		},
		{
			name:          "mixed schemes",
			uris:          []string{"https://example.com", "spiffe://cluster/svc", "ftp://ftp.example.com"},
			expectedCount: 3,
		},
		{
			name:          "no scheme - invalid",
			uris:          []string{"example.com", "another.com"},
			expectedCount: 0,
		},
		{
			name:          "mixed valid and invalid",
			uris:          []string{"https://valid.com", "no-scheme", "http://also-valid.com"},
			expectedCount: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			template := &x509.Certificate{}
			sans := &SubjectAlternativeNames{URIs: tt.uris}

			err := ApplySANsToTemplate(template, sans)
			if err != nil {
				t.Fatalf("ApplySANsToTemplate failed: %v", err)
			}

			if len(template.URIs) != tt.expectedCount {
				t.Errorf("URIs count = %d, want %d", len(template.URIs), tt.expectedCount)
			}
		})
	}
}

// =============================================================================
// SubjectAlternativeNames ParseIPs and ParseURIs Tests
// =============================================================================

func TestSubjectAlternativeNames_ParseIPs(t *testing.T) {
	tests := []struct {
		name     string
		sans     *SubjectAlternativeNames
		expected int
	}{
		{
			name:     "nil SANs",
			sans:     nil,
			expected: 0,
		},
		{
			name:     "empty IPs",
			sans:     &SubjectAlternativeNames{},
			expected: 0,
		},
		{
			name:     "valid IPs",
			sans:     &SubjectAlternativeNames{IPs: []string{"192.168.1.1", "10.0.0.1", "::1"}},
			expected: 3,
		},
		{
			name:     "invalid IPs",
			sans:     &SubjectAlternativeNames{IPs: []string{"not-an-ip", "also-invalid"}},
			expected: 0,
		},
		{
			name:     "mixed valid and invalid",
			sans:     &SubjectAlternativeNames{IPs: []string{"192.168.1.1", "invalid", "10.0.0.1"}},
			expected: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ips := tt.sans.ParseIPs()
			if len(ips) != tt.expected {
				t.Errorf("ParseIPs() count = %d, want %d", len(ips), tt.expected)
			}
		})
	}
}

func TestSubjectAlternativeNames_ParseURIs(t *testing.T) {
	tests := []struct {
		name     string
		sans     *SubjectAlternativeNames
		expected int
	}{
		{
			name:     "nil SANs",
			sans:     nil,
			expected: 0,
		},
		{
			name:     "empty URIs",
			sans:     &SubjectAlternativeNames{},
			expected: 0,
		},
		{
			name:     "valid URIs",
			sans:     &SubjectAlternativeNames{URIs: []string{"https://example.com", "http://test.com"}},
			expected: 2,
		},
		{
			name:     "no scheme URIs",
			sans:     &SubjectAlternativeNames{URIs: []string{"example.com", "test.com"}},
			expected: 0,
		},
		{
			name:     "mixed valid and invalid",
			sans:     &SubjectAlternativeNames{URIs: []string{"https://example.com", "no-scheme", "ftp://ftp.com"}},
			expected: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			uris := tt.sans.ParseURIs()
			if len(uris) != tt.expected {
				t.Errorf("ParseURIs() count = %d, want %d", len(uris), tt.expected)
			}
		})
	}
}

// =============================================================================
// Edge Cases
// =============================================================================

func TestApplySANsToTemplate_IPv6(t *testing.T) {
	template := &x509.Certificate{}
	sans := &SubjectAlternativeNames{
		IPs: []string{
			"::1",                          // loopback
			"2001:db8::1",                  // documentation
			"fe80::1",                      // link-local
			"2001:db8:85a3::8a2e:370:7334", // full address
		},
	}

	err := ApplySANsToTemplate(template, sans)
	if err != nil {
		t.Fatalf("ApplySANsToTemplate failed: %v", err)
	}

	if len(template.IPAddresses) != 4 {
		t.Errorf("IPv6 addresses count = %d, want 4", len(template.IPAddresses))
	}
}

func TestMergeSANs_PreservesOrder(t *testing.T) {
	base := &SubjectAlternativeNames{
		DNS: []string{"first.example.com", "second.example.com"},
	}
	additional := &SubjectAlternativeNames{
		DNS: []string{"third.example.com", "fourth.example.com"},
	}

	result := MergeSANs(base, additional)

	// Base entries should come first
	if result.DNS[0] != "first.example.com" {
		t.Errorf("First DNS = %q, want %q", result.DNS[0], "first.example.com")
	}
	if result.DNS[1] != "second.example.com" {
		t.Errorf("Second DNS = %q, want %q", result.DNS[1], "second.example.com")
	}
}

func TestApplySANsToTemplate_SPIFFEURIs(t *testing.T) {
	template := &x509.Certificate{}
	sans := &SubjectAlternativeNames{
		URIs: []string{
			"spiffe://cluster.local/ns/default/sa/myservice",
			"spiffe://example.org/workload/id",
		},
	}

	err := ApplySANsToTemplate(template, sans)
	if err != nil {
		t.Fatalf("ApplySANsToTemplate failed: %v", err)
	}

	if len(template.URIs) != 2 {
		t.Fatalf("SPIFFE URIs count = %d, want 2", len(template.URIs))
	}

	// Verify SPIFFE URIs are preserved correctly
	for _, uri := range template.URIs {
		if uri.Scheme != "spiffe" {
			t.Errorf("URI scheme = %q, want %q", uri.Scheme, "spiffe")
		}
	}
}

func TestParseCSR_MultipleCSRs(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// Create two CSRs
	csr1PEM, _ := CreateCSRWithKey(&CertificateRequest{Subject: Subject{CommonName: "first.example.com"}}, key)
	csr2PEM, _ := CreateCSRWithKey(&CertificateRequest{Subject: Subject{CommonName: "second.example.com"}}, key)

	// Combine them (only first should be parsed)
	combined := append(csr1PEM, csr2PEM...)

	csr, err := ParseCSR(combined)
	if err != nil {
		t.Fatalf("ParseCSR failed: %v", err)
	}

	// Should only parse the first CSR
	if csr.Subject.CommonName != "first.example.com" {
		t.Errorf("CommonName = %q, want %q", csr.Subject.CommonName, "first.example.com")
	}
}

func TestCreateCSRWithKey_LongCommonName(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// CommonName should be limited to 64 characters per RFC 5280
	longCN := strings.Repeat("a", 64)
	request := &CertificateRequest{
		Subject: Subject{CommonName: longCN},
	}

	csrPEM, err := CreateCSRWithKey(request, key)
	if err != nil {
		t.Fatalf("CreateCSRWithKey failed: %v", err)
	}

	block, _ := pem.Decode(csrPEM)
	csr, _ := x509.ParseCertificateRequest(block.Bytes)

	if csr.Subject.CommonName != longCN {
		t.Errorf("CommonName length = %d, want %d", len(csr.Subject.CommonName), 64)
	}
}

func TestApplySANsToTemplate_SpecialCharactersInEmail(t *testing.T) {
	template := &x509.Certificate{}
	sans := &SubjectAlternativeNames{
		Email: []string{
			"user+tag@example.com",
			"user.name@example.com",
			"user_name@example.com",
		},
	}

	err := ApplySANsToTemplate(template, sans)
	if err != nil {
		t.Fatalf("ApplySANsToTemplate failed: %v", err)
	}

	if len(template.EmailAddresses) != 3 {
		t.Errorf("EmailAddresses count = %d, want 3", len(template.EmailAddresses))
	}
}

func TestMergeSANs_LargeNumberOfEntries(t *testing.T) {
	// Create SANs with many entries
	baseDNS := make([]string, 100)
	addDNS := make([]string, 100)
	for i := 0; i < 100; i++ {
		baseDNS[i] = "base" + string(rune('0'+i%10)) + ".example.com"
		addDNS[i] = "add" + string(rune('0'+i%10)) + ".example.com"
	}

	base := &SubjectAlternativeNames{DNS: baseDNS}
	additional := &SubjectAlternativeNames{DNS: addDNS}

	result := MergeSANs(base, additional)
	if result == nil {
		t.Fatal("MergeSANs returned nil")
	}

	// Due to deduplication, we should have fewer entries
	// Base has 100 entries with 10 unique, add has 100 with 10 unique
	// But they don't overlap, so we should have 20 unique
	if len(result.DNS) != 20 {
		t.Errorf("DNS count = %d, want 20 (deduplicated)", len(result.DNS))
	}
}

// Test URI validation with various edge cases
func TestApplySANsToTemplate_URIEdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		uri      string
		expected bool // true if should be included
	}{
		{"empty string", "", false},
		{"only scheme", "https://", true},
		{"with port", "https://example.com:8443", true},
		{"with path", "https://example.com/path/to/resource", true},
		{"with query", "https://example.com?key=value", true},
		{"with fragment", "https://example.com#section", true},
		{"file scheme", "file:///path/to/file", true},
		{"custom scheme", "myapp://callback", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			template := &x509.Certificate{}
			sans := &SubjectAlternativeNames{URIs: []string{tt.uri}}

			err := ApplySANsToTemplate(template, sans)
			if err != nil {
				t.Fatalf("ApplySANsToTemplate failed: %v", err)
			}

			hasURI := len(template.URIs) == 1
			if hasURI != tt.expected {
				t.Errorf("URI included = %v, want %v", hasURI, tt.expected)
			}

			if hasURI {
				// Verify the URI was parsed correctly
				parsed, _ := url.Parse(tt.uri)
				if template.URIs[0].String() != parsed.String() {
					t.Errorf("URI = %q, want %q", template.URIs[0].String(), parsed.String())
				}
			}
		})
	}
}

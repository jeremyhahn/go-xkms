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
	"crypto/x509"
	"errors"
	"net"
	"testing"
)

// =============================================================================
// Subject Tests
// =============================================================================

func TestSubject_ToPkixName_WithAllFields(t *testing.T) {
	t.Parallel()

	subject := &Subject{
		CommonName:         "example.com",
		Organization:       "Example Org",
		OrganizationalUnit: "IT Department",
		Country:            "US",
		Province:           "California",
		Locality:           "San Francisco",
		Address:            "123 Main St",
		PostalCode:         "94105",
	}

	name := subject.ToPkixName()

	if name.CommonName != "example.com" {
		t.Errorf("CommonName: expected %q, got %q", "example.com", name.CommonName)
	}
	if len(name.Organization) != 1 || name.Organization[0] != "Example Org" {
		t.Errorf("Organization: expected [%q], got %v", "Example Org", name.Organization)
	}
	if len(name.OrganizationalUnit) != 1 || name.OrganizationalUnit[0] != "IT Department" {
		t.Errorf("OrganizationalUnit: expected [%q], got %v", "IT Department", name.OrganizationalUnit)
	}
	if len(name.Country) != 1 || name.Country[0] != "US" {
		t.Errorf("Country: expected [%q], got %v", "US", name.Country)
	}
	if len(name.Province) != 1 || name.Province[0] != "California" {
		t.Errorf("Province: expected [%q], got %v", "California", name.Province)
	}
	if len(name.Locality) != 1 || name.Locality[0] != "San Francisco" {
		t.Errorf("Locality: expected [%q], got %v", "San Francisco", name.Locality)
	}
	if len(name.StreetAddress) != 1 || name.StreetAddress[0] != "123 Main St" {
		t.Errorf("StreetAddress: expected [%q], got %v", "123 Main St", name.StreetAddress)
	}
	if len(name.PostalCode) != 1 || name.PostalCode[0] != "94105" {
		t.Errorf("PostalCode: expected [%q], got %v", "94105", name.PostalCode)
	}
}

func TestSubject_ToPkixName_WithOnlyRequiredFields(t *testing.T) {
	t.Parallel()

	subject := &Subject{
		CommonName: "minimal.example.com",
	}

	name := subject.ToPkixName()

	if name.CommonName != "minimal.example.com" {
		t.Errorf("CommonName: expected %q, got %q", "minimal.example.com", name.CommonName)
	}
	if len(name.Organization) != 0 {
		t.Errorf("Organization: expected empty, got %v", name.Organization)
	}
	if len(name.OrganizationalUnit) != 0 {
		t.Errorf("OrganizationalUnit: expected empty, got %v", name.OrganizationalUnit)
	}
	if len(name.Country) != 0 {
		t.Errorf("Country: expected empty, got %v", name.Country)
	}
	if len(name.Province) != 0 {
		t.Errorf("Province: expected empty, got %v", name.Province)
	}
	if len(name.Locality) != 0 {
		t.Errorf("Locality: expected empty, got %v", name.Locality)
	}
	if len(name.StreetAddress) != 0 {
		t.Errorf("StreetAddress: expected empty, got %v", name.StreetAddress)
	}
	if len(name.PostalCode) != 0 {
		t.Errorf("PostalCode: expected empty, got %v", name.PostalCode)
	}
}

func TestSubject_Validate_Success(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		subject Subject
	}{
		{
			name:    "simple common name",
			subject: Subject{CommonName: "example.com"},
		},
		{
			name:    "with organization",
			subject: Subject{CommonName: "example.com", Organization: "Org"},
		},
		{
			name:    "full subject",
			subject: Subject{CommonName: "CN", Organization: "O", Country: "US"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if err := tt.subject.Validate(); err != nil {
				t.Errorf("Validate() unexpected error: %v", err)
			}
		})
	}
}

func TestSubject_Validate_Error(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		subject     Subject
		expectedErr error
	}{
		{
			name:        "empty common name",
			subject:     Subject{CommonName: ""},
			expectedErr: ErrSubjectCommonNameRequired,
		},
		{
			name:        "only whitespace common name",
			subject:     Subject{CommonName: "", Organization: "Org"},
			expectedErr: ErrSubjectCommonNameRequired,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.subject.Validate()
			if err == nil {
				t.Fatal("Validate() expected error, got nil")
			}
			if !errors.Is(err, tt.expectedErr) {
				t.Errorf("Validate() error = %v, expected %v", err, tt.expectedErr)
			}
		})
	}
}

// =============================================================================
// SubjectAlternativeNames Tests
// =============================================================================

func TestSubjectAlternativeNames_ParseIPs_Success(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		sans     *SubjectAlternativeNames
		expected []string
	}{
		{
			name: "valid IPv4 addresses",
			sans: &SubjectAlternativeNames{
				IPs: []string{"192.168.1.1", "10.0.0.1", "127.0.0.1"},
			},
			expected: []string{"192.168.1.1", "10.0.0.1", "127.0.0.1"},
		},
		{
			name: "valid IPv6 addresses",
			sans: &SubjectAlternativeNames{
				IPs: []string{"::1", "2001:db8::1", "fe80::1"},
			},
			expected: []string{"::1", "2001:db8::1", "fe80::1"},
		},
		{
			name: "mixed IPv4 and IPv6",
			sans: &SubjectAlternativeNames{
				IPs: []string{"192.168.1.1", "::1"},
			},
			expected: []string{"192.168.1.1", "::1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ips := tt.sans.ParseIPs()
			if len(ips) != len(tt.expected) {
				t.Fatalf("ParseIPs() got %d IPs, expected %d", len(ips), len(tt.expected))
			}
			for i, expectedIP := range tt.expected {
				expected := net.ParseIP(expectedIP)
				if !ips[i].Equal(expected) {
					t.Errorf("ParseIPs()[%d] = %v, expected %v", i, ips[i], expected)
				}
			}
		})
	}
}

func TestSubjectAlternativeNames_ParseIPs_InvalidAddresses(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		sans        *SubjectAlternativeNames
		expectedLen int
	}{
		{
			name:        "nil SANs",
			sans:        nil,
			expectedLen: 0,
		},
		{
			name:        "empty IPs",
			sans:        &SubjectAlternativeNames{IPs: []string{}},
			expectedLen: 0,
		},
		{
			name:        "all invalid IPs",
			sans:        &SubjectAlternativeNames{IPs: []string{"invalid", "not-an-ip", "999.999.999.999"}},
			expectedLen: 0,
		},
		{
			name:        "mixed valid and invalid",
			sans:        &SubjectAlternativeNames{IPs: []string{"192.168.1.1", "invalid", "10.0.0.1"}},
			expectedLen: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ips := tt.sans.ParseIPs()
			if len(ips) != tt.expectedLen {
				t.Errorf("ParseIPs() got %d IPs, expected %d", len(ips), tt.expectedLen)
			}
		})
	}
}

func TestSubjectAlternativeNames_ParseURIs_Success(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		sans     *SubjectAlternativeNames
		expected []string
	}{
		{
			name: "valid HTTPS URIs",
			sans: &SubjectAlternativeNames{
				URIs: []string{"https://example.com", "https://test.example.com/path"},
			},
			expected: []string{"https://example.com", "https://test.example.com/path"},
		},
		{
			name: "various schemes",
			sans: &SubjectAlternativeNames{
				URIs: []string{"spiffe://trust.domain/workload", "urn:example:resource"},
			},
			expected: []string{"spiffe://trust.domain/workload", "urn:example:resource"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			uris := tt.sans.ParseURIs()
			if len(uris) != len(tt.expected) {
				t.Fatalf("ParseURIs() got %d URIs, expected %d", len(uris), len(tt.expected))
			}
			for i, expectedURI := range tt.expected {
				if uris[i].String() != expectedURI {
					t.Errorf("ParseURIs()[%d] = %q, expected %q", i, uris[i].String(), expectedURI)
				}
			}
		})
	}
}

func TestSubjectAlternativeNames_ParseURIs_InvalidURIs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		sans        *SubjectAlternativeNames
		expectedLen int
	}{
		{
			name:        "nil SANs",
			sans:        nil,
			expectedLen: 0,
		},
		{
			name:        "empty URIs",
			sans:        &SubjectAlternativeNames{URIs: []string{}},
			expectedLen: 0,
		},
		{
			name:        "URIs without scheme",
			sans:        &SubjectAlternativeNames{URIs: []string{"no-scheme-here", "/relative/path"}},
			expectedLen: 0,
		},
		{
			name:        "mixed valid and no-scheme",
			sans:        &SubjectAlternativeNames{URIs: []string{"https://example.com", "no-scheme"}},
			expectedLen: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			uris := tt.sans.ParseURIs()
			if len(uris) != tt.expectedLen {
				t.Errorf("ParseURIs() got %d URIs, expected %d", len(uris), tt.expectedLen)
			}
		})
	}
}

// =============================================================================
// CertificateRequest Tests
// =============================================================================

func TestCertificateRequest_Validate_Success(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		req  CertificateRequest
	}{
		{
			name: "minimal valid request",
			req: CertificateRequest{
				Subject: Subject{CommonName: "example.com"},
			},
		},
		{
			name: "with validity period",
			req: CertificateRequest{
				Subject: Subject{CommonName: "example.com"},
				Valid:   365,
			},
		},
		{
			name: "CA certificate request",
			req: CertificateRequest{
				Subject:    Subject{CommonName: "Intermediate CA"},
				IsCA:       true,
				MaxPathLen: 0,
			},
		},
		{
			name: "with SANs",
			req: CertificateRequest{
				Subject: Subject{CommonName: "example.com"},
				SANS: &SubjectAlternativeNames{
					DNS: []string{"www.example.com"},
					IPs: []string{"192.168.1.1"},
				},
			},
		},
		{
			name: "with key usage",
			req: CertificateRequest{
				Subject:     Subject{CommonName: "example.com"},
				KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
				ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if err := tt.req.Validate(); err != nil {
				t.Errorf("Validate() unexpected error: %v", err)
			}
		})
	}
}

func TestCertificateRequest_Validate_Error(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		req         CertificateRequest
		expectedErr error
	}{
		{
			name: "missing common name",
			req: CertificateRequest{
				Subject: Subject{CommonName: ""},
			},
			expectedErr: ErrSubjectCommonNameRequired,
		},
		{
			name: "negative validity period",
			req: CertificateRequest{
				Subject: Subject{CommonName: "example.com"},
				Valid:   -1,
			},
			expectedErr: ErrInvalidValidityPeriod,
		},
		{
			name: "negative path length for CA",
			req: CertificateRequest{
				Subject:    Subject{CommonName: "CA"},
				IsCA:       true,
				MaxPathLen: -1,
			},
			expectedErr: ErrInvalidPathLength,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.req.Validate()
			if err == nil {
				t.Fatal("Validate() expected error, got nil")
			}
			if !errors.Is(err, tt.expectedErr) {
				t.Errorf("Validate() error = %v, expected %v", err, tt.expectedErr)
			}
		})
	}
}

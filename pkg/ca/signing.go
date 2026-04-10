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

// Package ca provides CSR signing helper functions for the XKMSCA certificate authority.
//
// This file provides helper functions for certificate signing request (CSR) handling
// and Subject Alternative Name (SAN) operations that complement the main CA implementation.
package ca

import (
	"crypto/x509"
	"encoding/pem"
	"net"
	"net/url"
)

// =============================================================================
// CSR Signing Errors
// =============================================================================

// CSRSigningError wraps errors that occur during CSR signing operations.
type CSRSigningError struct {
	Op      string // operation that failed
	Err     error  // underlying error
	Details string // additional context
}

func (e *CSRSigningError) Error() string {
	if e.Details != "" {
		return "ca: " + e.Op + " failed: " + e.Details + ": " + e.Err.Error()
	}
	return "ca: " + e.Op + " failed: " + e.Err.Error()
}

func (e *CSRSigningError) Unwrap() error {
	return e.Err
}

// PEMDecodeError indicates that PEM decoding failed.
type PEMDecodeError struct {
	Reason string
}

func (e *PEMDecodeError) Error() string {
	return "ca: pem decode failed: " + e.Reason
}

// CSRParseError indicates that CSR parsing failed.
type CSRParseError struct {
	Err error
}

func (e *CSRParseError) Error() string {
	return "ca: csr parse failed: " + e.Err.Error()
}

func (e *CSRParseError) Unwrap() error {
	return e.Err
}

// CSRSignatureError indicates that CSR signature verification failed.
type CSRSignatureError struct {
	Err error
}

func (e *CSRSignatureError) Error() string {
	return "ca: csr signature verification failed: " + e.Err.Error()
}

func (e *CSRSignatureError) Unwrap() error {
	return e.Err
}

// CertificateCreationError indicates that certificate creation failed.
type CertificateCreationError struct {
	Err error
}

func (e *CertificateCreationError) Error() string {
	return "ca: certificate creation failed: " + e.Err.Error()
}

func (e *CertificateCreationError) Unwrap() error {
	return e.Err
}

// CertificateStoreError indicates that certificate storage failed.
type CertificateStoreError struct {
	Op  string
	Err error
}

func (e *CertificateStoreError) Error() string {
	return "ca: certificate store " + e.Op + " failed: " + e.Err.Error()
}

func (e *CertificateStoreError) Unwrap() error {
	return e.Err
}

// =============================================================================
// CSR Parsing Functions
// =============================================================================

// ParseCSR decodes and validates a PEM-encoded certificate signing request.
//
// This function:
//  1. Decodes the PEM block
//  2. Parses the CSR structure
//  3. Validates the CSR signature
//
// Returns typed errors for all failure cases:
//   - PEMDecodeError for PEM decoding failures
//   - CSRParseError for CSR structure parsing failures
//   - CSRSignatureError for signature verification failures
func ParseCSR(csrPEM []byte) (*x509.CertificateRequest, error) {
	if len(csrPEM) == 0 {
		return nil, &PEMDecodeError{Reason: "empty input"}
	}

	// Decode PEM block
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		return nil, &PEMDecodeError{Reason: "no valid PEM block found"}
	}

	// Validate PEM type
	if block.Type != "CERTIFICATE REQUEST" && block.Type != "NEW CERTIFICATE REQUEST" {
		return nil, &PEMDecodeError{Reason: "invalid PEM type: " + block.Type}
	}

	// Parse CSR
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, &CSRParseError{Err: err}
	}

	// Validate CSR signature
	if err := csr.CheckSignature(); err != nil {
		return nil, &CSRSignatureError{Err: err}
	}

	return csr, nil
}

// =============================================================================
// SAN Helper Functions
// =============================================================================

// ParseSANsFromCSR extracts Subject Alternative Names from a CSR.
//
// This function creates a SubjectAlternativeNames struct populated with:
//   - DNS names
//   - IP addresses
//   - Email addresses
//   - URIs
func ParseSANsFromCSR(csr *x509.CertificateRequest) *SubjectAlternativeNames {
	if csr == nil {
		return nil
	}

	// Check if CSR has any SANs
	if len(csr.DNSNames) == 0 && len(csr.IPAddresses) == 0 &&
		len(csr.EmailAddresses) == 0 && len(csr.URIs) == 0 {
		return nil
	}

	sans := &SubjectAlternativeNames{}

	// Copy DNS names
	if len(csr.DNSNames) > 0 {
		sans.DNS = make([]string, len(csr.DNSNames))
		copy(sans.DNS, csr.DNSNames)
	}

	// Convert IP addresses to strings
	if len(csr.IPAddresses) > 0 {
		sans.IPs = make([]string, 0, len(csr.IPAddresses))
		for _, ip := range csr.IPAddresses {
			sans.IPs = append(sans.IPs, ip.String())
		}
	}

	// Copy email addresses
	if len(csr.EmailAddresses) > 0 {
		sans.Email = make([]string, len(csr.EmailAddresses))
		copy(sans.Email, csr.EmailAddresses)
	}

	// Convert URIs to strings
	if len(csr.URIs) > 0 {
		sans.URIs = make([]string, 0, len(csr.URIs))
		for _, uri := range csr.URIs {
			sans.URIs = append(sans.URIs, uri.String())
		}
	}

	return sans
}

// MergeSANs combines two SubjectAlternativeNames structures, with additional
// values appended to base values. Duplicates are removed.
//
// If base is nil, returns a copy of additional.
// If additional is nil, returns a copy of base.
// If both are nil, returns nil.
func MergeSANs(base, additional *SubjectAlternativeNames) *SubjectAlternativeNames {
	if base == nil && additional == nil {
		return nil
	}

	result := &SubjectAlternativeNames{}

	// Helper function to merge string slices without duplicates
	mergeStrings := func(a, b []string) []string {
		if len(a) == 0 && len(b) == 0 {
			return nil
		}

		seen := make(map[string]struct{})
		merged := make([]string, 0, len(a)+len(b))

		for _, s := range a {
			if _, exists := seen[s]; !exists {
				seen[s] = struct{}{}
				merged = append(merged, s)
			}
		}
		for _, s := range b {
			if _, exists := seen[s]; !exists {
				seen[s] = struct{}{}
				merged = append(merged, s)
			}
		}

		if len(merged) == 0 {
			return nil
		}
		return merged
	}

	var baseDNS, baseIPs, baseEmail, baseURIs []string
	var addDNS, addIPs, addEmail, addURIs []string

	if base != nil {
		baseDNS = base.DNS
		baseIPs = base.IPs
		baseEmail = base.Email
		baseURIs = base.URIs
	}

	if additional != nil {
		addDNS = additional.DNS
		addIPs = additional.IPs
		addEmail = additional.Email
		addURIs = additional.URIs
	}

	result.DNS = mergeStrings(baseDNS, addDNS)
	result.IPs = mergeStrings(baseIPs, addIPs)
	result.Email = mergeStrings(baseEmail, addEmail)
	result.URIs = mergeStrings(baseURIs, addURIs)

	// Copy hardware module info from additional if present, otherwise from base
	if additional != nil && additional.HardwareModuleName != nil {
		result.HardwareModuleName = additional.HardwareModuleName
	} else if base != nil && base.HardwareModuleName != nil {
		result.HardwareModuleName = base.HardwareModuleName
	}

	// Check if result has any content
	if len(result.DNS) == 0 && len(result.IPs) == 0 &&
		len(result.Email) == 0 && len(result.URIs) == 0 &&
		result.HardwareModuleName == nil {
		return nil
	}

	return result
}

// ApplySANsToTemplate applies the SubjectAlternativeNames to a certificate template.
//
// This function:
//   - Converts DNS names directly
//   - Parses IP address strings to net.IP
//   - Copies email addresses directly
//   - Parses URI strings to *url.URL
//
// Invalid IP addresses or URIs are silently skipped.
func ApplySANsToTemplate(template *x509.Certificate, sans *SubjectAlternativeNames) error {
	if sans == nil || template == nil {
		return nil
	}

	// Apply DNS names
	if len(sans.DNS) > 0 {
		template.DNSNames = make([]string, len(sans.DNS))
		copy(template.DNSNames, sans.DNS)
	}

	// Parse and apply IP addresses
	if len(sans.IPs) > 0 {
		template.IPAddresses = make([]net.IP, 0, len(sans.IPs))
		for _, ipStr := range sans.IPs {
			if ip := net.ParseIP(ipStr); ip != nil {
				template.IPAddresses = append(template.IPAddresses, ip)
			}
		}
	}

	// Apply email addresses
	if len(sans.Email) > 0 {
		template.EmailAddresses = make([]string, len(sans.Email))
		copy(template.EmailAddresses, sans.Email)
	}

	// Parse and apply URIs
	if len(sans.URIs) > 0 {
		template.URIs = make([]*url.URL, 0, len(sans.URIs))
		for _, uriStr := range sans.URIs {
			if u, err := url.Parse(uriStr); err == nil && u.Scheme != "" {
				template.URIs = append(template.URIs, u)
			}
		}
	}

	return nil
}

// =============================================================================
// Certificate Template Helpers
// =============================================================================

// DefaultServerKeyUsage returns the default key usage for server certificates.
func DefaultServerKeyUsage() x509.KeyUsage {
	return x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
}

// DefaultClientKeyUsage returns the default key usage for client certificates.
func DefaultClientKeyUsage() x509.KeyUsage {
	return x509.KeyUsageDigitalSignature
}

// DefaultServerExtKeyUsage returns the default extended key usage for server certificates.
func DefaultServerExtKeyUsage() []x509.ExtKeyUsage {
	return []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
}

// DefaultClientExtKeyUsage returns the default extended key usage for client certificates.
func DefaultClientExtKeyUsage() []x509.ExtKeyUsage {
	return []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
}

// DefaultServerClientExtKeyUsage returns extended key usage for combined server/client certificates.
func DefaultServerClientExtKeyUsage() []x509.ExtKeyUsage {
	return []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
}

// IsValidCSRPEM validates that the provided data is valid PEM-encoded CSR without
// full parsing. This is useful for quick validation before expensive operations.
func IsValidCSRPEM(data []byte) bool {
	if len(data) == 0 {
		return false
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return false
	}

	return block.Type == "CERTIFICATE REQUEST" || block.Type == "NEW CERTIFICATE REQUEST"
}

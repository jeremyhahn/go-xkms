// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

// Package certstore provides high-level certificate management operations including
// certificate storage, chain management, CRL handling, and certificate verification.
//
// CertStore builds on storage.CertificateStorage by adding certificate validation,
// revocation checking, and certificate chain management capabilities.
package certstore

import (
	"crypto/x509"
)

// CertStore provides comprehensive certificate management operations.
// It extends basic certificate storage with validation, revocation checking,
// and chain management capabilities.
//
// All implementations must be thread-safe.
type CertStore interface {
	// ========================================================================
	// Basic Certificate Operations
	// ========================================================================

	// StoreCertificate stores a certificate identified by its Common Name.
	// Returns an error if the certificate already exists (depending on implementation).
	StoreCertificate(cert *x509.Certificate) error

	// GetCertificate retrieves a certificate by its Common Name.
	// Returns ErrCertNotFound if the certificate does not exist.
	GetCertificate(cn string) (*x509.Certificate, error)

	// DeleteCertificate removes a certificate by its Common Name.
	// Returns ErrCertNotFound if the certificate does not exist.
	DeleteCertificate(cn string) error

	// ListCertificates returns all certificates currently stored.
	// Returns an empty slice if no certificates exist.
	ListCertificates() ([]*x509.Certificate, error)

	// ========================================================================
	// Certificate Chain Operations
	// ========================================================================

	// StoreCertificateChain stores a certificate chain for the given Common Name.
	// The chain should be ordered from leaf to root.
	// The first certificate in the chain should be the end-entity certificate.
	StoreCertificateChain(chain []*x509.Certificate) error

	// GetCertificateChain retrieves a certificate chain by Common Name.
	// Returns the complete chain from leaf to root.
	// Returns ErrCertNotFound if the chain does not exist.
	GetCertificateChain(cn string) ([]*x509.Certificate, error)

	// ========================================================================
	// Certificate Revocation List (CRL) Operations
	// ========================================================================

	// StoreCRL stores a Certificate Revocation List.
	// The issuer parameter identifies which CA issued this CRL.
	StoreCRL(crl *x509.RevocationList) error

	// GetCRL retrieves a CRL for the given issuer.
	// Returns ErrCRLNotFound if the CRL does not exist.
	GetCRL(issuer string) (*x509.RevocationList, error)

	// ========================================================================
	// Certificate Validation Operations
	// ========================================================================

	// VerifyCertificate validates a certificate against a pool of trusted roots.
	// This performs full chain verification including:
	//   - Signature validation
	//   - Validity period checking
	//   - Chain of trust verification
	//   - Extended key usage validation
	//
	// Returns an error if verification fails.
	VerifyCertificate(cert *x509.Certificate, roots *x509.CertPool) error

	// IsRevoked checks if a certificate has been revoked.
	// This checks all available CRLs for the certificate's issuer.
	// Returns true if the certificate is revoked, false otherwise.
	// Returns an error if the check cannot be performed.
	IsRevoked(cert *x509.Certificate) (bool, error)

	// ========================================================================
	// Lifecycle
	// ========================================================================

	// Close releases all resources held by the cert store.
	Close() error
}

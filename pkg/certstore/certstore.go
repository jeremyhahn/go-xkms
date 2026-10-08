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

// Package certstore provides high-level certificate management operations including
// certificate storage, chain management, CRL handling, and certificate verification.
//
// A CertStore persists certificates and chains as go-qrdb DAO entities in
// the CA's database (DatabaseName), built from the DAO factory its
// composition root injects, and adds certificate validation, revocation
// checking, and certificate chain management.
package certstore

import (
	"crypto/x509"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
)

// CertificateKey returns the key StoreCertificate indexes cert under: its
// Subject.CommonName, or -- for a certificate with an empty Subject, such as
// the WebAuthn Level 2 §8.3.1 profile Local Attestation Key certificate
// go-xkms#715 introduced -- the SPKI SHA-256 thumbprint
// (qrdbsdk.ComputeSPKIThumbprint), base64url-encoded over the certificate's
// SubjectPublicKeyInfo.
//
// The SPKI thumbprint is qrdb's own canonical mTLS binding identifier
// (go-qrdb/pkg/user.ComputeSPKIThumbprint, re-exported through
// go-qrdb/sdk/go), not a go-xkms invention: the ownership/SDK-boundary
// constitution requires xkms to adopt the ONE cert-binding algorithm the rest
// of the stack already uses rather than define a parallel one. Because the
// thumbprint is computed over the public key alone, re-issuing a certificate
// for the same key -- the LAK is never rotated independently of its key --
// resolves to the same key both before and after reissuance.
//
// Returns "" for a nil certificate.
func CertificateKey(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	if cert.Subject.CommonName != "" {
		return cert.Subject.CommonName
	}
	return qrdbsdk.ComputeSPKIThumbprint(cert)
}

// CertStore provides comprehensive certificate management operations.
// It extends basic certificate storage with validation, revocation checking,
// and chain management capabilities.
//
// All implementations must be thread-safe.
type CertStore interface {
	// ========================================================================
	// Basic Certificate Operations
	// ========================================================================

	// StoreCertificate stores a certificate under its CertificateKey,
	// replacing any certificate stored there.
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
	// Returns ErrChainNotFound if the chain does not exist.
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

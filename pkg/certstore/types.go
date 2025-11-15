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

package certstore

import (
	"crypto/x509"
	"time"
)

// Config provides configuration for creating a new CertStore instance.
type Config struct {
	// CertStorage provides underlying certificate storage.
	// Required.
	CertStorage CertificateStorageAdapter

	// VerifyOptions provides default verification options.
	// Optional - if not provided, defaults will be used.
	VerifyOptions *x509.VerifyOptions

	// AllowRevoked if true, allows operations on revoked certificates.
	// Default is false - operations on revoked certs will fail.
	AllowRevoked bool
}

// CertificateStorageAdapter is a local interface that matches storage.CertificateStorage.
// This allows the certstore package to work with any compatible storage implementation
// without creating a direct dependency on the storage package.
//
// This interface is satisfied by storage.CertificateStorage.
type CertificateStorageAdapter interface {
	SaveCert(id string, cert *x509.Certificate) error
	GetCert(id string) (*x509.Certificate, error)
	DeleteCert(id string) error
	SaveCertChain(id string, chain []*x509.Certificate) error
	GetCertChain(id string) ([]*x509.Certificate, error)
	ListCerts() ([]string, error)
	CertExists(id string) (bool, error)
	Close() error
}

// CRLEntry represents a certificate revocation list entry.
type CRLEntry struct {
	// SerialNumber is the serial number of the revoked certificate.
	SerialNumber string

	// RevocationTime is when the certificate was revoked.
	RevocationTime time.Time

	// Reason is the revocation reason code.
	Reason int
}

// CertificateInfo provides detailed information about a stored certificate.
type CertificateInfo struct {
	// Certificate is the X.509 certificate.
	Certificate *x509.Certificate

	// CN is the Common Name from the certificate subject.
	CN string

	// Issuer is the Common Name of the issuing CA.
	Issuer string

	// NotBefore is the certificate validity start time.
	NotBefore time.Time

	// NotAfter is the certificate validity end time.
	NotAfter time.Time

	// IsCA indicates if this is a CA certificate.
	IsCA bool

	// IsRevoked indicates if the certificate is revoked.
	IsRevoked bool

	// KeyUsage describes the key usage extensions.
	KeyUsage x509.KeyUsage

	// ExtKeyUsage describes the extended key usage extensions.
	ExtKeyUsage []x509.ExtKeyUsage
}

// ChainInfo provides information about a certificate chain.
type ChainInfo struct {
	// Certificates is the complete chain from leaf to root.
	Certificates []*x509.Certificate

	// LeafCN is the Common Name of the end-entity certificate.
	LeafCN string

	// RootCN is the Common Name of the root CA certificate.
	RootCN string

	// IsValid indicates if the chain is valid and trusted.
	IsValid bool

	// ValidationError contains any validation errors.
	ValidationError error
}

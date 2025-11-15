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

package storage

import (
	"crypto/x509"
	"fmt"
)

// CertAdapter wraps a Backend to provide certificate-specific operations.
// It handles marshaling/unmarshaling of x509.Certificate objects to/from
// DER-encoded bytes for storage.
//
// This adapter implements the CertificateStorageAdapter interface used by
// the certstore and keychain packages.
type CertAdapter struct {
	backend Backend
}

// NewCertAdapter creates a new certificate adapter wrapping the given backend.
func NewCertAdapter(backend Backend) *CertAdapter {
	return &CertAdapter{
		backend: backend,
	}
}

// Backend returns the underlying storage backend.
func (ca *CertAdapter) Backend() Backend {
	return ca.backend
}

// SaveCert stores a certificate using the backend.
// The certificate is DER-encoded before storage.
func (ca *CertAdapter) SaveCert(id string, cert *x509.Certificate) error {
	if id == "" {
		return ErrInvalidID
	}
	if cert == nil {
		return fmt.Errorf("certificate cannot be nil")
	}

	certData := cert.Raw
	if len(certData) == 0 {
		return fmt.Errorf("certificate has no raw data")
	}

	key := CertPath(id)
	return ca.backend.Put(key, certData, nil)
}

// GetCert retrieves and parses a certificate from the backend.
func (ca *CertAdapter) GetCert(id string) (*x509.Certificate, error) {
	if id == "" {
		return nil, ErrInvalidID
	}

	key := CertPath(id)
	certData, err := ca.backend.Get(key)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(certData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert, nil
}

// DeleteCert removes a certificate from the backend.
func (ca *CertAdapter) DeleteCert(id string) error {
	if id == "" {
		return ErrInvalidID
	}

	key := CertPath(id)
	return ca.backend.Delete(key)
}

// SaveCertChain stores a certificate chain using the backend.
// The chain is PEM-encoded before storage.
func (ca *CertAdapter) SaveCertChain(id string, chain []*x509.Certificate) error {
	if id == "" {
		return ErrInvalidID
	}
	if len(chain) == 0 {
		return fmt.Errorf("certificate chain cannot be empty")
	}

	// Concatenate all certificate raw data
	var chainData []byte
	for i, cert := range chain {
		if cert == nil {
			return fmt.Errorf("certificate at index %d is nil", i)
		}
		if len(cert.Raw) == 0 {
			return fmt.Errorf("certificate at index %d has no raw data", i)
		}
		chainData = append(chainData, cert.Raw...)
	}

	key := CertChainPath(id)
	return ca.backend.Put(key, chainData, nil)
}

// GetCertChain retrieves and parses a certificate chain from the backend.
func (ca *CertAdapter) GetCertChain(id string) ([]*x509.Certificate, error) {
	if id == "" {
		return nil, ErrInvalidID
	}

	key := CertChainPath(id)
	chainData, err := ca.backend.Get(key)
	if err != nil {
		return nil, err
	}

	certs, err := x509.ParseCertificates(chainData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate chain: %w", err)
	}

	return certs, nil
}

// ListCerts returns all certificate IDs from the backend.
func (ca *CertAdapter) ListCerts() ([]string, error) {
	return ListCerts(ca.backend)
}

// CertExists checks if a certificate exists in the backend.
func (ca *CertAdapter) CertExists(id string) (bool, error) {
	if id == "" {
		return false, ErrInvalidID
	}

	key := CertPath(id)
	return ca.backend.Exists(key)
}

// Close releases resources held by the backend.
func (ca *CertAdapter) Close() error {
	return ca.backend.Close()
}

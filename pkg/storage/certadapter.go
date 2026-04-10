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

package storage

import (
	"context"
	"crypto/x509"
	"fmt"
)

// CertAdapter wraps a Backend to provide certificate-specific operations.
// It handles marshaling/unmarshaling of x509.Certificate objects to/from
// DER-encoded bytes for storage.
//
// This adapter implements the CertificateStorageAdapter interface used by
// the certstore and xkms packages.
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
func (ca *CertAdapter) SaveCert(ctx context.Context, id string, cert *x509.Certificate) error {
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
	return ca.backend.Put(ctx, key, certData)
}

// GetCert retrieves and parses a certificate from the backend.
func (ca *CertAdapter) GetCert(ctx context.Context, id string) (*x509.Certificate, error) {
	if id == "" {
		return nil, ErrInvalidID
	}

	key := CertPath(id)
	certData, err := ca.backend.Get(ctx, key)
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
func (ca *CertAdapter) DeleteCert(ctx context.Context, id string) error {
	if id == "" {
		return ErrInvalidID
	}

	key := CertPath(id)
	return ca.backend.Delete(ctx, key)
}

// SaveCertChain stores a certificate chain using the backend.
// The chain is PEM-encoded before storage.
func (ca *CertAdapter) SaveCertChain(ctx context.Context, id string, chain []*x509.Certificate) error {
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
	return ca.backend.Put(ctx, key, chainData)
}

// GetCertChain retrieves and parses a certificate chain from the backend.
func (ca *CertAdapter) GetCertChain(ctx context.Context, id string) ([]*x509.Certificate, error) {
	if id == "" {
		return nil, ErrInvalidID
	}

	key := CertChainPath(id)
	chainData, err := ca.backend.Get(ctx, key)
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
func (ca *CertAdapter) ListCerts(ctx context.Context) ([]string, error) {
	return ListCerts(ctx, ca.backend)
}

// CertExists checks if a certificate exists in the backend.
func (ca *CertAdapter) CertExists(ctx context.Context, id string) (bool, error) {
	if id == "" {
		return false, ErrInvalidID
	}

	key := CertPath(id)
	return ca.backend.Exists(ctx, key)
}

// Close releases resources held by the backend.
func (ca *CertAdapter) Close() error {
	return ca.backend.Close()
}

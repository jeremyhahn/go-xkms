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

package xkms

import (
	"context"
	"crypto/x509"
)

// ========================================================================
// Certificate Operations (delegated to CertificateStorage)
// ========================================================================

// SaveCert stores a certificate for the given key ID.
// The keyID typically matches the key's identifier/CN.
func (c *compositeBackend) SaveCert(keyID string, cert *x509.Certificate) error {
	if keyID == "" {
		return ErrInvalidKeyID
	}
	if cert == nil {
		return ErrNilCertificate
	}

	if err := c.certStorage.SaveCert(context.Background(), keyID, cert); err != nil {
		return &ErrCertOperation{Operation: "save certificate", Err: err}
	}

	return nil
}

// GetCert retrieves a certificate by key ID.
func (c *compositeBackend) GetCert(keyID string) (*x509.Certificate, error) {
	if keyID == "" {
		return nil, ErrInvalidKeyID
	}

	cert, err := c.certStorage.GetCert(context.Background(), keyID)
	if err != nil {
		return nil, &ErrCertOperation{Operation: "get certificate", Err: err}
	}

	return cert, nil
}

// DeleteCert removes a certificate by key ID.
func (c *compositeBackend) DeleteCert(keyID string) error {
	if keyID == "" {
		return ErrInvalidKeyID
	}

	if err := c.certStorage.DeleteCert(context.Background(), keyID); err != nil {
		return &ErrCertOperation{Operation: "delete certificate", Err: err}
	}

	return nil
}

// SaveCertChain stores a certificate chain for the given key ID.
// The chain should be ordered from leaf to root.
func (c *compositeBackend) SaveCertChain(keyID string, chain []*x509.Certificate) error {
	if keyID == "" {
		return ErrInvalidKeyID
	}
	if len(chain) == 0 {
		return ErrEmptyChain
	}

	if err := c.certStorage.SaveCertChain(context.Background(), keyID, chain); err != nil {
		return &ErrCertOperation{Operation: "save certificate chain", Err: err}
	}

	return nil
}

// GetCertChain retrieves a certificate chain by key ID.
func (c *compositeBackend) GetCertChain(keyID string) ([]*x509.Certificate, error) {
	if keyID == "" {
		return nil, ErrInvalidKeyID
	}

	chain, err := c.certStorage.GetCertChain(context.Background(), keyID)
	if err != nil {
		return nil, &ErrCertOperation{Operation: "get certificate chain", Err: err}
	}

	return chain, nil
}

// ListCerts returns all certificate IDs currently stored.
func (c *compositeBackend) ListCerts() ([]string, error) {
	ids, err := c.certStorage.ListCerts(context.Background())
	if err != nil {
		return nil, &ErrCertOperation{Operation: "list certificates", Err: err}
	}

	return ids, nil
}

// CertExists checks if a certificate exists for the given key ID.
func (c *compositeBackend) CertExists(keyID string) (bool, error) {
	if keyID == "" {
		return false, ErrInvalidKeyID
	}

	exists, err := c.certStorage.CertExists(context.Background(), keyID)
	if err != nil {
		return false, &ErrCertOperation{Operation: "check if certificate exists", Err: err}
	}

	return exists, nil
}

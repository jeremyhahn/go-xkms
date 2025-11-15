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

package keychain

import (
	"crypto/x509"
	"fmt"
)

// ========================================================================
// Certificate Operations (delegated to CertificateStorage)
// ========================================================================

// SaveCert stores a certificate for the given key ID.
// The keyID typically matches the key's identifier/CN.
func (ks *compositeKeyStore) SaveCert(keyID string, cert *x509.Certificate) error {
	if keyID == "" {
		return ErrInvalidKeyID
	}
	if cert == nil {
		return fmt.Errorf("certificate cannot be nil")
	}

	if err := ks.certStorage.SaveCert(keyID, cert); err != nil {
		return fmt.Errorf("failed to save certificate: %w", err)
	}

	return nil
}

// GetCert retrieves a certificate by key ID.
func (ks *compositeKeyStore) GetCert(keyID string) (*x509.Certificate, error) {
	if keyID == "" {
		return nil, ErrInvalidKeyID
	}

	cert, err := ks.certStorage.GetCert(keyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get certificate: %w", err)
	}

	return cert, nil
}

// DeleteCert removes a certificate by key ID.
func (ks *compositeKeyStore) DeleteCert(keyID string) error {
	if keyID == "" {
		return ErrInvalidKeyID
	}

	if err := ks.certStorage.DeleteCert(keyID); err != nil {
		return fmt.Errorf("failed to delete certificate: %w", err)
	}

	return nil
}

// SaveCertChain stores a certificate chain for the given key ID.
// The chain should be ordered from leaf to root.
func (ks *compositeKeyStore) SaveCertChain(keyID string, chain []*x509.Certificate) error {
	if keyID == "" {
		return ErrInvalidKeyID
	}
	if len(chain) == 0 {
		return fmt.Errorf("certificate chain cannot be empty")
	}

	if err := ks.certStorage.SaveCertChain(keyID, chain); err != nil {
		return fmt.Errorf("failed to save certificate chain: %w", err)
	}

	return nil
}

// GetCertChain retrieves a certificate chain by key ID.
func (ks *compositeKeyStore) GetCertChain(keyID string) ([]*x509.Certificate, error) {
	if keyID == "" {
		return nil, ErrInvalidKeyID
	}

	chain, err := ks.certStorage.GetCertChain(keyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get certificate chain: %w", err)
	}

	return chain, nil
}

// ListCerts returns all certificate IDs currently stored.
func (ks *compositeKeyStore) ListCerts() ([]string, error) {
	ids, err := ks.certStorage.ListCerts()
	if err != nil {
		return nil, fmt.Errorf("failed to list certificates: %w", err)
	}

	return ids, nil
}

// CertExists checks if a certificate exists for the given key ID.
func (ks *compositeKeyStore) CertExists(keyID string) (bool, error) {
	if keyID == "" {
		return false, ErrInvalidKeyID
	}

	exists, err := ks.certStorage.CertExists(keyID)
	if err != nil {
		return false, fmt.Errorf("failed to check if certificate exists: %w", err)
	}

	return exists, nil
}

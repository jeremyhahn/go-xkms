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

package store

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"sync"

	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// MemoryCertStore provides an in-memory implementation of CertificateStorer
// for testing purposes. This implementation is thread-safe.
type MemoryCertStore struct {
	logger *slog.Logger
	mu     sync.RWMutex
	certs  map[string]*x509.Certificate
}

// NewMemoryCertStore creates a new in-memory certificate store.
func NewMemoryCertStore(logger *slog.Logger) *MemoryCertStore {
	return &MemoryCertStore{
		logger: logger,
		certs:  make(map[string]*x509.Certificate),
	}
}

// certKey generates a unique key for a certificate based on key attributes.
func (m *MemoryCertStore) certKey(attrs *types.KeyAttributes) string {
	if attrs == nil {
		return ""
	}
	// Use CN as the primary identifier, with optional parent prefix
	key := attrs.CN
	if attrs.Parent != nil && attrs.Parent.CN != "" {
		key = fmt.Sprintf("%s/%s", attrs.Parent.CN, attrs.CN)
	}
	return key
}

// Get retrieves a certificate from the store.
func (m *MemoryCertStore) Get(attrs *types.KeyAttributes) (*x509.Certificate, error) {
	if attrs == nil {
		return nil, ErrInvalidKeyAttributes
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	key := m.certKey(attrs)
	cert, ok := m.certs[key]
	if !ok {
		return nil, ErrCertNotFound
	}

	m.logger.Debug("certificate retrieved from memory store",
		slog.String("key", key))

	return cert, nil
}

// Save stores a certificate in the store.
func (m *MemoryCertStore) Save(attrs *types.KeyAttributes, cert *x509.Certificate) error {
	if attrs == nil {
		return ErrInvalidKeyAttributes
	}
	if cert == nil {
		return fmt.Errorf("certificate is nil")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	key := m.certKey(attrs)
	m.certs[key] = cert

	m.logger.Debug("certificate saved to memory store",
		slog.String("key", key),
		slog.String("subject", cert.Subject.CommonName))

	return nil
}

// Delete removes a certificate from the store.
func (m *MemoryCertStore) Delete(attrs *types.KeyAttributes) error {
	if attrs == nil {
		return ErrInvalidKeyAttributes
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	key := m.certKey(attrs)
	if _, ok := m.certs[key]; !ok {
		return ErrCertNotFound
	}

	delete(m.certs, key)

	m.logger.Debug("certificate deleted from memory store",
		slog.String("key", key))

	return nil
}

// ImportCertificate imports a PEM-encoded certificate into the store.
func (m *MemoryCertStore) ImportCertificate(attrs *types.KeyAttributes, certPEM []byte) (*x509.Certificate, error) {
	if attrs == nil {
		return nil, ErrInvalidKeyAttributes
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	if err := m.Save(attrs, cert); err != nil {
		return nil, err
	}

	return cert, nil
}

// Verify MemoryCertStore implements CertificateStorer
var _ CertificateStorer = (*MemoryCertStore)(nil)

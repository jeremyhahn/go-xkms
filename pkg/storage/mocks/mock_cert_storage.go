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

package mocks

import (
	"crypto/x509"
	"fmt"
	"strings"
	"sync"

	"github.com/jeremyhahn/go-keychain/pkg/storage"
)

// MockCertStorage is a mock implementation of certificate storage for testing.
// It stores certificates in memory and provides configurable behavior for testing.
// It implements both the CertificateStorageAdapter and storage.Backend interfaces.
type MockCertStorage struct {
	mu sync.RWMutex

	// Storage
	certs  map[string]*x509.Certificate
	chains map[string][]*x509.Certificate
	data   map[string][]byte // For generic Backend operations

	// Configurable behavior
	SaveCertFunc      func(id string, cert *x509.Certificate) error
	GetCertFunc       func(id string) (*x509.Certificate, error)
	DeleteCertFunc    func(id string) error
	SaveCertChainFunc func(id string, chain []*x509.Certificate) error
	GetCertChainFunc  func(id string) ([]*x509.Certificate, error)
	ListCertsFunc     func() ([]string, error)
	CertExistsFunc    func(id string) (bool, error)
	CloseFunc         func() error

	// Call tracking
	SaveCertCalls      []string
	GetCertCalls       []string
	DeleteCertCalls    []string
	SaveCertChainCalls []string
	GetCertChainCalls  []string
	ListCertsCalls     int
	CertExistsCalls    []string
	CloseCalls         int

	// State
	closed bool
}

// NewMockCertStorage creates a new MockCertStorage with default behavior.
func NewMockCertStorage() *MockCertStorage {
	return &MockCertStorage{
		certs:  make(map[string]*x509.Certificate),
		chains: make(map[string][]*x509.Certificate),
		data:   make(map[string][]byte),
	}
}

// SaveCert stores a certificate.
func (m *MockCertStorage) SaveCert(id string, cert *x509.Certificate) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.SaveCertCalls = append(m.SaveCertCalls, id)

	if m.closed {
		return fmt.Errorf("storage is closed")
	}

	if m.SaveCertFunc != nil {
		return m.SaveCertFunc(id, cert)
	}

	m.certs[id] = cert
	return nil
}

// GetCert retrieves a certificate.
func (m *MockCertStorage) GetCert(id string) (*x509.Certificate, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	m.GetCertCalls = append(m.GetCertCalls, id)

	if m.closed {
		return nil, fmt.Errorf("storage is closed")
	}

	if m.GetCertFunc != nil {
		return m.GetCertFunc(id)
	}

	cert, ok := m.certs[id]
	if !ok {
		return nil, fmt.Errorf("certificate not found: %s", id)
	}
	return cert, nil
}

// DeleteCert removes a certificate.
func (m *MockCertStorage) DeleteCert(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.DeleteCertCalls = append(m.DeleteCertCalls, id)

	if m.closed {
		return fmt.Errorf("storage is closed")
	}

	if m.DeleteCertFunc != nil {
		return m.DeleteCertFunc(id)
	}

	if _, ok := m.certs[id]; !ok {
		return fmt.Errorf("certificate not found: %s", id)
	}
	delete(m.certs, id)
	return nil
}

// SaveCertChain stores a certificate chain.
func (m *MockCertStorage) SaveCertChain(id string, chain []*x509.Certificate) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.SaveCertChainCalls = append(m.SaveCertChainCalls, id)

	if m.closed {
		return fmt.Errorf("storage is closed")
	}

	if m.SaveCertChainFunc != nil {
		return m.SaveCertChainFunc(id, chain)
	}

	m.chains[id] = chain
	return nil
}

// GetCertChain retrieves a certificate chain.
func (m *MockCertStorage) GetCertChain(id string) ([]*x509.Certificate, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	m.GetCertChainCalls = append(m.GetCertChainCalls, id)

	if m.closed {
		return nil, fmt.Errorf("storage is closed")
	}

	if m.GetCertChainFunc != nil {
		return m.GetCertChainFunc(id)
	}

	chain, ok := m.chains[id]
	if !ok {
		return nil, fmt.Errorf("certificate chain not found: %s", id)
	}
	return chain, nil
}

// ListCerts returns all certificate IDs.
func (m *MockCertStorage) ListCerts() ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	m.ListCertsCalls++

	if m.closed {
		return nil, fmt.Errorf("storage is closed")
	}

	if m.ListCertsFunc != nil {
		return m.ListCertsFunc()
	}

	ids := make([]string, 0, len(m.certs))
	for id := range m.certs {
		ids = append(ids, id)
	}
	return ids, nil
}

// CertExists checks if a certificate exists.
func (m *MockCertStorage) CertExists(id string) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	m.CertExistsCalls = append(m.CertExistsCalls, id)

	if m.closed {
		return false, fmt.Errorf("storage is closed")
	}

	if m.CertExistsFunc != nil {
		return m.CertExistsFunc(id)
	}

	_, ok := m.certs[id]
	return ok, nil
}

// Close releases resources.
func (m *MockCertStorage) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.CloseCalls++
	m.closed = true

	if m.CloseFunc != nil {
		return m.CloseFunc()
	}

	return nil
}

// Reset clears all state and call tracking.
func (m *MockCertStorage) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.certs = make(map[string]*x509.Certificate)
	m.chains = make(map[string][]*x509.Certificate)
	m.data = make(map[string][]byte)
	m.SaveCertCalls = nil
	m.GetCertCalls = nil
	m.DeleteCertCalls = nil
	m.SaveCertChainCalls = nil
	m.GetCertChainCalls = nil
	m.ListCertsCalls = 0
	m.CertExistsCalls = nil
	m.CloseCalls = 0
	m.closed = false
}

// ========================================================================
// storage.Backend interface implementation
// ========================================================================

// Get retrieves the value for the given key (implements storage.Backend).
func (m *MockCertStorage) Get(key string) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return nil, fmt.Errorf("storage is closed")
	}

	// Track cert operations based on key pattern
	if strings.HasPrefix(key, "certs/") {
		// Need to distinguish between:
		// - "certs/foo.pem" (cert for ID "foo")
		// - "certs/foo-chain.pem" (cert for ID "foo-chain")
		// - "certs/foo-chain-chain.pem" (chain for ID "foo-chain")
		// Strategy: Check for actual chain files using the double-chain pattern first
		stripped := strings.TrimPrefix(key, "certs/")

		// Check if this is a chain file by seeing if it matches the pattern: {id}-chain.pem
		// where {id} doesn't end with ".pem"
		if strings.HasSuffix(stripped, "-chain.pem") {
			// Could be either:
			// 1. A cert file for an ID ending in "-chain" (e.g., "foo-chain.pem" for ID "foo-chain")
			// 2. A chain file (e.g., "foo-chain-chain.pem" for ID "foo-chain")

			// Extract what would be the ID if this were a chain file
			potentialID := strings.TrimSuffix(stripped, "-chain.pem")

			// If the potential ID doesn't end with ".pem", this is a chain file
			if !strings.HasSuffix(potentialID, ".pem") {
				// It's a chain file: "certs/{id}-chain.pem"
				m.GetCertChainCalls = append(m.GetCertChainCalls, potentialID)
				if m.GetCertChainFunc != nil {
					chain, err := m.GetCertChainFunc(potentialID)
					if err != nil {
						return nil, err
					}
					// Marshal chain to DER bytes
					var chainData []byte
					for _, cert := range chain {
						chainData = append(chainData, cert.Raw...)
					}
					return chainData, nil
				}
			} else {
				// It's a cert file where the ID happens to end in "-chain"
				// e.g., "certs/foo-chain.pem" for ID "foo-chain"
				id := strings.TrimSuffix(stripped, ".pem")
				m.GetCertCalls = append(m.GetCertCalls, id)
				if m.GetCertFunc != nil {
					cert, err := m.GetCertFunc(id)
					if err != nil {
						return nil, err
					}
					return cert.Raw, nil
				}
			}
		} else if strings.HasSuffix(stripped, ".pem") {
			// Regular cert file: "certs/{id}.pem"
			id := strings.TrimSuffix(stripped, ".pem")
			m.GetCertCalls = append(m.GetCertCalls, id)
			if m.GetCertFunc != nil {
				cert, err := m.GetCertFunc(id)
				if err != nil {
					return nil, err
				}
				return cert.Raw, nil
			}
		}
	}

	value, exists := m.data[key]
	if !exists {
		return nil, fmt.Errorf("key not found: %s", key)
	}

	// Return a defensive copy
	result := make([]byte, len(value))
	copy(result, value)
	return result, nil
}

// Put stores the value for the given key (implements storage.Backend).
func (m *MockCertStorage) Put(key string, value []byte, opts *storage.Options) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return fmt.Errorf("storage is closed")
	}

	// Track cert operations based on key pattern
	if strings.HasPrefix(key, "certs/") {
		if strings.HasSuffix(key, "-chain.pem") {
			// Extract ID from "certs/{id}-chain.pem"
			id := strings.TrimPrefix(key, "certs/")
			id = strings.TrimSuffix(id, "-chain.pem")
			m.SaveCertChainCalls = append(m.SaveCertChainCalls, id)
			// Check error function
			if m.SaveCertChainFunc != nil {
				// Parse chain for error func
				return m.SaveCertChainFunc(id, nil)
			}
		} else if strings.HasSuffix(key, ".pem") {
			// Extract ID from "certs/{id}.pem"
			id := strings.TrimPrefix(key, "certs/")
			id = strings.TrimSuffix(id, ".pem")
			m.SaveCertCalls = append(m.SaveCertCalls, id)
			// Check error function
			if m.SaveCertFunc != nil {
				return m.SaveCertFunc(id, nil)
			}
		}
	}

	// Store a defensive copy
	valueCopy := make([]byte, len(value))
	copy(valueCopy, value)
	m.data[key] = valueCopy

	return nil
}

// Delete removes the key and its value from storage (implements storage.Backend).
func (m *MockCertStorage) Delete(key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return fmt.Errorf("storage is closed")
	}

	// Track cert operations based on key pattern
	if strings.HasPrefix(key, "certs/") {
		if strings.HasSuffix(key, ".pem") && !strings.HasSuffix(key, "-chain.pem") {
			// Extract ID from "certs/{id}.pem"
			id := strings.TrimPrefix(key, "certs/")
			id = strings.TrimSuffix(id, ".pem")
			m.DeleteCertCalls = append(m.DeleteCertCalls, id)
		}
	}

	if _, exists := m.data[key]; !exists {
		return fmt.Errorf("key not found: %s", key)
	}

	delete(m.data, key)
	return nil
}

// List returns all keys with the given prefix (implements storage.Backend).
func (m *MockCertStorage) List(prefix string) ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return nil, fmt.Errorf("storage is closed")
	}

	// Track cert list operations
	if prefix == "certs/" || prefix == "" {
		m.ListCertsCalls++
		if m.ListCertsFunc != nil {
			return m.ListCertsFunc()
		}
	}

	var keys []string
	for key := range m.data {
		if prefix == "" || strings.HasPrefix(key, prefix) {
			keys = append(keys, key)
		}
	}

	return keys, nil
}

// Exists checks if a key exists in storage (implements storage.Backend).
func (m *MockCertStorage) Exists(key string) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return false, fmt.Errorf("storage is closed")
	}

	// Track cert exists operations
	if strings.HasPrefix(key, "certs/") {
		if strings.HasSuffix(key, ".pem") && !strings.HasSuffix(key, "-chain.pem") {
			// Extract ID from "certs/{id}.pem"
			id := strings.TrimPrefix(key, "certs/")
			id = strings.TrimSuffix(id, ".pem")
			m.CertExistsCalls = append(m.CertExistsCalls, id)
			if m.CertExistsFunc != nil {
				return m.CertExistsFunc(id)
			}
		}
	}

	_, exists := m.data[key]
	return exists, nil
}

// Verify interface compliance at compile time
var _ storage.Backend = (*MockCertStorage)(nil)

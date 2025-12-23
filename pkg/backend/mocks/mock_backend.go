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
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"sync"

	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// MockBackend is a mock implementation of types.Backend for testing.
type MockBackend struct {
	mu sync.RWMutex

	// Storage
	keys map[string]crypto.PrivateKey

	// Configurable behavior
	TypeFunc         func() types.BackendType
	CapabilitiesFunc func() types.Capabilities
	GenerateKeyFunc  func(*types.KeyAttributes) (crypto.PrivateKey, error)
	GetKeyFunc       func(*types.KeyAttributes) (crypto.PrivateKey, error)
	DeleteKeyFunc    func(*types.KeyAttributes) error
	ListKeysFunc     func() ([]*types.KeyAttributes, error)
	SignerFunc       func(*types.KeyAttributes) (crypto.Signer, error)
	DecrypterFunc    func(*types.KeyAttributes) (crypto.Decrypter, error)
	RotateKeyFunc    func(*types.KeyAttributes) error
	CloseFunc        func() error

	// Call tracking
	TypeCalls         int
	CapabilitiesCalls int
	GenerateKeyCalls  []string
	GetKeyCalls       []string
	DeleteKeyCalls    []string
	ListKeysCalls     int
	SignerCalls       []string
	DecrypterCalls    []string
	RotateKeyCalls    []string
	CloseCalls        int

	// State
	closed bool
}

// NewMockBackend creates a new MockBackend with default behavior.
func NewMockBackend() *MockBackend {
	return &MockBackend{
		keys: make(map[string]crypto.PrivateKey),
	}
}

// Type returns the backend type.
func (m *MockBackend) Type() types.BackendType {
	m.mu.RLock()
	defer m.mu.RUnlock()

	m.TypeCalls++

	if m.TypeFunc != nil {
		return m.TypeFunc()
	}
	return types.BackendTypeSoftware
}

// Capabilities returns backend capabilities.
func (m *MockBackend) Capabilities() types.Capabilities {
	m.mu.RLock()
	defer m.mu.RUnlock()

	m.CapabilitiesCalls++

	if m.CapabilitiesFunc != nil {
		return m.CapabilitiesFunc()
	}
	return types.Capabilities{
		Keys:           true,
		HardwareBacked: false,
		Signing:        true,
		Decryption:     true,
		KeyRotation:    true,
	}
}

// GenerateKey generates a new key.
func (m *MockBackend) GenerateKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.GenerateKeyCalls = append(m.GenerateKeyCalls, attrs.CN)

	if m.closed {
		return nil, fmt.Errorf("backend is closed")
	}

	if m.GenerateKeyFunc != nil {
		return m.GenerateKeyFunc(attrs)
	}

	// Generate a real key based on algorithm
	var key crypto.PrivateKey
	var err error

	switch attrs.KeyAlgorithm {
	case x509.RSA:
		keySize := 2048
		key, err = rsa.GenerateKey(rand.Reader, keySize)
	case x509.ECDSA:
		curve := elliptic.P256()
		key, err = ecdsa.GenerateKey(curve, rand.Reader)
	case x509.Ed25519:
		_, privateKey, genErr := ed25519.GenerateKey(rand.Reader)
		key = privateKey
		err = genErr
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", attrs.KeyAlgorithm)
	}

	if err != nil {
		return nil, err
	}

	m.keys[attrs.CN] = key
	return key, nil
}

// GetKey retrieves a key.
func (m *MockBackend) GetKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	m.GetKeyCalls = append(m.GetKeyCalls, attrs.CN)

	if m.closed {
		return nil, fmt.Errorf("backend is closed")
	}

	if m.GetKeyFunc != nil {
		return m.GetKeyFunc(attrs)
	}

	key, ok := m.keys[attrs.CN]
	if !ok {
		return nil, fmt.Errorf("key not found: %s", attrs.CN)
	}
	return key, nil
}

// DeleteKey removes a key.
func (m *MockBackend) DeleteKey(attrs *types.KeyAttributes) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.DeleteKeyCalls = append(m.DeleteKeyCalls, attrs.CN)

	if m.closed {
		return fmt.Errorf("backend is closed")
	}

	if m.DeleteKeyFunc != nil {
		return m.DeleteKeyFunc(attrs)
	}

	if _, ok := m.keys[attrs.CN]; !ok {
		return fmt.Errorf("key not found: %s", attrs.CN)
	}
	delete(m.keys, attrs.CN)
	return nil
}

// ListKeys returns all keys.
func (m *MockBackend) ListKeys() ([]*types.KeyAttributes, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	m.ListKeysCalls++

	if m.closed {
		return nil, fmt.Errorf("backend is closed")
	}

	if m.ListKeysFunc != nil {
		return m.ListKeysFunc()
	}

	attrs := make([]*types.KeyAttributes, 0, len(m.keys))
	for cn := range m.keys {
		attrs = append(attrs, &types.KeyAttributes{
			CN:           cn,
			KeyType:      types.KeyTypeTLS,
			StoreType:    types.StoreSoftware,
			KeyAlgorithm: x509.RSA,
		})
	}
	return attrs, nil
}

// Signer returns a crypto.Signer for the key.
func (m *MockBackend) Signer(attrs *types.KeyAttributes) (crypto.Signer, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	m.SignerCalls = append(m.SignerCalls, attrs.CN)

	if m.closed {
		return nil, fmt.Errorf("backend is closed")
	}

	if m.SignerFunc != nil {
		return m.SignerFunc(attrs)
	}

	key, ok := m.keys[attrs.CN]
	if !ok {
		return nil, fmt.Errorf("key not found: %s", attrs.CN)
	}

	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("key does not implement crypto.Signer")
	}
	return signer, nil
}

// Decrypter returns a crypto.Decrypter for the key.
func (m *MockBackend) Decrypter(attrs *types.KeyAttributes) (crypto.Decrypter, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	m.DecrypterCalls = append(m.DecrypterCalls, attrs.CN)

	if m.closed {
		return nil, fmt.Errorf("backend is closed")
	}

	if m.DecrypterFunc != nil {
		return m.DecrypterFunc(attrs)
	}

	key, ok := m.keys[attrs.CN]
	if !ok {
		return nil, fmt.Errorf("key not found: %s", attrs.CN)
	}

	decrypter, ok := key.(crypto.Decrypter)
	if !ok {
		return nil, fmt.Errorf("key does not implement crypto.Decrypter")
	}
	return decrypter, nil
}

// Close releases resources.
func (m *MockBackend) Close() error {
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
func (m *MockBackend) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.keys = make(map[string]crypto.PrivateKey)
	m.TypeCalls = 0
	m.CapabilitiesCalls = 0
	m.GenerateKeyCalls = nil
	m.GetKeyCalls = nil
	m.DeleteKeyCalls = nil
	m.ListKeysCalls = 0
	m.SignerCalls = nil
	m.DecrypterCalls = nil
	m.CloseCalls = 0
	m.closed = false
}

// mockSigner wraps a key and implements crypto.Signer for testing.

// PublicKey returns the public key for a private key.
func PublicKey(key crypto.PrivateKey) crypto.PublicKey {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	case ed25519.PrivateKey:
		return k.Public().(ed25519.PublicKey)
	default:
		return nil
	}
}

// KeyAlgorithm returns the algorithm for a key.
func KeyAlgorithm(key crypto.PrivateKey) x509.PublicKeyAlgorithm {
	switch key.(type) {
	case *rsa.PrivateKey:
		return x509.RSA
	case *ecdsa.PrivateKey:
		return x509.ECDSA
	case ed25519.PrivateKey:
		return x509.Ed25519
	default:
		return x509.UnknownPublicKeyAlgorithm
	}
}

// RotateKey rotates/updates a key identified by attrs.
func (m *MockBackend) RotateKey(attrs *types.KeyAttributes) error {
	m.mu.Lock()
	m.RotateKeyCalls = append(m.RotateKeyCalls, attrs.CN)
	m.mu.Unlock()

	if m.RotateKeyFunc != nil {
		return m.RotateKeyFunc(attrs)
	}
	return nil
}

// Verify interface compliance
var _ types.Backend = (*MockBackend)(nil)

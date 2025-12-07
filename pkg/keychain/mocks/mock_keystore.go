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
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"sync"

	backendmocks "github.com/jeremyhahn/go-keychain/pkg/backend/mocks"
	"github.com/jeremyhahn/go-keychain/pkg/certstore"
	storagemocks "github.com/jeremyhahn/go-keychain/pkg/storage/mocks"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// MockKeyStore is a mock implementation of keychain.KeyStore for testing.
// It provides configurable behavior and call tracking for all methods.
type MockKeyStore struct {
	mu sync.RWMutex

	// Embedded mocks for delegation
	BackendMock   *backendmocks.MockBackend
	CertStoreMock *storagemocks.MockCertStorage

	// Storage
	keys       map[string]crypto.PrivateKey
	certs      map[string]*x509.Certificate
	certChains map[string][]*x509.Certificate

	// Configurable behavior
	GenerateRSAFunc       func(*types.KeyAttributes) (crypto.PrivateKey, error)
	GenerateECDSAFunc     func(*types.KeyAttributes) (crypto.PrivateKey, error)
	GenerateEd25519Func   func(*types.KeyAttributes) (crypto.PrivateKey, error)
	GetKeyFunc            func(*types.KeyAttributes) (crypto.PrivateKey, error)
	DeleteKeyFunc         func(*types.KeyAttributes) error
	ListKeysFunc          func() ([]*types.KeyAttributes, error)
	RotateKeyFunc         func(*types.KeyAttributes) (crypto.PrivateKey, error)
	SignerFunc            func(*types.KeyAttributes) (crypto.Signer, error)
	DecrypterFunc         func(*types.KeyAttributes) (crypto.Decrypter, error)
	SaveCertFunc          func(string, *x509.Certificate) error
	GetCertFunc           func(string) (*x509.Certificate, error)
	DeleteCertFunc        func(string) error
	SaveCertChainFunc     func(string, []*x509.Certificate) error
	GetCertChainFunc      func(string) ([]*x509.Certificate, error)
	ListCertsFunc         func() ([]string, error)
	CertExistsFunc        func(string) (bool, error)
	GetTLSCertificateFunc func(string, *types.KeyAttributes) (tls.Certificate, error)
	GetKeyByIDFunc        func(string) (crypto.PrivateKey, error)
	GetSignerByIDFunc     func(string) (crypto.Signer, error)
	GetDecrypterByIDFunc  func(string) (crypto.Decrypter, error)
	SealFunc              func(context.Context, []byte, *types.SealOptions) (*types.SealedData, error)
	UnsealFunc            func(context.Context, *types.SealedData, *types.UnsealOptions) ([]byte, error)
	CanSealFunc           func() bool
	CloseFunc             func() error

	// Call tracking
	GenerateRSACalls      []string
	GenerateECDSACalls    []string
	GenerateEd25519Calls  []string
	GetKeyCalls           []string
	DeleteKeyCalls        []string
	ListKeysCalls         int
	RotateKeyCalls        []string
	SignerCalls           []string
	DecrypterCalls        []string
	SaveCertCalls         []string
	GetCertCalls          []string
	DeleteCertCalls       []string
	SaveCertChainCalls    []string
	GetCertChainCalls     []string
	ListCertsCalls        int
	CertExistsCalls       []string
	GetTLSCertCalls       []string
	GetKeyByIDCalls       []string
	GetSignerByIDCalls    []string
	GetDecrypterByIDCalls []string
	SealCalls             int
	UnsealCalls           int
	CanSealCalls          int
	CloseCalls            int

	// State
	closed bool
}

// NewMockKeyStore creates a new MockKeyStore with default behavior.
func NewMockKeyStore() *MockKeyStore {
	return &MockKeyStore{
		BackendMock:   backendmocks.NewMockBackend(),
		CertStoreMock: storagemocks.NewMockCertStorage(),
		keys:          make(map[string]crypto.PrivateKey),
		certs:         make(map[string]*x509.Certificate),
		certChains:    make(map[string][]*x509.Certificate),
	}
}

// GenerateRSA generates a new RSA key pair.
func (m *MockKeyStore) GenerateRSA(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.GenerateRSACalls = append(m.GenerateRSACalls, attrs.CN)

	if m.closed {
		return nil, fmt.Errorf("keystore is closed")
	}

	if m.GenerateRSAFunc != nil {
		return m.GenerateRSAFunc(attrs)
	}

	keySize := 2048
	if attrs.RSAAttributes != nil && attrs.RSAAttributes.KeySize > 0 {
		keySize = attrs.RSAAttributes.KeySize
	}

	key, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		return nil, err
	}

	m.keys[attrs.CN] = key
	return key, nil
}

// GenerateECDSA generates a new ECDSA key pair.
func (m *MockKeyStore) GenerateECDSA(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.GenerateECDSACalls = append(m.GenerateECDSACalls, attrs.CN)

	if m.closed {
		return nil, fmt.Errorf("keystore is closed")
	}

	if m.GenerateECDSAFunc != nil {
		return m.GenerateECDSAFunc(attrs)
	}

	curve := elliptic.P256()
	if attrs.ECCAttributes != nil && attrs.ECCAttributes.Curve != nil {
		curve = attrs.ECCAttributes.Curve
	}

	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, err
	}

	m.keys[attrs.CN] = key
	return key, nil
}

// GenerateEd25519 generates a new Ed25519 key pair.
func (m *MockKeyStore) GenerateEd25519(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.GenerateEd25519Calls = append(m.GenerateEd25519Calls, attrs.CN)

	if m.closed {
		return nil, fmt.Errorf("keystore is closed")
	}

	if m.GenerateEd25519Func != nil {
		return m.GenerateEd25519Func(attrs)
	}

	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	m.keys[attrs.CN] = privateKey
	return privateKey, nil
}

// GetKey retrieves an existing private key by its attributes.
func (m *MockKeyStore) GetKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	m.GetKeyCalls = append(m.GetKeyCalls, attrs.CN)

	if m.closed {
		return nil, fmt.Errorf("keystore is closed")
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

// DeleteKey removes a key identified by its attributes.
func (m *MockKeyStore) DeleteKey(attrs *types.KeyAttributes) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.DeleteKeyCalls = append(m.DeleteKeyCalls, attrs.CN)

	if m.closed {
		return fmt.Errorf("keystore is closed")
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

// ListKeys returns attributes for all keys managed by this keychain.
func (m *MockKeyStore) ListKeys() ([]*types.KeyAttributes, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	m.ListKeysCalls++

	if m.closed {
		return nil, fmt.Errorf("keystore is closed")
	}

	if m.ListKeysFunc != nil {
		return m.ListKeysFunc()
	}

	attrs := make([]*types.KeyAttributes, 0, len(m.keys))
	for cn := range m.keys {
		attrs = append(attrs, &types.KeyAttributes{
			CN:           cn,
			KeyType:      types.KeyTypeTLS,
			StoreType:    types.StorePKCS8,
			KeyAlgorithm: x509.RSA,
		})
	}
	return attrs, nil
}

// RotateKey replaces an existing key with a newly generated key.
func (m *MockKeyStore) RotateKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.RotateKeyCalls = append(m.RotateKeyCalls, attrs.CN)

	if m.closed {
		return nil, fmt.Errorf("keystore is closed")
	}

	if m.RotateKeyFunc != nil {
		return m.RotateKeyFunc(attrs)
	}

	// Delete old key and generate new one
	delete(m.keys, attrs.CN)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	m.keys[attrs.CN] = key
	return key, nil
}

// Signer returns a crypto.Signer for the specified key.
func (m *MockKeyStore) Signer(attrs *types.KeyAttributes) (crypto.Signer, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	m.SignerCalls = append(m.SignerCalls, attrs.CN)

	if m.closed {
		return nil, fmt.Errorf("keystore is closed")
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

// Decrypter returns a crypto.Decrypter for the specified key.
func (m *MockKeyStore) Decrypter(attrs *types.KeyAttributes) (crypto.Decrypter, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	m.DecrypterCalls = append(m.DecrypterCalls, attrs.CN)

	if m.closed {
		return nil, fmt.Errorf("keystore is closed")
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

// SaveCert stores a certificate for the given key ID.
func (m *MockKeyStore) SaveCert(keyID string, cert *x509.Certificate) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.SaveCertCalls = append(m.SaveCertCalls, keyID)

	if m.closed {
		return fmt.Errorf("keystore is closed")
	}

	if m.SaveCertFunc != nil {
		return m.SaveCertFunc(keyID, cert)
	}

	m.certs[keyID] = cert
	return nil
}

// GetCert retrieves a certificate by key ID.
func (m *MockKeyStore) GetCert(keyID string) (*x509.Certificate, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	m.GetCertCalls = append(m.GetCertCalls, keyID)

	if m.closed {
		return nil, fmt.Errorf("keystore is closed")
	}

	if m.GetCertFunc != nil {
		return m.GetCertFunc(keyID)
	}

	cert, ok := m.certs[keyID]
	if !ok {
		return nil, fmt.Errorf("certificate not found: %s", keyID)
	}
	return cert, nil
}

// DeleteCert removes a certificate by key ID.
func (m *MockKeyStore) DeleteCert(keyID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.DeleteCertCalls = append(m.DeleteCertCalls, keyID)

	if m.closed {
		return fmt.Errorf("keystore is closed")
	}

	if m.DeleteCertFunc != nil {
		return m.DeleteCertFunc(keyID)
	}

	if _, ok := m.certs[keyID]; !ok {
		return fmt.Errorf("certificate not found: %s", keyID)
	}
	delete(m.certs, keyID)
	return nil
}

// SaveCertChain stores a certificate chain for the given key ID.
func (m *MockKeyStore) SaveCertChain(keyID string, chain []*x509.Certificate) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.SaveCertChainCalls = append(m.SaveCertChainCalls, keyID)

	if m.closed {
		return fmt.Errorf("keystore is closed")
	}

	if m.SaveCertChainFunc != nil {
		return m.SaveCertChainFunc(keyID, chain)
	}

	m.certChains[keyID] = chain
	return nil
}

// GetCertChain retrieves a certificate chain by key ID.
func (m *MockKeyStore) GetCertChain(keyID string) ([]*x509.Certificate, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	m.GetCertChainCalls = append(m.GetCertChainCalls, keyID)

	if m.closed {
		return nil, fmt.Errorf("keystore is closed")
	}

	if m.GetCertChainFunc != nil {
		return m.GetCertChainFunc(keyID)
	}

	chain, ok := m.certChains[keyID]
	if !ok {
		return nil, fmt.Errorf("certificate chain not found: %s", keyID)
	}
	return chain, nil
}

// ListCerts returns all certificate IDs currently stored.
func (m *MockKeyStore) ListCerts() ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	m.ListCertsCalls++

	if m.closed {
		return nil, fmt.Errorf("keystore is closed")
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

// CertExists checks if a certificate exists for the given key ID.
func (m *MockKeyStore) CertExists(keyID string) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	m.CertExistsCalls = append(m.CertExistsCalls, keyID)

	if m.closed {
		return false, fmt.Errorf("keystore is closed")
	}

	if m.CertExistsFunc != nil {
		return m.CertExistsFunc(keyID)
	}

	_, ok := m.certs[keyID]
	return ok, nil
}

// GetTLSCertificate returns a complete tls.Certificate ready for use.
func (m *MockKeyStore) GetTLSCertificate(keyID string, attrs *types.KeyAttributes) (tls.Certificate, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	m.GetTLSCertCalls = append(m.GetTLSCertCalls, keyID)

	if m.closed {
		return tls.Certificate{}, fmt.Errorf("keystore is closed")
	}

	if m.GetTLSCertificateFunc != nil {
		return m.GetTLSCertificateFunc(keyID, attrs)
	}

	key, ok := m.keys[keyID]
	if !ok {
		return tls.Certificate{}, fmt.Errorf("key not found: %s", keyID)
	}

	cert, ok := m.certs[keyID]
	if !ok {
		return tls.Certificate{}, fmt.Errorf("certificate not found: %s", keyID)
	}

	return tls.Certificate{
		Certificate: [][]byte{cert.Raw},
		PrivateKey:  key,
		Leaf:        cert,
	}, nil
}

// GetKeyByID retrieves a key using the unified Key ID format.
func (m *MockKeyStore) GetKeyByID(keyID string) (crypto.PrivateKey, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	m.GetKeyByIDCalls = append(m.GetKeyByIDCalls, keyID)

	if m.closed {
		return nil, fmt.Errorf("keystore is closed")
	}

	if m.GetKeyByIDFunc != nil {
		return m.GetKeyByIDFunc(keyID)
	}

	key, ok := m.keys[keyID]
	if !ok {
		return nil, fmt.Errorf("key not found: %s", keyID)
	}
	return key, nil
}

// GetSignerByID retrieves a crypto.Signer using the unified Key ID format.
func (m *MockKeyStore) GetSignerByID(keyID string) (crypto.Signer, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	m.GetSignerByIDCalls = append(m.GetSignerByIDCalls, keyID)

	if m.closed {
		return nil, fmt.Errorf("keystore is closed")
	}

	if m.GetSignerByIDFunc != nil {
		return m.GetSignerByIDFunc(keyID)
	}

	key, ok := m.keys[keyID]
	if !ok {
		return nil, fmt.Errorf("key not found: %s", keyID)
	}

	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("key does not implement crypto.Signer")
	}
	return signer, nil
}

// GetDecrypterByID retrieves a crypto.Decrypter using the unified Key ID format.
func (m *MockKeyStore) GetDecrypterByID(keyID string) (crypto.Decrypter, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	m.GetDecrypterByIDCalls = append(m.GetDecrypterByIDCalls, keyID)

	if m.closed {
		return nil, fmt.Errorf("keystore is closed")
	}

	if m.GetDecrypterByIDFunc != nil {
		return m.GetDecrypterByIDFunc(keyID)
	}

	key, ok := m.keys[keyID]
	if !ok {
		return nil, fmt.Errorf("key not found: %s", keyID)
	}

	decrypter, ok := key.(crypto.Decrypter)
	if !ok {
		return nil, fmt.Errorf("key does not implement crypto.Decrypter")
	}
	return decrypter, nil
}

// Seal encrypts/protects data using the backend's native sealing mechanism.
func (m *MockKeyStore) Seal(ctx context.Context, data []byte, opts *types.SealOptions) (*types.SealedData, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.SealCalls++

	if m.closed {
		return nil, fmt.Errorf("keystore is closed")
	}

	if m.SealFunc != nil {
		return m.SealFunc(ctx, data, opts)
	}

	return nil, fmt.Errorf("sealing not supported")
}

// Unseal decrypts/recovers data that was previously sealed.
func (m *MockKeyStore) Unseal(ctx context.Context, sealed *types.SealedData, opts *types.UnsealOptions) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.UnsealCalls++

	if m.closed {
		return nil, fmt.Errorf("keystore is closed")
	}

	if m.UnsealFunc != nil {
		return m.UnsealFunc(ctx, sealed, opts)
	}

	return nil, fmt.Errorf("unsealing not supported")
}

// CanSeal returns true if the backend supports sealing operations.
func (m *MockKeyStore) CanSeal() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	m.CanSealCalls++

	if m.CanSealFunc != nil {
		return m.CanSealFunc()
	}

	return false
}

// Backend returns the underlying backend for direct access if needed.
func (m *MockKeyStore) Backend() types.Backend {
	return m.BackendMock
}

// CertStorage returns the underlying certificate storage for direct access if needed.
func (m *MockKeyStore) CertStorage() certstore.CertificateStorageAdapter {
	return m.CertStoreMock
}

// Close releases all resources held by the keychain.
func (m *MockKeyStore) Close() error {
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
func (m *MockKeyStore) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.keys = make(map[string]crypto.PrivateKey)
	m.certs = make(map[string]*x509.Certificate)
	m.certChains = make(map[string][]*x509.Certificate)
	m.GenerateRSACalls = nil
	m.GenerateECDSACalls = nil
	m.GenerateEd25519Calls = nil
	m.GetKeyCalls = nil
	m.DeleteKeyCalls = nil
	m.ListKeysCalls = 0
	m.RotateKeyCalls = nil
	m.SignerCalls = nil
	m.DecrypterCalls = nil
	m.SaveCertCalls = nil
	m.GetCertCalls = nil
	m.DeleteCertCalls = nil
	m.SaveCertChainCalls = nil
	m.GetCertChainCalls = nil
	m.ListCertsCalls = 0
	m.CertExistsCalls = nil
	m.GetTLSCertCalls = nil
	m.GetKeyByIDCalls = nil
	m.GetSignerByIDCalls = nil
	m.GetDecrypterByIDCalls = nil
	m.SealCalls = 0
	m.UnsealCalls = 0
	m.CanSealCalls = 0
	m.CloseCalls = 0
	m.closed = false

	if m.BackendMock != nil {
		m.BackendMock.Reset()
	}
	if m.CertStoreMock != nil {
		m.CertStoreMock.Reset()
	}
}

// SetKey allows tests to directly set a key in storage.
func (m *MockKeyStore) SetKey(keyID string, key crypto.PrivateKey) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.keys[keyID] = key
}

// SetCert allows tests to directly set a certificate in storage.
func (m *MockKeyStore) SetCert(keyID string, cert *x509.Certificate) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.certs[keyID] = cert
}

// SetCertChain allows tests to directly set a certificate chain in storage.
func (m *MockKeyStore) SetCertChain(keyID string, chain []*x509.Certificate) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.certChains[keyID] = chain
}

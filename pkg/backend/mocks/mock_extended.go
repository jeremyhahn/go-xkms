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
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"sync"

	"github.com/jeremyhahn/go-keychain/pkg/backend"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// ExtendedMockBackend extends MockBackend with SymmetricBackend and ImportExportBackend interfaces.
type ExtendedMockBackend struct {
	*MockBackend

	mu sync.RWMutex

	// Symmetric key storage
	symmetricKeys map[string][]byte

	// Configurable behavior for symmetric operations
	GenerateSymmetricKeyFunc func(*types.KeyAttributes) (types.SymmetricKey, error)
	GetSymmetricKeyFunc      func(*types.KeyAttributes) (types.SymmetricKey, error)
	SymmetricEncrypterFunc   func(*types.KeyAttributes) (types.SymmetricEncrypter, error)

	// Configurable behavior for import/export operations
	GetImportParametersFunc func(*types.KeyAttributes, backend.WrappingAlgorithm) (*backend.ImportParameters, error)
	WrapKeyFunc             func([]byte, *backend.ImportParameters) (*backend.WrappedKeyMaterial, error)
	UnwrapKeyFunc           func(*backend.WrappedKeyMaterial, *backend.ImportParameters) ([]byte, error)
	ImportKeyFunc           func(*types.KeyAttributes, *backend.WrappedKeyMaterial) error
	ExportKeyFunc           func(*types.KeyAttributes, backend.WrappingAlgorithm) (*backend.WrappedKeyMaterial, error)

	// Call tracking for symmetric operations
	GenerateSymmetricKeyCalls []string
	GetSymmetricKeyCalls      []string
	SymmetricEncrypterCalls   []string

	// Call tracking for import/export operations
	GetImportParametersCalls []string
	WrapKeyCalls             int
	UnwrapKeyCalls           int
	ImportKeyCalls           []string
	ExportKeyCalls           []string
}

// NewExtendedMockBackend creates a new ExtendedMockBackend with default behavior.
func NewExtendedMockBackend() *ExtendedMockBackend {
	return &ExtendedMockBackend{
		MockBackend:   NewMockBackend(),
		symmetricKeys: make(map[string][]byte),
	}
}

// GenerateSymmetricKey generates a new symmetric key.
func (m *ExtendedMockBackend) GenerateSymmetricKey(attrs *types.KeyAttributes) (types.SymmetricKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.GenerateSymmetricKeyCalls = append(m.GenerateSymmetricKeyCalls, attrs.CN)

	if m.GenerateSymmetricKeyFunc != nil {
		return m.GenerateSymmetricKeyFunc(attrs)
	}

	// Determine key size from algorithm
	var keySize int
	switch attrs.SymmetricAlgorithm {
	case types.SymmetricAES128GCM:
		keySize = 16
	case types.SymmetricAES192GCM:
		keySize = 24
	case types.SymmetricAES256GCM:
		keySize = 32
	default:
		keySize = 32 // Default to AES-256
	}

	// Generate random key material
	keyMaterial := make([]byte, keySize)
	if _, err := rand.Read(keyMaterial); err != nil {
		return nil, fmt.Errorf("failed to generate key material: %w", err)
	}

	m.symmetricKeys[attrs.CN] = keyMaterial

	return &MockSymmetricKey{
		cn:          attrs.CN,
		keyMaterial: keyMaterial,
		algorithm:   string(attrs.SymmetricAlgorithm),
		keySize:     keySize * 8, // Convert bytes to bits
	}, nil
}

// GetSymmetricKey retrieves an existing symmetric key.
func (m *ExtendedMockBackend) GetSymmetricKey(attrs *types.KeyAttributes) (types.SymmetricKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.GetSymmetricKeyCalls = append(m.GetSymmetricKeyCalls, attrs.CN)

	if m.GetSymmetricKeyFunc != nil {
		return m.GetSymmetricKeyFunc(attrs)
	}

	keyMaterial, ok := m.symmetricKeys[attrs.CN]
	if !ok {
		return nil, fmt.Errorf("symmetric key not found: %s", attrs.CN)
	}

	return &MockSymmetricKey{
		cn:          attrs.CN,
		keyMaterial: keyMaterial,
		algorithm:   string(attrs.SymmetricAlgorithm),
		keySize:     len(keyMaterial) * 8,
	}, nil
}

// SymmetricEncrypter returns a SymmetricEncrypter for the key.
func (m *ExtendedMockBackend) SymmetricEncrypter(attrs *types.KeyAttributes) (types.SymmetricEncrypter, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.SymmetricEncrypterCalls = append(m.SymmetricEncrypterCalls, attrs.CN)

	if m.SymmetricEncrypterFunc != nil {
		return m.SymmetricEncrypterFunc(attrs)
	}

	keyMaterial, ok := m.symmetricKeys[attrs.CN]
	if !ok {
		return nil, fmt.Errorf("symmetric key not found: %s", attrs.CN)
	}

	return &MockSymmetricEncrypter{
		KeyMaterial: keyMaterial,
		Algorithm:   string(attrs.SymmetricAlgorithm),
	}, nil
}

// GetImportParameters retrieves import parameters for a key.
func (m *ExtendedMockBackend) GetImportParameters(attrs *types.KeyAttributes, algorithm backend.WrappingAlgorithm) (*backend.ImportParameters, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.GetImportParametersCalls = append(m.GetImportParametersCalls, attrs.CN)

	if m.GetImportParametersFunc != nil {
		return m.GetImportParametersFunc(attrs, algorithm)
	}

	// Generate a mock wrapping key (RSA public key)
	wrappingPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate wrapping key: %w", err)
	}

	return &backend.ImportParameters{
		WrappingPublicKey: &wrappingPrivKey.PublicKey,
		Algorithm:         algorithm,
		ImportToken:       []byte("mock-import-token"),
	}, nil
}

// WrapKey wraps key material for secure transport.
func (m *ExtendedMockBackend) WrapKey(keyMaterial []byte, params *backend.ImportParameters) (*backend.WrappedKeyMaterial, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.WrapKeyCalls++

	if m.WrapKeyFunc != nil {
		return m.WrapKeyFunc(keyMaterial, params)
	}

	// Simple mock wrapping: just return the key material (for testing only)
	return &backend.WrappedKeyMaterial{
		WrappedKey:  keyMaterial,
		Algorithm:   params.Algorithm,
		ImportToken: params.ImportToken,
	}, nil
}

// UnwrapKey unwraps key material.
func (m *ExtendedMockBackend) UnwrapKey(wrapped *backend.WrappedKeyMaterial, params *backend.ImportParameters) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.UnwrapKeyCalls++

	if m.UnwrapKeyFunc != nil {
		return m.UnwrapKeyFunc(wrapped, params)
	}

	// Simple mock unwrapping: just return the wrapped key (for testing only)
	return wrapped.WrappedKey, nil
}

// ImportKey imports externally generated key material.
func (m *ExtendedMockBackend) ImportKey(attrs *types.KeyAttributes, wrapped *backend.WrappedKeyMaterial) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.ImportKeyCalls = append(m.ImportKeyCalls, attrs.CN)

	if m.ImportKeyFunc != nil {
		return m.ImportKeyFunc(attrs, wrapped)
	}

	// Store the unwrapped key material as a symmetric key
	m.symmetricKeys[attrs.CN] = wrapped.WrappedKey

	return nil
}

// ExportKey exports a key in wrapped form.
func (m *ExtendedMockBackend) ExportKey(attrs *types.KeyAttributes, algorithm backend.WrappingAlgorithm) (*backend.WrappedKeyMaterial, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.ExportKeyCalls = append(m.ExportKeyCalls, attrs.CN)

	if m.ExportKeyFunc != nil {
		return m.ExportKeyFunc(attrs, algorithm)
	}

	// Check if the key exists (try both asymmetric and symmetric)
	var keyMaterial []byte
	if key, ok := m.keys[attrs.CN]; ok {
		// For asymmetric keys, serialize (mock)
		keyMaterial = []byte(fmt.Sprintf("mock-exported-key:%v", key))
	} else if symKey, ok := m.symmetricKeys[attrs.CN]; ok {
		keyMaterial = symKey
	} else {
		return nil, fmt.Errorf("key not found: %s", attrs.CN)
	}

	return &backend.WrappedKeyMaterial{
		WrappedKey: keyMaterial,
		Algorithm:  algorithm,
	}, nil
}

// Reset clears all state and call tracking.
func (m *ExtendedMockBackend) Reset() {
	m.MockBackend.Reset()
	m.mu.Lock()
	defer m.mu.Unlock()

	m.symmetricKeys = make(map[string][]byte)
	m.GenerateSymmetricKeyCalls = nil
	m.GetSymmetricKeyCalls = nil
	m.SymmetricEncrypterCalls = nil
	m.GetImportParametersCalls = nil
	m.WrapKeyCalls = 0
	m.UnwrapKeyCalls = 0
	m.ImportKeyCalls = nil
	m.ExportKeyCalls = nil
}

// StoreKey directly stores a key for testing (bypasses GenerateKey).
func (m *ExtendedMockBackend) StoreKey(cn string, key crypto.PrivateKey) {
	m.MockBackend.mu.Lock()
	defer m.MockBackend.mu.Unlock()
	m.keys[cn] = key
}

// StoreSymmetricKey directly stores a symmetric key for testing.
func (m *ExtendedMockBackend) StoreSymmetricKey(cn string, keyMaterial []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.symmetricKeys[cn] = keyMaterial
}

// MockSymmetricKey implements types.SymmetricKey for testing.
type MockSymmetricKey struct {
	cn          string
	keyMaterial []byte
	algorithm   string
	keySize     int
}

// Algorithm returns the symmetric algorithm.
func (k *MockSymmetricKey) Algorithm() string {
	return k.algorithm
}

// KeySize returns the key size in bits.
func (k *MockSymmetricKey) KeySize() int {
	return k.keySize
}

// Raw returns the raw key bytes.
func (k *MockSymmetricKey) Raw() ([]byte, error) {
	return k.keyMaterial, nil
}

// MockSymmetricEncrypter implements types.SymmetricEncrypter for testing.
type MockSymmetricEncrypter struct {
	// Exported fields for test construction
	KeyMaterial []byte
	Algorithm   string

	// Configurable error behavior
	EncryptError error
	DecryptError error
}

// Encrypt encrypts plaintext using AES-GCM.
func (e *MockSymmetricEncrypter) Encrypt(plaintext []byte, opts *types.EncryptOptions) (*types.EncryptedData, error) {
	if e.EncryptError != nil {
		return nil, e.EncryptError
	}

	block, err := aes.NewCipher(e.KeyMaterial)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	var aad []byte
	if opts != nil {
		aad = opts.AdditionalData
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, aad)

	// Split ciphertext and tag
	tagSize := gcm.Overhead()
	tag := ciphertext[len(ciphertext)-tagSize:]
	actualCiphertext := ciphertext[:len(ciphertext)-tagSize]

	return &types.EncryptedData{
		Ciphertext: actualCiphertext,
		Nonce:      nonce,
		Tag:        tag,
		Algorithm:  e.Algorithm,
	}, nil
}

// Decrypt decrypts ciphertext using AES-GCM.
func (e *MockSymmetricEncrypter) Decrypt(encrypted *types.EncryptedData, opts *types.DecryptOptions) ([]byte, error) {
	if e.DecryptError != nil {
		return nil, e.DecryptError
	}

	block, err := aes.NewCipher(e.KeyMaterial)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	var aad []byte
	if opts != nil {
		aad = opts.AdditionalData
	}

	// Combine ciphertext and tag for GCM.Open
	ciphertextWithTag := append(encrypted.Ciphertext, encrypted.Tag...)

	plaintext, err := gcm.Open(nil, encrypted.Nonce, ciphertextWithTag, aad)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	return plaintext, nil
}

// Verify interface compliance
var (
	_ types.Backend               = (*ExtendedMockBackend)(nil)
	_ types.SymmetricBackend      = (*ExtendedMockBackend)(nil)
	_ backend.ImportExportBackend = (*ExtendedMockBackend)(nil)
)

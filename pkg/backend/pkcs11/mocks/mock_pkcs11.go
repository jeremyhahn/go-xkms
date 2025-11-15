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
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io"
	"sync"
)

// KeyPairCall represents a recorded key pair operation.
type KeyPairCall struct {
	ID     []byte
	Label  []byte
	Result crypto.Signer
	Error  error
}

// GenerateRSACall represents a recorded RSA key generation.
type GenerateRSACall struct {
	ID      []byte
	KeySize int
	Result  crypto.Signer
	Error   error
}

// GenerateECDSACall represents a recorded ECDSA key generation.
type GenerateECDSACall struct {
	ID     []byte
	Curve  elliptic.Curve
	Result crypto.Signer
	Error  error
}

// MockPKCS11Context is a mock implementation of crypto11.Context for testing.
// It simulates PKCS#11 HSM operations without requiring actual hardware.
//
// The mock supports:
//   - RSA and ECDSA key generation
//   - Key pair lookup by ID
//   - Signing operations
//   - Error injection for testing
//   - Call history tracking
//
// Example usage:
//
//	mock := &MockPKCS11Context{
//	    FindKeyPairFunc: func(id, label []byte) (crypto.Signer, error) {
//	        return mockSigner, nil
//	    },
//	}
type MockPKCS11Context struct {
	mu sync.RWMutex

	// FindKeyPairFunc is called by FindKeyPair.
	// If nil, returns nil signer and no error.
	FindKeyPairFunc func(id, label []byte) (crypto.Signer, error)

	// GenerateRSAKeyPairFunc is called by GenerateRSAKeyPair.
	// If nil, generates an actual RSA key pair in memory.
	GenerateRSAKeyPairFunc func(id []byte, bits int) (crypto.Signer, error)

	// GenerateECDSAKeyPairFunc is called by GenerateECDSAKeyPair.
	// If nil, generates an actual ECDSA key pair in memory.
	GenerateECDSAKeyPairFunc func(id []byte, curve elliptic.Curve) (crypto.Signer, error)

	// CloseFunc is called by Close.
	// If nil, returns nil (success).
	CloseFunc func() error

	// Call tracking
	FindKeyPairCalls   []KeyPairCall
	GenerateRSACalls   []GenerateRSACall
	GenerateECDSACalls []GenerateECDSACall
	CloseCalls         int

	// Storage for generated/stored keys
	keys map[string]crypto.Signer
}

// NewMockPKCS11Context creates a new MockPKCS11Context with default behavior.
func NewMockPKCS11Context() *MockPKCS11Context {
	return &MockPKCS11Context{
		keys: make(map[string]crypto.Signer),
	}
}

// FindKeyPair finds a key pair by ID and optional label.
// If FindKeyPairFunc is set, it's called; otherwise searches internal storage.
func (m *MockPKCS11Context) FindKeyPair(id, label []byte) (crypto.Signer, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var signer crypto.Signer
	var err error

	if m.FindKeyPairFunc != nil {
		signer, err = m.FindKeyPairFunc(id, label)
	} else {
		// Search internal storage
		signer = m.keys[string(id)]
	}

	m.FindKeyPairCalls = append(m.FindKeyPairCalls, KeyPairCall{
		ID:     id,
		Label:  label,
		Result: signer,
		Error:  err,
	})

	return signer, err
}

// GenerateRSAKeyPair generates an RSA key pair with the specified ID and bit size.
// If GenerateRSAKeyPairFunc is set, it's called; otherwise generates a real key in memory.
func (m *MockPKCS11Context) GenerateRSAKeyPair(id []byte, bits int) (crypto.Signer, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var signer crypto.Signer
	var err error

	if m.GenerateRSAKeyPairFunc != nil {
		signer, err = m.GenerateRSAKeyPairFunc(id, bits)
	} else {
		// Generate real RSA key in memory for testing
		key, genErr := rsa.GenerateKey(rand.Reader, bits)
		if genErr != nil {
			err = genErr
		} else {
			signer = &MockSigner{
				privateKey: key,
				publicKey:  &key.PublicKey,
			}
			// Store in internal map
			m.keys[string(id)] = signer
		}
	}

	m.GenerateRSACalls = append(m.GenerateRSACalls, GenerateRSACall{
		ID:      id,
		KeySize: bits,
		Result:  signer,
		Error:   err,
	})

	return signer, err
}

// GenerateECDSAKeyPair generates an ECDSA key pair with the specified ID and curve.
// If GenerateECDSAKeyPairFunc is set, it's called; otherwise generates a real key in memory.
func (m *MockPKCS11Context) GenerateECDSAKeyPair(id []byte, curve elliptic.Curve) (crypto.Signer, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var signer crypto.Signer
	var err error

	if m.GenerateECDSAKeyPairFunc != nil {
		signer, err = m.GenerateECDSAKeyPairFunc(id, curve)
	} else {
		// Generate real ECDSA key in memory for testing
		key, genErr := ecdsa.GenerateKey(curve, rand.Reader)
		if genErr != nil {
			err = genErr
		} else {
			signer = &MockSigner{
				privateKey: key,
				publicKey:  &key.PublicKey,
			}
			// Store in internal map
			m.keys[string(id)] = signer
		}
	}

	m.GenerateECDSACalls = append(m.GenerateECDSACalls, GenerateECDSACall{
		ID:     id,
		Curve:  curve,
		Result: signer,
		Error:  err,
	})

	return signer, err
}

// Close closes the PKCS#11 context.
// If CloseFunc is set, it's called; otherwise returns nil.
func (m *MockPKCS11Context) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.CloseCalls++

	if m.CloseFunc != nil {
		return m.CloseFunc()
	}
	return nil
}

// Reset clears all call history and stored keys.
func (m *MockPKCS11Context) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.FindKeyPairCalls = nil
	m.GenerateRSACalls = nil
	m.GenerateECDSACalls = nil
	m.CloseCalls = 0
	m.keys = make(map[string]crypto.Signer)
}

// GetKey retrieves a stored key by ID (for testing).
func (m *MockPKCS11Context) GetKey(id []byte) crypto.Signer {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.keys[string(id)]
}

// SetKey stores a key by ID (for testing setup).
func (m *MockPKCS11Context) SetKey(id []byte, signer crypto.Signer) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.keys[string(id)] = signer
}

// MockSigner is a mock crypto.Signer that wraps real keys for testing.
type MockSigner struct {
	mu         sync.RWMutex
	privateKey crypto.PrivateKey
	publicKey  crypto.PublicKey

	// SignFunc allows overriding sign behavior
	SignFunc func(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error)

	// Track sign calls
	SignCalls int
}

// Public returns the public key.
func (m *MockSigner) Public() crypto.PublicKey {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.publicKey
}

// Sign signs the digest using the private key.
func (m *MockSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.SignCalls++

	if m.SignFunc != nil {
		return m.SignFunc(rand, digest, opts)
	}

	// Use real signing based on key type
	switch key := m.privateKey.(type) {
	case *rsa.PrivateKey:
		return rsa.SignPKCS1v15(rand, key, opts.HashFunc(), digest)
	case *ecdsa.PrivateKey:
		return ecdsa.SignASN1(rand, key, digest)
	default:
		return nil, fmt.Errorf("unsupported key type: %T", m.privateKey)
	}
}

// NewMockSigner creates a mock signer with a real key pair.
func NewMockRSASigner(bits int) (*MockSigner, error) {
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}
	return &MockSigner{
		privateKey: key,
		publicKey:  &key.PublicKey,
	}, nil
}

// NewMockECDSASigner creates a mock ECDSA signer.
func NewMockECDSASigner(curve elliptic.Curve) (*MockSigner, error) {
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, err
	}
	return &MockSigner{
		privateKey: key,
		publicKey:  &key.PublicKey,
	}, nil
}

// MockDecrypter wraps MockSigner to add Decrypt capability for RSA keys.
type MockDecrypter struct {
	*MockSigner
	DecryptFunc  func(rand io.Reader, ciphertext []byte, opts crypto.DecrypterOpts) ([]byte, error)
	DecryptCalls int
}

// Decrypt decrypts the ciphertext.
func (m *MockDecrypter) Decrypt(rand io.Reader, ciphertext []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.DecryptCalls++

	if m.DecryptFunc != nil {
		return m.DecryptFunc(rand, ciphertext, opts)
	}

	// Use real decryption for RSA
	if key, ok := m.privateKey.(*rsa.PrivateKey); ok {
		return rsa.DecryptPKCS1v15(rand, key, ciphertext)
	}

	return nil, fmt.Errorf("key type does not support decryption")
}

// MockPKCS11Error simulates various PKCS#11 errors.
type MockPKCS11Error struct {
	Code    uint
	Message string
}

func (e MockPKCS11Error) Error() string {
	return fmt.Sprintf("PKCS11: %s (0x%08X)", e.Message, e.Code)
}

// Common PKCS#11 error codes
const (
	CKR_OK                       = 0x00000000
	CKR_CRYPTOKI_NOT_INITIALIZED = 0x00000190
	CKR_DEVICE_ERROR             = 0x00000030
	CKR_KEY_HANDLE_INVALID       = 0x00000060
	CKR_KEY_SIZE_RANGE           = 0x00000062
	CKR_OBJECT_HANDLE_INVALID    = 0x00000082
	CKR_PIN_INCORRECT            = 0x000000A0
	CKR_PIN_LOCKED               = 0x000000A4
	CKR_SESSION_CLOSED           = 0x000000B0
	CKR_SESSION_HANDLE_INVALID   = 0x000000B3
	CKR_TOKEN_NOT_PRESENT        = 0x000000E0
	CKR_TOKEN_NOT_RECOGNIZED     = 0x000000E1
	CKR_USER_NOT_LOGGED_IN       = 0x00000101
)

// NewPKCS11Error creates a mock PKCS#11 error.
func NewPKCS11Error(code uint, message string) error {
	return MockPKCS11Error{Code: code, Message: message}
}

// Helper functions for common error scenarios

// ErrNotInitialized returns a PKCS#11 not initialized error.
func ErrNotInitialized() error {
	return NewPKCS11Error(CKR_CRYPTOKI_NOT_INITIALIZED, "cryptoki not initialized")
}

// ErrPINIncorrect returns a PKCS#11 incorrect PIN error.
func ErrPINIncorrect() error {
	return NewPKCS11Error(CKR_PIN_INCORRECT, "PIN incorrect")
}

// ErrTokenNotPresent returns a PKCS#11 token not present error.
func ErrTokenNotPresent() error {
	return NewPKCS11Error(CKR_TOKEN_NOT_PRESENT, "token not present")
}

// ErrUserNotLoggedIn returns a PKCS#11 user not logged in error.
func ErrUserNotLoggedIn() error {
	return NewPKCS11Error(CKR_USER_NOT_LOGGED_IN, "user not logged in")
}

// Ensure MockSigner implements crypto.Signer
var _ crypto.Signer = (*MockSigner)(nil)

// Ensure MockDecrypter implements crypto.Decrypter
var _ crypto.Decrypter = (*MockDecrypter)(nil)

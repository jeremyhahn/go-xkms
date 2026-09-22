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

package mocks

import (
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"slices"
	"sync"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

// gcmNonceSize and gcmTagSize name the 96-bit GCM nonce and 128-bit
// authentication tag lengths. cipher.NewGCMWithRandomNonce reports a NonceSize
// of zero and folds both into Overhead because it manages the nonce itself.
const (
	gcmNonceSize = 12
	gcmTagSize   = 16
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
	ExportKeyToFunc         func(*types.KeyAttributes, *backend.ImportParameters) (*backend.WrappedKeyMaterial, error)
	ExportKeyMaterialFunc   func(*types.KeyAttributes) ([]byte, error)

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
	ExportKeyToCalls         []string
	ExportKeyMaterialCalls   []string
}

// NewExtendedMockBackend creates a new ExtendedMockBackend with default behavior.
func NewExtendedMockBackend() *ExtendedMockBackend {
	return &ExtendedMockBackend{
		MockBackend:   NewMockBackend(),
		symmetricKeys: make(map[string][]byte),
	}
}

// GenerateSymmetricKey generates a new symmetric key.
func (m *ExtendedMockBackend) GenerateSymmetricKey(ctx context.Context, attrs *types.KeyAttributes) (types.SymmetricKey, error) {
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
		return nil, &errs.Wrapped{Msg: "failed to generate key material", Err: err}
	}

	m.symmetricKeys[attrs.CN] = keyMaterial

	buf, err := bufferizeKeyMaterial(keyMaterial)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to seal generated key material", Err: err}
	}

	return &MockSymmetricKey{
		cn:          attrs.CN,
		keyMaterial: buf,
		algorithm:   string(attrs.SymmetricAlgorithm),
		keySize:     keySize * 8, // Convert bytes to bits
	}, nil
}

// GetSymmetricKey retrieves an existing symmetric key.
func (m *ExtendedMockBackend) GetSymmetricKey(ctx context.Context, attrs *types.KeyAttributes) (types.SymmetricKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.GetSymmetricKeyCalls = append(m.GetSymmetricKeyCalls, attrs.CN)

	if m.GetSymmetricKeyFunc != nil {
		return m.GetSymmetricKeyFunc(attrs)
	}

	keyMaterial, ok := m.symmetricKeys[attrs.CN]
	if !ok {
		return nil, &errs.Message{Msg: fmt.Sprintf("symmetric key not found: %s", attrs.CN)}
	}

	buf, err := bufferizeKeyMaterial(keyMaterial)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to seal key material", Err: err}
	}

	return &MockSymmetricKey{
		cn:          attrs.CN,
		keyMaterial: buf,
		algorithm:   string(attrs.SymmetricAlgorithm),
		keySize:     len(keyMaterial) * 8,
	}, nil
}

// SymmetricEncrypter returns a SymmetricEncrypter for the key.
func (m *ExtendedMockBackend) SymmetricEncrypter(ctx context.Context, attrs *types.KeyAttributes) (types.SymmetricEncrypter, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.SymmetricEncrypterCalls = append(m.SymmetricEncrypterCalls, attrs.CN)

	if m.SymmetricEncrypterFunc != nil {
		return m.SymmetricEncrypterFunc(attrs)
	}

	keyMaterial, ok := m.symmetricKeys[attrs.CN]
	if !ok {
		return nil, &errs.Message{Msg: fmt.Sprintf("symmetric key not found: %s", attrs.CN)}
	}

	buf, err := bufferizeKeyMaterial(keyMaterial)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to seal key material", Err: err}
	}

	return &MockSymmetricEncrypter{
		KeyMaterial: buf,
		Algorithm:   string(attrs.SymmetricAlgorithm),
	}, nil
}

// GetImportParameters retrieves import parameters for a key.
func (m *ExtendedMockBackend) GetImportParameters(ctx context.Context, attrs *types.KeyAttributes, algorithm backend.WrappingAlgorithm) (*backend.ImportParameters, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.GetImportParametersCalls = append(m.GetImportParametersCalls, attrs.CN)

	if m.GetImportParametersFunc != nil {
		return m.GetImportParametersFunc(attrs, algorithm)
	}

	// Generate a mock wrapping key (RSA public key)
	wrappingPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to generate wrapping key", Err: err}
	}

	return &backend.ImportParameters{
		WrappingPublicKey: &wrappingPrivKey.PublicKey,
		Algorithm:         algorithm,
		ImportToken:       []byte("mock-import-token"),
	}, nil
}

// WrapKey wraps key material for secure transport.
func (m *ExtendedMockBackend) WrapKey(ctx context.Context, keyMaterial []byte, params *backend.ImportParameters) (*backend.WrappedKeyMaterial, error) {
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
func (m *ExtendedMockBackend) UnwrapKey(ctx context.Context, wrapped *backend.WrappedKeyMaterial, params *backend.ImportParameters) ([]byte, error) {
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
func (m *ExtendedMockBackend) ImportKey(ctx context.Context, attrs *types.KeyAttributes, wrapped *backend.WrappedKeyMaterial) error {
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
func (m *ExtendedMockBackend) ExportKey(ctx context.Context, attrs *types.KeyAttributes, algorithm backend.WrappingAlgorithm) (*backend.WrappedKeyMaterial, error) {
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
		return nil, &errs.Message{Msg: fmt.Sprintf("key not found: %s", attrs.CN)}
	}

	return &backend.WrappedKeyMaterial{
		WrappedKey: keyMaterial,
		Algorithm:  algorithm,
	}, nil
}

// ExportKeyTo exports a key wrapped for dstParams -- the destination's own
// import parameters -- rather than an algorithm this mock would otherwise
// have to mint parameters for itself. Mirrors ExportKey's lookup, but tags
// the result with dstParams' own Algorithm and ImportToken so a caller
// asserting on the returned WrappedKeyMaterial sees exactly what a real
// cross-backend ExportKeyTo would produce.
func (m *ExtendedMockBackend) ExportKeyTo(ctx context.Context, attrs *types.KeyAttributes, dstParams *backend.ImportParameters) (*backend.WrappedKeyMaterial, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.ExportKeyToCalls = append(m.ExportKeyToCalls, attrs.CN)

	if m.ExportKeyToFunc != nil {
		return m.ExportKeyToFunc(attrs, dstParams)
	}

	if dstParams == nil {
		return nil, &errs.Detail{Err: backend.ErrInvalidAttributes, Detail: "destination import parameters cannot be nil"}
	}

	// Check if the key exists (try both asymmetric and symmetric)
	var keyMaterial []byte
	if key, ok := m.keys[attrs.CN]; ok {
		// For asymmetric keys, serialize (mock)
		keyMaterial = []byte(fmt.Sprintf("mock-exported-key:%v", key))
	} else if symKey, ok := m.symmetricKeys[attrs.CN]; ok {
		keyMaterial = symKey
	} else {
		return nil, &errs.Message{Msg: fmt.Sprintf("key not found: %s", attrs.CN)}
	}

	return &backend.WrappedKeyMaterial{
		WrappedKey:  keyMaterial,
		Algorithm:   dstParams.Algorithm,
		ImportToken: dstParams.ImportToken,
	}, nil
}

// ExportKeyMaterial returns the raw key material for extractable symmetric keys only.
// This method provides direct access to the plaintext key bytes without wrapping.
func (m *ExtendedMockBackend) ExportKeyMaterial(ctx context.Context, attrs *types.KeyAttributes) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.ExportKeyMaterialCalls = append(m.ExportKeyMaterialCalls, attrs.CN)

	if m.ExportKeyMaterialFunc != nil {
		return m.ExportKeyMaterialFunc(attrs)
	}

	// Security check: Reject asymmetric keys
	if !attrs.IsSymmetric() {
		return nil, backend.ErrAsymmetricKeyExportNotAllowed
	}

	// Check if key is marked as exportable
	if !attrs.Exportable {
		return nil, backend.ErrKeyNotExportable
	}

	// Get the symmetric key material
	keyMaterial, ok := m.symmetricKeys[attrs.CN]
	if !ok {
		return nil, backend.ErrKeyNotFound
	}

	return keyMaterial, nil
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
	m.ExportKeyMaterialCalls = nil
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

// bufferizeKeyMaterial copies material into a fresh *secure.Buffer without
// consuming the caller's own slice. secure.NewBufferFromBytes wipes its
// input on return, which is correct when the caller is done with the
// slice -- but every call site here also keeps material in
// ExtendedMockBackend.symmetricKeys, so wrapping that slice directly would
// zero the mock's own store out from under later reads. Copying first keeps
// the two independent, the same way software.SoftwareBackend keeps its
// sealed wrapping key and its caller's slice independent (see
// pkg/backend/software/software.go's GetImportParameters).
func bufferizeKeyMaterial(material []byte) (*secure.Buffer, error) {
	cp := make([]byte, len(material))
	copy(cp, material)
	return secure.NewBufferFromBytes(cp)
}

// MockSymmetricKey implements types.SymmetricKey for testing.
type MockSymmetricKey struct {
	cn          string
	keyMaterial *secure.Buffer
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

// Raw returns the raw key bytes. Buffer.Bytes() is nil-safe, so a
// zero-value MockSymmetricKey (keyMaterial never set) returns nil rather
// than panicking, matching the pre-*secure.Buffer zero-value behavior.
func (k *MockSymmetricKey) Raw() ([]byte, error) {
	return k.keyMaterial.Bytes(), nil
}

// NewMockSymmetricEncrypter builds a MockSymmetricEncrypter sealing
// keyMaterial into a *secure.Buffer, for callers that need to construct one
// directly rather than through ExtendedMockBackend.SymmetricEncrypter.
func NewMockSymmetricEncrypter(keyMaterial []byte, algorithm string) (*MockSymmetricEncrypter, error) {
	buf, err := bufferizeKeyMaterial(keyMaterial)
	if err != nil {
		return nil, err
	}
	return &MockSymmetricEncrypter{KeyMaterial: buf, Algorithm: algorithm}, nil
}

// MockSymmetricEncrypter implements types.SymmetricEncrypter for testing.
type MockSymmetricEncrypter struct {
	// KeyMaterial is exported for test construction; use
	// NewMockSymmetricEncrypter rather than a composite literal so the
	// material is sealed the same way ExtendedMockBackend.SymmetricEncrypter
	// seals it.
	KeyMaterial *secure.Buffer
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

	block, err := aes.NewCipher(e.KeyMaterial.Bytes())
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to create cipher", Err: err}
	}

	// NewGCMWithRandomNonce, not NewGCM: FIPS 140-3 (SP 800-38D, CMVP IG C.H)
	// requires the GCM IV be generated inside the module boundary, and
	// GODEBUG=fips140=only rejects an externally supplied one. Seal prepends
	// the nonce and Open strips it, so splitting it back into the
	// EncryptedData fields keeps this mock's shape identical to the real
	// symmetric backends it stands in for.
	gcm, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to create GCM", Err: err}
	}

	var aad []byte
	if opts != nil {
		aad = opts.AdditionalData
	}

	// Seal emits nonce || ciphertext || tag; split all three apart for the
	// EncryptedData fields.
	sealed := gcm.Seal(nil, nil, plaintext, aad)
	nonce := sealed[:gcmNonceSize]
	body := sealed[gcmNonceSize:]
	tag := body[len(body)-gcmTagSize:]
	actualCiphertext := body[:len(body)-gcmTagSize]

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

	if encrypted == nil {
		return nil, &errs.Message{Msg: "mocks: encrypted data is nil"}
	}

	block, err := aes.NewCipher(e.KeyMaterial.Bytes())
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to create cipher", Err: err}
	}

	// NewGCMWithRandomNonce, not NewGCM: FIPS 140-3 (SP 800-38D, CMVP IG C.H)
	// requires the GCM IV be generated inside the module boundary, and
	// GODEBUG=fips140=only rejects an externally supplied one. Seal prepends
	// the nonce and Open strips it, so splitting it back into the
	// EncryptedData fields keeps this mock's shape identical to the real
	// symmetric backends it stands in for.
	gcm, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to create GCM", Err: err}
	}

	// The random-nonce AEAD reports a NonceSize of zero because it manages the
	// nonce itself, so the stored nonce is checked against the constant. Keeping
	// the check means a misbehaving caller under test still gets an error rather
	// than a confusing authentication failure.
	if len(encrypted.Nonce) != gcmNonceSize {
		return nil, &errs.Message{Msg: fmt.Sprintf(
			"mocks: nonce is %d bytes, want %d", len(encrypted.Nonce), gcmNonceSize)}
	}

	var aad []byte
	if opts != nil {
		aad = opts.AdditionalData
	}

	// Open expects the nonce prepended and the tag appended.
	blob := slices.Concat(encrypted.Nonce, encrypted.Ciphertext, encrypted.Tag)

	plaintext, err := gcm.Open(nil, nil, blob, aad)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to decrypt", Err: err}
	}

	return plaintext, nil
}

// Verify interface compliance
var (
	_ types.KeyProvider           = (*ExtendedMockBackend)(nil)
	_ types.SymmetricKeyProvider  = (*ExtendedMockBackend)(nil)
	_ backend.ImportExportBackend = (*ExtendedMockBackend)(nil)
)

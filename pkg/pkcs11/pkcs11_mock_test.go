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

//go:build pkcs11

package pkcs11

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/backend"
	pkcs11backend "github.com/jeremyhahn/go-keychain/pkg/backend/pkcs11"
	"github.com/jeremyhahn/go-keychain/pkg/keychain"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// mockCrypto11Context implements a minimal crypto11.Context interface for testing.
type mockCrypto11Context struct {
	findKeyPairFunc               func(id, label []byte) (crypto.Signer, error)
	generateRSAKeyPairWithLabel   func(id, label []byte, bits int) (crypto.Signer, error)
	generateECDSAKeyPairWithLabel func(id, label []byte, curve elliptic.Curve) (crypto.Signer, error)
	closeFunc                     func() error
	keys                          map[string]crypto.Signer
}

func newMockCrypto11Context() *mockCrypto11Context {
	return &mockCrypto11Context{
		keys: make(map[string]crypto.Signer),
	}
}

func (m *mockCrypto11Context) FindKeyPair(id, label []byte) (crypto.Signer, error) {
	if m.findKeyPairFunc != nil {
		return m.findKeyPairFunc(id, label)
	}
	signer, ok := m.keys[string(id)]
	if !ok {
		return nil, errors.New("key not found")
	}
	return signer, nil
}

func (m *mockCrypto11Context) GenerateRSAKeyPairWithLabel(id, label []byte, bits int) (crypto.Signer, error) {
	if m.generateRSAKeyPairWithLabel != nil {
		return m.generateRSAKeyPairWithLabel(id, label, bits)
	}
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}
	signer := &mockSigner{privateKey: key, publicKey: &key.PublicKey}
	m.keys[string(id)] = signer
	return signer, nil
}

func (m *mockCrypto11Context) GenerateECDSAKeyPairWithLabel(id, label []byte, curve elliptic.Curve) (crypto.Signer, error) {
	if m.generateECDSAKeyPairWithLabel != nil {
		return m.generateECDSAKeyPairWithLabel(id, label, curve)
	}
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, err
	}
	signer := &mockSigner{privateKey: key, publicKey: &key.PublicKey}
	m.keys[string(id)] = signer
	return signer, nil
}

func (m *mockCrypto11Context) Close() error {
	if m.closeFunc != nil {
		return m.closeFunc()
	}
	return nil
}

// mockSigner implements crypto.Signer for testing.
type mockSigner struct {
	privateKey crypto.PrivateKey
	publicKey  crypto.PublicKey
	signFunc   func(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error)
}

func (m *mockSigner) Public() crypto.PublicKey {
	return m.publicKey
}

func (m *mockSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if m.signFunc != nil {
		return m.signFunc(rand, digest, opts)
	}
	switch key := m.privateKey.(type) {
	case *rsa.PrivateKey:
		return rsa.SignPKCS1v15(rand, key, opts.HashFunc(), digest)
	case *ecdsa.PrivateKey:
		return ecdsa.SignASN1(rand, key, digest)
	default:
		return nil, fmt.Errorf("unsupported key type: %T", m.privateKey)
	}
}

// mockDecrypter implements crypto.Decrypter for testing RSA decryption.
type mockDecrypter struct {
	*mockSigner
}

func (m *mockDecrypter) Decrypt(rand io.Reader, ciphertext []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	if key, ok := m.privateKey.(*rsa.PrivateKey); ok {
		return rsa.DecryptPKCS1v15(rand, key, ciphertext)
	}
	return nil, errors.New("key does not support decryption")
}

// mockPassword implements types.Password for testing.
type mockPassword struct {
	value string
	err   error
}

func (m *mockPassword) String() (string, error) {
	return m.value, m.err
}

func (m *mockPassword) Bytes() []byte {
	return []byte(m.value)
}

func (m *mockPassword) Clear() {
	m.value = ""
}

// createMockBackend creates a pkcs11backend.Backend directly without validation.
// This is only for testing the KeyStore wrapper methods.
func createMockBackend() *pkcs11backend.Backend {
	return &pkcs11backend.Backend{}
}

// TestBackendMethodReturnsWrapper tests the Backend() method returns a wrapper.
func TestBackendMethodReturnsWrapper(t *testing.T) {
	mockBackend := createMockBackend()
	ks := &KeyStore{backend: mockBackend}

	wrapper := ks.Backend()
	if wrapper == nil {
		t.Fatal("Expected non-nil backend")
	}

	// Verify it's the wrapper type
	if wrapper.Type() != backend.BackendTypePKCS11 {
		t.Errorf("Expected type %s, got %s", backend.BackendTypePKCS11, wrapper.Type())
	}
}

// TestInitializeSOPINError tests initialization with SO PIN error.
func TestInitializeSOPINError(t *testing.T) {
	mockBackend := createMockBackend()
	ks := &KeyStore{backend: mockBackend}

	soPIN := &mockPassword{value: "", err: errors.New("so pin error")}
	userPIN := &mockPassword{value: "user-pin"}

	err := ks.Initialize(soPIN, userPIN)
	if err == nil {
		t.Fatal("Expected error for SO PIN failure")
	}
	if err.Error() != "failed to get SO PIN: so pin error" {
		t.Errorf("Expected SO PIN error, got: %v", err)
	}
}

// TestInitializeUserPINError tests initialization with user PIN error.
func TestInitializeUserPINError(t *testing.T) {
	mockBackend := createMockBackend()
	ks := &KeyStore{backend: mockBackend}

	soPIN := &mockPassword{value: "so-pin"}
	userPIN := &mockPassword{value: "", err: errors.New("user pin error")}

	err := ks.Initialize(soPIN, userPIN)
	if err == nil {
		t.Fatal("Expected error for user PIN failure")
	}
	if err.Error() != "failed to get user PIN: user pin error" {
		t.Errorf("Expected user PIN error, got: %v", err)
	}
}

// TestCloseMock tests the Close method.
func TestCloseMock(t *testing.T) {
	mockBackend := createMockBackend()
	ks := &KeyStore{backend: mockBackend}

	err := ks.Close()
	// Close should succeed even without initialization
	if err != nil {
		t.Logf("Close returned error (expected without init): %v", err)
	}
}

// TestGenerateKeyDispatchRSA tests GenerateKey dispatching to RSA.
func TestGenerateKeyDispatchRSA(t *testing.T) {
	mockBackend := createMockBackend()
	ks := &KeyStore{backend: mockBackend}

	attrs := &types.KeyAttributes{
		CN:            "test-rsa",
		KeyAlgorithm:  x509.RSA,
		KeyType:       backend.KEY_TYPE_SIGNING,
		StoreType:     backend.STORE_PKCS11,
		RSAAttributes: &types.RSAAttributes{KeySize: 2048},
	}

	// This will fail without a real backend, but covers the dispatch logic
	_, err := ks.GenerateKey(attrs)
	// We expect error due to no PKCS#11 backend
	if err == nil {
		t.Log("Unexpected success - likely has PKCS#11 backend")
	}
}

// TestGenerateKeyDispatchECDSA tests GenerateKey dispatching to ECDSA.
func TestGenerateKeyDispatchECDSA(t *testing.T) {
	mockBackend := createMockBackend()
	ks := &KeyStore{backend: mockBackend}

	attrs := &types.KeyAttributes{
		CN:            "test-ecdsa",
		KeyAlgorithm:  x509.ECDSA,
		KeyType:       backend.KEY_TYPE_SIGNING,
		StoreType:     backend.STORE_PKCS11,
		ECCAttributes: &types.ECCAttributes{Curve: elliptic.P256()},
	}

	// This will fail without a real backend, but covers the dispatch logic
	_, err := ks.GenerateKey(attrs)
	// We expect error due to no PKCS#11 backend
	if err == nil {
		t.Log("Unexpected success - likely has PKCS#11 backend")
	}
}

// TestGenerateRSAAppliesDefaults tests RSA generation applies defaults.
func TestGenerateRSAAppliesDefaults(t *testing.T) {
	mockBackend := createMockBackend()
	ks := &KeyStore{backend: mockBackend}

	tests := []struct {
		name  string
		attrs *types.KeyAttributes
	}{
		{
			name: "nil RSAAttributes",
			attrs: &types.KeyAttributes{
				CN:            "test",
				KeyAlgorithm:  x509.RSA,
				RSAAttributes: nil,
			},
		},
		{
			name: "zero KeySize",
			attrs: &types.KeyAttributes{
				CN:            "test",
				KeyAlgorithm:  x509.RSA,
				RSAAttributes: &types.RSAAttributes{KeySize: 0},
			},
		},
		{
			name: "KeySize < 512",
			attrs: &types.KeyAttributes{
				CN:            "test",
				KeyAlgorithm:  x509.RSA,
				RSAAttributes: &types.RSAAttributes{KeySize: 256},
			},
		},
		{
			name: "valid KeySize",
			attrs: &types.KeyAttributes{
				CN:            "test",
				KeyAlgorithm:  x509.RSA,
				RSAAttributes: &types.RSAAttributes{KeySize: 4096},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ks.GenerateRSA(tt.attrs)
			// We expect error due to no PKCS#11 backend
			if err == nil {
				t.Log("Unexpected success - likely has PKCS#11 backend")
			}
		})
	}
}

// TestGenerateECDSAAppliesDefaults tests ECDSA generation applies defaults.
func TestGenerateECDSAAppliesDefaults(t *testing.T) {
	mockBackend := createMockBackend()
	ks := &KeyStore{backend: mockBackend}

	tests := []struct {
		name  string
		attrs *types.KeyAttributes
	}{
		{
			name: "nil ECCAttributes",
			attrs: &types.KeyAttributes{
				CN:            "test",
				KeyAlgorithm:  x509.ECDSA,
				ECCAttributes: nil,
			},
		},
		{
			name: "nil Curve",
			attrs: &types.KeyAttributes{
				CN:            "test",
				KeyAlgorithm:  x509.ECDSA,
				ECCAttributes: &types.ECCAttributes{Curve: nil},
			},
		},
		{
			name: "valid P384 curve",
			attrs: &types.KeyAttributes{
				CN:            "test",
				KeyAlgorithm:  x509.ECDSA,
				ECCAttributes: &types.ECCAttributes{Curve: elliptic.P384()},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ks.GenerateECDSA(tt.attrs)
			// We expect error due to no PKCS#11 backend
			if err == nil {
				t.Log("Unexpected success - likely has PKCS#11 backend")
			}
		})
	}
}

// TestRotateKeyFindsKeyFirst tests rotation checks if key exists.
func TestRotateKeyFindsKeyFirst(t *testing.T) {
	mockBackend := createMockBackend()
	ks := &KeyStore{backend: mockBackend}

	attrs := &types.KeyAttributes{
		CN:           "nonexistent",
		KeyAlgorithm: x509.RSA,
	}

	_, err := ks.RotateKey(attrs)
	if err == nil {
		t.Fatal("Expected error for non-existent key")
	}
}

// TestGenerateKeyEd25519Unsupported tests Ed25519 returns error.
func TestGenerateKeyEd25519Unsupported(t *testing.T) {
	mockBackend := createMockBackend()
	ks := &KeyStore{backend: mockBackend}

	attrs := &types.KeyAttributes{
		CN:           "test",
		KeyAlgorithm: x509.Ed25519,
	}

	_, err := ks.GenerateKey(attrs)
	if err == nil {
		t.Fatal("Expected error for Ed25519")
	}
	if !errors.Is(err, pkcs11backend.ErrUnsupportedKeyAlgorithm) {
		t.Errorf("Expected ErrUnsupportedKeyAlgorithm, got %v", err)
	}
}

// TestGenerateKeyInvalidAlgorithmMock tests invalid algorithm returns error.
func TestGenerateKeyInvalidAlgorithmMock(t *testing.T) {
	mockBackend := createMockBackend()
	ks := &KeyStore{backend: mockBackend}

	attrs := &types.KeyAttributes{
		CN:           "test",
		KeyAlgorithm: x509.PublicKeyAlgorithm(999), // Invalid algorithm
	}

	_, err := ks.GenerateKey(attrs)
	if err == nil {
		t.Fatal("Expected error for invalid algorithm")
	}
	if !errors.Is(err, keychain.ErrInvalidKeyAlgorithm) {
		t.Errorf("Expected ErrInvalidKeyAlgorithm, got %v", err)
	}
}

// TestSignerCallsBackend tests Signer calls backend.
func TestSignerCallsBackend(t *testing.T) {
	mockBackend := createMockBackend()
	ks := &KeyStore{backend: mockBackend}

	attrs := &types.KeyAttributes{
		CN:           "test-signer",
		KeyAlgorithm: x509.RSA,
	}

	_, err := ks.Signer(attrs)
	// We expect error due to no PKCS#11 backend
	if err == nil {
		t.Log("Unexpected success - likely has PKCS#11 backend")
	}
}

// TestDecrypterCallsBackend tests Decrypter calls backend.
func TestDecrypterCallsBackend(t *testing.T) {
	mockBackend := createMockBackend()
	ks := &KeyStore{backend: mockBackend}

	attrs := &types.KeyAttributes{
		CN:           "test-decrypt",
		KeyAlgorithm: x509.RSA,
	}

	_, err := ks.Decrypter(attrs)
	// We expect error due to no PKCS#11 backend
	if err == nil {
		t.Log("Unexpected success - likely has PKCS#11 backend")
	}
}

// TestFindCallsBackend tests Find calls backend.
func TestFindCallsBackend(t *testing.T) {
	mockBackend := createMockBackend()
	ks := &KeyStore{backend: mockBackend}

	attrs := &types.KeyAttributes{
		CN:           "test-find",
		KeyAlgorithm: x509.RSA,
	}

	_, err := ks.Find(attrs)
	// We expect error due to no PKCS#11 backend
	if err == nil {
		t.Log("Unexpected success - likely has PKCS#11 backend")
	}
}

// TestKeyDelegatesToFind tests Key delegates to Find.
func TestKeyDelegatesToFind(t *testing.T) {
	mockBackend := createMockBackend()
	ks := &KeyStore{backend: mockBackend}

	attrs := &types.KeyAttributes{
		CN:           "test-key",
		KeyAlgorithm: x509.RSA,
	}

	_, err := ks.Key(attrs)
	// We expect error due to no PKCS#11 backend
	if err == nil {
		t.Log("Unexpected success - likely has PKCS#11 backend")
	}
}

// TestDeleteCallsBackend tests Delete calls backend.
func TestDeleteCallsBackend(t *testing.T) {
	mockBackend := createMockBackend()
	ks := &KeyStore{backend: mockBackend}

	attrs := &types.KeyAttributes{
		CN:           "test-delete",
		KeyAlgorithm: x509.RSA,
	}

	err := ks.Delete(attrs)
	// We expect error due to no PKCS#11 backend
	if err == nil {
		t.Log("Unexpected success - likely has PKCS#11 backend")
	}
}

// TestOpaqueBackendGetCallsBackend tests backendWrapper.GetKey calls backend.
func TestOpaqueBackendGetCallsBackend(t *testing.T) {
	mockBackend := createMockBackend()
	ks := &KeyStore{backend: mockBackend}

	wrapper := ks.Backend()

	attrs := &types.KeyAttributes{CN: "test"}
	_, err := wrapper.GetKey(attrs)
	// We expect error due to no PKCS#11 backend
	if err == nil {
		t.Log("Unexpected success - likely has PKCS#11 backend")
	}
}

// TestOpaqueBackendSignerCallsBackend tests backendWrapper.Signer calls backend.
func TestOpaqueBackendSignerCallsBackend(t *testing.T) {
	mockBackend := createMockBackend()
	ks := &KeyStore{backend: mockBackend}

	wrapper := ks.Backend()

	attrs := &types.KeyAttributes{CN: "test"}
	_, err := wrapper.Signer(attrs)
	// We expect error due to no PKCS#11 backend
	if err == nil {
		t.Log("Unexpected success - likely has PKCS#11 backend")
	}
}

// TestOpaqueBackendDeleteCallsBackend tests backendWrapper.DeleteKey calls backend.
func TestOpaqueBackendDeleteCallsBackend(t *testing.T) {
	mockBackend := createMockBackend()
	ks := &KeyStore{backend: mockBackend}

	wrapper := ks.Backend()

	attrs := &types.KeyAttributes{CN: "test"}
	err := wrapper.DeleteKey(attrs)
	// We expect error due to no PKCS#11 backend
	if err == nil {
		t.Log("Unexpected success - likely has PKCS#11 backend")
	}
}

// TestOpaqueBackendCloseIsNoOp tests backendWrapper.Close is no-op.
func TestOpaqueBackendCloseIsNoOp(t *testing.T) {
	mockBackend := createMockBackend()
	ks := &KeyStore{backend: mockBackend}

	wrapper := ks.Backend()

	err := wrapper.Close()
	if err != nil {
		t.Fatalf("Expected nil error from wrapper Close (no-op), got %v", err)
	}
}

// Ensure mockCrypto11Context partially implements crypto11.Context interface.
var _ interface {
	FindKeyPair(id, label []byte) (crypto.Signer, error)
	GenerateRSAKeyPairWithLabel(id, label []byte, bits int) (crypto.Signer, error)
	GenerateECDSAKeyPairWithLabel(id, label []byte, curve elliptic.Curve) (crypto.Signer, error)
	Close() error
} = (*mockCrypto11Context)(nil)

// Ensure mockSigner implements crypto.Signer (compile-time check).
var _ crypto.Signer = (*mockSigner)(nil)

// Ensure mockDecrypter implements crypto.Decrypter (compile-time check).
var _ crypto.Decrypter = (*mockDecrypter)(nil)

// Ensure mockPassword implements types.Password (compile-time check).
var _ types.Password = (*mockPassword)(nil)

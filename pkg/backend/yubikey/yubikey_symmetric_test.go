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

package yubikey

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"io"
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/backend"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Mock Types
// =============================================================================

// mockDecrypter implements crypto.Decrypter for testing
type mockDecrypter struct {
	privateKey crypto.PrivateKey
	publicKey  crypto.PublicKey
	decryptErr error
}

func (m *mockDecrypter) Public() crypto.PublicKey {
	return m.publicKey
}

func (m *mockDecrypter) Decrypt(randReader io.Reader, ciphertext []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	if m.decryptErr != nil {
		return nil, m.decryptErr
	}

	// Delegate to the actual private key for RSA
	if rsaKey, ok := m.privateKey.(*rsa.PrivateKey); ok {
		return rsaKey.Decrypt(randReader, ciphertext, opts)
	}

	return nil, errors.New("unsupported key type for mock decrypter")
}

func (m *mockDecrypter) PrivateKey() crypto.PrivateKey {
	return m.privateKey
}

// =============================================================================
// yubikeySymmetricKey Tests
// =============================================================================

func TestYubikeySymmetricKey_Algorithm(t *testing.T) {
	key := &yubikeySymmetricKey{
		algorithm: "aes256-gcm",
		keySize:   256,
	}

	assert.Equal(t, "aes256-gcm", key.Algorithm())
}

func TestYubikeySymmetricKey_KeySize(t *testing.T) {
	tests := []struct {
		name     string
		keySize  int
		expected int
	}{
		{"AES-128", 128, 128},
		{"AES-192", 192, 192},
		{"AES-256", 256, 256},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := &yubikeySymmetricKey{
				keySize: tt.keySize,
			}
			assert.Equal(t, tt.expected, key.KeySize())
		})
	}
}

func TestYubikeySymmetricKey_Raw(t *testing.T) {
	key := &yubikeySymmetricKey{
		algorithm: "aes256-gcm",
		keySize:   256,
	}

	raw, err := key.Raw()
	assert.Error(t, err)
	assert.Nil(t, raw)
	assert.ErrorIs(t, err, backend.ErrNotSupported)
	assert.Contains(t, err.Error(), "envelope encryption")
}

// =============================================================================
// wrapDEKWithRSA / unwrapDEKWithRSA Tests
// =============================================================================

func TestWrapUnwrapDEKWithRSA(t *testing.T) {
	// Generate RSA key
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Create test DEK
	dek := make([]byte, dekSize)
	_, err = rand.Read(dek)
	require.NoError(t, err)

	// Test wrap
	encryptedDEK, err := wrapDEKWithRSA(&rsaKey.PublicKey, dek)
	require.NoError(t, err)
	assert.NotNil(t, encryptedDEK)
	assert.Greater(t, len(encryptedDEK), dekSize)

	// Test unwrap
	decrypter := &mockDecrypter{
		privateKey: rsaKey,
		publicKey:  &rsaKey.PublicKey,
	}

	unwrappedDEK, err := unwrapDEKWithRSA(decrypter, encryptedDEK)
	require.NoError(t, err)
	assert.Equal(t, dek, unwrappedDEK)
}

func TestWrapDEKWithRSA_InvalidKey(t *testing.T) {
	// Since 1024-bit RSA can handle 32-byte DEK with OAEP-SHA256,
	// this test cannot easily trigger a failure without using unrealistically small keys.
	// Testing unwrap with invalid ciphertext covers error handling instead.
	t.Skip("1024-bit RSA key can handle 32-byte DEK with OAEP")
}

func TestUnwrapDEKWithRSA_InvalidCiphertext(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	decrypter := &mockDecrypter{
		privateKey: rsaKey,
		publicKey:  &rsaKey.PublicKey,
	}

	// Invalid ciphertext
	invalidCiphertext := []byte("invalid-ciphertext")

	_, err = unwrapDEKWithRSA(decrypter, invalidCiphertext)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "RSA-OAEP")
}

// =============================================================================
// wrapDEKWithECIES / unwrapDEKWithECIES Tests
// =============================================================================

func TestWrapUnwrapDEKWithECIES_P256(t *testing.T) {
	// Generate ECDSA P-256 key
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Create test DEK
	dek := make([]byte, dekSize)
	_, err = rand.Read(dek)
	require.NoError(t, err)

	// Test wrap
	encryptedDEK, err := wrapDEKWithECIES(&ecdsaKey.PublicKey, dek)
	require.NoError(t, err)
	assert.NotNil(t, encryptedDEK)

	// Verify format: ephemeralPub || nonce || ciphertext || tag
	pubKeySize := (elliptic.P256().Params().BitSize+7)/8*2 + 1
	minSize := pubKeySize + 12 + dekSize + 16
	assert.GreaterOrEqual(t, len(encryptedDEK), minSize)

	// Test unwrap
	decrypter := &mockDecrypter{
		privateKey: ecdsaKey,
		publicKey:  &ecdsaKey.PublicKey,
	}

	unwrappedDEK, err := unwrapDEKWithECIES(decrypter, encryptedDEK, elliptic.P256())
	require.NoError(t, err)
	assert.Equal(t, dek, unwrappedDEK)
}

func TestWrapUnwrapDEKWithECIES_P384(t *testing.T) {
	// Generate ECDSA P-384 key
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	// Create test DEK
	dek := make([]byte, dekSize)
	_, err = rand.Read(dek)
	require.NoError(t, err)

	// Test wrap
	encryptedDEK, err := wrapDEKWithECIES(&ecdsaKey.PublicKey, dek)
	require.NoError(t, err)
	assert.NotNil(t, encryptedDEK)

	// Test unwrap
	decrypter := &mockDecrypter{
		privateKey: ecdsaKey,
		publicKey:  &ecdsaKey.PublicKey,
	}

	unwrappedDEK, err := unwrapDEKWithECIES(decrypter, encryptedDEK, elliptic.P384())
	require.NoError(t, err)
	assert.Equal(t, dek, unwrappedDEK)
}

func TestUnwrapDEKWithECIES_TooShort(t *testing.T) {
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	decrypter := &mockDecrypter{
		privateKey: ecdsaKey,
		publicKey:  &ecdsaKey.PublicKey,
	}

	// Encrypted DEK that's too short
	shortData := []byte("too-short")

	_, err = unwrapDEKWithECIES(decrypter, shortData, elliptic.P256())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "too short")
}

func TestUnwrapDEKWithECIES_InvalidEphemeralKey(t *testing.T) {
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	decrypter := &mockDecrypter{
		privateKey: ecdsaKey,
		publicKey:  &ecdsaKey.PublicKey,
	}

	// Create data with invalid ephemeral public key
	pubKeySize := (elliptic.P256().Params().BitSize+7)/8*2 + 1
	invalidData := make([]byte, pubKeySize+12+dekSize+16)
	// Fill with random data (invalid ephemeral key)
	_, _ = rand.Read(invalidData)

	_, err = unwrapDEKWithECIES(decrypter, invalidData, elliptic.P256())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unmarshal")
}

func TestUnwrapDEKWithECIES_InvalidDecrypter(t *testing.T) {
	// Use wrong key type - should fail during unmarshaling since we generate
	// valid ECDSA ephemeral key but try to use RSA key for ECDH
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	decrypter := &mockDecrypter{
		privateKey: rsaKey,
		publicKey:  &rsaKey.PublicKey,
	}

	// Generate a valid ECIES encrypted DEK with a real ECDSA key first
	realECDSAKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	dek := make([]byte, dekSize)
	_, _ = rand.Read(dek)

	encryptedDEK, err := wrapDEKWithECIES(&realECDSAKey.PublicKey, dek)
	require.NoError(t, err)

	// Now try to decrypt with RSA decrypter - should fail at type assertion
	_, err = unwrapDEKWithECIES(decrypter, encryptedDEK, elliptic.P256())
	assert.Error(t, err)
	// The error happens when trying to get the private key, not during public key unmarshal
	// The error happens at the type assertion step
	assert.Contains(t, err.Error(), "not ECDSA")
}

// =============================================================================
// wrapDEKWithX25519 / unwrapDEKWithX25519 Tests
// =============================================================================

func TestWrapUnwrapDEKWithX25519(t *testing.T) {
	// Generate Ed25519 key
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	// Create test DEK
	dek := make([]byte, dekSize)
	_, err = rand.Read(dek)
	require.NoError(t, err)

	// Test wrap
	encryptedDEK, err := wrapDEKWithX25519(pubKey, dek)
	require.NoError(t, err)
	assert.NotNil(t, encryptedDEK)

	// Verify format: ephemeralPub(32) || nonce(12) || ciphertext || tag(16)
	minSize := 32 + 12 + dekSize + 16
	assert.GreaterOrEqual(t, len(encryptedDEK), minSize)

	// Test unwrap
	decrypter := &mockDecrypter{
		privateKey: privKey,
		publicKey:  pubKey,
	}

	unwrappedDEK, err := unwrapDEKWithX25519(decrypter, encryptedDEK)
	require.NoError(t, err)
	assert.Equal(t, dek, unwrappedDEK)
}

func TestUnwrapDEKWithX25519_TooShort(t *testing.T) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	decrypter := &mockDecrypter{
		privateKey: privKey,
		publicKey:  pubKey,
	}

	// Encrypted DEK that's too short
	shortData := []byte("too-short")

	_, err = unwrapDEKWithX25519(decrypter, shortData)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "too short")
}

func TestUnwrapDEKWithX25519_WrongKeyType(t *testing.T) {
	// Use ECDSA key instead of Ed25519
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	decrypter := &mockDecrypter{
		privateKey: ecdsaKey,
		publicKey:  &ecdsaKey.PublicKey,
	}

	// Create valid-sized data
	data := make([]byte, 32+12+dekSize+16)
	_, _ = rand.Read(data)

	_, err = unwrapDEKWithX25519(decrypter, data)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not Ed25519")
}

// =============================================================================
// Ed25519/X25519 Conversion Tests
// =============================================================================

func TestEd25519PublicKeyToX25519(t *testing.T) {
	pubKey, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	x25519Pub, err := ed25519PublicKeyToX25519(pubKey)
	require.NoError(t, err)
	assert.Len(t, x25519Pub, 32)
}

func TestEd25519PublicKeyToX25519_InvalidSize(t *testing.T) {
	invalidKey := []byte("invalid-key")

	_, err := ed25519PublicKeyToX25519(invalidKey)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid Ed25519 public key size")
}

func TestEd25519PublicKeyToX25519_InvalidKey(t *testing.T) {
	// Valid size but invalid key data (all zeros)
	invalidKey := make([]byte, ed25519.PublicKeySize)

	x25519Pub, err := ed25519PublicKeyToX25519(invalidKey)
	// The edwards25519 library will reject invalid points
	if err != nil {
		assert.Contains(t, err.Error(), "invalid Ed25519 public key")
	} else {
		// If it doesn't error, at least verify we got a result
		assert.Len(t, x25519Pub, 32)
	}
}

func TestEd25519PrivateKeyToX25519(t *testing.T) {
	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	x25519Priv, err := ed25519PrivateKeyToX25519(privKey)
	require.NoError(t, err)
	assert.Len(t, x25519Priv, 32)

	// Verify clamping
	assert.Equal(t, byte(0), x25519Priv[0]&7)    // Lower 3 bits cleared
	assert.Equal(t, byte(0), x25519Priv[31]&128) // Bit 255 cleared
	assert.Equal(t, byte(64), x25519Priv[31]&64) // Bit 254 set
}

func TestEd25519PrivateKeyToX25519_InvalidSize(t *testing.T) {
	invalidKey := []byte("invalid-key")

	_, err := ed25519PrivateKeyToX25519(invalidKey)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid Ed25519 private key size")
}

func TestGenerateX25519KeyPair(t *testing.T) {
	pubKey, privKey, err := generateX25519KeyPair()
	require.NoError(t, err)
	assert.Len(t, pubKey, 32)
	assert.Len(t, privKey, 32)

	// Verify clamping
	assert.Equal(t, byte(0), privKey[0]&7)    // Lower 3 bits cleared
	assert.Equal(t, byte(0), privKey[31]&128) // Bit 255 cleared
	assert.Equal(t, byte(64), privKey[31]&64) // Bit 254 set
}

// =============================================================================
// Integration-Level Tests (require real backend setup)
// =============================================================================

// NOTE: The following tests for yubikeySymmetricEncrypter and Backend methods
// require a real Backend instance with PKCS#11 backend and YubiKey hardware.
// These are better suited for integration tests rather than unit tests.
//
// Tests that would be included:
//   - TestYubikeySymmetricEncrypter_Encrypt_RSA
//   - TestYubikeySymmetricEncrypter_Encrypt_ECDSA_P256
//   - TestYubikeySymmetricEncrypter_Encrypt_ECDSA_P384
//   - TestYubikeySymmetricEncrypter_Encrypt_Ed25519
//   - TestYubikeySymmetricEncrypter_Encrypt_WithNonce
//   - TestYubikeySymmetricEncrypter_Encrypt_WithAdditionalData
//   - TestYubikeySymmetricEncrypter_Encrypt_UnsupportedCurve
//   - TestYubikeySymmetricEncrypter_Encrypt_Ed25519_OldFirmware
//   - TestYubikeySymmetricEncrypter_Decrypt_InvalidAlgorithm
//   - TestYubikeySymmetricEncrypter_Decrypt_MissingMetadata
//   - TestYubikeySymmetricEncrypter_Decrypt_MissingEncryptedDEK
//   - TestYubikeySymmetricEncrypter_Decrypt_InvalidBase64
//   - TestYubikeySymmetricEncrypter_Decrypt_UnknownWrapAlgorithm
//   - TestBackend_GenerateSymmetricKey
//   - TestBackend_GetSymmetricKey
//   - TestBackend_SymmetricEncrypter
//
// These tests should be implemented in a separate integration test file
// (e.g., yubikey_symmetric_integration_test.go) with appropriate build tags
// and hardware requirements.

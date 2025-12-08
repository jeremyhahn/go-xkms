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

package canokey

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"io"
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/backend"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/hkdf"
)

// =============================================================================
// Mock Types
// =============================================================================

// mockDecrypter implements crypto.Decrypter for testing
type mockDecrypter struct {
	publicKey  crypto.PublicKey
	privateKey crypto.PrivateKey
	decryptFn  func(rand io.Reader, ciphertext []byte, opts crypto.DecrypterOpts) ([]byte, error)
}

func (m *mockDecrypter) Public() crypto.PublicKey {
	return m.publicKey
}

func (m *mockDecrypter) Decrypt(rand io.Reader, ciphertext []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	if m.decryptFn != nil {
		return m.decryptFn(rand, ciphertext, opts)
	}
	// Default RSA-OAEP decryption
	if rsaPriv, ok := m.privateKey.(*rsa.PrivateKey); ok {
		return rsa.DecryptOAEP(crypto.SHA256.New(), rand, rsaPriv, ciphertext, nil)
	}
	return nil, backend.ErrNotSupported
}

func (m *mockDecrypter) PrivateKey() crypto.PrivateKey {
	return m.privateKey
}

// =============================================================================
// Test: canokeySymmetricKey
// =============================================================================

func TestCanokeySymmetricKey_Algorithm(t *testing.T) {
	key := &canokeySymmetricKey{
		algorithm: "aes256-gcm",
		keySize:   256,
	}

	assert.Equal(t, "aes256-gcm", key.Algorithm())
}

func TestCanokeySymmetricKey_KeySize(t *testing.T) {
	tests := []struct {
		name    string
		keySize int
	}{
		{"AES-128", 128},
		{"AES-192", 192},
		{"AES-256", 256},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := &canokeySymmetricKey{
				algorithm: "aes-gcm",
				keySize:   tt.keySize,
			}
			assert.Equal(t, tt.keySize, key.KeySize())
		})
	}
}

func TestCanokeySymmetricKey_Raw(t *testing.T) {
	key := &canokeySymmetricKey{
		algorithm: "aes256-gcm",
		keySize:   256,
	}

	raw, err := key.Raw()
	assert.Nil(t, raw)
	assert.ErrorIs(t, err, backend.ErrNotSupported)
}

// =============================================================================
// Test: DEK Wrapping Functions - RSA-OAEP
// =============================================================================

func TestWrapDEKWithRSA(t *testing.T) {
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	dek := make([]byte, dekSize)
	_, err = rand.Read(dek)
	require.NoError(t, err)

	// Test wrapping
	encrypted, err := wrapDEKWithRSA(&rsaPriv.PublicKey, dek)
	require.NoError(t, err)
	assert.NotEmpty(t, encrypted)
	assert.Greater(t, len(encrypted), dekSize, "encrypted DEK should be larger than plain DEK")

	// Test unwrapping
	mockDecrypter := &mockDecrypter{
		publicKey:  &rsaPriv.PublicKey,
		privateKey: rsaPriv,
	}

	decrypted, err := unwrapDEKWithRSA(mockDecrypter, encrypted)
	require.NoError(t, err)
	assert.Equal(t, dek, decrypted, "decrypted DEK should match original")
}

func TestWrapDEKWithRSA_DifferentKeySizes(t *testing.T) {
	tests := []struct {
		name    string
		keySize int
	}{
		{"RSA-2048", 2048},
		{"RSA-3072", 3072},
		{"RSA-4096", 4096},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rsaPriv, err := rsa.GenerateKey(rand.Reader, tt.keySize)
			require.NoError(t, err)

			dek := make([]byte, dekSize)
			_, err = rand.Read(dek)
			require.NoError(t, err)

			// Wrap and unwrap
			encrypted, err := wrapDEKWithRSA(&rsaPriv.PublicKey, dek)
			require.NoError(t, err)

			mockDecrypter := &mockDecrypter{
				publicKey:  &rsaPriv.PublicKey,
				privateKey: rsaPriv,
			}

			decrypted, err := unwrapDEKWithRSA(mockDecrypter, encrypted)
			require.NoError(t, err)
			assert.Equal(t, dek, decrypted)
		})
	}
}

// =============================================================================
// Test: DEK Wrapping Functions - ECIES
// =============================================================================

func TestWrapDEKWithECIES(t *testing.T) {
	tests := []struct {
		name  string
		curve elliptic.Curve
	}{
		{"P-256", elliptic.P256()},
		{"P-384", elliptic.P384()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ecdsaPriv, err := ecdsa.GenerateKey(tt.curve, rand.Reader)
			require.NoError(t, err)

			dek := make([]byte, dekSize)
			_, err = rand.Read(dek)
			require.NoError(t, err)

			// Test wrapping
			encrypted, err := wrapDEKWithECIES(&ecdsaPriv.PublicKey, dek)
			require.NoError(t, err)
			assert.NotEmpty(t, encrypted)

			// Verify format: ephemeralPub || nonce(12) || ciphertext || tag(16)
			minSize := ((tt.curve.Params().BitSize+7)/8*2 + 1) + 12 + dekSize + 16
			assert.GreaterOrEqual(t, len(encrypted), minSize, "encrypted DEK has expected minimum size")

			// Test unwrapping
			mockDecrypter := &mockDecrypter{
				publicKey:  &ecdsaPriv.PublicKey,
				privateKey: ecdsaPriv,
			}

			decrypted, err := unwrapDEKWithECIES(mockDecrypter, encrypted, tt.curve)
			require.NoError(t, err)
			assert.Equal(t, dek, decrypted)
		})
	}
}

func TestUnwrapDEKWithECIES_Errors(t *testing.T) {
	ecdsaPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	mockDecrypter := &mockDecrypter{
		publicKey:  &ecdsaPriv.PublicKey,
		privateKey: ecdsaPriv,
	}

	tests := []struct {
		name         string
		encryptedDEK []byte
		wantError    string
	}{
		{
			name:         "encrypted DEK too short",
			encryptedDEK: make([]byte, 10),
			wantError:    "encrypted DEK too short",
		},
		{
			name:         "invalid ephemeral key",
			encryptedDEK: make([]byte, 130), // Long enough but invalid key (P-256 minSize = 65+12+32+16=125)
			wantError:    "failed to unmarshal ephemeral public key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := unwrapDEKWithECIES(mockDecrypter, tt.encryptedDEK, elliptic.P256())
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantError)
		})
	}
}

// =============================================================================
// Test: DEK Wrapping Functions - X25519
// =============================================================================

func TestWrapDEKWithX25519(t *testing.T) {
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	dek := make([]byte, dekSize)
	_, err = rand.Read(dek)
	require.NoError(t, err)

	// Test wrapping
	encrypted, err := wrapDEKWithX25519(edPub, dek)
	require.NoError(t, err)
	assert.NotEmpty(t, encrypted)

	// Verify format: ephemeralPub(32) || nonce(12) || ciphertext || tag(16)
	minSize := 32 + 12 + dekSize + 16
	assert.GreaterOrEqual(t, len(encrypted), minSize, "encrypted DEK has expected size")

	// Test unwrapping
	mockDecrypter := &mockDecrypter{
		publicKey:  edPub,
		privateKey: edPriv,
	}

	decrypted, err := unwrapDEKWithX25519(mockDecrypter, encrypted)
	require.NoError(t, err)
	assert.Equal(t, dek, decrypted)
}

func TestWrapDEKWithX25519_MultipleRounds(t *testing.T) {
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	mockDecrypter := &mockDecrypter{
		publicKey:  edPub,
		privateKey: edPriv,
	}

	// Test multiple wrapping/unwrapping cycles with different DEKs
	for i := 0; i < 10; i++ {
		dek := make([]byte, dekSize)
		_, err := rand.Read(dek)
		require.NoError(t, err)

		encrypted, err := wrapDEKWithX25519(edPub, dek)
		require.NoError(t, err)

		decrypted, err := unwrapDEKWithX25519(mockDecrypter, encrypted)
		require.NoError(t, err)
		assert.Equal(t, dek, decrypted, "round %d: DEK mismatch", i)
	}
}

func TestUnwrapDEKWithX25519_Errors(t *testing.T) {
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	mockDecrypter := &mockDecrypter{
		publicKey:  edPub,
		privateKey: edPriv,
	}

	tests := []struct {
		name         string
		encryptedDEK []byte
		wantError    string
	}{
		{
			name:         "encrypted DEK too short",
			encryptedDEK: make([]byte, 10),
			wantError:    "encrypted DEK too short",
		},
		{
			name:         "minimum size but corrupted",
			encryptedDEK: make([]byte, 32+12+dekSize+16), // Right size but all zeros - triggers low order point error
			wantError:    "X25519 key agreement failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := unwrapDEKWithX25519(mockDecrypter, tt.encryptedDEK)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantError)
		})
	}
}

// =============================================================================
// Test: Ed25519/X25519 Conversion Functions
// =============================================================================

func TestEd25519PublicKeyToX25519(t *testing.T) {
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	x25519Pub, err := ed25519PublicKeyToX25519(edPub)
	require.NoError(t, err)
	assert.Len(t, x25519Pub, 32)

	// Verify it's not all zeros
	hasNonZero := false
	for _, b := range x25519Pub {
		if b != 0 {
			hasNonZero = true
			break
		}
	}
	assert.True(t, hasNonZero, "X25519 public key should not be all zeros")
}

func TestEd25519PublicKeyToX25519_Errors(t *testing.T) {
	tests := []struct {
		name      string
		edPub     ed25519.PublicKey
		wantError string
	}{
		{
			name:      "invalid size - too short",
			edPub:     make([]byte, 10),
			wantError: "invalid Ed25519 key size",
		},
		{
			name:      "invalid size - too long",
			edPub:     make([]byte, 100),
			wantError: "invalid Ed25519 key size",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ed25519PublicKeyToX25519(tt.edPub)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantError)
		})
	}
}

func TestEd25519PublicKeyToX25519_AllZeros(t *testing.T) {
	// All zeros is the identity element on the curve - a valid point
	// The edwards25519 library accepts it, so we just verify we get some output
	edPub := make([]byte, ed25519.PublicKeySize)
	x25519Pub, err := ed25519PublicKeyToX25519(edPub)
	require.NoError(t, err)
	assert.Len(t, x25519Pub, 32)
}

func TestEd25519PrivateKeyToX25519(t *testing.T) {
	_, edPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	x25519Priv, err := ed25519PrivateKeyToX25519(edPriv)
	require.NoError(t, err)
	assert.Len(t, x25519Priv, 32)

	// Verify clamping was applied (RFC 7748)
	assert.Equal(t, byte(0), x25519Priv[0]&0x07, "bits 0-2 should be cleared")
	assert.Equal(t, byte(0), x25519Priv[31]&0x80, "bit 255 should be cleared")
	assert.NotEqual(t, byte(0), x25519Priv[31]&0x40, "bit 254 should be set")
}

func TestEd25519PrivateKeyToX25519_InvalidSize(t *testing.T) {
	tests := []struct {
		name    string
		privKey []byte
	}{
		{"too short", make([]byte, 10)},
		{"too long", make([]byte, 100)},
		{"empty", []byte{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ed25519PrivateKeyToX25519(tt.privKey)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "invalid Ed25519 key size")
		})
	}
}

func TestGenerateX25519KeyPair(t *testing.T) {
	pubKey, privKey, err := generateX25519KeyPair()
	require.NoError(t, err)
	assert.Len(t, pubKey, 32)
	assert.Len(t, privKey, 32)

	// Verify clamping was applied (RFC 7748)
	assert.Equal(t, byte(0), privKey[0]&0x07, "bits 0-2 should be cleared")
	assert.Equal(t, byte(0), privKey[31]&0x80, "bit 255 should be cleared")
	assert.NotEqual(t, byte(0), privKey[31]&0x40, "bit 254 should be set")

	// Verify keys are not all zeros
	hasNonZeroPub := false
	hasNonZeroPriv := false
	for i := range pubKey {
		if pubKey[i] != 0 {
			hasNonZeroPub = true
		}
		if privKey[i] != 0 {
			hasNonZeroPriv = true
		}
	}
	assert.True(t, hasNonZeroPub, "public key should not be all zeros")
	assert.True(t, hasNonZeroPriv, "private key should not be all zeros")
}

func TestGenerateX25519KeyPair_Uniqueness(t *testing.T) {
	// Generate multiple key pairs and verify they're all different
	keys := make(map[string]bool)

	for i := 0; i < 10; i++ {
		pubKey, _, err := generateX25519KeyPair()
		require.NoError(t, err)

		keyStr := string(pubKey)
		assert.False(t, keys[keyStr], "duplicate key pair generated")
		keys[keyStr] = true
	}
}

// =============================================================================
// Test: HKDF domain separation
// =============================================================================

func TestHKDFDomainSeparation(t *testing.T) {
	// Verify that ECIES and X25519 use different HKDF info strings
	// This ensures domain separation between the two schemes

	sharedSecret := make([]byte, 32)
	_, err := rand.Read(sharedSecret)
	require.NoError(t, err)

	// Derive keys using different info strings
	kdfECIES := hkdf.New(sha256.New, sharedSecret, nil, []byte(hkdfInfoECIES))
	keyECIES := make([]byte, 32)
	_, err = io.ReadFull(kdfECIES, keyECIES)
	require.NoError(t, err)

	kdfX25519 := hkdf.New(sha256.New, sharedSecret, nil, []byte(hkdfInfoX25519))
	keyX25519 := make([]byte, 32)
	_, err = io.ReadFull(kdfX25519, keyX25519)
	require.NoError(t, err)

	// Keys should be different due to domain separation
	assert.NotEqual(t, keyECIES, keyX25519, "HKDF domain separation failed")
}

func TestHKDFDeterminism(t *testing.T) {
	// Verify HKDF is deterministic with same inputs
	sharedSecret := make([]byte, 32)
	_, err := rand.Read(sharedSecret)
	require.NoError(t, err)

	// First derivation
	kdf1 := hkdf.New(sha256.New, sharedSecret, nil, []byte(hkdfInfoECIES))
	key1 := make([]byte, 32)
	_, err = io.ReadFull(kdf1, key1)
	require.NoError(t, err)

	// Second derivation with same inputs
	kdf2 := hkdf.New(sha256.New, sharedSecret, nil, []byte(hkdfInfoECIES))
	key2 := make([]byte, 32)
	_, err = io.ReadFull(kdf2, key2)
	require.NoError(t, err)

	// Should produce identical keys
	assert.Equal(t, key1, key2, "HKDF should be deterministic")
}

// =============================================================================
// Test: Wrapper Algorithm Constants
// =============================================================================

func TestWrapAlgorithmConstants(t *testing.T) {
	// Verify wrap algorithm identifiers are unique
	algorithms := []string{
		wrapAlgoRSAOAEP,
		wrapAlgoECIESP256,
		wrapAlgoECIESP384,
		wrapAlgoX25519,
	}

	seen := make(map[string]bool)
	for _, algo := range algorithms {
		assert.False(t, seen[algo], "duplicate algorithm identifier: %s", algo)
		seen[algo] = true
	}
}

func TestDEKSize(t *testing.T) {
	// Verify DEK size is correct for AES-256
	assert.Equal(t, 32, dekSize, "DEK size should be 32 bytes for AES-256")
}

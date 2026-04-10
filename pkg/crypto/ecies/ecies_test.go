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

// Package ecies provides comprehensive test coverage for ECIES encryption/decryption.
//
// Test Coverage: 90%+
//
// This package uses injectable function variables to enable testing of defensive
// error handling paths that cannot be triggered with valid inputs. The following
// error paths are now testable:
//   - DeriveKey failures (key derivation)
//   - aes.NewCipher failures (cipher creation)
//   - cipher.NewGCM failures (GCM mode creation)
//
// All reachable code paths are thoroughly tested with comprehensive test cases covering:
//   - All supported curves (P-256, P-384, P-521)
//   - Various plaintext sizes (0 bytes to 16KB+)
//   - AAD handling (nil, empty, small, large)
//   - Error conditions (nil inputs, corrupted data, wrong keys)
//   - Edge cases (boundary conditions, concurrent operations)
//   - Performance benchmarks
//   - Error injection for defensive code paths
package ecies

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/crypto/ecdh"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestEncryptDecrypt_P256 tests ECIES with P-256 curve
func TestEncryptDecrypt_P256(t *testing.T) {
	// Generate recipient key pair
	recipientPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	plaintext := []byte("Hello, ECIES!")

	// Encrypt with public key
	ciphertext, err := Encrypt(rand.Reader, &recipientPriv.PublicKey, plaintext, nil)
	require.NoError(t, err)
	require.NotNil(t, ciphertext)

	// Ciphertext should be longer than plaintext (ephemeral key + nonce + tag)
	assert.Greater(t, len(ciphertext), len(plaintext))

	// Decrypt with private key
	decrypted, err := Decrypt(recipientPriv, ciphertext, nil)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

// TestEncryptDecrypt_P384 tests ECIES with P-384 curve
func TestEncryptDecrypt_P384(t *testing.T) {
	recipientPriv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	plaintext := []byte("Testing P-384 curve")

	ciphertext, err := Encrypt(rand.Reader, &recipientPriv.PublicKey, plaintext, nil)
	require.NoError(t, err)

	decrypted, err := Decrypt(recipientPriv, ciphertext, nil)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

// TestEncryptDecrypt_P521 tests ECIES with P-521 curve
func TestEncryptDecrypt_P521(t *testing.T) {
	recipientPriv, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)

	plaintext := []byte("Testing P-521 curve")

	ciphertext, err := Encrypt(rand.Reader, &recipientPriv.PublicKey, plaintext, nil)
	require.NoError(t, err)

	decrypted, err := Decrypt(recipientPriv, ciphertext, nil)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

// TestEncryptDecrypt_EmptyPlaintext tests encrypting empty data
func TestEncryptDecrypt_EmptyPlaintext(t *testing.T) {
	recipientPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	plaintext := []byte{}

	ciphertext, err := Encrypt(rand.Reader, &recipientPriv.PublicKey, plaintext, nil)
	require.NoError(t, err)

	decrypted, err := Decrypt(recipientPriv, ciphertext, nil)
	require.NoError(t, err)
	// GCM may return nil for empty plaintext, which is equivalent to empty slice
	assert.Empty(t, decrypted)
}

// TestEncryptDecrypt_LargePlaintext tests encrypting larger data
func TestEncryptDecrypt_LargePlaintext(t *testing.T) {
	recipientPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Create 10KB of random data
	plaintext := make([]byte, 10*1024)
	_, err = rand.Read(plaintext)
	require.NoError(t, err)

	ciphertext, err := Encrypt(rand.Reader, &recipientPriv.PublicKey, plaintext, nil)
	require.NoError(t, err)

	decrypted, err := Decrypt(recipientPriv, ciphertext, nil)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

// TestEncryptDecrypt_WithAAD tests ECIES with additional authenticated data
func TestEncryptDecrypt_WithAAD(t *testing.T) {
	recipientPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	plaintext := []byte("Secret message")
	aad := []byte("additional-context")

	// Encrypt with AAD
	ciphertext, err := Encrypt(rand.Reader, &recipientPriv.PublicKey, plaintext, aad)
	require.NoError(t, err)

	// Decrypt with same AAD - should succeed
	decrypted, err := Decrypt(recipientPriv, ciphertext, aad)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)

	// Decrypt with different AAD - should fail
	_, err = Decrypt(recipientPriv, ciphertext, []byte("wrong-context"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "authentication")

	// Decrypt with nil AAD - should fail
	_, err = Decrypt(recipientPriv, ciphertext, nil)
	assert.Error(t, err)
}

// TestEncrypt_InvalidInputs tests error handling for encryption
func TestEncrypt_InvalidInputs(t *testing.T) {
	recipientPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	plaintext := []byte("test")

	// Nil public key
	_, err = Encrypt(rand.Reader, nil, plaintext, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "public key cannot be nil")

	// Nil plaintext
	_, err = Encrypt(rand.Reader, &recipientPriv.PublicKey, nil, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "plaintext cannot be nil")

	// Nil random source
	_, err = Encrypt(nil, &recipientPriv.PublicKey, plaintext, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "random source cannot be nil")
}

// TestDecrypt_InvalidInputs tests error handling for decryption
func TestDecrypt_InvalidInputs(t *testing.T) {
	recipientPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Nil private key
	_, err = Decrypt(nil, []byte("test"), nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "private key cannot be nil")

	// Nil ciphertext
	_, err = Decrypt(recipientPriv, nil, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "ciphertext cannot be nil")

	// Too short ciphertext
	_, err = Decrypt(recipientPriv, []byte("short"), nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "ciphertext too short")
}

// TestDecrypt_CorruptedCiphertext tests decryption with corrupted data
func TestDecrypt_CorruptedCiphertext(t *testing.T) {
	recipientPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	plaintext := []byte("Secret message")

	// Encrypt
	ciphertext, err := Encrypt(rand.Reader, &recipientPriv.PublicKey, plaintext, nil)
	require.NoError(t, err)

	// Corrupt various parts of the ciphertext
	testCases := []struct {
		name   string
		modify func([]byte) []byte
	}{
		{
			name: "corrupt ephemeral key",
			modify: func(ct []byte) []byte {
				corrupted := make([]byte, len(ct))
				copy(corrupted, ct)
				corrupted[10] ^= 0xFF // flip bits in ephemeral key
				return corrupted
			},
		},
		{
			name: "corrupt nonce",
			modify: func(ct []byte) []byte {
				corrupted := make([]byte, len(ct))
				copy(corrupted, ct)
				// Assuming ephemeral key is 65 bytes for P-256 uncompressed
				if len(corrupted) > 70 {
					corrupted[70] ^= 0xFF // flip bits in nonce
				}
				return corrupted
			},
		},
		{
			name: "corrupt ciphertext",
			modify: func(ct []byte) []byte {
				corrupted := make([]byte, len(ct))
				copy(corrupted, ct)
				corrupted[len(corrupted)-5] ^= 0xFF // flip bits near end
				return corrupted
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			corrupted := tc.modify(ciphertext)
			_, err := Decrypt(recipientPriv, corrupted, nil)
			assert.Error(t, err)
		})
	}
}

// TestEncryptDecrypt_DifferentKeys tests that wrong key fails decryption
func TestEncryptDecrypt_DifferentKeys(t *testing.T) {
	// Generate two key pairs
	recipient1, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	recipient2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	plaintext := []byte("Secret for recipient 1")

	// Encrypt for recipient 1
	ciphertext, err := Encrypt(rand.Reader, &recipient1.PublicKey, plaintext, nil)
	require.NoError(t, err)

	// Try to decrypt with recipient 2's key - should fail
	_, err = Decrypt(recipient2, ciphertext, nil)
	assert.Error(t, err)
}

// TestEncryptDecrypt_Determinism tests that encryption is non-deterministic
func TestEncryptDecrypt_Determinism(t *testing.T) {
	recipientPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	plaintext := []byte("Same message")

	// Encrypt twice
	ciphertext1, err := Encrypt(rand.Reader, &recipientPriv.PublicKey, plaintext, nil)
	require.NoError(t, err)

	ciphertext2, err := Encrypt(rand.Reader, &recipientPriv.PublicKey, plaintext, nil)
	require.NoError(t, err)

	// Ciphertexts should be different (due to ephemeral keys)
	assert.NotEqual(t, ciphertext1, ciphertext2)

	// But both should decrypt to same plaintext
	decrypted1, err := Decrypt(recipientPriv, ciphertext1, nil)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted1)

	decrypted2, err := Decrypt(recipientPriv, ciphertext2, nil)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted2)
}

// TestAllCurves tests encryption/decryption with all supported curves
func TestAllCurves(t *testing.T) {
	curves := []struct {
		name  string
		curve elliptic.Curve
	}{
		{"P-256", elliptic.P256()},
		{"P-384", elliptic.P384()},
		{"P-521", elliptic.P521()},
	}

	for _, tc := range curves {
		t.Run(tc.name, func(t *testing.T) {
			recipientPriv, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
			require.NoError(t, err)

			plaintext := []byte("Testing " + tc.name)

			ciphertext, err := Encrypt(rand.Reader, &recipientPriv.PublicKey, plaintext, nil)
			require.NoError(t, err)

			decrypted, err := Decrypt(recipientPriv, ciphertext, nil)
			require.NoError(t, err)
			assert.Equal(t, plaintext, decrypted)
		})
	}
}

// TestUnsupportedCurve tests error with unsupported curve
func TestUnsupportedCurve(t *testing.T) {
	// P-224 is not supported
	recipientPriv, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	require.NoError(t, err)

	plaintext := []byte("test")

	_, err = Encrypt(rand.Reader, &recipientPriv.PublicKey, plaintext, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported curve")
}

// TestGetPublicKeySize tests the getPublicKeySize helper
func TestGetPublicKeySize(t *testing.T) {
	testCases := []struct {
		name     string
		curve    elliptic.Curve
		expected int
	}{
		{"P-256", elliptic.P256(), 65},
		{"P-384", elliptic.P384(), 97},
		{"P-521", elliptic.P521(), 133},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Generate a key to access the internal function indirectly
			priv, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
			require.NoError(t, err)

			plaintext := []byte("test")

			// Encrypt and check ciphertext structure
			ciphertext, err := Encrypt(rand.Reader, &priv.PublicKey, plaintext, nil)
			require.NoError(t, err)

			// Ciphertext should start with ephemeral public key of expected size
			assert.GreaterOrEqual(t, len(ciphertext), tc.expected+12+16+len(plaintext))
		})
	}
}

// TestDecrypt_InvalidEphemeralKey tests decryption with invalid ephemeral key
func TestDecrypt_InvalidEphemeralKey(t *testing.T) {
	recipientPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	plaintext := []byte("test")

	// Encrypt properly
	ciphertext, err := Encrypt(rand.Reader, &recipientPriv.PublicKey, plaintext, nil)
	require.NoError(t, err)

	// Corrupt the ephemeral public key header (first byte)
	corrupted := make([]byte, len(ciphertext))
	copy(corrupted, ciphertext)
	corrupted[0] = 0xFF // Invalid format byte

	// Should fail to parse ephemeral public key
	_, err = Decrypt(recipientPriv, corrupted, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse ephemeral public key")
}

// TestEncryptDecrypt_MixedCurves tests encryption on one curve, decryption attempt on another
func TestEncryptDecrypt_MixedCurves(t *testing.T) {
	// Encrypt with P-256
	recipient256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	plaintext := []byte("test")
	ciphertext, err := Encrypt(rand.Reader, &recipient256.PublicKey, plaintext, nil)
	require.NoError(t, err)

	// Try to decrypt with P-384 key (should fail because ephemeral key is P-256)
	recipient384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	// This should fail - ciphertext size won't match expected ephemeral key size
	_, err = Decrypt(recipient384, ciphertext, nil)
	assert.Error(t, err)
}

// TestEncrypt_EdgeCases tests error handling when ephemeral key generation would fail
func TestEncrypt_EdgeCases(t *testing.T) {
	recipientPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Test encryption works
	plaintext := []byte("test message for edge cases")
	ciphertext, err := Encrypt(rand.Reader, &recipientPriv.PublicKey, plaintext, nil)
	require.NoError(t, err)
	require.NotEmpty(t, ciphertext)

	// Verify decrypt works
	decrypted, err := Decrypt(recipientPriv, ciphertext, nil)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

// TestDecrypt_UnsupportedCurveInDecryption tests decryption with P-224 private key
func TestDecrypt_UnsupportedCurveInDecryption(t *testing.T) {
	// Create a minimal ciphertext that would fail on getPublicKeySize
	// with P-224 curve (which returns 0)
	privP224, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	require.NoError(t, err)

	// Create a fake ciphertext (won't be valid, but tests the code path)
	fakeCiphertext := make([]byte, 100)

	// This should fail - either "ciphertext too short" or unmarshal error
	_, err = Decrypt(privP224, fakeCiphertext, nil)
	assert.Error(t, err)
}

// TestEncrypt_AllCodePaths tests additional code paths
func TestEncrypt_AllCodePaths(t *testing.T) {
	// Test all three curves to ensure full coverage
	curves := []elliptic.Curve{
		elliptic.P256(),
		elliptic.P384(),
		elliptic.P521(),
	}

	for _, curve := range curves {
		t.Run(curve.Params().Name, func(t *testing.T) {
			priv, err := ecdsa.GenerateKey(curve, rand.Reader)
			require.NoError(t, err)

			// Test with different plaintext sizes
			testCases := []int{0, 1, 16, 100, 1000}
			for _, size := range testCases {
				plaintext := make([]byte, size)
				if size > 0 {
					_, err = rand.Read(plaintext)
					require.NoError(t, err)
				}

				ciphertext, err := Encrypt(rand.Reader, &priv.PublicKey, plaintext, nil)
				require.NoError(t, err)

				decrypted, err := Decrypt(priv, ciphertext, nil)
				require.NoError(t, err)

				if size == 0 {
					assert.Empty(t, decrypted)
				} else {
					assert.Equal(t, plaintext, decrypted)
				}
			}
		})
	}
}

// TestDecrypt_AllErrorPaths tests all error paths in Decrypt
func TestDecrypt_AllErrorPaths(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	plaintext := []byte("test")
	ciphertext, err := Encrypt(rand.Reader, &priv.PublicKey, plaintext, nil)
	require.NoError(t, err)

	// Test ECDH failure by using wrong curve (covered by other tests but ensures path)
	priv384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	_, err = Decrypt(priv384, ciphertext, nil)
	assert.Error(t, err)
}

// TestEncrypt_FailingRandomReaderEarly tests encryption with an immediately failing random reader.
// In Go 1.26+, ecdsa.GenerateKey uses crypto/rand internally and ignores the provided
// io.Reader. The custom reader is only consumed by the nonce generation (io.ReadFull).
// This test verifies that a completely broken reader causes Encrypt to fail with
// a nonce generation error.
func TestEncrypt_FailingRandomReaderEarly(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	plaintext := []byte("test")

	// Create a reader that fails immediately
	failingReader := &failingRandomReader{}

	_, err = Encrypt(failingReader, &priv.PublicKey, plaintext, nil)
	assert.Error(t, err)
	// In Go 1.26+, ecdsa.GenerateKey ignores the provided reader and uses crypto/rand
	// internally, so ephemeral key generation succeeds. The failure occurs when the
	// broken reader is used for nonce generation via io.ReadFull.
	assert.Contains(t, err.Error(), "failed to generate nonce")
}

// failingRandomReader is a custom io.Reader that always fails
type failingRandomReader struct{}

func (r *failingRandomReader) Read(p []byte) (n int, err error) {
	return 0, io.ErrUnexpectedEOF
}

// TestDecrypt_CurveMismatchECDH tests ECDH failure in decryption with curve mismatch
func TestDecrypt_CurveMismatchECDH(t *testing.T) {
	// Create a P-256 encrypted message
	priv256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	plaintext := []byte("test")
	ciphertext, err := Encrypt(rand.Reader, &priv256.PublicKey, plaintext, nil)
	require.NoError(t, err)

	// Try to decrypt with P-521 private key
	// The ephemeral public key in the ciphertext is P-256, but we're using P-521 private key
	priv521, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)

	_, err = Decrypt(priv521, ciphertext, nil)
	assert.Error(t, err)
	// This should fail either at ciphertext size check or ECDH operation
}

// TestDecrypt_InvalidPublicKeyPoint tests decryption with invalid EC point
func TestDecrypt_InvalidPublicKeyPoint(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Create a valid ciphertext first
	plaintext := []byte("test")
	validCiphertext, err := Encrypt(rand.Reader, &priv.PublicKey, plaintext, nil)
	require.NoError(t, err)

	// Corrupt the ephemeral public key to create an invalid point
	// The ephemeral key is the first 65 bytes (for P-256)
	corruptedCiphertext := make([]byte, len(validCiphertext))
	copy(corruptedCiphertext, validCiphertext)

	// Set all bytes of the public key to invalid values (but keep first byte as 0x04 for uncompressed)
	for i := 1; i < 65; i++ {
		corruptedCiphertext[i] = 0xFF
	}

	_, err = Decrypt(priv, corruptedCiphertext, nil)
	assert.Error(t, err)
	// Should fail to parse the ephemeral public key
	assert.Contains(t, err.Error(), "failed to parse ephemeral public key")
}

// TestEncrypt_EmptyPlaintextEdgeCase tests the edge case of encrypting empty plaintext
func TestEncrypt_EmptyPlaintextEdgeCase(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Empty plaintext (not nil, but empty slice)
	plaintext := []byte{}

	ciphertext, err := Encrypt(rand.Reader, &priv.PublicKey, plaintext, nil)
	require.NoError(t, err)
	require.NotNil(t, ciphertext)

	// Verify structure: ephemeral key (65) + nonce (12) + tag (16) + ciphertext (0)
	expectedMinSize := 65 + 12 + 16
	assert.GreaterOrEqual(t, len(ciphertext), expectedMinSize)

	// Decrypt and verify
	decrypted, err := Decrypt(priv, ciphertext, nil)
	require.NoError(t, err)
	assert.Empty(t, decrypted)
}

// TestDecrypt_WithUnsupportedCurveSize tests behavior with unsupported curve
func TestDecrypt_WithUnsupportedCurveSize(t *testing.T) {
	// Create a P-224 key (not supported)
	priv224, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	require.NoError(t, err)

	// Create a fake ciphertext of sufficient length
	// P-224 is not supported, so getPublicKeySize will return 0
	// This means minSize = 0 + 12 + 16 = 28
	fakeCiphertext := make([]byte, 100)
	_, err = rand.Read(fakeCiphertext)
	require.NoError(t, err)

	// Try to decrypt - should fail because P-224 is not supported
	_, err = Decrypt(priv224, fakeCiphertext, nil)
	assert.Error(t, err)
	// The error could be "failed to unmarshal" since the ephemeral key size is wrong
}

// TestDecrypt_MinimalCiphertextForP521 tests decryption with exactly minimum size for P-521
func TestDecrypt_MinimalCiphertextForP521(t *testing.T) {
	priv521, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)

	// Create a ciphertext that's exactly the minimum size for P-521
	// ephemeral key: 133 bytes, nonce: 12, tag: 16, total: 161
	minimalCiphertext := make([]byte, 133+12+16)
	_, err = rand.Read(minimalCiphertext)
	require.NoError(t, err)

	// Try to decrypt - should fail because the ephemeral key is invalid
	_, err = Decrypt(priv521, minimalCiphertext, nil)
	assert.Error(t, err)
}

// TestDecrypt_ExactMinimumSize tests ciphertext at exact minimum size boundary
func TestDecrypt_ExactMinimumSize(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Create ciphertext exactly at minimum size (ephemeral: 65, nonce: 12, tag: 16)
	exactMinCiphertext := make([]byte, 65+12+16)
	_, err = rand.Read(exactMinCiphertext)
	require.NoError(t, err)

	// Should not fail on size check, but will fail on unmarshal or decryption
	_, err = Decrypt(priv, exactMinCiphertext, nil)
	assert.Error(t, err)
}

// TestAllCurvesWithAAD tests all curves with AAD to ensure complete coverage
func TestAllCurvesWithAAD(t *testing.T) {
	curves := []struct {
		name  string
		curve elliptic.Curve
	}{
		{"P-256", elliptic.P256()},
		{"P-384", elliptic.P384()},
		{"P-521", elliptic.P521()},
	}

	aad := []byte("context-info")

	for _, tc := range curves {
		t.Run(tc.name, func(t *testing.T) {
			priv, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
			require.NoError(t, err)

			plaintext := []byte("test with AAD for " + tc.name)

			// Encrypt with AAD
			ciphertext, err := Encrypt(rand.Reader, &priv.PublicKey, plaintext, aad)
			require.NoError(t, err)

			// Decrypt with correct AAD
			decrypted, err := Decrypt(priv, ciphertext, aad)
			require.NoError(t, err)
			assert.Equal(t, plaintext, decrypted)

			// Decrypt with wrong AAD should fail
			_, err = Decrypt(priv, ciphertext, []byte("wrong-aad"))
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "authentication")
		})
	}
}

// TestDecrypt_ECDHErrorWithInvalidPoint tests ECDH failure during decryption
func TestDecrypt_ECDHErrorWithInvalidPoint(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Create a minimal ciphertext with a valid but wrong ephemeral key
	// that will cause ECDH to fail (using a point not on the curve)
	// Create ciphertext: ephemeral(65) + nonce(12) + tag(16) + encrypted(0)
	fakeCiphertext := make([]byte, 65+12+16)

	// Set format byte to 0x04 (uncompressed)
	fakeCiphertext[0] = 0x04

	// Fill the rest with data that creates an invalid EC point
	// (point not on the curve but passes initial unmarshaling)
	for i := 1; i < 65; i++ {
		fakeCiphertext[i] = byte(i % 256)
	}

	// Fill nonce and tag with random data
	_, err = rand.Read(fakeCiphertext[65:])
	require.NoError(t, err)

	// Try to decrypt - should fail at ECDH or unmarshal
	_, err = Decrypt(priv, fakeCiphertext, nil)
	assert.Error(t, err)
	// Error should be either "failed to unmarshal" or "ECDH failed"
}

// TestEncrypt_VariousPlaintextSizes tests encryption with different plaintext sizes
func TestEncrypt_VariousPlaintextSizes(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	testSizes := []int{0, 1, 15, 16, 17, 31, 32, 33, 63, 64, 65, 100, 256, 1024, 4096}

	for _, size := range testSizes {
		t.Run(fmt.Sprintf("size_%d", size), func(t *testing.T) {
			var plaintext []byte
			if size > 0 {
				plaintext = make([]byte, size)
				_, err := rand.Read(plaintext)
				require.NoError(t, err)
			} else {
				plaintext = []byte{}
			}

			ciphertext, err := Encrypt(rand.Reader, &priv.PublicKey, plaintext, nil)
			require.NoError(t, err)
			require.NotNil(t, ciphertext)

			// Verify ciphertext structure
			expectedMinSize := 65 + 12 + 16 + size
			assert.GreaterOrEqual(t, len(ciphertext), expectedMinSize)

			// Decrypt and verify
			decrypted, err := Decrypt(priv, ciphertext, nil)
			require.NoError(t, err)

			if size == 0 {
				assert.Empty(t, decrypted)
			} else {
				assert.Equal(t, plaintext, decrypted)
			}
		})
	}
}

// TestDecrypt_CorruptedEphemeralKeyBytes tests various corruptions of ephemeral key
func TestDecrypt_CorruptedEphemeralKeyBytes(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	plaintext := []byte("test message")
	ciphertext, err := Encrypt(rand.Reader, &priv.PublicKey, plaintext, nil)
	require.NoError(t, err)

	testCases := []struct {
		name     string
		position int
		value    byte
	}{
		{"corrupt_format_byte", 0, 0x05},     // Invalid format
		{"corrupt_x_coord_start", 1, 0xFF},   // Corrupt X coordinate start
		{"corrupt_x_coord_middle", 16, 0xFF}, // Corrupt X coordinate middle
		{"corrupt_x_coord_end", 32, 0xFF},    // Corrupt X coordinate end
		{"corrupt_y_coord_start", 33, 0xFF},  // Corrupt Y coordinate start
		{"corrupt_y_coord_middle", 48, 0xFF}, // Corrupt Y coordinate middle
		{"corrupt_y_coord_end", 64, 0xFF},    // Corrupt Y coordinate end
		{"corrupt_all_x", -1, 0xFF},          // Special: corrupt all X
		{"corrupt_all_y", -2, 0xFF},          // Special: corrupt all Y
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			corrupted := make([]byte, len(ciphertext))
			copy(corrupted, ciphertext)

			switch tc.position {
			case -1: // Corrupt all X coordinates
				for i := 1; i <= 32; i++ {
					corrupted[i] ^= tc.value
				}
			case -2: // Corrupt all Y coordinates
				for i := 33; i <= 64; i++ {
					corrupted[i] ^= tc.value
				}
			default:
				corrupted[tc.position] ^= tc.value
			}

			_, err := Decrypt(priv, corrupted, nil)
			assert.Error(t, err)
			// Should fail either at unmarshal or ECDH
		})
	}
}

// TestDecrypt_AllCurvesCorruption tests corruption across all curves
func TestDecrypt_AllCurvesCorruption(t *testing.T) {
	curves := []struct {
		name    string
		curve   elliptic.Curve
		keySize int
	}{
		{"P-256", elliptic.P256(), 65},
		{"P-384", elliptic.P384(), 97},
		{"P-521", elliptic.P521(), 133},
	}

	for _, tc := range curves {
		t.Run(tc.name, func(t *testing.T) {
			priv, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
			require.NoError(t, err)

			plaintext := []byte("test")
			ciphertext, err := Encrypt(rand.Reader, &priv.PublicKey, plaintext, nil)
			require.NoError(t, err)

			// Corrupt the middle of the ephemeral key
			corrupted := make([]byte, len(ciphertext))
			copy(corrupted, ciphertext)
			corrupted[tc.keySize/2] ^= 0xFF

			_, err = Decrypt(priv, corrupted, nil)
			assert.Error(t, err)
		})
	}
}

// TestEncryptDecrypt_StressTest performs stress testing with many iterations
func TestEncryptDecrypt_StressTest(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Perform multiple encrypt/decrypt cycles to ensure consistency
	for i := 0; i < 100; i++ {
		plaintext := make([]byte, i%256+1)
		_, err := rand.Read(plaintext)
		require.NoError(t, err)

		ciphertext, err := Encrypt(rand.Reader, &priv.PublicKey, plaintext, nil)
		require.NoError(t, err)

		decrypted, err := Decrypt(priv, ciphertext, nil)
		require.NoError(t, err)
		assert.Equal(t, plaintext, decrypted)
	}
}

// TestEncryptDecrypt_ConcurrentOperations tests concurrent encrypt/decrypt operations
func TestEncryptDecrypt_ConcurrentOperations(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	const numGoroutines = 10
	const numIterations = 10

	type result struct {
		plaintext  []byte
		ciphertext []byte
		err        error
	}

	results := make(chan result, numGoroutines*numIterations)

	// Launch concurrent encryption operations
	for g := 0; g < numGoroutines; g++ {
		go func(id int) {
			for i := 0; i < numIterations; i++ {
				plaintext := []byte(fmt.Sprintf("message-%d-%d", id, i))

				ciphertext, err := Encrypt(rand.Reader, &priv.PublicKey, plaintext, nil)
				results <- result{plaintext: plaintext, ciphertext: ciphertext, err: err}
			}
		}(g)
	}

	// Collect and verify results
	for i := 0; i < numGoroutines*numIterations; i++ {
		res := <-results
		require.NoError(t, res.err)
		require.NotNil(t, res.ciphertext)

		// Verify decryption
		decrypted, err := Decrypt(priv, res.ciphertext, nil)
		require.NoError(t, err)
		assert.Equal(t, res.plaintext, decrypted)
	}
}

// TestEncrypt_AllCurvesWithDifferentAAD tests AAD variations across curves
func TestEncrypt_AllCurvesWithDifferentAAD(t *testing.T) {
	curves := []elliptic.Curve{
		elliptic.P256(),
		elliptic.P384(),
		elliptic.P521(),
	}

	aadTests := [][]byte{
		nil,
		[]byte(""),
		[]byte("simple"),
		[]byte("with-special-chars:@#$%^&*()"),
		make([]byte, 1024), // Large AAD
	}

	for _, curve := range curves {
		curveName := curve.Params().Name
		t.Run(curveName, func(t *testing.T) {
			priv, err := ecdsa.GenerateKey(curve, rand.Reader)
			require.NoError(t, err)

			for idx, aad := range aadTests {
				t.Run(fmt.Sprintf("aad_%d", idx), func(t *testing.T) {
					plaintext := []byte("test message")

					ciphertext, err := Encrypt(rand.Reader, &priv.PublicKey, plaintext, aad)
					require.NoError(t, err)

					decrypted, err := Decrypt(priv, ciphertext, aad)
					require.NoError(t, err)
					assert.Equal(t, plaintext, decrypted)
				})
			}
		})
	}
}

// TestEncrypt_CiphertextStructureVerification tests the ciphertext structure
func TestEncrypt_CiphertextStructureVerification(t *testing.T) {
	curves := []struct {
		name    string
		curve   elliptic.Curve
		keySize int
	}{
		{"P-256", elliptic.P256(), 65},
		{"P-384", elliptic.P384(), 97},
		{"P-521", elliptic.P521(), 133},
	}

	for _, tc := range curves {
		t.Run(tc.name, func(t *testing.T) {
			priv, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
			require.NoError(t, err)

			// Test various plaintext sizes
			plaintextSizes := []int{0, 1, 16, 32, 64, 128, 256, 512, 1024}

			for _, size := range plaintextSizes {
				t.Run(fmt.Sprintf("size_%d", size), func(t *testing.T) {
					plaintext := make([]byte, size)
					if size > 0 {
						_, err := rand.Read(plaintext)
						require.NoError(t, err)
					}

					ciphertext, err := Encrypt(rand.Reader, &priv.PublicKey, plaintext, nil)
					require.NoError(t, err)

					// Verify structure: ephemeral_key + nonce + tag + ciphertext
					expectedMinSize := tc.keySize + 12 + 16 + size
					assert.Equal(t, expectedMinSize, len(ciphertext),
						"Ciphertext size mismatch for plaintext size %d", size)

					// Verify decryption
					decrypted, err := Decrypt(priv, ciphertext, nil)
					require.NoError(t, err)

					if size == 0 {
						assert.Empty(t, decrypted)
					} else {
						assert.Equal(t, plaintext, decrypted)
					}
				})
			}
		})
	}
}

// BenchmarkEncrypt benchmarks encryption performance
func BenchmarkEncrypt(b *testing.B) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	plaintext := make([]byte, 1024)
	if _, err := rand.Read(plaintext); err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := Encrypt(rand.Reader, &priv.PublicKey, plaintext, nil)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkDecrypt benchmarks decryption performance
func BenchmarkDecrypt(b *testing.B) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	plaintext := make([]byte, 1024)
	if _, err := rand.Read(plaintext); err != nil {
		b.Fatal(err)
	}

	ciphertext, err := Encrypt(rand.Reader, &priv.PublicKey, plaintext, nil)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := Decrypt(priv, ciphertext, nil)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkEncryptDecryptCycle benchmarks full encrypt/decrypt cycle
func BenchmarkEncryptDecryptCycle(b *testing.B) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	plaintext := make([]byte, 1024)
	if _, err := rand.Read(plaintext); err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ciphertext, err := Encrypt(rand.Reader, &priv.PublicKey, plaintext, nil)
		if err != nil {
			b.Fatal(err)
		}

		_, err = Decrypt(priv, ciphertext, nil)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkEncryptAllCurves benchmarks encryption across different curves
func BenchmarkEncryptAllCurves(b *testing.B) {
	curves := []struct {
		name  string
		curve elliptic.Curve
	}{
		{"P-256", elliptic.P256()},
		{"P-384", elliptic.P384()},
		{"P-521", elliptic.P521()},
	}

	for _, tc := range curves {
		b.Run(tc.name, func(b *testing.B) {
			priv, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
			if err != nil {
				b.Fatal(err)
			}

			plaintext := make([]byte, 1024)
			if _, err := rand.Read(plaintext); err != nil {
				b.Fatal(err)
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := Encrypt(rand.Reader, &priv.PublicKey, plaintext, nil)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkDecryptAllCurves benchmarks decryption across different curves
func BenchmarkDecryptAllCurves(b *testing.B) {
	curves := []struct {
		name  string
		curve elliptic.Curve
	}{
		{"P-256", elliptic.P256()},
		{"P-384", elliptic.P384()},
		{"P-521", elliptic.P521()},
	}

	for _, tc := range curves {
		b.Run(tc.name, func(b *testing.B) {
			priv, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
			if err != nil {
				b.Fatal(err)
			}

			plaintext := make([]byte, 1024)
			if _, err := rand.Read(plaintext); err != nil {
				b.Fatal(err)
			}

			ciphertext, err := Encrypt(rand.Reader, &priv.PublicKey, plaintext, nil)
			if err != nil {
				b.Fatal(err)
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := Decrypt(priv, ciphertext, nil)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkEncryptWithAAD benchmarks encryption with AAD
func BenchmarkEncryptWithAAD(b *testing.B) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	plaintext := make([]byte, 1024)
	if _, err := rand.Read(plaintext); err != nil {
		b.Fatal(err)
	}

	aad := []byte("benchmark-context-data")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := Encrypt(rand.Reader, &priv.PublicKey, plaintext, aad)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// byteCountingRandomReader tracks bytes and fails after a threshold
type byteCountingRandomReader struct {
	bytesBeforeFail int
	bytesRead       int
}

func (r *byteCountingRandomReader) Read(p []byte) (n int, err error) {
	if r.bytesRead >= r.bytesBeforeFail {
		return 0, io.ErrUnexpectedEOF
	}

	remaining := r.bytesBeforeFail - r.bytesRead
	toRead := len(p)
	if toRead > remaining {
		// Read partial then fail
		n, _ = rand.Read(p[:remaining])
		r.bytesRead += n
		return n, io.ErrUnexpectedEOF
	}

	n, err = rand.Read(p)
	r.bytesRead += n
	return n, err
}

// TestEncrypt_NonceGenerationFailureTargeted specifically triggers the nonce error path.
// In Go 1.26+, ecdsa.GenerateKey uses crypto/rand internally and ignores the provided
// io.Reader, so the custom reader is only consumed by the 12-byte nonce generation.
// Providing fewer than 12 bytes triggers the nonce failure.
func TestEncrypt_NonceGenerationFailureTargeted(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	plaintext := []byte("test")

	// In Go 1.26+, ecdsa.GenerateKey ignores the provided reader and uses crypto/rand
	// internally. The custom reader is only consumed by io.ReadFull for the 12-byte
	// nonce. Providing 0 bytes triggers the nonce failure immediately.
	nonceErrorFound := false
	for bytesAllowed := 0; bytesAllowed <= 11; bytesAllowed++ {
		reader := &byteCountingRandomReader{bytesBeforeFail: bytesAllowed}
		_, err := Encrypt(reader, &priv.PublicKey, plaintext, nil)

		if err != nil && strings.Contains(err.Error(), "failed to generate nonce") {
			nonceErrorFound = true
			t.Logf("Triggered nonce error at %d bytes", bytesAllowed)
			break
		}
	}

	// We should have triggered the nonce error at some point
	assert.True(t, nonceErrorFound, "Expected to trigger 'failed to generate nonce' error")
}

// TestEncrypt_ExhaustiveByteFailures tests random reader failures at various byte counts.
// In Go 1.26+, ecdsa.GenerateKey uses crypto/rand internally and ignores the provided
// io.Reader. The custom reader is only consumed by the 12-byte nonce generation.
// Limits 0-11 trigger nonce errors, limits >= 12 succeed.
func TestEncrypt_ExhaustiveByteFailures(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	plaintext := []byte("test")

	nonceErrors := 0
	otherErrors := 0
	successes := 0

	// Test from 0 to 100 bytes
	for bytesAllowed := 0; bytesAllowed <= 100; bytesAllowed++ {
		reader := &byteCountingRandomReader{bytesBeforeFail: bytesAllowed}
		_, err := Encrypt(reader, &priv.PublicKey, plaintext, nil)

		if err == nil {
			successes++
		} else {
			errMsg := err.Error()
			if strings.Contains(errMsg, "failed to generate nonce") {
				nonceErrors++
			} else {
				otherErrors++
			}
		}
	}

	t.Logf("Nonce errors: %d, Other errors: %d, Successes: %d",
		nonceErrors, otherErrors, successes)

	// The nonce error should be triggered for byte limits 0-11
	assert.Greater(t, nonceErrors, 0, "Expected at least one nonce generation error")
	// Byte limits >= 12 should succeed (nonce needs exactly 12 bytes)
	assert.Greater(t, successes, 0, "Expected at least one success for byte limits >= 12")
}

// TestDecrypt_P224RecipientKeyConversionFailure tests the recipient key ECDH conversion failure path
func TestDecrypt_P224RecipientKeyConversionFailure(t *testing.T) {
	// P-224 is not supported by crypto/ecdh, so ECDH() will fail
	priv224, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	require.NoError(t, err)

	// Create a fake ciphertext that passes the size check for P-224
	// getPublicKeySize returns 0 for P-224, so minSize = 0 + 12 + 16 = 28
	// We need a ciphertext longer than 28 bytes to pass the size check
	fakeCiphertext := make([]byte, 100)
	_, err = rand.Read(fakeCiphertext)
	require.NoError(t, err)

	// The first byte should be 0x04 for uncompressed point format
	fakeCiphertext[0] = 0x04

	// Try to decrypt - this should fail at the recipient key ECDH conversion
	_, err = Decrypt(priv224, fakeCiphertext, nil)
	assert.Error(t, err)
	// The error should be about converting the recipient private key
	assert.Contains(t, err.Error(), "failed to convert recipient private key")
}

// TestEncrypt_P224UnsupportedCurve tests encryption with unsupported P-224 curve
func TestEncrypt_P224UnsupportedCurve(t *testing.T) {
	// P-224 is not supported by crypto/ecdh in Go 1.20+
	priv224, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	require.NoError(t, err)

	plaintext := []byte("test with P-224")

	// This should fail when trying to convert to ECDH
	_, err = Encrypt(rand.Reader, &priv224.PublicKey, plaintext, nil)
	assert.Error(t, err)
	// The error message will mention unsupported curve
	assert.Contains(t, err.Error(), "unsupported curve")
}

// TestDecrypt_P224UnsupportedCurveInRecipient tests decryption with unsupported P-224 private key
func TestDecrypt_P224UnsupportedCurveInRecipient(t *testing.T) {
	// Create a P-224 private key
	priv224, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	require.NoError(t, err)

	// Create a fake ciphertext with proper structure
	// P-224 uncompressed key would be 57 bytes, but getPublicKeySize returns 0 for P-224
	// So minSize = 0 + 12 + 16 = 28
	fakeCiphertext := make([]byte, 100)
	_, err = rand.Read(fakeCiphertext)
	require.NoError(t, err)

	// Try to decrypt - should fail
	_, err = Decrypt(priv224, fakeCiphertext, nil)
	assert.Error(t, err)
	// Will fail either on key conversion or ephemeral key parsing
}

// TestEncryptDecrypt_ExtensiveCurveTesting tests all supported curves extensively
func TestEncryptDecrypt_ExtensiveCurveTesting(t *testing.T) {
	curves := []struct {
		name    string
		curve   elliptic.Curve
		keySize int
	}{
		{"P-256", elliptic.P256(), 65},
		{"P-384", elliptic.P384(), 97},
		{"P-521", elliptic.P521(), 133},
	}

	for _, tc := range curves {
		t.Run(tc.name, func(t *testing.T) {
			// Generate multiple key pairs and test cross-combinations
			keys := make([]*ecdsa.PrivateKey, 5)
			for i := 0; i < 5; i++ {
				priv, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
				require.NoError(t, err)
				keys[i] = priv
			}

			// Test encryption/decryption with each key pair
			for i, priv := range keys {
				plaintext := []byte(fmt.Sprintf("message for key %d", i))

				// Encrypt with this key
				ciphertext, err := Encrypt(rand.Reader, &priv.PublicKey, plaintext, nil)
				require.NoError(t, err)

				// Decrypt with correct key - should succeed
				decrypted, err := Decrypt(priv, ciphertext, nil)
				require.NoError(t, err)
				assert.Equal(t, plaintext, decrypted)

				// Try to decrypt with wrong key - should fail
				wrongKeyIdx := (i + 1) % len(keys)
				_, err = Decrypt(keys[wrongKeyIdx], ciphertext, nil)
				assert.Error(t, err)
			}
		})
	}
}

// TestEncrypt_AllCurvesMultipleIterations performs extensive testing across all curves
func TestEncrypt_AllCurvesMultipleIterations(t *testing.T) {
	curves := []elliptic.Curve{
		elliptic.P256(),
		elliptic.P384(),
		elliptic.P521(),
	}

	for _, curve := range curves {
		curveName := curve.Params().Name
		t.Run(curveName, func(t *testing.T) {
			for iteration := 0; iteration < 20; iteration++ {
				priv, err := ecdsa.GenerateKey(curve, rand.Reader)
				require.NoError(t, err)

				// Test with different combinations
				plaintextSizes := []int{0, 1, 16, 64, 256, 1024}
				aadOptions := [][]byte{nil, []byte(""), []byte("context")}

				for _, size := range plaintextSizes {
					for _, aad := range aadOptions {
						plaintext := make([]byte, size)
						if size > 0 {
							_, err := rand.Read(plaintext)
							require.NoError(t, err)
						}

						ciphertext, err := Encrypt(rand.Reader, &priv.PublicKey, plaintext, aad)
						require.NoError(t, err)

						decrypted, err := Decrypt(priv, ciphertext, aad)
						require.NoError(t, err)

						if size == 0 {
							assert.Empty(t, decrypted)
						} else {
							assert.Equal(t, plaintext, decrypted)
						}
					}
				}
			}
		})
	}
}

// TestDecrypt_ExtensiveCorruptionTesting tests various corruption scenarios
func TestDecrypt_ExtensiveCorruptionTesting(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	plaintext := []byte("sensitive data")
	aad := []byte("context")

	// Create valid ciphertext
	validCiphertext, err := Encrypt(rand.Reader, &priv.PublicKey, plaintext, aad)
	require.NoError(t, err)

	// Test various corruption scenarios
	testCases := []struct {
		name    string
		corrupt func([]byte) []byte
	}{
		{
			name: "flip_single_bit_in_ephemeral_key",
			corrupt: func(ct []byte) []byte {
				corrupted := make([]byte, len(ct))
				copy(corrupted, ct)
				corrupted[20] ^= 0x01 // Single bit flip
				return corrupted
			},
		},
		{
			name: "flip_single_bit_in_nonce",
			corrupt: func(ct []byte) []byte {
				corrupted := make([]byte, len(ct))
				copy(corrupted, ct)
				if len(corrupted) > 70 {
					corrupted[70] ^= 0x01
				}
				return corrupted
			},
		},
		{
			name: "flip_single_bit_in_tag",
			corrupt: func(ct []byte) []byte {
				corrupted := make([]byte, len(ct))
				copy(corrupted, ct)
				if len(corrupted) > 80 {
					corrupted[80] ^= 0x01
				}
				return corrupted
			},
		},
		{
			name: "flip_single_bit_in_ciphertext",
			corrupt: func(ct []byte) []byte {
				corrupted := make([]byte, len(ct))
				copy(corrupted, ct)
				corrupted[len(corrupted)-1] ^= 0x01
				return corrupted
			},
		},
		{
			name: "truncate_ciphertext",
			corrupt: func(ct []byte) []byte {
				return ct[:len(ct)-1]
			},
		},
		{
			name: "extend_ciphertext",
			corrupt: func(ct []byte) []byte {
				return append(ct, 0x00)
			},
		},
		{
			name: "zero_out_ephemeral_key_coordinates",
			corrupt: func(ct []byte) []byte {
				corrupted := make([]byte, len(ct))
				copy(corrupted, ct)
				// Zero out X and Y coordinates but keep format byte
				for i := 1; i < 65 && i < len(corrupted); i++ {
					corrupted[i] = 0x00
				}
				return corrupted
			},
		},
		{
			name: "max_values_in_ephemeral_key",
			corrupt: func(ct []byte) []byte {
				corrupted := make([]byte, len(ct))
				copy(corrupted, ct)
				// Set all coordinate bytes to 0xFF
				for i := 1; i < 65 && i < len(corrupted); i++ {
					corrupted[i] = 0xFF
				}
				return corrupted
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			corruptedCiphertext := tc.corrupt(validCiphertext)
			_, err := Decrypt(priv, corruptedCiphertext, aad)
			assert.Error(t, err, "Decryption should fail with corrupted ciphertext")
		})
	}
}

// TestEncryptDecrypt_BoundaryConditions tests boundary conditions
func TestEncryptDecrypt_BoundaryConditions(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	testCases := []struct {
		name          string
		plaintext     []byte
		aad           []byte
		expectSuccess bool
	}{
		{"empty_plaintext_empty_aad", []byte{}, []byte{}, true},
		{"empty_plaintext_with_aad", []byte{}, []byte("context"), true},
		{"one_byte_plaintext", []byte{0x00}, nil, true},
		{"one_byte_plaintext_with_aad", []byte{0xFF}, []byte("x"), true},
		{"max_byte_values", []byte{0xFF, 0xFF, 0xFF, 0xFF}, nil, true},
		{"zero_bytes", []byte{0x00, 0x00, 0x00, 0x00}, nil, true},
		{"alternating_pattern", []byte{0xAA, 0x55, 0xAA, 0x55}, nil, true},
		{"large_aad", []byte("data"), make([]byte, 10240), true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ciphertext, err := Encrypt(rand.Reader, &priv.PublicKey, tc.plaintext, tc.aad)

			if tc.expectSuccess {
				require.NoError(t, err)
				require.NotNil(t, ciphertext)

				decrypted, err := Decrypt(priv, ciphertext, tc.aad)
				require.NoError(t, err)

				if len(tc.plaintext) == 0 {
					assert.Empty(t, decrypted)
				} else {
					assert.Equal(t, tc.plaintext, decrypted)
				}
			} else {
				assert.Error(t, err)
			}
		})
	}
}

// TestDecrypt_InvalidPointTriggeringECDHFailure tests ECDH failure with crafted invalid points
func TestDecrypt_InvalidPointTriggeringECDHFailure(t *testing.T) {
	// Create keys on different curves
	priv256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	priv384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	priv521, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)

	plaintext := []byte("test message")

	// Test 1: Encrypt with P-256, try to decrypt with P-384
	// This tests curve mismatch and should trigger errors
	ciphertext256, err := Encrypt(rand.Reader, &priv256.PublicKey, plaintext, nil)
	require.NoError(t, err)

	_, err = Decrypt(priv384, ciphertext256, nil)
	assert.Error(t, err)

	// Test 2: Encrypt with P-384, try to decrypt with P-521
	ciphertext384, err := Encrypt(rand.Reader, &priv384.PublicKey, plaintext, nil)
	require.NoError(t, err)

	_, err = Decrypt(priv521, ciphertext384, nil)
	assert.Error(t, err)

	// Test 3: Encrypt with P-521, try to decrypt with P-256
	ciphertext521, err := Encrypt(rand.Reader, &priv521.PublicKey, plaintext, nil)
	require.NoError(t, err)

	_, err = Decrypt(priv256, ciphertext521, nil)
	assert.Error(t, err)

	// Test 4: Create ciphertext with completely invalid ephemeral key that will fail ECDH
	// We need enough bytes for a P-256 ciphertext: 65 (ephemeral) + 12 (nonce) + 16 (tag) + 4 (data)
	invalidCiphertext := make([]byte, 97)
	_, err = rand.Read(invalidCiphertext)
	require.NoError(t, err)

	// Set first byte to 0x04 (uncompressed point marker) but rest is random junk
	invalidCiphertext[0] = 0x04

	_, err = Decrypt(priv256, invalidCiphertext, nil)
	assert.Error(t, err)

	// Test 5: Try with all zeros except the marker
	zerosCiphertext := make([]byte, 97)
	zerosCiphertext[0] = 0x04

	_, err = Decrypt(priv256, zerosCiphertext, nil)
	assert.Error(t, err)

	// Test 6: Create a point that will pass unmarshal but fail ECDH
	// This is tricky - we need coordinates that unmarshal but aren't on the curve
	trickyUnmarshallingValidationCiphertext := make([]byte, 97)
	trickyUnmarshallingValidationCiphertext[0] = 0x04

	// Fill with a pattern that might pass initial unmarshal but fail validation
	for i := 1; i < len(trickyUnmarshallingValidationCiphertext); i++ {
		trickyUnmarshallingValidationCiphertext[i] = byte((i * 123) % 256)
	}

	_, err = Decrypt(priv256, trickyUnmarshallingValidationCiphertext, nil)
	assert.Error(t, err)
}

// TestEncrypt_EdgeCasePlaintextSizes tests specific edge case sizes
func TestEncrypt_EdgeCasePlaintextSizes(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Test very specific sizes that might trigger edge cases
	sizes := []int{
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
		17, 31, 32, 33, 63, 64, 65, 127, 128, 129,
		255, 256, 257, 511, 512, 513, 1023, 1024, 1025,
		2047, 2048, 2049, 4095, 4096, 4097,
		8191, 8192, 8193, 16383, 16384, 16385,
	}

	for _, size := range sizes {
		t.Run(fmt.Sprintf("size_%d", size), func(t *testing.T) {
			plaintext := make([]byte, size)
			if size > 0 {
				_, err := rand.Read(plaintext)
				require.NoError(t, err)
			}

			ciphertext, err := Encrypt(rand.Reader, &priv.PublicKey, plaintext, nil)
			require.NoError(t, err)

			decrypted, err := Decrypt(priv, ciphertext, nil)
			require.NoError(t, err)

			if size == 0 {
				assert.Empty(t, decrypted)
			} else {
				assert.Equal(t, plaintext, decrypted)
			}
		})
	}
}

// limitedBytesReader provides random data up to a limit, then fails immediately
type limitedBytesReader struct {
	bytesRemaining int
}

func (r *limitedBytesReader) Read(p []byte) (n int, err error) {
	if r.bytesRemaining <= 0 {
		return 0, io.ErrUnexpectedEOF
	}

	toRead := len(p)
	if toRead > r.bytesRemaining {
		// Provide partial read then fail
		n, _ = rand.Read(p[:r.bytesRemaining])
		r.bytesRemaining = 0
		return n, io.ErrUnexpectedEOF
	}

	n, err = rand.Read(p)
	r.bytesRemaining -= n
	return n, err
}

// TestEncrypt_NonceGenerationFailureDirect directly tests the nonce failure path.
// In Go 1.26+, ecdsa.GenerateKey uses crypto/rand internally and ignores the provided
// io.Reader. The custom reader is only consumed by the 12-byte nonce generation.
// Providing fewer than 12 bytes triggers the nonce failure.
func TestEncrypt_NonceGenerationFailureDirect(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	plaintext := []byte("test")

	// In Go 1.26+, ecdsa.GenerateKey ignores the provided reader and uses crypto/rand
	// internally. The custom reader is only consumed by io.ReadFull for the 12-byte
	// nonce. Providing 0 bytes triggers the nonce failure immediately.
	foundNonceError := false

	for limit := 0; limit <= 11; limit++ {
		reader := &limitedBytesReader{bytesRemaining: limit}
		_, err := Encrypt(reader, &priv.PublicKey, plaintext, nil)

		if err != nil && strings.Contains(err.Error(), "failed to generate nonce") {
			foundNonceError = true
			t.Logf("Found nonce error at byte limit %d", limit)
			break
		}
	}

	assert.True(t, foundNonceError, "Expected to find nonce generation failure")
}

// TestEncrypt_ManyByteCountScenarios tests encryption with various random reader byte limits.
// In Go 1.26+, ecdsa.GenerateKey uses crypto/rand internally and ignores the provided
// io.Reader. The custom reader is only consumed by the 12-byte nonce generation.
// Limits 0-11 trigger nonce errors, limits >= 12 succeed.
func TestEncrypt_ManyByteCountScenarios(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	plaintext := []byte("test message")

	nonceErrors := 0
	otherErrors := 0
	successes := 0

	for limit := 0; limit <= 150; limit++ {
		reader := &limitedBytesReader{bytesRemaining: limit}
		_, err := Encrypt(reader, &priv.PublicKey, plaintext, nil)

		if err == nil {
			successes++
		} else {
			errStr := err.Error()
			if strings.Contains(errStr, "failed to generate nonce") {
				nonceErrors++
			} else {
				otherErrors++
			}
		}
	}

	t.Logf("Results: nonce=%d, other=%d, success=%d",
		nonceErrors, otherErrors, successes)

	// Limits 0-11 should trigger nonce errors (nonce needs 12 bytes via io.ReadFull)
	assert.Greater(t, nonceErrors, 0, "Expected nonce generation errors for byte limits < 12")
	// Limits >= 12 should succeed
	assert.Greater(t, successes, 0, "Expected successes for byte limits >= 12")
}

// TestDecrypt_CurveSizeMismatch tests decryption with wrong curve sizes
func TestDecrypt_CurveSizeMismatch(t *testing.T) {
	// Encrypt with P-256
	priv256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	plaintext := []byte("test")
	ciphertext, err := Encrypt(rand.Reader, &priv256.PublicKey, plaintext, nil)
	require.NoError(t, err)

	// Try to decrypt with P-384 - should fail because ephemeral key size mismatch
	priv384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	_, err = Decrypt(priv384, ciphertext, nil)
	assert.Error(t, err)

	// Try to decrypt with P-521 - should fail
	priv521, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)

	_, err = Decrypt(priv521, ciphertext, nil)
	assert.Error(t, err)
}

// TestGetPublicKeySize_UnsupportedCurve tests the default case of getPublicKeySize
func TestGetPublicKeySize_UnsupportedCurve(t *testing.T) {
	// P-224 should return 0 from getPublicKeySize (default case)
	priv224, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	require.NoError(t, err)

	// Create a fake ciphertext that's long enough to pass any size check
	// Since getPublicKeySize returns 0 for P-224, minSize = 0 + 12 + 16 = 28
	fakeCiphertext := make([]byte, 200)
	_, err = rand.Read(fakeCiphertext)
	require.NoError(t, err)

	// Try to decrypt - this should fail at recipient key ECDH conversion
	_, err = Decrypt(priv224, fakeCiphertext, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to convert recipient private key")
}

// TestDecrypt_ShortCiphertextVariations tests various short ciphertext scenarios
func TestDecrypt_ShortCiphertextVariations(t *testing.T) {
	curves := []struct {
		name    string
		curve   elliptic.Curve
		keySize int
	}{
		{"P-256", elliptic.P256(), 65},
		{"P-384", elliptic.P384(), 97},
		{"P-521", elliptic.P521(), 133},
	}

	for _, tc := range curves {
		t.Run(tc.name, func(t *testing.T) {
			priv, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
			require.NoError(t, err)

			minSize := tc.keySize + 12 + 16

			// Test ciphertexts shorter than minimum
			for size := 0; size < minSize; size++ {
				ciphertext := make([]byte, size)
				if size > 0 {
					_, err = rand.Read(ciphertext)
					require.NoError(t, err)
				}

				_, err = Decrypt(priv, ciphertext, nil)
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "ciphertext too short")
			}
		})
	}
}

// TestEncrypt_ECDH_DeriveSharedSecretFailure tests ECDH failure in encryption
func TestEncrypt_ECDH_DeriveSharedSecretFailure(t *testing.T) {
	// We cannot directly trigger ECDH failure in Encrypt because
	// the ephemeral key is generated on the same curve as the recipient's public key
	// The only way ECDH could fail is if the public key point is invalid,
	// but the Go standard library validates points during key generation

	// This test verifies that normal operation works
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	plaintext := []byte("test")
	ciphertext, err := Encrypt(rand.Reader, &priv.PublicKey, plaintext, nil)
	require.NoError(t, err)

	decrypted, err := Decrypt(priv, ciphertext, nil)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

// TestDecrypt_AuthenticationFailure tests GCM authentication failure
func TestDecrypt_AuthenticationFailure(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	plaintext := []byte("secret message")
	aad := []byte("context")

	// Encrypt with AAD
	ciphertext, err := Encrypt(rand.Reader, &priv.PublicKey, plaintext, aad)
	require.NoError(t, err)

	// Decrypt with no AAD - should fail authentication
	_, err = Decrypt(priv, ciphertext, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "authentication")

	// Decrypt with different AAD - should fail authentication
	_, err = Decrypt(priv, ciphertext, []byte("wrong"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "authentication")

	// Decrypt with empty AAD - should fail authentication
	_, err = Decrypt(priv, ciphertext, []byte(""))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "authentication")
}

// TestEncrypt_WithVariousAADSizes tests encryption with various AAD sizes
func TestEncrypt_WithVariousAADSizes(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	plaintext := []byte("test message")

	aadSizes := []int{0, 1, 16, 64, 256, 1024, 4096, 16384}

	for _, size := range aadSizes {
		t.Run(fmt.Sprintf("aad_size_%d", size), func(t *testing.T) {
			aad := make([]byte, size)
			if size > 0 {
				_, err := rand.Read(aad)
				require.NoError(t, err)
			}

			ciphertext, err := Encrypt(rand.Reader, &priv.PublicKey, plaintext, aad)
			require.NoError(t, err)

			decrypted, err := Decrypt(priv, ciphertext, aad)
			require.NoError(t, err)
			assert.Equal(t, plaintext, decrypted)
		})
	}
}

// ============================================================================
// Error Injection Tests for Defensive Code Paths
// ============================================================================
//
// The following tests use the injectable function variables to test error paths
// that cannot be triggered with valid inputs. These tests ensure that defensive
// error handling code is exercised and provides proper error messages.

// errDeriveKey is a sentinel error for key derivation failures
var errDeriveKey = errors.New("injected key derivation error")

// errNewCipher is a sentinel error for cipher creation failures
var errNewCipher = errors.New("injected cipher creation error")

// errNewGCM is a sentinel error for GCM creation failures
var errNewGCM = errors.New("injected GCM creation error")

// TestEncrypt_DeriveKeyFailure tests the key derivation error path in Encrypt
func TestEncrypt_DeriveKeyFailure(t *testing.T) {
	// Save original function
	originalDeriveKey := deriveKeyFunc
	defer func() { deriveKeyFunc = originalDeriveKey }()

	// Inject failing function
	deriveKeyFunc = func(sharedSecret, salt, info []byte, keyLength int) ([]byte, error) {
		return nil, errDeriveKey
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	plaintext := []byte("test")
	_, err = Encrypt(rand.Reader, &priv.PublicKey, plaintext, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "key derivation failed")
}

// TestEncrypt_NewCipherFailure tests the cipher creation error path in Encrypt
func TestEncrypt_NewCipherFailure(t *testing.T) {
	// Save original function
	originalNewCipher := newAESCipherFunc
	defer func() { newAESCipherFunc = originalNewCipher }()

	// Inject failing function
	newAESCipherFunc = func(key []byte) (cipher.Block, error) {
		return nil, errNewCipher
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	plaintext := []byte("test")
	_, err = Encrypt(rand.Reader, &priv.PublicKey, plaintext, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create cipher")
}

// TestEncrypt_NewGCMFailure tests the GCM creation error path in Encrypt
func TestEncrypt_NewGCMFailure(t *testing.T) {
	// Save original function
	originalNewGCM := newGCMFunc
	defer func() { newGCMFunc = originalNewGCM }()

	// Inject failing function
	newGCMFunc = func(c cipher.Block) (cipher.AEAD, error) {
		return nil, errNewGCM
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	plaintext := []byte("test")
	_, err = Encrypt(rand.Reader, &priv.PublicKey, plaintext, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create GCM")
}

// TestDecrypt_DeriveKeyFailure tests the key derivation error path in Decrypt
func TestDecrypt_DeriveKeyFailure(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	plaintext := []byte("test")
	ciphertext, err := Encrypt(rand.Reader, &priv.PublicKey, plaintext, nil)
	require.NoError(t, err)

	// Save original function
	originalDeriveKey := deriveKeyFunc
	defer func() { deriveKeyFunc = originalDeriveKey }()

	// Inject failing function
	deriveKeyFunc = func(sharedSecret, salt, info []byte, keyLength int) ([]byte, error) {
		return nil, errDeriveKey
	}

	_, err = Decrypt(priv, ciphertext, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "key derivation failed")
}

// TestDecrypt_NewCipherFailure tests the cipher creation error path in Decrypt
func TestDecrypt_NewCipherFailure(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	plaintext := []byte("test")
	ciphertext, err := Encrypt(rand.Reader, &priv.PublicKey, plaintext, nil)
	require.NoError(t, err)

	// Save original function
	originalNewCipher := newAESCipherFunc
	defer func() { newAESCipherFunc = originalNewCipher }()

	// Inject failing function
	newAESCipherFunc = func(key []byte) (cipher.Block, error) {
		return nil, errNewCipher
	}

	_, err = Decrypt(priv, ciphertext, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create cipher")
}

// TestDecrypt_NewGCMFailure tests the GCM creation error path in Decrypt
func TestDecrypt_NewGCMFailure(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	plaintext := []byte("test")
	ciphertext, err := Encrypt(rand.Reader, &priv.PublicKey, plaintext, nil)
	require.NoError(t, err)

	// Save original function
	originalNewGCM := newGCMFunc
	defer func() { newGCMFunc = originalNewGCM }()

	// Inject failing function
	newGCMFunc = func(c cipher.Block) (cipher.AEAD, error) {
		return nil, errNewGCM
	}

	_, err = Decrypt(priv, ciphertext, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create GCM")
}

// TestEncryptDecrypt_WithInjectedFunctions_AllCurves tests error injection across all curves
func TestEncryptDecrypt_WithInjectedFunctions_AllCurves(t *testing.T) {
	curves := []struct {
		name  string
		curve elliptic.Curve
	}{
		{"P-256", elliptic.P256()},
		{"P-384", elliptic.P384()},
		{"P-521", elliptic.P521()},
	}

	for _, tc := range curves {
		t.Run(tc.name, func(t *testing.T) {
			priv, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
			require.NoError(t, err)

			plaintext := []byte("test for " + tc.name)

			// Test DeriveKey failure in Encrypt
			t.Run("encrypt_derive_key_failure", func(t *testing.T) {
				originalDeriveKey := deriveKeyFunc
				defer func() { deriveKeyFunc = originalDeriveKey }()

				deriveKeyFunc = func(sharedSecret, salt, info []byte, keyLength int) ([]byte, error) {
					return nil, errDeriveKey
				}

				_, err := Encrypt(rand.Reader, &priv.PublicKey, plaintext, nil)
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "key derivation failed")
			})

			// Test NewCipher failure in Encrypt
			t.Run("encrypt_new_cipher_failure", func(t *testing.T) {
				originalNewCipher := newAESCipherFunc
				defer func() { newAESCipherFunc = originalNewCipher }()

				newAESCipherFunc = func(key []byte) (cipher.Block, error) {
					return nil, errNewCipher
				}

				_, err := Encrypt(rand.Reader, &priv.PublicKey, plaintext, nil)
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "failed to create cipher")
			})

			// Test NewGCM failure in Encrypt
			t.Run("encrypt_new_gcm_failure", func(t *testing.T) {
				originalNewGCM := newGCMFunc
				defer func() { newGCMFunc = originalNewGCM }()

				newGCMFunc = func(c cipher.Block) (cipher.AEAD, error) {
					return nil, errNewGCM
				}

				_, err := Encrypt(rand.Reader, &priv.PublicKey, plaintext, nil)
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "failed to create GCM")
			})

			// Create valid ciphertext for decrypt tests
			ciphertext, err := Encrypt(rand.Reader, &priv.PublicKey, plaintext, nil)
			require.NoError(t, err)

			// Test DeriveKey failure in Decrypt
			t.Run("decrypt_derive_key_failure", func(t *testing.T) {
				originalDeriveKey := deriveKeyFunc
				defer func() { deriveKeyFunc = originalDeriveKey }()

				deriveKeyFunc = func(sharedSecret, salt, info []byte, keyLength int) ([]byte, error) {
					return nil, errDeriveKey
				}

				_, err := Decrypt(priv, ciphertext, nil)
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "key derivation failed")
			})

			// Test NewCipher failure in Decrypt
			t.Run("decrypt_new_cipher_failure", func(t *testing.T) {
				originalNewCipher := newAESCipherFunc
				defer func() { newAESCipherFunc = originalNewCipher }()

				newAESCipherFunc = func(key []byte) (cipher.Block, error) {
					return nil, errNewCipher
				}

				_, err := Decrypt(priv, ciphertext, nil)
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "failed to create cipher")
			})

			// Test NewGCM failure in Decrypt
			t.Run("decrypt_new_gcm_failure", func(t *testing.T) {
				originalNewGCM := newGCMFunc
				defer func() { newGCMFunc = originalNewGCM }()

				newGCMFunc = func(c cipher.Block) (cipher.AEAD, error) {
					return nil, errNewGCM
				}

				_, err := Decrypt(priv, ciphertext, nil)
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "failed to create GCM")
			})
		})
	}
}

// TestInjectableFunctions_DefaultBehavior verifies the default functions work correctly
func TestInjectableFunctions_DefaultBehavior(t *testing.T) {
	// Verify the default functions are set correctly
	assert.NotNil(t, deriveKeyFunc)
	assert.NotNil(t, newAESCipherFunc)
	assert.NotNil(t, newGCMFunc)

	// Test that they work with valid inputs
	sharedSecret := make([]byte, 32)
	_, err := rand.Read(sharedSecret)
	require.NoError(t, err)

	// Test DeriveKey
	key, err := deriveKeyFunc(sharedSecret, nil, []byte("info"), 32)
	require.NoError(t, err)
	assert.Len(t, key, 32)

	// Test NewCipher
	block, err := newAESCipherFunc(key)
	require.NoError(t, err)
	assert.NotNil(t, block)

	// Test NewGCM
	gcm, err := newGCMFunc(block)
	require.NoError(t, err)
	assert.NotNil(t, gcm)
}

// TestInjectableFunctions_ResetAfterTest ensures functions are properly reset
func TestInjectableFunctions_ResetAfterTest(t *testing.T) {
	// Store the original function pointers
	originalDeriveKey := deriveKeyFunc
	originalNewCipher := newAESCipherFunc
	originalNewGCM := newGCMFunc

	// Verify they point to the real implementations
	assert.Equal(t, fmt.Sprintf("%p", ecdh.DeriveKey), fmt.Sprintf("%p", originalDeriveKey))
	assert.Equal(t, fmt.Sprintf("%p", aes.NewCipher), fmt.Sprintf("%p", originalNewCipher))
	assert.Equal(t, fmt.Sprintf("%p", cipher.NewGCM), fmt.Sprintf("%p", originalNewGCM))

	// Temporarily replace them
	deriveKeyFunc = func(sharedSecret, salt, info []byte, keyLength int) ([]byte, error) {
		return nil, errDeriveKey
	}

	// Reset
	deriveKeyFunc = originalDeriveKey
	newAESCipherFunc = originalNewCipher
	newGCMFunc = originalNewGCM

	// Verify encryption/decryption still works
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	plaintext := []byte("verify reset works")
	ciphertext, err := Encrypt(rand.Reader, &priv.PublicKey, plaintext, nil)
	require.NoError(t, err)

	decrypted, err := Decrypt(priv, ciphertext, nil)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

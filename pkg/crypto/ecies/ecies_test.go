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
//   - The ciphertext layout for plaintext sizes from 0 bytes to 1KB
//   - AAD binding (a missing, empty or wrong AAD fails authentication)
//   - Error conditions (nil inputs, corrupted data, wrong keys)
//   - Concurrent operations
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
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/crypto/ecdh"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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

// TestEncrypt_FailingRandomReaderNoLongerFatal pins the consequence of moving
// nonce generation inside the FIPS module boundary.
//
// The caller-supplied reader used to be the nonce source, so a broken one made
// Encrypt fail with "failed to generate nonce". SP 800-38D / CMVP IG C.H
// require the GCM IV come from inside the module, so the nonce now comes from
// cipher.NewGCMWithRandomNonce and this reader is no longer consumed at all:
// Go 1.26's ecdsa.GenerateKey ignores it too, using crypto/rand internally.
//
// A broken reader is therefore no longer an error path, and the ciphertext it
// produces is still sound. Asserting that here keeps the change visible rather
// than letting a silently-unused parameter go unnoticed.
func TestEncrypt_FailingRandomReaderNoLongerFatal(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	plaintext := []byte("test")

	// A reader that fails on every call.
	failingReader := &failingRandomReader{}

	ciphertext, err := Encrypt(failingReader, &priv.PublicKey, plaintext, nil)
	require.NoError(t, err, "the caller's reader is no longer a nonce source")

	round, err := Decrypt(priv, ciphertext, nil)
	require.NoError(t, err)
	assert.Equal(t, plaintext, round)
}

// failingRandomReader is a custom io.Reader that always fails
type failingRandomReader struct{}

func (r *failingRandomReader) Read(p []byte) (n int, err error) {
	return 0, io.ErrUnexpectedEOF
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

// TestEncrypt_CallerReaderIsNotConsumed replaces four tests that walked a
// byte-budget-limited io.Reader looking for "failed to generate nonce".
//
// That error path is gone. SP 800-38D / CMVP IG C.H require the GCM IV be
// generated inside the module, so the nonce comes from
// cipher.NewGCMWithRandomNonce, and Go 1.26's ecdsa.GenerateKey draws the
// ephemeral key from crypto/rand regardless of what it is handed. Nothing in
// Encrypt reads the caller's reader any more.
//
// The old tests asserted that a starved reader fails and a fed one succeeds.
// The contract that replaced it is stronger and is what this asserts: the
// byte budget is irrelevant, every budget succeeds, and every ciphertext
// round-trips.
func TestEncrypt_CallerReaderIsNotConsumed(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	plaintext := []byte("test")

	for _, budget := range []int{0, 1, 11, 12, 100} {
		for name, reader := range map[string]io.Reader{
			"byteCounting": &byteCountingRandomReader{bytesBeforeFail: budget},
			"limitedBytes": &limitedBytesReader{bytesRemaining: budget},
		} {
			ciphertext, err := Encrypt(reader, &priv.PublicKey, plaintext, nil)
			require.NoErrorf(t, err, "%s reader with a %d-byte budget", name, budget)

			round, err := Decrypt(priv, ciphertext, nil)
			require.NoErrorf(t, err, "%s reader with a %d-byte budget", name, budget)
			assert.Equal(t, plaintext, round)
		}
	}
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

// TestDecrypt_AuthenticationFailure tests GCM authentication failure
func TestDecrypt_AuthenticationFailure(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	plaintext := []byte("secret message")
	aad := []byte("context")

	// Encrypt with AAD
	ciphertext, err := Encrypt(rand.Reader, &priv.PublicKey, plaintext, aad)
	require.NoError(t, err)

	// Decrypt with the same AAD - should succeed
	decrypted, err := Decrypt(priv, ciphertext, aad)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)

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
	assert.Equal(t, fmt.Sprintf("%p", cipher.NewGCMWithRandomNonce), fmt.Sprintf("%p", originalNewGCM))

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

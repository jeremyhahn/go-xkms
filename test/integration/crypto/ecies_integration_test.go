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

//go:build integration

package crypto_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/crypto/ecies"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestECIES_EncryptDecrypt(t *testing.T) {
	curves := []struct {
		name  string
		curve elliptic.Curve
	}{
		{"P-256", elliptic.P256()},
		{"P-384", elliptic.P384()},
		{"P-521", elliptic.P521()},
	}

	for _, c := range curves {
		t.Run(c.name, func(t *testing.T) {
			// Generate recipient key pair
			privateKey, err := ecdsa.GenerateKey(c.curve, rand.Reader)
			require.NoError(t, err)

			plaintext := []byte("Secret message for ECIES encryption")

			// Encrypt with public key
			ciphertext, err := ecies.Encrypt(rand.Reader, &privateKey.PublicKey, plaintext, nil)
			require.NoError(t, err)
			require.NotNil(t, ciphertext)

			// Ciphertext should be larger than plaintext
			// (ephemeral public key + nonce + tag + ciphertext)
			assert.Greater(t, len(ciphertext), len(plaintext))

			// Decrypt with private key
			decrypted, err := ecies.Decrypt(privateKey, ciphertext, nil)
			require.NoError(t, err)
			assert.Equal(t, plaintext, decrypted)
		})
	}
}

func TestECIES_WithAdditionalData(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	plaintext := []byte("Message with AAD")
	aad := []byte("version:1.0,user:alice")

	// Encrypt with AAD
	ciphertext, err := ecies.Encrypt(rand.Reader, &privateKey.PublicKey, plaintext, aad)
	require.NoError(t, err)

	// Decrypt with correct AAD should succeed
	decrypted, err := ecies.Decrypt(privateKey, ciphertext, aad)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)

	// Decrypt with wrong AAD should fail
	wrongAAD := []byte("version:2.0,user:bob")
	_, err = ecies.Decrypt(privateKey, ciphertext, wrongAAD)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "authentication error")

	// Decrypt with no AAD should fail
	_, err = ecies.Decrypt(privateKey, ciphertext, nil)
	assert.Error(t, err)
}

func TestECIES_EmptyPlaintext(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	plaintext := []byte{}

	ciphertext, err := ecies.Encrypt(rand.Reader, &privateKey.PublicKey, plaintext, nil)
	require.NoError(t, err)

	decrypted, err := ecies.Decrypt(privateKey, ciphertext, nil)
	require.NoError(t, err)
	// Empty slice and nil slice are equivalent
	assert.Len(t, decrypted, 0)
}

func TestECIES_LargePlaintext(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	sizes := []int{
		1024,        // 1 KB
		64 * 1024,   // 64 KB
		1024 * 1024, // 1 MB
	}

	for _, size := range sizes {
		t.Run(fmt.Sprintf("Size_%d_bytes", size), func(t *testing.T) {
			plaintext := make([]byte, size)
			_, err := rand.Read(plaintext)
			require.NoError(t, err)

			ciphertext, err := ecies.Encrypt(rand.Reader, &privateKey.PublicKey, plaintext, nil)
			require.NoError(t, err)

			decrypted, err := ecies.Decrypt(privateKey, ciphertext, nil)
			require.NoError(t, err)
			assert.Equal(t, plaintext, decrypted)
		})
	}
}

func TestECIES_MultipleRecipients(t *testing.T) {
	// Generate multiple recipient key pairs
	const numRecipients = 5
	recipients := make([]*ecdsa.PrivateKey, numRecipients)

	for i := 0; i < numRecipients; i++ {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		recipients[i] = key
	}

	plaintext := []byte("Message for multiple recipients")

	// Encrypt for each recipient
	ciphertexts := make([][]byte, numRecipients)
	for i, recipient := range recipients {
		ciphertext, err := ecies.Encrypt(rand.Reader, &recipient.PublicKey, plaintext, nil)
		require.NoError(t, err)
		ciphertexts[i] = ciphertext

		// Each ciphertext should be different (different ephemeral keys)
		for j := 0; j < i; j++ {
			assert.NotEqual(t, ciphertexts[j], ciphertext)
		}
	}

	// Each recipient can decrypt their own ciphertext
	for i, recipient := range recipients {
		decrypted, err := ecies.Decrypt(recipient, ciphertexts[i], nil)
		require.NoError(t, err, "Recipient %d failed to decrypt", i)
		assert.Equal(t, plaintext, decrypted)
	}

	// Recipients cannot decrypt each other's messages
	for i, recipient := range recipients {
		for j, ciphertext := range ciphertexts {
			if i == j {
				continue // Skip own message
			}
			_, err := ecies.Decrypt(recipient, ciphertext, nil)
			assert.Error(t, err, "Recipient %d should not decrypt message %d", i, j)
		}
	}
}

func TestECIES_EncryptionUniqueness(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	plaintext := []byte("Same message, different encryptions")
	const numEncryptions = 100

	ciphertexts := make([][]byte, numEncryptions)
	for i := 0; i < numEncryptions; i++ {
		ciphertext, err := ecies.Encrypt(rand.Reader, &privateKey.PublicKey, plaintext, nil)
		require.NoError(t, err)
		ciphertexts[i] = ciphertext

		// Each ciphertext should be unique (different ephemeral keys and nonces)
		for j := 0; j < i; j++ {
			assert.NotEqual(t, ciphertexts[j], ciphertext,
				"Encryptions %d and %d should be different", j, i)
		}

		// All should decrypt to the same plaintext
		decrypted, err := ecies.Decrypt(privateKey, ciphertext, nil)
		require.NoError(t, err)
		assert.Equal(t, plaintext, decrypted)
	}
}

func TestECIES_InvalidInputs(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	plaintext := []byte("test")

	tests := []struct {
		name      string
		random    func() interface{}
		publicKey func() *ecdsa.PublicKey
		plaintext func() []byte
		expectErr bool
	}{
		{
			name:      "Nil random source",
			random:    func() interface{} { return nil },
			publicKey: func() *ecdsa.PublicKey { return &privateKey.PublicKey },
			plaintext: func() []byte { return plaintext },
			expectErr: true,
		},
		{
			name:      "Nil public key",
			random:    func() interface{} { return rand.Reader },
			publicKey: func() *ecdsa.PublicKey { return nil },
			plaintext: func() []byte { return plaintext },
			expectErr: true,
		},
		{
			name:      "Nil plaintext",
			random:    func() interface{} { return rand.Reader },
			publicKey: func() *ecdsa.PublicKey { return &privateKey.PublicKey },
			plaintext: func() []byte { return nil },
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var r interface{}
			if tt.random != nil {
				r = tt.random()
			}
			reader, _ := r.(interface {
				Read([]byte) (int, error)
			})

			_, err := ecies.Encrypt(reader, tt.publicKey(), tt.plaintext(), nil)
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestECIES_TamperedCiphertext(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	plaintext := []byte("Original message")
	ciphertext, err := ecies.Encrypt(rand.Reader, &privateKey.PublicKey, plaintext, nil)
	require.NoError(t, err)

	tests := []struct {
		name   string
		tamper func([]byte) []byte
	}{
		{
			name: "Flip bit in ephemeral public key",
			tamper: func(ct []byte) []byte {
				tampered := append([]byte{}, ct...)
				tampered[0] ^= 0xFF
				return tampered
			},
		},
		{
			name: "Flip bit in nonce",
			tamper: func(ct []byte) []byte {
				tampered := append([]byte{}, ct...)
				// Nonce is after ephemeral public key (65 bytes for P-256)
				if len(tampered) > 65 {
					tampered[65] ^= 0xFF
				}
				return tampered
			},
		},
		{
			name: "Flip bit in tag",
			tamper: func(ct []byte) []byte {
				tampered := append([]byte{}, ct...)
				// Tag is after ephemeral key (65) + nonce (12)
				if len(tampered) > 77 {
					tampered[77] ^= 0xFF
				}
				return tampered
			},
		},
		{
			name: "Flip bit in ciphertext",
			tamper: func(ct []byte) []byte {
				tampered := append([]byte{}, ct...)
				// Ciphertext is after ephemeral key (65) + nonce (12) + tag (16)
				if len(tampered) > 93 {
					tampered[93] ^= 0xFF
				}
				return tampered
			},
		},
		{
			name: "Truncate ciphertext",
			tamper: func(ct []byte) []byte {
				if len(ct) > 10 {
					return ct[:len(ct)-10]
				}
				return ct[:5]
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tampered := tt.tamper(ciphertext)
			_, err := ecies.Decrypt(privateKey, tampered, nil)
			assert.Error(t, err)
		})
	}
}

func TestECIES_InvalidCiphertextSize(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tests := []struct {
		name           string
		ciphertextSize int
	}{
		{"Empty ciphertext", 0},
		{"Too short", 10},
		{"Just under minimum", 65 + 12 + 16 - 1}, // ephemeral_key + nonce + tag - 1
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ciphertext := make([]byte, tt.ciphertextSize)
			_, err := ecies.Decrypt(privateKey, ciphertext, nil)
			assert.Error(t, err)
		})
	}
}

func TestECIES_WrongPrivateKey(t *testing.T) {
	// Generate two different key pairs
	alice, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	bob, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	plaintext := []byte("Message for Alice")

	// Encrypt for Alice
	ciphertext, err := ecies.Encrypt(rand.Reader, &alice.PublicKey, plaintext, nil)
	require.NoError(t, err)

	// Alice can decrypt
	decrypted, err := ecies.Decrypt(alice, ciphertext, nil)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)

	// Bob cannot decrypt
	_, err = ecies.Decrypt(bob, ciphertext, nil)
	assert.Error(t, err)
}

func TestECIES_CrossCurveIncompatibility(t *testing.T) {
	// This test verifies that you can't mix curves
	privateKeyP256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	privateKeyP384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	plaintext := []byte("Test message")

	// Encrypt for P-256
	ciphertext, err := ecies.Encrypt(rand.Reader, &privateKeyP256.PublicKey, plaintext, nil)
	require.NoError(t, err)

	// Try to decrypt with P-384 key (should fail)
	_, err = ecies.Decrypt(privateKeyP384, ciphertext, nil)
	assert.Error(t, err)
}

func TestECIES_BinaryData(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Test with various binary patterns
	tests := []struct {
		name      string
		plaintext []byte
	}{
		{"All zeros", make([]byte, 100)},
		{"All ones", func() []byte {
			data := make([]byte, 100)
			for i := range data {
				data[i] = 0xFF
			}
			return data
		}()},
		{"Random binary", func() []byte {
			data := make([]byte, 100)
			rand.Read(data)
			return data
		}()},
		{"Alternating pattern", func() []byte {
			data := make([]byte, 100)
			for i := range data {
				data[i] = byte(i % 2 * 0xFF)
			}
			return data
		}()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ciphertext, err := ecies.Encrypt(rand.Reader, &privateKey.PublicKey, tt.plaintext, nil)
			require.NoError(t, err)

			decrypted, err := ecies.Decrypt(privateKey, ciphertext, nil)
			require.NoError(t, err)
			assert.Equal(t, tt.plaintext, decrypted)
		})
	}
}

func TestECIES_NilPrivateKey(t *testing.T) {
	ciphertext := make([]byte, 100)
	_, err := ecies.Decrypt(nil, ciphertext, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "private key cannot be nil")
}

func TestECIES_NilCiphertext(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	_, err = ecies.Decrypt(privateKey, nil, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "ciphertext cannot be nil")
}

func BenchmarkECIES_Encrypt_P256(b *testing.B) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	plaintext := make([]byte, 1024)
	rand.Read(plaintext)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ecies.Encrypt(rand.Reader, &privateKey.PublicKey, plaintext, nil)
	}
}

func BenchmarkECIES_Decrypt_P256(b *testing.B) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	plaintext := make([]byte, 1024)
	rand.Read(plaintext)
	ciphertext, _ := ecies.Encrypt(rand.Reader, &privateKey.PublicKey, plaintext, nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ecies.Decrypt(privateKey, ciphertext, nil)
	}
}

func BenchmarkECIES_Encrypt_P384(b *testing.B) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	plaintext := make([]byte, 1024)
	rand.Read(plaintext)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ecies.Encrypt(rand.Reader, &privateKey.PublicKey, plaintext, nil)
	}
}

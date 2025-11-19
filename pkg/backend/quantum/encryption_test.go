//go:build quantum

package quantum

import (
	"bytes"
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/storage"
	"github.com/jeremyhahn/go-keychain/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMLKEMEncryptDecrypt(t *testing.T) {
	// Setup
	store, err := storage.NewMemoryBackend()
	require.NoError(t, err)

	backend, err := New(store)
	require.NoError(t, err)
	defer func() { _ = backend.Close() }()

	// Generate ML-KEM-768 key
	attrs := &types.KeyAttributes{
		CN:        "test-encryption-key",
		KeyType:   types.KeyTypeEncryption,
		StoreType: types.StoreQuantum,
		QuantumAttributes: &types.QuantumAttributes{
			Algorithm: types.QuantumAlgorithmMLKEM768,
		},
	}

	privKey, err := backend.GenerateKey(attrs)
	require.NoError(t, err)

	mlkemKey := privKey.(*MLKEMPrivateKey)
	recipientPubKey := mlkemKey.PublicKey.Bytes()

	t.Run("Basic encryption and decryption", func(t *testing.T) {
		plaintext := []byte("This is a secret message protected by quantum-safe cryptography!")

		// Encrypt
		kemCiphertext, encryptedData, err := mlkemKey.Encrypt(plaintext, recipientPubKey)
		require.NoError(t, err)
		assert.NotNil(t, kemCiphertext)
		assert.NotNil(t, encryptedData)

		t.Logf("Plaintext size: %d bytes", len(plaintext))
		t.Logf("KEM ciphertext size: %d bytes", len(kemCiphertext))
		t.Logf("Encrypted data size: %d bytes", len(encryptedData))
		t.Logf("Total overhead: %d bytes", len(kemCiphertext)+len(encryptedData)-len(plaintext))

		// Verify sizes
		assert.Equal(t, 1088, len(kemCiphertext), "ML-KEM-768 ciphertext should be 1088 bytes")

		// Decrypt
		decrypted, err := mlkemKey.Decrypt(kemCiphertext, encryptedData)
		require.NoError(t, err)
		assert.Equal(t, plaintext, decrypted)

		t.Logf("✓ Decrypted successfully")
	})

	t.Run("Encryption with AAD", func(t *testing.T) {
		plaintext := []byte("Sensitive data")
		aad := []byte("user-id:12345|timestamp:2025-01-01T00:00:00Z")

		// Encrypt with AAD
		kemCiphertext, encryptedData, err := mlkemKey.EncryptWithAAD(plaintext, aad, recipientPubKey)
		require.NoError(t, err)

		// Decrypt with AAD
		decrypted, err := mlkemKey.DecryptWithAAD(kemCiphertext, encryptedData, aad)
		require.NoError(t, err)
		assert.Equal(t, plaintext, decrypted)

		// Decrypt with wrong AAD should fail
		wrongAAD := []byte("wrong-aad")
		_, err = mlkemKey.DecryptWithAAD(kemCiphertext, encryptedData, wrongAAD)
		assert.Error(t, err, "Should fail with wrong AAD")

		t.Logf("✓ AAD authentication working correctly")
	})

	t.Run("Multiple messages with same key", func(t *testing.T) {
		messages := [][]byte{
			[]byte("First message"),
			[]byte("Second message with more data"),
			[]byte("Third message"),
		}

		var encrypted []struct {
			kemCiphertext []byte
			encryptedData []byte
		}

		// Encrypt multiple messages
		for _, msg := range messages {
			kemCt, encData, err := mlkemKey.Encrypt(msg, recipientPubKey)
			require.NoError(t, err)
			encrypted = append(encrypted, struct {
				kemCiphertext []byte
				encryptedData []byte
			}{kemCt, encData})
		}

		// Decrypt and verify
		for i, enc := range encrypted {
			decrypted, err := mlkemKey.Decrypt(enc.kemCiphertext, enc.encryptedData)
			require.NoError(t, err)
			assert.Equal(t, messages[i], decrypted)
		}

		t.Logf("✓ Successfully encrypted/decrypted %d messages", len(messages))
	})

	t.Run("Large data encryption", func(t *testing.T) {
		// Test with 1MB of data
		plaintext := bytes.Repeat([]byte("A"), 1024*1024)

		kemCiphertext, encryptedData, err := mlkemKey.Encrypt(plaintext, recipientPubKey)
		require.NoError(t, err)

		decrypted, err := mlkemKey.Decrypt(kemCiphertext, encryptedData)
		require.NoError(t, err)
		assert.Equal(t, plaintext, decrypted)

		t.Logf("✓ Successfully encrypted/decrypted 1MB of data")
		t.Logf("  Plaintext: %d bytes", len(plaintext))
		t.Logf("  Encrypted: %d bytes", len(encryptedData))
		t.Logf("  Overhead: %d bytes (%.2f%%)",
			len(encryptedData)-len(plaintext),
			float64(len(encryptedData)-len(plaintext))/float64(len(plaintext))*100)
	})

	t.Run("Tampered ciphertext detection", func(t *testing.T) {
		plaintext := []byte("Protected message")

		kemCiphertext, encryptedData, err := mlkemKey.Encrypt(plaintext, recipientPubKey)
		require.NoError(t, err)

		// Tamper with encrypted data
		tamperedData := make([]byte, len(encryptedData))
		copy(tamperedData, encryptedData)
		tamperedData[len(tamperedData)/2] ^= 0xFF // Flip bits

		// Should fail to decrypt
		_, err = mlkemKey.Decrypt(kemCiphertext, tamperedData)
		assert.Error(t, err, "Should detect tampered ciphertext")

		t.Logf("✓ Tampering detection working correctly")
	})

	t.Run("Empty and small messages", func(t *testing.T) {
		testCases := [][]byte{
			[]byte(""),      // Empty
			[]byte("X"),     // Single byte
			[]byte("Hello"), // Small message
		}

		for _, tc := range testCases {
			kemCiphertext, encryptedData, err := mlkemKey.Encrypt(tc, recipientPubKey)
			require.NoError(t, err)

			decrypted, err := mlkemKey.Decrypt(kemCiphertext, encryptedData)
			require.NoError(t, err)

			// Handle nil vs empty slice comparison
			if len(tc) == 0 && len(decrypted) == 0 {
				// Both empty - OK
			} else {
				assert.Equal(t, tc, decrypted)
			}
		}

		t.Logf("✓ Edge cases handled correctly")
	})
}

func TestMLKEMEncryptDecryptAllAlgorithms(t *testing.T) {
	algorithms := []types.QuantumAlgorithm{
		types.QuantumAlgorithmMLKEM512,
		types.QuantumAlgorithmMLKEM768,
		types.QuantumAlgorithmMLKEM1024,
	}

	expectedCiphertextSizes := map[types.QuantumAlgorithm]int{
		types.QuantumAlgorithmMLKEM512:  768,
		types.QuantumAlgorithmMLKEM768:  1088,
		types.QuantumAlgorithmMLKEM1024: 1568,
	}

	for _, algo := range algorithms {
		t.Run(string(algo), func(t *testing.T) {
			// Setup
			store, err := storage.NewMemoryBackend()
			require.NoError(t, err)

			backend, err := New(store)
			require.NoError(t, err)
			defer func() { _ = backend.Close() }()

			// Generate key
			attrs := &types.KeyAttributes{
				CN:        "test-key-" + string(algo),
				KeyType:   types.KeyTypeEncryption,
				StoreType: types.StoreQuantum,
				QuantumAttributes: &types.QuantumAttributes{
					Algorithm: algo,
				},
			}

			privKey, err := backend.GenerateKey(attrs)
			require.NoError(t, err)

			mlkemKey := privKey.(*MLKEMPrivateKey)
			recipientPubKey := mlkemKey.PublicKey.Bytes()

			// Test encryption/decryption
			plaintext := []byte("Testing " + string(algo))

			kemCiphertext, encryptedData, err := mlkemKey.Encrypt(plaintext, recipientPubKey)
			require.NoError(t, err)

			// Verify ciphertext size
			expectedSize := expectedCiphertextSizes[algo]
			assert.Equal(t, expectedSize, len(kemCiphertext),
				"%s ciphertext should be %d bytes", algo, expectedSize)

			// Decrypt and verify
			decrypted, err := mlkemKey.Decrypt(kemCiphertext, encryptedData)
			require.NoError(t, err)
			assert.Equal(t, plaintext, decrypted)

			t.Logf("✓ %s: KEM ciphertext=%d bytes, encrypted=%d bytes",
				algo, len(kemCiphertext), len(encryptedData))
		})
	}
}

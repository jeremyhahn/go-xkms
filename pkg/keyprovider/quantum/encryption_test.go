package quantum

import (
	"bytes"
	"context"
	"crypto"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- helper ---

func newTestBackend(t *testing.T) (*QuantumBackend, storage.Backend) {
	t.Helper()
	store, err := storage.NewMemoryBackend()
	require.NoError(t, err)
	qb, err := New(store)
	require.NoError(t, err)
	return qb, store
}

func mldsaAttrs(cn string, algo types.QuantumAlgorithm) *types.KeyAttributes {
	return &types.KeyAttributes{
		CN:        cn,
		KeyType:   types.KeyTypeSigning,
		StoreType: types.StoreQuantum,
		QuantumAttributes: &types.QuantumAttributes{
			Algorithm: algo,
		},
	}
}

func mlkemAttrs(cn string, algo types.QuantumAlgorithm) *types.KeyAttributes {
	return &types.KeyAttributes{
		CN:        cn,
		KeyType:   types.KeyTypeEncryption,
		StoreType: types.StoreQuantum,
		QuantumAttributes: &types.QuantumAttributes{
			Algorithm: algo,
		},
	}
}

// --- Encryption / Decryption round-trip tests ---

func TestMLKEMEncryptDecrypt(t *testing.T) {
	qb, _ := newTestBackend(t)
	defer func() { _ = qb.Close() }()

	attrs := mlkemAttrs("test-encryption-key", types.QuantumAlgorithmMLKEM768)
	privKey, err := qb.GenerateKey(attrs)
	require.NoError(t, err)

	mlkemKey := privKey.(*MLKEMPrivateKey)
	recipientPubKey := mlkemKey.PublicKey.Bytes()

	t.Run("Basic encryption and decryption", func(t *testing.T) {
		plaintext := []byte("This is a secret message protected by quantum-safe cryptography!")

		kemCiphertext, encryptedData, err := mlkemKey.Encrypt(plaintext, recipientPubKey)
		require.NoError(t, err)
		assert.NotNil(t, kemCiphertext)
		assert.NotNil(t, encryptedData)
		assert.Equal(t, 1088, len(kemCiphertext), "ML-KEM-768 ciphertext should be 1088 bytes")

		decrypted, err := mlkemKey.Decrypt(kemCiphertext, encryptedData)
		require.NoError(t, err)
		assert.Equal(t, plaintext, decrypted)
	})

	t.Run("Encryption with AAD", func(t *testing.T) {
		plaintext := []byte("Sensitive data")
		aad := []byte("user-id:12345|timestamp:2025-01-01T00:00:00Z")

		kemCiphertext, encryptedData, err := mlkemKey.EncryptWithAAD(plaintext, aad, recipientPubKey)
		require.NoError(t, err)

		decrypted, err := mlkemKey.DecryptWithAAD(kemCiphertext, encryptedData, aad)
		require.NoError(t, err)
		assert.Equal(t, plaintext, decrypted)

		wrongAAD := []byte("wrong-aad")
		_, err = mlkemKey.DecryptWithAAD(kemCiphertext, encryptedData, wrongAAD)
		assert.Error(t, err, "Should fail with wrong AAD")
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

		for _, msg := range messages {
			kemCt, encData, err := mlkemKey.Encrypt(msg, recipientPubKey)
			require.NoError(t, err)
			encrypted = append(encrypted, struct {
				kemCiphertext []byte
				encryptedData []byte
			}{kemCt, encData})
		}

		for i, enc := range encrypted {
			decrypted, err := mlkemKey.Decrypt(enc.kemCiphertext, enc.encryptedData)
			require.NoError(t, err)
			assert.Equal(t, messages[i], decrypted)
		}
	})

	t.Run("Large data encryption", func(t *testing.T) {
		plaintext := bytes.Repeat([]byte("A"), 1024*1024)

		kemCiphertext, encryptedData, err := mlkemKey.Encrypt(plaintext, recipientPubKey)
		require.NoError(t, err)

		decrypted, err := mlkemKey.Decrypt(kemCiphertext, encryptedData)
		require.NoError(t, err)
		assert.Equal(t, plaintext, decrypted)
	})

	t.Run("Tampered ciphertext detection", func(t *testing.T) {
		plaintext := []byte("Protected message")

		kemCiphertext, encryptedData, err := mlkemKey.Encrypt(plaintext, recipientPubKey)
		require.NoError(t, err)

		tamperedData := make([]byte, len(encryptedData))
		copy(tamperedData, encryptedData)
		tamperedData[len(tamperedData)/2] ^= 0xFF

		_, err = mlkemKey.Decrypt(kemCiphertext, tamperedData)
		assert.Error(t, err, "Should detect tampered ciphertext")
	})

	t.Run("Empty and small messages", func(t *testing.T) {
		testCases := [][]byte{
			[]byte(""),
			[]byte("X"),
			[]byte("Hello"),
		}

		for _, tc := range testCases {
			kemCiphertext, encryptedData, err := mlkemKey.Encrypt(tc, recipientPubKey)
			require.NoError(t, err)

			decrypted, err := mlkemKey.Decrypt(kemCiphertext, encryptedData)
			require.NoError(t, err)

			if len(tc) == 0 && len(decrypted) == 0 {
				// Both empty - OK
			} else {
				assert.Equal(t, tc, decrypted)
			}
		}
	})
}

func TestMLKEMEncryptDecryptAllAlgorithms(t *testing.T) {
	algorithms := []types.QuantumAlgorithm{
		types.QuantumAlgorithmMLKEM768,
		types.QuantumAlgorithmMLKEM1024,
	}

	expectedCiphertextSizes := map[types.QuantumAlgorithm]int{
		types.QuantumAlgorithmMLKEM768:  1088,
		types.QuantumAlgorithmMLKEM1024: 1568,
	}

	for _, algo := range algorithms {
		t.Run(string(algo), func(t *testing.T) {
			qb, _ := newTestBackend(t)
			defer func() { _ = qb.Close() }()

			attrs := mlkemAttrs("test-key-"+string(algo), algo)
			privKey, err := qb.GenerateKey(attrs)
			require.NoError(t, err)

			mlkemKey := privKey.(*MLKEMPrivateKey)
			recipientPubKey := mlkemKey.PublicKey.Bytes()

			plaintext := []byte("Testing " + string(algo))
			kemCiphertext, encryptedData, err := mlkemKey.Encrypt(plaintext, recipientPubKey)
			require.NoError(t, err)

			expectedSize := expectedCiphertextSizes[algo]
			assert.Equal(t, expectedSize, len(kemCiphertext))

			decrypted, err := mlkemKey.Decrypt(kemCiphertext, encryptedData)
			require.NoError(t, err)
			assert.Equal(t, plaintext, decrypted)
		})
	}
}

func TestMLKEM512Unsupported(t *testing.T) {
	qb, _ := newTestBackend(t)
	defer func() { _ = qb.Close() }()

	attrs := mlkemAttrs("test-unsupported-512", types.QuantumAlgorithmMLKEM512)
	_, err := qb.GenerateKey(attrs)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported quantum algorithm")
}

// --- Backend Type / Capabilities ---

func TestQuantumBackend_Type(t *testing.T) {
	qb, _ := newTestBackend(t)
	defer func() { _ = qb.Close() }()
	assert.Equal(t, types.BackendTypeQuantum, qb.Type())
}

func TestQuantumBackend_Capabilities(t *testing.T) {
	qb, _ := newTestBackend(t)
	defer func() { _ = qb.Close() }()

	caps := qb.Capabilities()
	assert.True(t, caps.Keys)
	assert.True(t, caps.Signing)
	assert.True(t, caps.KeyRotation)
	assert.True(t, caps.Import)
	assert.True(t, caps.Export)
	assert.True(t, caps.KeyAgreement)
	assert.False(t, caps.HardwareBacked)
	assert.False(t, caps.Decryption)
	assert.False(t, caps.SymmetricEncryption)
	assert.False(t, caps.ECIES)
}

// --- NewWithConfig error paths ---

func TestNewWithConfig_NilStorage(t *testing.T) {
	_, err := NewWithConfig(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "storage backend cannot be nil")
}

func TestNewWithConfig_WithTracker(t *testing.T) {
	store, err := storage.NewMemoryBackend()
	require.NoError(t, err)

	tracker := backend.NewMemoryAEADTracker()
	qb, err := NewWithConfig(store, &Config{Tracker: tracker})
	require.NoError(t, err)
	defer func() { _ = qb.Close() }()
	assert.NotNil(t, qb.tracker)
}

// --- GenerateKey error paths ---

func TestGenerateKey_NilQuantumAttributes(t *testing.T) {
	qb, _ := newTestBackend(t)
	defer func() { _ = qb.Close() }()

	// Without QuantumAttributes, attrs.Validate() rejects the attributes
	// because neither KeyAlgorithm nor QuantumAttributes is set, wrapping
	// the error as backend.ErrInvalidAttributes.
	attrs := &types.KeyAttributes{
		CN:        "test-nil-qa",
		KeyType:   types.KeyTypeSigning,
		StoreType: types.StoreQuantum,
	}
	_, err := qb.GenerateKey(attrs)
	require.Error(t, err)
	assert.ErrorIs(t, err, backend.ErrInvalidAttributes)
}

func TestGenerateKey_DuplicateKey(t *testing.T) {
	qb, _ := newTestBackend(t)
	defer func() { _ = qb.Close() }()

	attrs := mldsaAttrs("dup-key", types.QuantumAlgorithmMLDSA65)
	_, err := qb.GenerateKey(attrs)
	require.NoError(t, err)

	_, err = qb.GenerateKey(attrs)
	require.Error(t, err)
	assert.ErrorIs(t, err, backend.ErrKeyAlreadyExists)
}

func TestGenerateKey_InvalidAttributes(t *testing.T) {
	qb, _ := newTestBackend(t)
	defer func() { _ = qb.Close() }()

	// An unknown algorithm is rejected by attrs.Validate() which the backend
	// wraps as backend.ErrInvalidAttributes.
	attrs := &types.KeyAttributes{
		CN:        "test-unsupported",
		KeyType:   types.KeyTypeSigning,
		StoreType: types.StoreQuantum,
		QuantumAttributes: &types.QuantumAttributes{
			Algorithm: types.QuantumAlgorithm("UNSUPPORTED-42"),
		},
	}
	_, err := qb.GenerateKey(attrs)
	require.Error(t, err)
	assert.ErrorIs(t, err, backend.ErrInvalidAttributes)
}

func TestGenerateKey_ClosedBackend(t *testing.T) {
	qb, _ := newTestBackend(t)
	require.NoError(t, qb.Close())

	attrs := mldsaAttrs("closed-test", types.QuantumAlgorithmMLDSA65)
	_, err := qb.GenerateKey(attrs)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrStorageClosed)
}

// --- ML-DSA signing: generate, get, sign, verify ---

func TestMLDSA_GenerateAndSign_AllAlgorithms(t *testing.T) {
	algorithms := []types.QuantumAlgorithm{
		types.QuantumAlgorithmMLDSA44,
		types.QuantumAlgorithmMLDSA65,
		types.QuantumAlgorithmMLDSA87,
	}

	for _, algo := range algorithms {
		t.Run(string(algo), func(t *testing.T) {
			qb, _ := newTestBackend(t)
			defer func() { _ = qb.Close() }()

			attrs := mldsaAttrs("sign-"+string(algo), algo)
			privKey, err := qb.GenerateKey(attrs)
			require.NoError(t, err)

			mldsaKey, ok := privKey.(*MLDSAPrivateKey)
			require.True(t, ok)

			// Public()
			pub := mldsaKey.Public()
			require.NotNil(t, pub)
			pubKey, ok := pub.(*MLDSAPublicKey)
			require.True(t, ok)
			assert.NotEmpty(t, pubKey.Key)
			assert.Equal(t, string(algo), pubKey.Algorithm)

			// Sign
			message := []byte("test message for signing")
			sig, err := mldsaKey.Sign(nil, message, crypto.Hash(0))
			require.NoError(t, err)
			assert.NotEmpty(t, sig)

			// Verify
			valid, err := mldsaKey.Verify(message, sig)
			require.NoError(t, err)
			assert.True(t, valid)

			// Verify with wrong message
			valid, err = mldsaKey.Verify([]byte("wrong message"), sig)
			require.NoError(t, err)
			assert.False(t, valid)
		})
	}
}

func TestMLDSAPrivateKey_Sign_NilSK(t *testing.T) {
	key := &MLDSAPrivateKey{sk: nil}
	_, err := key.Sign(nil, []byte("msg"), crypto.Hash(0))
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNotInitialized)
}

func TestMLDSAPrivateKey_Sign_UnsupportedType(t *testing.T) {
	key := &MLDSAPrivateKey{sk: "not-a-real-key"}
	_, err := key.Sign(nil, []byte("msg"), crypto.Hash(0))
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrSigningFailed)
}

func TestMLDSAPrivateKey_Verify_NilPK(t *testing.T) {
	key := &MLDSAPrivateKey{pk: nil}
	_, err := key.Verify([]byte("msg"), []byte("sig"))
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNotInitialized)
}

func TestMLDSAPrivateKey_Verify_UnsupportedAlgorithm(t *testing.T) {
	key := &MLDSAPrivateKey{pk: "something", Algorithm: "BOGUS"}
	_, err := key.Verify([]byte("msg"), []byte("sig"))
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrUnsupportedAlgorithm)
}

func TestMLDSAPrivateKey_Clean(t *testing.T) {
	qb, _ := newTestBackend(t)
	defer func() { _ = qb.Close() }()

	attrs := mldsaAttrs("clean-key", types.QuantumAlgorithmMLDSA44)
	privKey, err := qb.GenerateKey(attrs)
	require.NoError(t, err)

	mldsaKey := privKey.(*MLDSAPrivateKey)
	assert.NotNil(t, mldsaKey.sk)
	assert.NotNil(t, mldsaKey.pk)

	mldsaKey.Clean()
	assert.Nil(t, mldsaKey.sk)
	assert.Nil(t, mldsaKey.pk)
	for _, b := range mldsaKey.seed {
		assert.Equal(t, byte(0), b)
	}
}

func TestMLDSAPrivateKey_ExportSecretKey(t *testing.T) {
	qb, _ := newTestBackend(t)
	defer func() { _ = qb.Close() }()

	attrs := mldsaAttrs("export-key", types.QuantumAlgorithmMLDSA65)
	privKey, err := qb.GenerateKey(attrs)
	require.NoError(t, err)

	mldsaKey := privKey.(*MLDSAPrivateKey)
	exported := mldsaKey.ExportSecretKey()
	require.NotNil(t, exported)
	assert.Len(t, exported, mldsaSeedSize)
	assert.Equal(t, mldsaKey.seed, exported)

	// Returned slice should be a copy
	exported[0] ^= 0xFF
	assert.NotEqual(t, mldsaKey.seed[0], exported[0])
}

func TestMLDSAPrivateKey_ExportSecretKey_NilSeed(t *testing.T) {
	key := &MLDSAPrivateKey{seed: nil}
	result := key.ExportSecretKey()
	assert.Nil(t, result)
}

// --- ML-KEM public key / encapsulation error paths ---

func TestMLKEMPrivateKey_Public(t *testing.T) {
	qb, _ := newTestBackend(t)
	defer func() { _ = qb.Close() }()

	attrs := mlkemAttrs("pub-key", types.QuantumAlgorithmMLKEM768)
	privKey, err := qb.GenerateKey(attrs)
	require.NoError(t, err)

	mlkemKey := privKey.(*MLKEMPrivateKey)
	pub := mlkemKey.Public()
	require.NotNil(t, pub)
	pubKey, ok := pub.(*MLKEMPublicKey)
	require.True(t, ok)
	assert.NotEmpty(t, pubKey.Key)
}

func TestMLKEMPrivateKey_Clean(t *testing.T) {
	qb, _ := newTestBackend(t)
	defer func() { _ = qb.Close() }()

	attrs := mlkemAttrs("clean-kem", types.QuantumAlgorithmMLKEM768)
	privKey, err := qb.GenerateKey(attrs)
	require.NoError(t, err)

	mlkemKey := privKey.(*MLKEMPrivateKey)
	assert.NotNil(t, mlkemKey.dk)

	mlkemKey.Clean()
	assert.Nil(t, mlkemKey.dk)
	for _, b := range mlkemKey.seed {
		assert.Equal(t, byte(0), b)
	}
}

func TestMLKEMPrivateKey_ExportSecretKey(t *testing.T) {
	qb, _ := newTestBackend(t)
	defer func() { _ = qb.Close() }()

	attrs := mlkemAttrs("export-kem", types.QuantumAlgorithmMLKEM768)
	privKey, err := qb.GenerateKey(attrs)
	require.NoError(t, err)

	mlkemKey := privKey.(*MLKEMPrivateKey)
	exported := mlkemKey.ExportSecretKey()
	require.NotNil(t, exported)
	assert.Equal(t, len(mlkemKey.seed), len(exported))

	// Returned slice should be a copy
	exported[0] ^= 0xFF
	assert.NotEqual(t, mlkemKey.seed[0], exported[0])
}

func TestMLKEMPrivateKey_ExportSecretKey_NilSeed(t *testing.T) {
	key := &MLKEMPrivateKey{seed: nil}
	result := key.ExportSecretKey()
	assert.Nil(t, result)
}

func TestMLKEMPrivateKey_Encapsulate_NilDK(t *testing.T) {
	key := &MLKEMPrivateKey{dk: nil}
	_, _, err := key.Encapsulate([]byte("pub"))
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNotInitialized)
}

func TestMLKEMPrivateKey_Encapsulate_UnsupportedAlgorithm(t *testing.T) {
	key := &MLKEMPrivateKey{dk: "not-nil", Algorithm: "BOGUS"}
	_, _, err := key.Encapsulate([]byte("pub"))
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrUnsupportedAlgorithm)
}

func TestMLKEMPrivateKey_Decapsulate_NilDK(t *testing.T) {
	key := &MLKEMPrivateKey{dk: nil}
	_, err := key.Decapsulate([]byte("ct"))
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNotInitialized)
}

func TestMLKEMPrivateKey_Decapsulate_UnsupportedAlgorithm(t *testing.T) {
	key := &MLKEMPrivateKey{dk: "not-nil", Algorithm: "BOGUS"}
	_, err := key.Decapsulate([]byte("ct"))
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrUnsupportedAlgorithm)
}

func TestMLKEMPrivateKey_Encrypt_NilDK(t *testing.T) {
	key := &MLKEMPrivateKey{dk: nil}
	_, _, err := key.Encrypt([]byte("pt"), []byte("pub"))
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNotInitialized)
}

func TestMLKEMPrivateKey_Decrypt_NilDK(t *testing.T) {
	key := &MLKEMPrivateKey{dk: nil}
	_, err := key.Decrypt([]byte("ct"), []byte("enc"))
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNotInitialized)
}

func TestMLKEMPrivateKey_EncryptWithAAD_NilDK(t *testing.T) {
	key := &MLKEMPrivateKey{dk: nil}
	_, _, err := key.EncryptWithAAD([]byte("pt"), []byte("aad"), []byte("pub"))
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNotInitialized)
}

func TestMLKEMPrivateKey_DecryptWithAAD_NilDK(t *testing.T) {
	key := &MLKEMPrivateKey{dk: nil}
	_, err := key.DecryptWithAAD([]byte("ct"), []byte("enc"), []byte("aad"))
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNotInitialized)
}

// --- GetKey: ML-DSA path ---

func TestGetKey_MLDSA_RoundTrip(t *testing.T) {
	qb, _ := newTestBackend(t)
	defer func() { _ = qb.Close() }()

	attrs := mldsaAttrs("get-dsa-key", types.QuantumAlgorithmMLDSA65)
	privKey, err := qb.GenerateKey(attrs)
	require.NoError(t, err)

	originalKey := privKey.(*MLDSAPrivateKey)

	// Retrieve key
	retrieved, err := qb.GetKey(attrs)
	require.NoError(t, err)

	loadedKey := retrieved.(*MLDSAPrivateKey)
	assert.Equal(t, originalKey.Algorithm, loadedKey.Algorithm)
	assert.Equal(t, originalKey.PublicKey.Key, loadedKey.PublicKey.Key)

	// Verify sign/verify still works after round-trip
	message := []byte("round-trip signing")
	sig, err := loadedKey.Sign(nil, message, crypto.Hash(0))
	require.NoError(t, err)

	valid, err := loadedKey.Verify(message, sig)
	require.NoError(t, err)
	assert.True(t, valid)
}

func TestGetKey_MLKEM_RoundTrip(t *testing.T) {
	qb, _ := newTestBackend(t)
	defer func() { _ = qb.Close() }()

	attrs := mlkemAttrs("get-kem-key", types.QuantumAlgorithmMLKEM768)
	privKey, err := qb.GenerateKey(attrs)
	require.NoError(t, err)

	originalKey := privKey.(*MLKEMPrivateKey)
	recipientPubKey := originalKey.PublicKey.Bytes()

	// Encrypt with original key
	plaintext := []byte("round-trip encryption")
	kemCt, encData, err := originalKey.Encrypt(plaintext, recipientPubKey)
	require.NoError(t, err)

	// Retrieve key and decrypt
	retrieved, err := qb.GetKey(attrs)
	require.NoError(t, err)
	loadedKey := retrieved.(*MLKEMPrivateKey)

	decrypted, err := loadedKey.Decrypt(kemCt, encData)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestGetKey_NotFound(t *testing.T) {
	qb, _ := newTestBackend(t)
	defer func() { _ = qb.Close() }()

	attrs := mldsaAttrs("nonexistent", types.QuantumAlgorithmMLDSA44)
	_, err := qb.GetKey(attrs)
	require.Error(t, err)
	assert.ErrorIs(t, err, backend.ErrKeyNotFound)
}

func TestGetKey_ClosedBackend(t *testing.T) {
	qb, _ := newTestBackend(t)
	require.NoError(t, qb.Close())

	attrs := mldsaAttrs("closed-get", types.QuantumAlgorithmMLDSA44)
	_, err := qb.GetKey(attrs)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrStorageClosed)
}

// --- DeleteKey ---

func TestDeleteKey_MLDSA(t *testing.T) {
	qb, _ := newTestBackend(t)
	defer func() { _ = qb.Close() }()

	attrs := mldsaAttrs("delete-dsa", types.QuantumAlgorithmMLDSA44)
	_, err := qb.GenerateKey(attrs)
	require.NoError(t, err)

	// Key exists
	_, err = qb.GetKey(attrs)
	require.NoError(t, err)

	// Delete
	err = qb.DeleteKey(attrs)
	require.NoError(t, err)

	// Key no longer exists
	_, err = qb.GetKey(attrs)
	require.Error(t, err)
	assert.ErrorIs(t, err, backend.ErrKeyNotFound)
}

func TestDeleteKey_NotFound(t *testing.T) {
	qb, _ := newTestBackend(t)
	defer func() { _ = qb.Close() }()

	attrs := mldsaAttrs("no-such-key", types.QuantumAlgorithmMLDSA65)
	err := qb.DeleteKey(attrs)
	require.Error(t, err)
	assert.ErrorIs(t, err, backend.ErrKeyNotFound)
}

func TestDeleteKey_ClosedBackend(t *testing.T) {
	qb, _ := newTestBackend(t)
	require.NoError(t, qb.Close())

	attrs := mldsaAttrs("closed-del", types.QuantumAlgorithmMLDSA44)
	err := qb.DeleteKey(attrs)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrStorageClosed)
}

// --- ListKeys ---

func TestListKeys_Empty(t *testing.T) {
	qb, _ := newTestBackend(t)
	defer func() { _ = qb.Close() }()

	keys, err := qb.ListKeys()
	require.NoError(t, err)
	assert.Empty(t, keys)
}

func TestListKeys_WithMultipleKeys(t *testing.T) {
	qb, _ := newTestBackend(t)
	defer func() { _ = qb.Close() }()

	// Generate ML-DSA-44 key
	_, err := qb.GenerateKey(mldsaAttrs("list-dsa44", types.QuantumAlgorithmMLDSA44))
	require.NoError(t, err)

	// Generate ML-KEM-768 key
	_, err = qb.GenerateKey(mlkemAttrs("list-kem768", types.QuantumAlgorithmMLKEM768))
	require.NoError(t, err)

	keys, err := qb.ListKeys()
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(keys), 2)
}

func TestListKeys_ClosedBackend(t *testing.T) {
	qb, _ := newTestBackend(t)
	require.NoError(t, qb.Close())

	_, err := qb.ListKeys()
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrStorageClosed)
}

func TestListKeys_FiltersNonQuantumKeys(t *testing.T) {
	qb, store := newTestBackend(t)
	defer func() { _ = qb.Close() }()

	// Store a quantum key normally
	_, err := qb.GenerateKey(mldsaAttrs("real-key", types.QuantumAlgorithmMLDSA44))
	require.NoError(t, err)

	// Manually store a key with a non-quantum algorithm in the ID
	// Format: storetype:keytype:cn:algorithm
	err = storage.SaveKey(context.Background(), store, "quantum:signing:fake:rsa", []byte(`{"algorithm":"RSA"}`))
	require.NoError(t, err)

	// Manually store a key with a short ID (fewer than 4 parts)
	err = storage.SaveKey(context.Background(), store, "short:id", []byte(`{"algorithm":"ML-DSA-44"}`))
	require.NoError(t, err)

	keys, err := qb.ListKeys()
	require.NoError(t, err)

	// Only the real quantum key should be returned
	assert.Len(t, keys, 1)
	assert.Equal(t, types.QuantumAlgorithmMLDSA44, keys[0].QuantumAttributes.Algorithm)
}

// --- Signer ---

func TestSigner_MLDSA(t *testing.T) {
	qb, _ := newTestBackend(t)
	defer func() { _ = qb.Close() }()

	attrs := mldsaAttrs("signer-key", types.QuantumAlgorithmMLDSA65)
	_, err := qb.GenerateKey(attrs)
	require.NoError(t, err)

	signer, err := qb.Signer(attrs)
	require.NoError(t, err)
	require.NotNil(t, signer)

	// Use the signer
	msg := []byte("signer interface test")
	sig, err := signer.Sign(nil, msg, crypto.Hash(0))
	require.NoError(t, err)
	assert.NotEmpty(t, sig)
}

func TestSigner_MLKEM_ReturnsError(t *testing.T) {
	qb, _ := newTestBackend(t)
	defer func() { _ = qb.Close() }()

	attrs := mlkemAttrs("signer-kem", types.QuantumAlgorithmMLKEM768)
	_, err := qb.GenerateKey(attrs)
	require.NoError(t, err)

	_, err = qb.Signer(attrs)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrKeyNotSigner)
}

func TestSigner_NotFound(t *testing.T) {
	qb, _ := newTestBackend(t)
	defer func() { _ = qb.Close() }()

	attrs := mldsaAttrs("signer-missing", types.QuantumAlgorithmMLDSA44)
	_, err := qb.Signer(attrs)
	require.Error(t, err)
	assert.ErrorIs(t, err, backend.ErrKeyNotFound)
}

// --- Decrypter ---

func TestDecrypter_AlwaysReturnsError(t *testing.T) {
	qb, _ := newTestBackend(t)
	defer func() { _ = qb.Close() }()

	attrs := mlkemAttrs("dec-key", types.QuantumAlgorithmMLKEM768)
	_, err := qb.Decrypter(attrs)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrKeyNotDecrypter)
}

// --- RotateKey ---

func TestRotateKey_MLDSA(t *testing.T) {
	qb, _ := newTestBackend(t)
	defer func() { _ = qb.Close() }()

	attrs := mldsaAttrs("rotate-dsa", types.QuantumAlgorithmMLDSA65)
	privKey, err := qb.GenerateKey(attrs)
	require.NoError(t, err)
	originalKey := privKey.(*MLDSAPrivateKey)
	originalPub := originalKey.PublicKey.Key

	err = qb.RotateKey(attrs)
	require.NoError(t, err)

	// The rotated key should have different public key material
	newKey, err := qb.GetKey(attrs)
	require.NoError(t, err)
	rotatedKey := newKey.(*MLDSAPrivateKey)
	assert.NotEqual(t, originalPub, rotatedKey.PublicKey.Key)
}

func TestRotateKey_MLKEM(t *testing.T) {
	qb, _ := newTestBackend(t)
	defer func() { _ = qb.Close() }()

	attrs := mlkemAttrs("rotate-kem", types.QuantumAlgorithmMLKEM768)
	privKey, err := qb.GenerateKey(attrs)
	require.NoError(t, err)
	originalKey := privKey.(*MLKEMPrivateKey)
	originalPub := originalKey.PublicKey.Key

	err = qb.RotateKey(attrs)
	require.NoError(t, err)

	// The rotated key should have different public key material
	newKey, err := qb.GetKey(attrs)
	require.NoError(t, err)
	rotatedKey := newKey.(*MLKEMPrivateKey)
	assert.NotEqual(t, originalPub, rotatedKey.PublicKey.Key)

	// Verify the new key can still encrypt/decrypt
	recipientPubKey := rotatedKey.PublicKey.Bytes()
	plaintext := []byte("rotated key encryption")
	kemCt, encData, err := rotatedKey.Encrypt(plaintext, recipientPubKey)
	require.NoError(t, err)

	decrypted, err := rotatedKey.Decrypt(kemCt, encData)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestRotateKey_NotFound(t *testing.T) {
	qb, _ := newTestBackend(t)
	defer func() { _ = qb.Close() }()

	attrs := mldsaAttrs("rotate-missing", types.QuantumAlgorithmMLDSA44)
	err := qb.RotateKey(attrs)
	require.Error(t, err)
	assert.ErrorIs(t, err, backend.ErrKeyNotFound)
}

func TestRotateKey_ClosedBackend(t *testing.T) {
	qb, _ := newTestBackend(t)
	require.NoError(t, qb.Close())

	attrs := mldsaAttrs("rotate-closed", types.QuantumAlgorithmMLDSA65)
	err := qb.RotateKey(attrs)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrStorageClosed)
}

func TestRotateKey_CorruptedMetadata(t *testing.T) {
	qb, store := newTestBackend(t)
	defer func() { _ = qb.Close() }()

	attrs := mldsaAttrs("rotate-corrupt", types.QuantumAlgorithmMLDSA44)

	// Generate the key first so KeyExists returns true
	_, err := qb.GenerateKey(attrs)
	require.NoError(t, err)

	// Overwrite with corrupted metadata
	keyID := attrs.ID()
	err = storage.SaveKey(context.Background(), store, keyID, []byte("not-valid-json"))
	require.NoError(t, err)

	err = qb.RotateKey(attrs)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to deserialize key metadata")
}

func TestRotateKey_StoredUnsupportedAlgorithm(t *testing.T) {
	qb, store := newTestBackend(t)
	defer func() { _ = qb.Close() }()

	attrs := mldsaAttrs("rotate-unsupported", types.QuantumAlgorithmMLDSA65)

	// Generate the key first so KeyExists returns true
	_, err := qb.GenerateKey(attrs)
	require.NoError(t, err)

	// Overwrite with metadata containing an unsupported algorithm
	keyID := attrs.ID()
	meta := `{"algorithm":"UNKNOWN-ALG","public_key":"AAAA","seed":"BBBB"}`
	err = storage.SaveKey(context.Background(), store, keyID, []byte(meta))
	require.NoError(t, err)

	err = qb.RotateKey(attrs)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrUnsupportedAlgorithm)
}

// --- Close ---

func TestClose_Double(t *testing.T) {
	qb, _ := newTestBackend(t)
	err := qb.Close()
	require.NoError(t, err)

	err = qb.Close()
	require.NoError(t, err)
}

// --- encryptWithAESGCM / decryptWithAESGCM error paths ---

func TestEncryptWithAESGCM_InvalidKeySize(t *testing.T) {
	// AES requires 16, 24, or 32 byte keys. Use a 7-byte key to trigger error.
	badKey := make([]byte, 7)
	_, err := encryptWithAESGCM([]byte("plaintext"), badKey, nil, nil, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create AES cipher")
}

func TestDecryptWithAESGCM_InvalidKeySize(t *testing.T) {
	// AES requires 16, 24, or 32 byte keys. Use a 7-byte key to trigger error.
	badKey := make([]byte, 7)
	// ciphertext must be at least 12 bytes (nonce size) to pass the length check
	ciphertext := make([]byte, 32)
	_, err := decryptWithAESGCM(ciphertext, badKey, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create AES cipher")
}

func TestDecryptWithAESGCM_CiphertextTooShort(t *testing.T) {
	key := make([]byte, 32)
	_, err := decryptWithAESGCM([]byte("short"), key, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ciphertext too short")
}

func TestDecryptWithAESGCM_TamperedCiphertext(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	// Encrypt valid data
	ct, err := encryptWithAESGCM([]byte("test data"), key, nil, nil, "")
	require.NoError(t, err)

	// Tamper with the ciphertext portion (after the 12-byte nonce)
	tampered := make([]byte, len(ct))
	copy(tampered, ct)
	tampered[len(tampered)-1] ^= 0xFF

	_, err = decryptWithAESGCM(tampered, key, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decryption failed")
}

func TestEncryptDecryptWithAESGCM_WithAAD(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	plaintext := []byte("data with aad")
	aad := []byte("additional data")

	ct, err := encryptWithAESGCM(plaintext, key, aad, nil, "")
	require.NoError(t, err)

	// Decrypt with correct AAD
	decrypted, err := decryptWithAESGCM(ct, key, aad)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)

	// Decrypt with wrong AAD
	_, err = decryptWithAESGCM(ct, key, []byte("wrong-aad"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decryption failed")
}

// --- Encapsulate with bad public key ---

func TestMLKEMPrivateKey_Encapsulate_InvalidPubKey(t *testing.T) {
	qb, _ := newTestBackend(t)
	defer func() { _ = qb.Close() }()

	attrs := mlkemAttrs("bad-pubkey", types.QuantumAlgorithmMLKEM768)
	privKey, err := qb.GenerateKey(attrs)
	require.NoError(t, err)

	mlkemKey := privKey.(*MLKEMPrivateKey)
	_, _, err = mlkemKey.Encapsulate([]byte("invalid-public-key"))
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrEncapsulationFailed)
}

// --- loadMLDSAKey error paths ---

func TestLoadMLDSAKey_BadSeedSize(t *testing.T) {
	qb, _ := newTestBackend(t)
	meta := &keyMetadata{
		Algorithm: "ML-DSA-44",
		Seed:      []byte("too-short"),
	}
	_, err := qb.loadMLDSAKey(meta)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid ML-DSA seed size")
}

func TestLoadMLDSAKey_UnsupportedAlgorithm(t *testing.T) {
	qb, _ := newTestBackend(t)
	meta := &keyMetadata{
		Algorithm: "ML-DSA-999",
		Seed:      make([]byte, mldsaSeedSize),
	}
	_, err := qb.loadMLDSAKey(meta)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrUnsupportedAlgorithm)
}

// --- loadMLKEMKey error paths ---

func TestLoadMLKEMKey_UnsupportedAlgorithm(t *testing.T) {
	qb, _ := newTestBackend(t)
	meta := &keyMetadata{
		Algorithm: "ML-KEM-999",
		Seed:      make([]byte, 64),
	}
	_, err := qb.loadMLKEMKey(meta, "test-id")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrUnsupportedAlgorithm)
}

func TestLoadMLKEMKey_BadSeedSize(t *testing.T) {
	qb, _ := newTestBackend(t)
	// ML-KEM-768 seed should be exactly 64 bytes. Passing 10 bytes triggers
	// the "failed to reconstruct" error from NewDecapsulationKey768.
	meta := &keyMetadata{
		Algorithm: "ML-KEM-768",
		Seed:      make([]byte, 10),
	}
	_, err := qb.loadMLKEMKey(meta, "test-bad-seed")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to reconstruct ML-KEM key from seed")
}

// --- GetKey with corrupted stored data ---

func TestGetKey_CorruptedMetadata(t *testing.T) {
	qb, store := newTestBackend(t)
	defer func() { _ = qb.Close() }()

	attrs := mldsaAttrs("corrupt-key", types.QuantumAlgorithmMLDSA65)

	// Manually store corrupted data
	keyID := attrs.ID()
	err := storage.SaveKey(context.Background(), store, keyID, []byte("not-valid-json"))
	require.NoError(t, err)

	_, err = qb.GetKey(attrs)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to deserialize key metadata")
}

// --- GetKey with unsupported algorithm in stored metadata ---

func TestGetKey_StoredUnsupportedAlgorithm(t *testing.T) {
	qb, store := newTestBackend(t)
	defer func() { _ = qb.Close() }()

	attrs := &types.KeyAttributes{
		CN:        "stored-unsupported",
		KeyType:   types.KeyTypeSigning,
		StoreType: types.StoreQuantum,
		QuantumAttributes: &types.QuantumAttributes{
			Algorithm: types.QuantumAlgorithm("ML-DSA-65"),
		},
	}

	// Store valid JSON with unsupported algorithm prefix
	keyID := attrs.ID()
	meta := `{"algorithm":"UNKNOWN-ALG","public_key":"AAAA","seed":"BBBB"}`
	err := storage.SaveKey(context.Background(), store, keyID, []byte(meta))
	require.NoError(t, err)

	_, err = qb.GetKey(attrs)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrUnsupportedAlgorithm))
}

// --- Encrypt/Decrypt with failed Encapsulate/Decapsulate ---

func TestMLKEMPrivateKey_Encrypt_EncapsulationError(t *testing.T) {
	qb, _ := newTestBackend(t)
	defer func() { _ = qb.Close() }()

	attrs := mlkemAttrs("enc-err", types.QuantumAlgorithmMLKEM768)
	privKey, err := qb.GenerateKey(attrs)
	require.NoError(t, err)

	mlkemKey := privKey.(*MLKEMPrivateKey)

	// Pass an invalid public key to trigger encapsulation error
	_, _, err = mlkemKey.Encrypt([]byte("plaintext"), []byte("bad-pubkey"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "encapsulation failed")
}

func TestMLKEMPrivateKey_EncryptWithAAD_EncapsulationError(t *testing.T) {
	qb, _ := newTestBackend(t)
	defer func() { _ = qb.Close() }()

	attrs := mlkemAttrs("enc-aad-err", types.QuantumAlgorithmMLKEM768)
	privKey, err := qb.GenerateKey(attrs)
	require.NoError(t, err)

	mlkemKey := privKey.(*MLKEMPrivateKey)

	// Pass an invalid public key to trigger encapsulation error
	_, _, err = mlkemKey.EncryptWithAAD([]byte("plaintext"), []byte("aad"), []byte("bad-pubkey"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "encapsulation failed")
}

func TestMLKEMPrivateKey_Decrypt_WrongSizeKemCiphertext(t *testing.T) {
	qb, _ := newTestBackend(t)
	defer func() { _ = qb.Close() }()

	attrs := mlkemAttrs("dec-wrong-size", types.QuantumAlgorithmMLKEM768)
	privKey, err := qb.GenerateKey(attrs)
	require.NoError(t, err)

	mlkemKey := privKey.(*MLKEMPrivateKey)

	// Wrong-size KEM ciphertext triggers Decapsulate error (expects 1088 bytes)
	shortKemCt := []byte("too-short")
	_, err = mlkemKey.Decrypt(shortKemCt, []byte("enc-data"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decapsulation failed")
}

func TestMLKEMPrivateKey_Decrypt_WrongSharedSecret(t *testing.T) {
	qb, _ := newTestBackend(t)
	defer func() { _ = qb.Close() }()

	attrs := mlkemAttrs("dec-bad-secret", types.QuantumAlgorithmMLKEM768)
	privKey, err := qb.GenerateKey(attrs)
	require.NoError(t, err)

	mlkemKey := privKey.(*MLKEMPrivateKey)

	// Correct-size KEM ciphertext (1088 bytes) will succeed in Decapsulate
	// (implicit rejection) but produce a wrong shared secret, causing
	// AES-GCM decryption to fail.
	badKemCt := make([]byte, 1088)
	validEncData := make([]byte, 40) // at least nonce + tag

	_, err = mlkemKey.Decrypt(badKemCt, validEncData)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decryption failed")
}

func TestMLKEMPrivateKey_DecryptWithAAD_WrongSizeKemCiphertext(t *testing.T) {
	qb, _ := newTestBackend(t)
	defer func() { _ = qb.Close() }()

	attrs := mlkemAttrs("dec-aad-wrong-size", types.QuantumAlgorithmMLKEM768)
	privKey, err := qb.GenerateKey(attrs)
	require.NoError(t, err)

	mlkemKey := privKey.(*MLKEMPrivateKey)

	// Wrong-size KEM ciphertext triggers Decapsulate error
	shortKemCt := []byte("too-short")
	_, err = mlkemKey.DecryptWithAAD(shortKemCt, []byte("enc-data"), []byte("aad"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decapsulation failed")
}

func TestMLKEMPrivateKey_DecryptWithAAD_WrongSharedSecret(t *testing.T) {
	qb, _ := newTestBackend(t)
	defer func() { _ = qb.Close() }()

	attrs := mlkemAttrs("dec-aad-bad-secret", types.QuantumAlgorithmMLKEM768)
	privKey, err := qb.GenerateKey(attrs)
	require.NoError(t, err)

	mlkemKey := privKey.(*MLKEMPrivateKey)

	// Same as above but with AAD path
	badKemCt := make([]byte, 1088)
	validEncData := make([]byte, 40)

	_, err = mlkemKey.DecryptWithAAD(badKemCt, validEncData, []byte("aad"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decryption failed")
}

// --- MLKEMPublicKey.Bytes() ---

func TestMLKEMPublicKey_Bytes(t *testing.T) {
	pk := &MLKEMPublicKey{
		Algorithm: "ML-KEM-768",
		Key:       []byte{1, 2, 3, 4},
	}
	assert.Equal(t, []byte{1, 2, 3, 4}, pk.Bytes())
}

// --- Decapsulate with invalid ciphertext size ---

func TestMLKEMPrivateKey_Decapsulate_768_InvalidSize(t *testing.T) {
	qb, _ := newTestBackend(t)
	defer func() { _ = qb.Close() }()

	attrs := mlkemAttrs("decap-bad-size", types.QuantumAlgorithmMLKEM768)
	privKey, err := qb.GenerateKey(attrs)
	require.NoError(t, err)

	mlkemKey := privKey.(*MLKEMPrivateKey)

	// ML-KEM-768 expects exactly 1088-byte ciphertext; a wrong-size input
	// should trigger ErrDecapsulationFailed.
	_, err = mlkemKey.Decapsulate([]byte("too-short"))
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrDecapsulationFailed)
}

func TestMLKEMPrivateKey_Decapsulate_1024_InvalidSize(t *testing.T) {
	qb, _ := newTestBackend(t)
	defer func() { _ = qb.Close() }()

	attrs := mlkemAttrs("decap-bad-1024", types.QuantumAlgorithmMLKEM1024)
	privKey, err := qb.GenerateKey(attrs)
	require.NoError(t, err)

	mlkemKey := privKey.(*MLKEMPrivateKey)

	// ML-KEM-1024 expects exactly 1568-byte ciphertext
	_, err = mlkemKey.Decapsulate([]byte("too-short"))
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrDecapsulationFailed)
}

// --- encryptWithAESGCM with no tracker (nil tracker and empty keyID) ---

func TestEncryptWithAESGCM_NilTracker(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	plaintext := []byte("no tracker test")

	ct, err := encryptWithAESGCM(plaintext, key, nil, nil, "")
	require.NoError(t, err)
	assert.NotEmpty(t, ct)

	// Verify we can decrypt it
	decrypted, err := decryptWithAESGCM(ct, key, nil)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

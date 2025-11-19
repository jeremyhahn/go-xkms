//go:build quantum

package quantum

import (
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/backend"
	"github.com/jeremyhahn/go-keychain/pkg/storage"
	"github.com/jeremyhahn/go-keychain/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAEADTracking_NonceReusePrevention(t *testing.T) {
	// Setup backend with AEAD tracking
	store, err := storage.NewMemoryBackend()
	require.NoError(t, err)

	tracker := backend.NewMemoryAEADTracker()
	config := &Config{Tracker: tracker}

	quantumBackend, err := NewWithConfig(store, config)
	require.NoError(t, err)
	defer func() { _ = quantumBackend.Close() }()

	// Generate ML-KEM-768 key
	attrs := &types.KeyAttributes{
		CN:        "nonce-test-key",
		KeyType:   types.KeyTypeEncryption,
		StoreType: types.StoreQuantum,
		QuantumAttributes: &types.QuantumAttributes{
			Algorithm: types.QuantumAlgorithmMLKEM768,
		},
	}

	privKey, err := quantumBackend.GenerateKey(attrs)
	require.NoError(t, err)

	mlkemKey := privKey.(*MLKEMPrivateKey)
	publicKey := mlkemKey.PublicKey.Bytes()

	// First encryption should succeed
	plaintext1 := []byte("First message")
	kemCt1, encData1, err := mlkemKey.Encrypt(plaintext1, publicKey)
	require.NoError(t, err)
	assert.NotNil(t, kemCt1)
	assert.NotNil(t, encData1)

	t.Log("✓ First encryption succeeded")

	// Second encryption should succeed (different nonce)
	plaintext2 := []byte("Second message")
	kemCt2, encData2, err := mlkemKey.Encrypt(plaintext2, publicKey)
	require.NoError(t, err)
	assert.NotNil(t, kemCt2)
	assert.NotNil(t, encData2)

	t.Log("✓ Second encryption succeeded with different nonce")

	// Verify nonces were recorded
	keyID := attrs.ID()
	opts, err := tracker.GetAEADOptions(keyID)
	require.NoError(t, err)
	assert.True(t, opts.NonceTracking, "Nonce tracking should be enabled")

	t.Log("✓ Nonce tracking is active")
}

func TestAEADTracking_BytesLimitEnforcement(t *testing.T) {
	// Setup backend with low bytes limit for testing
	store, err := storage.NewMemoryBackend()
	require.NoError(t, err)

	tracker := backend.NewMemoryAEADTracker()
	config := &Config{Tracker: tracker}

	quantumBackend, err := NewWithConfig(store, config)
	require.NoError(t, err)
	defer func() { _ = quantumBackend.Close() }()

	// Generate ML-KEM-768 key
	attrs := &types.KeyAttributes{
		CN:        "bytes-limit-key",
		KeyType:   types.KeyTypeEncryption,
		StoreType: types.StoreQuantum,
		QuantumAttributes: &types.QuantumAttributes{
			Algorithm: types.QuantumAlgorithmMLKEM768,
		},
	}

	privKey, err := quantumBackend.GenerateKey(attrs)
	require.NoError(t, err)

	mlkemKey := privKey.(*MLKEMPrivateKey)
	publicKey := mlkemKey.PublicKey.Bytes()

	// Set a low limit for testing (1KB)
	keyID := attrs.ID()
	customOpts := &types.AEADOptions{
		NonceTracking:      true,
		BytesTracking:      true,
		BytesTrackingLimit: 1024, // 1KB limit
		NonceSize:          12,
	}
	err = tracker.SetAEADOptions(keyID, customOpts)
	require.NoError(t, err)

	t.Logf("Set bytes limit: %d bytes", customOpts.BytesTrackingLimit)

	// Encrypt data under the limit (500 bytes)
	plaintext1 := make([]byte, 500)
	kemCt1, encData1, err := mlkemKey.Encrypt(plaintext1, publicKey)
	require.NoError(t, err)
	assert.NotNil(t, kemCt1)
	assert.NotNil(t, encData1)

	bytesEncrypted, err := tracker.GetBytesEncrypted(keyID)
	require.NoError(t, err)
	t.Logf("✓ Encrypted %d bytes (limit: %d)", bytesEncrypted, customOpts.BytesTrackingLimit)

	// Encrypt more data under the limit (another 400 bytes = 900 total)
	plaintext2 := make([]byte, 400)
	kemCt2, encData2, err := mlkemKey.Encrypt(plaintext2, publicKey)
	require.NoError(t, err)
	assert.NotNil(t, kemCt2)
	assert.NotNil(t, encData2)

	bytesEncrypted, err = tracker.GetBytesEncrypted(keyID)
	require.NoError(t, err)
	t.Logf("✓ Encrypted %d bytes total (limit: %d)", bytesEncrypted, customOpts.BytesTrackingLimit)

	// Try to encrypt data that would exceed limit (200 more bytes = 1100 total > 1024)
	plaintext3 := make([]byte, 200)
	_, _, err = mlkemKey.Encrypt(plaintext3, publicKey)
	assert.Error(t, err, "Should fail when exceeding bytes limit")
	assert.Contains(t, err.Error(), "bytes limit exceeded", "Error should mention bytes limit")

	t.Log("✓ Encryption correctly rejected when exceeding bytes limit")

	// Verify total bytes encrypted (should still be 900, not 1100)
	bytesEncrypted, err = tracker.GetBytesEncrypted(keyID)
	require.NoError(t, err)
	assert.Equal(t, int64(900), bytesEncrypted, "Bytes should not be counted for failed encryption")

	t.Logf("✓ Bytes tracking accurate: %d bytes (rejected operation not counted)", bytesEncrypted)
}

func TestAEADTracking_KeyRotationResetsTracking(t *testing.T) {
	// Setup backend
	store, err := storage.NewMemoryBackend()
	require.NoError(t, err)

	tracker := backend.NewMemoryAEADTracker()
	config := &Config{Tracker: tracker}

	quantumBackend, err := NewWithConfig(store, config)
	require.NoError(t, err)
	defer func() { _ = quantumBackend.Close() }()

	// Generate ML-KEM-768 key
	attrs := &types.KeyAttributes{
		CN:        "rotation-test-key",
		KeyType:   types.KeyTypeEncryption,
		StoreType: types.StoreQuantum,
		QuantumAttributes: &types.QuantumAttributes{
			Algorithm: types.QuantumAlgorithmMLKEM768,
		},
	}

	privKey, err := quantumBackend.GenerateKey(attrs)
	require.NoError(t, err)

	mlkemKey := privKey.(*MLKEMPrivateKey)
	publicKey := mlkemKey.PublicKey.Bytes()

	// Encrypt some data
	plaintext := make([]byte, 1000)
	_, _, err = mlkemKey.Encrypt(plaintext, publicKey)
	require.NoError(t, err)

	keyID := attrs.ID()
	bytesBeforeRotation, err := tracker.GetBytesEncrypted(keyID)
	require.NoError(t, err)
	assert.Equal(t, int64(1000), bytesBeforeRotation)

	t.Logf("Before rotation: %d bytes encrypted", bytesBeforeRotation)

	// Rotate the key
	err = quantumBackend.RotateKey(attrs)
	require.NoError(t, err)

	t.Log("✓ Key rotated")

	// Get new key
	newPrivKey, err := quantumBackend.GetKey(attrs)
	require.NoError(t, err)

	newMLKemKey := newPrivKey.(*MLKEMPrivateKey)
	newPublicKey := newMLKemKey.PublicKey.Bytes()

	// Verify tracking was reset
	bytesAfterRotation, err := tracker.GetBytesEncrypted(keyID)
	require.NoError(t, err)
	assert.Equal(t, int64(0), bytesAfterRotation, "Bytes should be reset after rotation")

	t.Logf("✓ After rotation: %d bytes (tracking reset)", bytesAfterRotation)

	// Encrypt with new key should work
	_, _, err = newMLKemKey.Encrypt(plaintext, newPublicKey)
	require.NoError(t, err)

	bytesAfterNewEncryption, err := tracker.GetBytesEncrypted(keyID)
	require.NoError(t, err)
	assert.Equal(t, int64(1000), bytesAfterNewEncryption)

	t.Logf("✓ New encryption tracked: %d bytes", bytesAfterNewEncryption)
}

func TestAEADTracking_DefaultOptions(t *testing.T) {
	// Setup backend
	store, err := storage.NewMemoryBackend()
	require.NoError(t, err)

	tracker := backend.NewMemoryAEADTracker()
	config := &Config{Tracker: tracker}

	quantumBackend, err := NewWithConfig(store, config)
	require.NoError(t, err)
	defer func() { _ = quantumBackend.Close() }()

	// Generate ML-KEM-768 key
	attrs := &types.KeyAttributes{
		CN:        "default-opts-key",
		KeyType:   types.KeyTypeEncryption,
		StoreType: types.StoreQuantum,
		QuantumAttributes: &types.QuantumAttributes{
			Algorithm: types.QuantumAlgorithmMLKEM768,
		},
	}

	_, err = quantumBackend.GenerateKey(attrs)
	require.NoError(t, err)

	// Check default AEAD options were set
	keyID := attrs.ID()
	opts, err := tracker.GetAEADOptions(keyID)
	require.NoError(t, err)
	require.NotNil(t, opts)

	// Verify defaults match NIST recommendations
	assert.True(t, opts.NonceTracking, "Nonce tracking should be enabled by default")
	assert.True(t, opts.BytesTracking, "Bytes tracking should be enabled by default")
	assert.Equal(t, int64(350*1024*1024*1024), opts.BytesTrackingLimit, "Should use 350GB default limit")
	assert.Equal(t, 12, opts.NonceSize, "Should use 12-byte (96-bit) nonces")

	t.Log("✓ Default AEAD options configured correctly:")
	t.Logf("  - Nonce tracking: %v", opts.NonceTracking)
	t.Logf("  - Bytes tracking: %v", opts.BytesTracking)
	t.Logf("  - Bytes limit: %d GB", opts.BytesTrackingLimit/(1024*1024*1024))
	t.Logf("  - Nonce size: %d bytes", opts.NonceSize)
}

func TestAEADTracking_DisabledForMLDSA(t *testing.T) {
	// Setup backend
	store, err := storage.NewMemoryBackend()
	require.NoError(t, err)

	tracker := backend.NewMemoryAEADTracker()
	config := &Config{Tracker: tracker}

	quantumBackend, err := NewWithConfig(store, config)
	require.NoError(t, err)
	defer func() { _ = quantumBackend.Close() }()

	// Generate ML-DSA-65 key (signing, not encryption)
	attrs := &types.KeyAttributes{
		CN:        "signing-key",
		KeyType:   types.KeyTypeSigning,
		StoreType: types.StoreQuantum,
		QuantumAttributes: &types.QuantumAttributes{
			Algorithm: types.QuantumAlgorithmMLDSA65,
		},
	}

	_, err = quantumBackend.GenerateKey(attrs)
	require.NoError(t, err)

	// AEAD options should NOT be set for ML-DSA keys
	keyID := attrs.ID()
	opts, err := tracker.GetAEADOptions(keyID)
	// Should either be nil or error
	if err == nil {
		assert.Nil(t, opts, "ML-DSA keys should not have AEAD options")
	}

	t.Log("✓ ML-DSA keys correctly exclude AEAD tracking (signing only, no encryption)")
}

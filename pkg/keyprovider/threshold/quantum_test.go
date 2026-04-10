// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.

package threshold

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestThresholdBackend_GenerateQuantumKey_MLDSA44(t *testing.T) {
	keyStorage := storage.New()
	config := DefaultConfig(keyStorage)
	backend, err := NewBackend(config)
	require.NoError(t, err)
	defer func() { _ = backend.Close() }()

	attrs := &types.KeyAttributes{
		CN:        "test-mldsa44-key",
		KeyType:   types.KeyTypeSigning,
		StoreType: types.StoreThreshold,
		QuantumAttributes: &types.QuantumAttributes{
			Algorithm: types.QuantumAlgorithmMLDSA44,
		},
		ThresholdAttributes: &types.ThresholdAttributes{
			Threshold:    3,
			Total:        5,
			Algorithm:    types.ThresholdAlgorithmShamir,
			Participants: []string{"node1", "node2", "node3", "node4", "node5"},
		},
	}

	privKey, err := backend.GenerateKey(attrs)
	require.NoError(t, err)
	require.NotNil(t, privKey)

	// Verify the returned key is the correct circl type
	_, ok := privKey.(*mldsa44.PrivateKey)
	assert.True(t, ok, "expected *mldsa44.PrivateKey, got %T", privKey)

	// Verify shares were stored
	keyID := backend.getKeyID(attrs)
	for i := 1; i <= 5; i++ {
		shareKey := "threshold/shares/" + keyID + "/share-" + string(rune('0'+i))
		exists, err := keyStorage.Exists(context.Background(), shareKey)
		require.NoError(t, err)
		t.Logf("Quantum share %d exists: %v", i, exists)
	}
}

func TestThresholdBackend_GenerateQuantumKey_MLDSA65(t *testing.T) {
	keyStorage := storage.New()
	config := DefaultConfig(keyStorage)
	backend, err := NewBackend(config)
	require.NoError(t, err)
	defer func() { _ = backend.Close() }()

	attrs := &types.KeyAttributes{
		CN:        "test-mldsa65-key",
		KeyType:   types.KeyTypeSigning,
		StoreType: types.StoreThreshold,
		QuantumAttributes: &types.QuantumAttributes{
			Algorithm: types.QuantumAlgorithmMLDSA65,
		},
		ThresholdAttributes: &types.ThresholdAttributes{
			Threshold:    2,
			Total:        3,
			Algorithm:    types.ThresholdAlgorithmShamir,
			Participants: []string{"node1", "node2", "node3"},
		},
	}

	privKey, err := backend.GenerateKey(attrs)
	require.NoError(t, err)
	require.NotNil(t, privKey)

	_, ok := privKey.(*mldsa65.PrivateKey)
	assert.True(t, ok, "expected *mldsa65.PrivateKey, got %T", privKey)
}

func TestThresholdBackend_GenerateQuantumKey_MLDSA87(t *testing.T) {
	keyStorage := storage.New()
	config := DefaultConfig(keyStorage)
	backend, err := NewBackend(config)
	require.NoError(t, err)
	defer func() { _ = backend.Close() }()

	attrs := &types.KeyAttributes{
		CN:        "test-mldsa87-key",
		KeyType:   types.KeyTypeSigning,
		StoreType: types.StoreThreshold,
		QuantumAttributes: &types.QuantumAttributes{
			Algorithm: types.QuantumAlgorithmMLDSA87,
		},
		ThresholdAttributes: &types.ThresholdAttributes{
			Threshold:    3,
			Total:        5,
			Algorithm:    types.ThresholdAlgorithmShamir,
			Participants: []string{"node1", "node2", "node3", "node4", "node5"},
		},
	}

	privKey, err := backend.GenerateKey(attrs)
	require.NoError(t, err)
	require.NotNil(t, privKey)

	_, ok := privKey.(*mldsa87.PrivateKey)
	assert.True(t, ok, "expected *mldsa87.PrivateKey, got %T", privKey)
}

func TestThresholdBackend_GenerateQuantumKey_NilAttributes(t *testing.T) {
	keyStorage := storage.New()
	config := DefaultConfig(keyStorage)
	backend, err := NewBackend(config)
	require.NoError(t, err)
	defer func() { _ = backend.Close() }()

	attrs := &types.KeyAttributes{
		CN:        "test-no-quantum",
		KeyType:   types.KeyTypeSigning,
		StoreType: types.StoreThreshold,
		ThresholdAttributes: &types.ThresholdAttributes{
			Threshold:    3,
			Total:        5,
			Algorithm:    types.ThresholdAlgorithmShamir,
			Participants: []string{"node1", "node2", "node3", "node4", "node5"},
		},
	}

	_, err = backend.generateQuantumKey(attrs)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "quantum attributes required")
}

func TestThresholdBackend_GenerateQuantumKey_UnsupportedMLKEM(t *testing.T) {
	keyStorage := storage.New()
	config := DefaultConfig(keyStorage)
	backend, err := NewBackend(config)
	require.NoError(t, err)
	defer func() { _ = backend.Close() }()

	attrs := &types.KeyAttributes{
		CN:        "test-mlkem",
		KeyType:   types.KeyTypeSigning,
		StoreType: types.StoreThreshold,
		QuantumAttributes: &types.QuantumAttributes{
			Algorithm: types.QuantumAlgorithm("ML-KEM-768"),
		},
		ThresholdAttributes: &types.ThresholdAttributes{
			Threshold:    3,
			Total:        5,
			Algorithm:    types.ThresholdAlgorithmShamir,
			Participants: []string{"node1", "node2", "node3", "node4", "node5"},
		},
	}

	_, err = backend.generateQuantumKey(attrs)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "only ML-DSA algorithms are supported")
}

func TestThresholdBackend_GenerateQuantumKey_UnsupportedLevel(t *testing.T) {
	keyStorage := storage.New()
	config := DefaultConfig(keyStorage)
	backend, err := NewBackend(config)
	require.NoError(t, err)
	defer func() { _ = backend.Close() }()

	attrs := &types.KeyAttributes{
		CN:        "test-bad-level",
		KeyType:   types.KeyTypeSigning,
		StoreType: types.StoreThreshold,
		QuantumAttributes: &types.QuantumAttributes{
			Algorithm: types.QuantumAlgorithm("ML-DSA-99"),
		},
		ThresholdAttributes: &types.ThresholdAttributes{
			Threshold:    3,
			Total:        5,
			Algorithm:    types.ThresholdAlgorithmShamir,
			Participants: []string{"node1", "node2", "node3", "node4", "node5"},
		},
	}

	_, err = backend.generateQuantumKey(attrs)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported ML-DSA algorithm")
}

func TestThresholdSigner_Quantum_MLDSA44(t *testing.T) {
	keyStorage := storage.New()
	config := DefaultConfig(keyStorage)
	backend, err := NewBackend(config)
	require.NoError(t, err)
	defer func() { _ = backend.Close() }()

	attrs := &types.KeyAttributes{
		CN:        "test-quantum-signer",
		KeyType:   types.KeyTypeSigning,
		StoreType: types.StoreThreshold,
		QuantumAttributes: &types.QuantumAttributes{
			Algorithm: types.QuantumAlgorithmMLDSA44,
		},
		ThresholdAttributes: &types.ThresholdAttributes{
			Threshold:    3,
			Total:        5,
			Algorithm:    types.ThresholdAlgorithmShamir,
			Participants: []string{"node1", "node2", "node3", "node4", "node5"},
		},
	}

	privKey, err := backend.GenerateKey(attrs)
	require.NoError(t, err)
	require.NotNil(t, privKey)

	signer, err := backend.Signer(attrs)
	require.NoError(t, err)
	require.NotNil(t, signer)

	// ML-DSA signs the full message, not just the hash.
	// crypto.Hash(0) signals to Sign that no prehash was done.
	message := []byte("test message for threshold quantum signing")
	signature, err := signer.Sign(rand.Reader, message, crypto.Hash(0))
	require.NoError(t, err)
	require.NotEmpty(t, signature)

	// Verify the signature using the public key
	pubKey := signer.Public()
	require.NotNil(t, pubKey)
	pk, ok := pubKey.(*mldsa44.PublicKey)
	require.True(t, ok, "expected *mldsa44.PublicKey, got %T", pubKey)
	assert.True(t, mldsa44.Verify(pk, message, nil, signature))

	t.Logf("Threshold quantum signature generated and verified successfully (%d bytes)", len(signature))
}

func TestThresholdSigner_Quantum_MLDSA65_SignVerify(t *testing.T) {
	keyStorage := storage.New()
	config := DefaultConfig(keyStorage)
	config.DefaultThreshold = 2
	config.DefaultTotal = 3
	config.Participants = []string{"node1", "node2", "node3"}
	backend, err := NewBackend(config)
	require.NoError(t, err)
	defer func() { _ = backend.Close() }()

	attrs := &types.KeyAttributes{
		CN:        "test-quantum-signer-65",
		KeyType:   types.KeyTypeSigning,
		StoreType: types.StoreThreshold,
		QuantumAttributes: &types.QuantumAttributes{
			Algorithm: types.QuantumAlgorithmMLDSA65,
		},
		ThresholdAttributes: &types.ThresholdAttributes{
			Threshold:    2,
			Total:        3,
			Algorithm:    types.ThresholdAlgorithmShamir,
			Participants: []string{"node1", "node2", "node3"},
		},
	}

	_, err = backend.GenerateKey(attrs)
	require.NoError(t, err)

	signer, err := backend.Signer(attrs)
	require.NoError(t, err)

	message := []byte("ML-DSA-65 threshold test message")
	signature, err := signer.Sign(rand.Reader, message, crypto.Hash(0))
	require.NoError(t, err)
	require.NotEmpty(t, signature)

	pubKey := signer.Public()
	require.NotNil(t, pubKey)
	pk, ok := pubKey.(*mldsa65.PublicKey)
	require.True(t, ok)
	assert.True(t, mldsa65.Verify(pk, message, nil, signature))
}

func TestThresholdSigner_Quantum_MLDSA87_SignVerify(t *testing.T) {
	keyStorage := storage.New()
	config := DefaultConfig(keyStorage)
	backend, err := NewBackend(config)
	require.NoError(t, err)
	defer func() { _ = backend.Close() }()

	attrs := &types.KeyAttributes{
		CN:        "test-quantum-signer-87",
		KeyType:   types.KeyTypeSigning,
		StoreType: types.StoreThreshold,
		QuantumAttributes: &types.QuantumAttributes{
			Algorithm: types.QuantumAlgorithmMLDSA87,
		},
		ThresholdAttributes: &types.ThresholdAttributes{
			Threshold:    3,
			Total:        5,
			Algorithm:    types.ThresholdAlgorithmShamir,
			Participants: []string{"node1", "node2", "node3", "node4", "node5"},
		},
	}

	_, err = backend.GenerateKey(attrs)
	require.NoError(t, err)

	signer, err := backend.Signer(attrs)
	require.NoError(t, err)

	message := []byte("ML-DSA-87 threshold test message")
	signature, err := signer.Sign(rand.Reader, message, crypto.Hash(0))
	require.NoError(t, err)
	require.NotEmpty(t, signature)

	pubKey := signer.Public()
	require.NotNil(t, pubKey)
	pk, ok := pubKey.(*mldsa87.PublicKey)
	require.True(t, ok)
	assert.True(t, mldsa87.Verify(pk, message, nil, signature))
}

func TestSupportsQuantum(t *testing.T) {
	assert.True(t, supportsQuantum(), "Quantum support should always be enabled with circl")
}

func TestThresholdBackend_QuantumCapabilities(t *testing.T) {
	keyStorage := storage.New()
	config := DefaultConfig(keyStorage)
	backend, err := NewBackend(config)
	require.NoError(t, err)
	defer func() { _ = backend.Close() }()

	caps := backend.Capabilities()
	assert.True(t, caps.Signing, "should support signing with quantum keys")
	assert.True(t, caps.Keys, "should support key management")
}

func TestMarshalQuantumKey_MLDSA44(t *testing.T) {
	_, sk, err := mldsa44.GenerateKey(rand.Reader)
	require.NoError(t, err)

	keyBytes, err := marshalQuantumKey(sk)
	require.NoError(t, err)
	assert.Equal(t, mldsa44.PrivateKeySize, len(keyBytes))
}

func TestMarshalQuantumKey_MLDSA65(t *testing.T) {
	_, sk, err := mldsa65.GenerateKey(rand.Reader)
	require.NoError(t, err)

	keyBytes, err := marshalQuantumKey(sk)
	require.NoError(t, err)
	assert.Equal(t, mldsa65.PrivateKeySize, len(keyBytes))
}

func TestMarshalQuantumKey_MLDSA87(t *testing.T) {
	_, sk, err := mldsa87.GenerateKey(rand.Reader)
	require.NoError(t, err)

	keyBytes, err := marshalQuantumKey(sk)
	require.NoError(t, err)
	assert.Equal(t, mldsa87.PrivateKeySize, len(keyBytes))
}

func TestMarshalQuantumKey_InvalidKeyType(t *testing.T) {
	_, err := marshalQuantumKey("not-a-quantum-key")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not a quantum ML-DSA private key")
}

func TestUnmarshalQuantumKey_MLDSA44_RoundTrip(t *testing.T) {
	_, sk, err := mldsa44.GenerateKey(rand.Reader)
	require.NoError(t, err)

	keyBytes, err := marshalQuantumKey(sk)
	require.NoError(t, err)

	restored, err := unmarshalQuantumKey(keyBytes, "ML-DSA-44")
	require.NoError(t, err)

	restoredSK, ok := restored.(*mldsa44.PrivateKey)
	require.True(t, ok)

	// Sign with both keys and verify signatures match
	message := []byte("round-trip test message")
	sig1, err := sk.Sign(rand.Reader, message, crypto.Hash(0))
	require.NoError(t, err)

	sig2, err := restoredSK.Sign(rand.Reader, message, crypto.Hash(0))
	require.NoError(t, err)

	// ML-DSA-44 with randomized=false produces deterministic signatures
	// But Sign via crypto.Signer uses SignTo with randomized=false, so they should match
	assert.Equal(t, sig1, sig2, "signatures from original and restored keys should match")
}

func TestUnmarshalQuantumKey_MLDSA65_RoundTrip(t *testing.T) {
	_, sk, err := mldsa65.GenerateKey(rand.Reader)
	require.NoError(t, err)

	keyBytes, err := marshalQuantumKey(sk)
	require.NoError(t, err)

	restored, err := unmarshalQuantumKey(keyBytes, "ML-DSA-65")
	require.NoError(t, err)

	restoredSK, ok := restored.(*mldsa65.PrivateKey)
	require.True(t, ok)

	message := []byte("round-trip test ML-DSA-65")
	sig1, err := sk.Sign(rand.Reader, message, crypto.Hash(0))
	require.NoError(t, err)

	sig2, err := restoredSK.Sign(rand.Reader, message, crypto.Hash(0))
	require.NoError(t, err)
	assert.Equal(t, sig1, sig2)
}

func TestUnmarshalQuantumKey_MLDSA87_RoundTrip(t *testing.T) {
	_, sk, err := mldsa87.GenerateKey(rand.Reader)
	require.NoError(t, err)

	keyBytes, err := marshalQuantumKey(sk)
	require.NoError(t, err)

	restored, err := unmarshalQuantumKey(keyBytes, "ML-DSA-87")
	require.NoError(t, err)

	restoredSK, ok := restored.(*mldsa87.PrivateKey)
	require.True(t, ok)

	message := []byte("round-trip test ML-DSA-87")
	sig1, err := sk.Sign(rand.Reader, message, crypto.Hash(0))
	require.NoError(t, err)

	sig2, err := restoredSK.Sign(rand.Reader, message, crypto.Hash(0))
	require.NoError(t, err)
	assert.Equal(t, sig1, sig2)
}

func TestUnmarshalQuantumKey_InvalidAlgorithm(t *testing.T) {
	_, err := unmarshalQuantumKey([]byte("dummy"), "ML-DSA-99")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported ML-DSA algorithm")
}

func TestUnmarshalQuantumKey_InvalidKeyBytes(t *testing.T) {
	_, err := unmarshalQuantumKey([]byte("too-short"), "ML-DSA-44")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to unmarshal ML-DSA-44 key")

	_, err = unmarshalQuantumKey([]byte("too-short"), "ML-DSA-65")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to unmarshal ML-DSA-65 key")

	_, err = unmarshalQuantumKey([]byte("too-short"), "ML-DSA-87")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to unmarshal ML-DSA-87 key")
}

func TestThresholdSigner_Quantum_KeyReconstruction(t *testing.T) {
	// This test verifies that a key split into shares via Shamir Secret Sharing
	// can be correctly reconstructed and produces valid signatures.
	keyStorage := storage.New()
	config := DefaultConfig(keyStorage)
	backend, err := NewBackend(config)
	require.NoError(t, err)
	defer func() { _ = backend.Close() }()

	attrs := &types.KeyAttributes{
		CN:        "test-reconstruction",
		KeyType:   types.KeyTypeSigning,
		StoreType: types.StoreThreshold,
		QuantumAttributes: &types.QuantumAttributes{
			Algorithm: types.QuantumAlgorithmMLDSA44,
		},
		ThresholdAttributes: &types.ThresholdAttributes{
			Threshold:    3,
			Total:        5,
			Algorithm:    types.ThresholdAlgorithmShamir,
			Participants: []string{"node1", "node2", "node3", "node4", "node5"},
		},
	}

	// Generate the key (splits and stores shares)
	originalKey, err := backend.GenerateKey(attrs)
	require.NoError(t, err)
	require.NotNil(t, originalKey)

	// Get a signer (reconstructs the key from shares)
	signer, err := backend.Signer(attrs)
	require.NoError(t, err)
	require.NotNil(t, signer)

	// Sign a message with the reconstructed key
	message := []byte("key reconstruction verification message")
	_ = sha256.Sum256(message)
	signature, err := signer.Sign(rand.Reader, message, crypto.Hash(0))
	require.NoError(t, err)
	require.NotEmpty(t, signature)

	// Verify the signature using the original key's public component
	originalSigner, ok := originalKey.(crypto.Signer)
	require.True(t, ok)
	originalPK, ok := originalSigner.Public().(*mldsa44.PublicKey)
	require.True(t, ok)
	assert.True(t, mldsa44.Verify(originalPK, message, nil, signature),
		"signature from reconstructed key should verify with original public key")
}

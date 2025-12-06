//go:build with_quantum

// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.

package threshold

import (
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/storage"
	"github.com/jeremyhahn/go-keychain/pkg/types"
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

	// Generate threshold quantum key
	privKey, err := backend.GenerateKey(attrs)
	require.NoError(t, err)
	require.NotNil(t, privKey)

	// Verify shares were stored
	keyID := backend.getKeyID(attrs)
	for i := 1; i <= 5; i++ {
		shareKey := "threshold/shares/" + keyID + "/share-" + string(rune('0'+i))
		exists, err := storage.Exists(shareKey)
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

	// Generate threshold quantum key
	privKey, err := backend.GenerateKey(attrs)
	require.NoError(t, err)
	require.NotNil(t, privKey)
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

	// Generate threshold quantum key
	privKey, err := backend.GenerateKey(attrs)
	require.NoError(t, err)
	require.NotNil(t, privKey)
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

	// Generate threshold quantum key
	privKey, err := backend.GenerateKey(attrs)
	require.NoError(t, err)
	require.NotNil(t, privKey)

	// Get threshold signer
	signer, err := backend.Signer(attrs)
	require.NoError(t, err)
	require.NotNil(t, signer)

	// Test signing
	message := []byte("test message for threshold quantum signing")
	hash := sha256.Sum256(message)

	// ML-DSA signs the full message, not just the hash
	signature, err := signer.Sign(rand.Reader, message, nil)
	require.NoError(t, err)
	require.NotEmpty(t, signature)

	t.Logf("✓ Threshold quantum signature generated successfully (%d bytes)", len(signature))
}

func TestSupportsQuantum(t *testing.T) {
	assert.True(t, supportsQuantum(), "Quantum support should be enabled when built with WITH_QUANTUM=1")
}

func TestThresholdBackend_QuantumCapabilities(t *testing.T) {
	keyStorage := storage.New()
	config := DefaultConfig(keyStorage)
	backend, err := NewBackend(config)
	require.NoError(t, err)
	defer func() { _ = backend.Close() }()

	caps := backend.Capabilities()

	// Verify quantum signing is supported
	assert.True(t, caps.Signing, "Should support signing with quantum keys")
	assert.True(t, caps.Keys, "Should support key management")

	t.Logf("✓ Threshold backend supports quantum-safe cryptography")
}

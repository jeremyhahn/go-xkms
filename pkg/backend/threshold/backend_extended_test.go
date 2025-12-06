// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.

package threshold

import (
	"crypto/x509"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/storage"
	"github.com/jeremyhahn/go-keychain/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ========================================================================
// Test GetKey
// ========================================================================

func TestThresholdBackend_GetKey(t *testing.T) {
	keyStorage := storage.New()
	config := DefaultConfig(keyStorage)
	backend, err := NewBackend(config)
	require.NoError(t, err)
	defer func() { _ = backend.Close() }()

	attrs := &types.KeyAttributes{
		CN:           "test-getkey",
		KeyType:      types.KeyTypeSigning,
		StoreType:    types.StoreThreshold,
		KeyAlgorithm: x509.Ed25519,
	}

	// GetKey should return ErrNotImplemented (requires distributed coordination)
	_, err = backend.GetKey(attrs)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrNotImplemented)
}

func TestThresholdBackend_GetKey_BackendClosed(t *testing.T) {
	keyStorage := storage.New()
	config := DefaultConfig(keyStorage)
	backend, err := NewBackend(config)
	require.NoError(t, err)

	// Close the backend
	err = backend.Close()
	require.NoError(t, err)

	attrs := &types.KeyAttributes{
		CN:           "test",
		KeyType:      types.KeyTypeSigning,
		StoreType:    types.StoreThreshold,
		KeyAlgorithm: x509.Ed25519,
	}

	_, err = backend.GetKey(attrs)
	assert.ErrorIs(t, err, ErrBackendClosed)
}

// ========================================================================
// Test Decrypter
// ========================================================================

func TestThresholdBackend_Decrypter(t *testing.T) {
	keyStorage := storage.New()
	config := DefaultConfig(keyStorage)
	backend, err := NewBackend(config)
	require.NoError(t, err)
	defer func() { _ = backend.Close() }()

	attrs := &types.KeyAttributes{
		CN:           "test-decrypter",
		KeyType:      types.KeyTypeSigning,
		StoreType:    types.StoreThreshold,
		KeyAlgorithm: x509.RSA,
	}

	// Decrypter should return ErrNotImplemented
	_, err = backend.Decrypter(attrs)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrNotImplemented)
}

func TestThresholdBackend_Decrypter_BackendClosed(t *testing.T) {
	keyStorage := storage.New()
	config := DefaultConfig(keyStorage)
	backend, err := NewBackend(config)
	require.NoError(t, err)

	// Close the backend
	err = backend.Close()
	require.NoError(t, err)

	attrs := &types.KeyAttributes{
		CN:           "test",
		KeyType:      types.KeyTypeSigning,
		StoreType:    types.StoreThreshold,
		KeyAlgorithm: x509.RSA,
	}

	_, err = backend.Decrypter(attrs)
	assert.ErrorIs(t, err, ErrBackendClosed)
}

// ========================================================================
// Test RotateKey
// ========================================================================

func TestThresholdBackend_RotateKey(t *testing.T) {
	keyStorage := storage.New()
	config := DefaultConfig(keyStorage)
	backend, err := NewBackend(config)
	require.NoError(t, err)
	defer func() { _ = backend.Close() }()

	attrs := &types.KeyAttributes{
		CN:           "test-rotate",
		KeyType:      types.KeyTypeSigning,
		StoreType:    types.StoreThreshold,
		KeyAlgorithm: x509.Ed25519,
	}

	// RotateKey should return ErrNotImplemented
	err = backend.RotateKey(attrs)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrNotImplemented)
}

func TestThresholdBackend_RotateKey_BackendClosed(t *testing.T) {
	keyStorage := storage.New()
	config := DefaultConfig(keyStorage)
	backend, err := NewBackend(config)
	require.NoError(t, err)

	// Close the backend
	err = backend.Close()
	require.NoError(t, err)

	attrs := &types.KeyAttributes{
		CN:           "test",
		KeyType:      types.KeyTypeSigning,
		StoreType:    types.StoreThreshold,
		KeyAlgorithm: x509.Ed25519,
	}

	err = backend.RotateKey(attrs)
	assert.ErrorIs(t, err, ErrBackendClosed)
}

// ========================================================================
// Test Error Types
// ========================================================================

func TestShareNotFoundError(t *testing.T) {
	err := &ShareNotFoundError{
		KeyID:   "test-key-123",
		ShareID: 3,
	}

	// Test Error method
	errorMsg := err.Error()
	assert.Contains(t, errorMsg, "share 3 not found")
	assert.Contains(t, errorMsg, "test-key-123")

	// Test Unwrap method
	unwrapped := err.Unwrap()
	assert.ErrorIs(t, unwrapped, ErrShareNotFound)
	assert.True(t, errors.Is(err, ErrShareNotFound))
}

func TestInsufficientSharesError(t *testing.T) {
	err := &InsufficientSharesError{
		Have:      2,
		Threshold: 3,
	}

	// Test Error method
	errorMsg := err.Error()
	assert.Contains(t, errorMsg, "have 2")
	assert.Contains(t, errorMsg, "need 3")

	// Test Unwrap method
	unwrapped := err.Unwrap()
	assert.ErrorIs(t, unwrapped, ErrInsufficientShares)
	assert.True(t, errors.Is(err, ErrInsufficientShares))
}

// ========================================================================
// Test additional edge cases
// ========================================================================

func TestThresholdBackend_Signer_BackendClosed(t *testing.T) {
	keyStorage := storage.New()
	config := DefaultConfig(keyStorage)
	backend, err := NewBackend(config)
	require.NoError(t, err)

	// Close the backend
	err = backend.Close()
	require.NoError(t, err)

	attrs := &types.KeyAttributes{
		CN:           "test",
		KeyType:      types.KeyTypeSigning,
		StoreType:    types.StoreThreshold,
		KeyAlgorithm: x509.Ed25519,
	}

	_, err = backend.Signer(attrs)
	assert.ErrorIs(t, err, ErrBackendClosed)
}

func TestThresholdBackend_DeleteKey_BackendClosed(t *testing.T) {
	keyStorage := storage.New()
	config := DefaultConfig(keyStorage)
	backend, err := NewBackend(config)
	require.NoError(t, err)

	// Close the backend
	err = backend.Close()
	require.NoError(t, err)

	attrs := &types.KeyAttributes{
		CN:           "test",
		KeyType:      types.KeyTypeSigning,
		StoreType:    types.StoreThreshold,
		KeyAlgorithm: x509.Ed25519,
	}

	err = backend.DeleteKey(attrs)
	assert.ErrorIs(t, err, ErrBackendClosed)
}

func TestThresholdBackend_Close_Multiple(t *testing.T) {
	keyStorage := storage.New()
	config := DefaultConfig(keyStorage)
	backend, err := NewBackend(config)
	require.NoError(t, err)

	// First close should succeed
	err = backend.Close()
	assert.NoError(t, err)

	// Second close should be idempotent (return nil)
	err = backend.Close()
	assert.NoError(t, err)
}

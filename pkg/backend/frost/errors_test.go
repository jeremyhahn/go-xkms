//go:build frost

// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.

package frost

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSentinelErrors(t *testing.T) {
	// Test that all sentinel errors are defined and distinct
	sentinelErrors := []error{
		ErrBackendClosed,
		ErrKeyNotFound,
		ErrKeyAlreadyExists,
		ErrInsufficientShares,
		ErrNonceAlreadyUsed,
		ErrNonceNotFound,
		ErrInvalidSignature,
		ErrInvalidCommitment,
		ErrInvalidShare,
		ErrSessionNotFound,
		ErrSessionExpired,
		ErrNotImplemented,
		ErrInvalidConfig,
		ErrInvalidAttributes,
		ErrUnsupportedAlgorithm,
		ErrInvalidParticipant,
		ErrDKGFailed,
		ErrAggregationFailed,
		ErrDecryptionNotSupported,
	}

	for i, err := range sentinelErrors {
		require.NotNil(t, err, "Sentinel error %d should not be nil", i)
		assert.NotEmpty(t, err.Error(), "Sentinel error %d should have a message", i)
	}

	// Verify uniqueness
	seen := make(map[string]bool)
	for _, err := range sentinelErrors {
		msg := err.Error()
		assert.False(t, seen[msg], "Duplicate error message: %s", msg)
		seen[msg] = true
	}
}

func TestKeyNotFoundError(t *testing.T) {
	err := &KeyNotFoundError{KeyID: "test-key"}

	// Test Error() method
	assert.Contains(t, err.Error(), "test-key")
	assert.Contains(t, err.Error(), "key not found")

	// Test Unwrap() method
	assert.True(t, errors.Is(err, ErrKeyNotFound))
}

func TestShareNotFoundError(t *testing.T) {
	err := &ShareNotFoundError{KeyID: "test-key", ParticipantID: 2}

	// Test Error() method
	assert.Contains(t, err.Error(), "test-key")
	assert.Contains(t, err.Error(), "2")
	assert.Contains(t, err.Error(), "share not found")

	// Test Unwrap() method
	assert.True(t, errors.Is(err, ErrKeyNotFound))
}

func TestNonceReuseError(t *testing.T) {
	err := &NonceReuseError{
		KeyID:         "test-key",
		ParticipantID: 3,
		SessionID:     "session-123",
	}

	// Test Error() method
	assert.Contains(t, err.Error(), "test-key")
	assert.Contains(t, err.Error(), "3")
	assert.Contains(t, err.Error(), "session-123")
	assert.Contains(t, err.Error(), "nonce reuse")

	// Test Unwrap() method
	assert.True(t, errors.Is(err, ErrNonceAlreadyUsed))
}

func TestCulpritError(t *testing.T) {
	err := &CulpritError{
		KeyID:    "test-key",
		Culprits: []uint32{2, 3},
		Reason:   "invalid share",
	}

	// Test Error() method
	assert.Contains(t, err.Error(), "test-key")
	assert.Contains(t, err.Error(), "2")
	assert.Contains(t, err.Error(), "3")
	assert.Contains(t, err.Error(), "invalid share")

	// Test Unwrap() method
	assert.True(t, errors.Is(err, ErrInvalidShare))
}

func TestCulpritError_EmptyCulprits(t *testing.T) {
	err := &CulpritError{
		KeyID:    "test-key",
		Culprits: nil,
		Reason:   "unknown error",
	}

	// Should still work with empty culprits
	assert.Contains(t, err.Error(), "test-key")
	assert.Contains(t, err.Error(), "unknown error")
}

func TestConfigError(t *testing.T) {
	err := &ConfigError{
		Field:   "Threshold",
		Message: "must be at least 2",
	}

	// Test Error() method
	assert.Contains(t, err.Error(), "Threshold")
	assert.Contains(t, err.Error(), "must be at least 2")
	assert.Contains(t, err.Error(), "invalid config")

	// Test Unwrap() method
	assert.True(t, errors.Is(err, ErrInvalidConfig))
}

func TestAlgorithmError(t *testing.T) {
	err := &AlgorithmError{Algorithm: "FROST-invalid"}

	// Test Error() method
	assert.Contains(t, err.Error(), "FROST-invalid")
	assert.Contains(t, err.Error(), "unsupported algorithm")

	// Test Unwrap() method
	assert.True(t, errors.Is(err, ErrUnsupportedAlgorithm))
}

func TestErrorWrapping(t *testing.T) {
	// Test that errors can be wrapped and unwrapped correctly
	tests := []struct {
		name      string
		err       error
		wantMatch error
	}{
		{"KeyNotFoundError", &KeyNotFoundError{KeyID: "k"}, ErrKeyNotFound},
		{"ShareNotFoundError", &ShareNotFoundError{KeyID: "k", ParticipantID: 1}, ErrKeyNotFound},
		{"NonceReuseError", &NonceReuseError{KeyID: "k", ParticipantID: 1, SessionID: "s"}, ErrNonceAlreadyUsed},
		{"CulpritError", &CulpritError{KeyID: "k", Reason: "r"}, ErrInvalidShare},
		{"ConfigError", &ConfigError{Field: "f", Message: "m"}, ErrInvalidConfig},
		{"AlgorithmError", &AlgorithmError{Algorithm: "a"}, ErrUnsupportedAlgorithm},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.True(t, errors.Is(tt.err, tt.wantMatch))
		})
	}
}

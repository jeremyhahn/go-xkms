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

package hardware

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestIsCapacityError tests the IsCapacityError helper function
func TestIsCapacityError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "ErrCapacityExceeded",
			err:      ErrCapacityExceeded,
			expected: true,
		},
		{
			name:     "ErrCertificateTooLarge",
			err:      ErrCertificateTooLarge,
			expected: true,
		},
		{
			name:     "ErrTokenFull",
			err:      ErrTokenFull,
			expected: true,
		},
		{
			name:     "WrappedCapacityExceeded",
			err:      fmt.Errorf("wrapper: %w", ErrCapacityExceeded),
			expected: true,
		},
		{
			name:     "WrappedCertificateTooLarge",
			err:      fmt.Errorf("wrapper: %w", ErrCertificateTooLarge),
			expected: true,
		},
		{
			name:     "WrappedTokenFull",
			err:      fmt.Errorf("wrapper: %w", ErrTokenFull),
			expected: true,
		},
		{
			name:     "NonCapacityError",
			err:      ErrNotSupported,
			expected: false,
		},
		{
			name:     "GenericError",
			err:      errors.New("generic error"),
			expected: false,
		},
		{
			name:     "NilError",
			err:      nil,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsCapacityError(tt.err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestIsHardwareError tests the IsHardwareError helper function
func TestIsHardwareError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "ErrHardwareUnavailable",
			err:      ErrHardwareUnavailable,
			expected: true,
		},
		{
			name:     "ErrNVIndexUnavailable",
			err:      ErrNVIndexUnavailable,
			expected: true,
		},
		{
			name:     "ErrNotSupported",
			err:      ErrNotSupported,
			expected: true,
		},
		{
			name:     "WrappedHardwareUnavailable",
			err:      fmt.Errorf("wrapper: %w", ErrHardwareUnavailable),
			expected: true,
		},
		{
			name:     "WrappedNVIndexUnavailable",
			err:      fmt.Errorf("wrapper: %w", ErrNVIndexUnavailable),
			expected: true,
		},
		{
			name:     "WrappedNotSupported",
			err:      fmt.Errorf("wrapper: %w", ErrNotSupported),
			expected: true,
		},
		{
			name:     "NonHardwareError",
			err:      ErrCapacityExceeded,
			expected: false,
		},
		{
			name:     "GenericError",
			err:      errors.New("generic error"),
			expected: false,
		},
		{
			name:     "NilError",
			err:      nil,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsHardwareError(tt.err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestOperationError_Error tests the OperationError.Error method
func TestOperationError_Error(t *testing.T) {
	t.Run("WithUnderlyingError", func(t *testing.T) {
		underlyingErr := errors.New("underlying error")
		opErr := &OperationError{
			Op:  "create certificate object",
			Err: underlyingErr,
		}

		errMsg := opErr.Error()
		assert.Equal(t, "create certificate object: underlying error", errMsg)
	})

	t.Run("WithNilUnderlyingError", func(t *testing.T) {
		opErr := &OperationError{
			Op:  "delete NV index",
			Err: nil,
		}

		errMsg := opErr.Error()
		assert.Equal(t, "operation failed: delete NV index", errMsg)
	})

	t.Run("EmptyOperation", func(t *testing.T) {
		underlyingErr := errors.New("some error")
		opErr := &OperationError{
			Op:  "",
			Err: underlyingErr,
		}

		errMsg := opErr.Error()
		assert.Equal(t, ": some error", errMsg)
	})

	t.Run("BothEmpty", func(t *testing.T) {
		opErr := &OperationError{
			Op:  "",
			Err: nil,
		}

		errMsg := opErr.Error()
		assert.Equal(t, "operation failed: ", errMsg)
	})
}

// TestOperationError_Unwrap tests the OperationError.Unwrap method
func TestOperationError_Unwrap(t *testing.T) {
	t.Run("WithUnderlyingError", func(t *testing.T) {
		underlyingErr := errors.New("underlying error")
		opErr := &OperationError{
			Op:  "test operation",
			Err: underlyingErr,
		}

		unwrapped := opErr.Unwrap()
		assert.Equal(t, underlyingErr, unwrapped)
	})

	t.Run("WithNilUnderlyingError", func(t *testing.T) {
		opErr := &OperationError{
			Op:  "test operation",
			Err: nil,
		}

		unwrapped := opErr.Unwrap()
		assert.Nil(t, unwrapped)
	})

	t.Run("ErrorsIs", func(t *testing.T) {
		opErr := NewOperationError("test", ErrCapacityExceeded)

		assert.True(t, errors.Is(opErr, ErrCapacityExceeded))
	})

	t.Run("ErrorsAs", func(t *testing.T) {
		opErr := NewOperationError("test op", errors.New("specific error"))

		var targetErr *OperationError
		assert.True(t, errors.As(opErr, &targetErr))
		assert.Equal(t, "test op", targetErr.Op)
	})
}

// TestNewOperationError tests the NewOperationError constructor
func TestNewOperationError(t *testing.T) {
	t.Run("WithError", func(t *testing.T) {
		underlyingErr := errors.New("test error")
		opErr := NewOperationError("create key", underlyingErr)

		require.NotNil(t, opErr)

		var target *OperationError
		assert.True(t, errors.As(opErr, &target))
		assert.Equal(t, "create key", target.Op)
		assert.Equal(t, underlyingErr, target.Err)
	})

	t.Run("WithNilError", func(t *testing.T) {
		opErr := NewOperationError("delete index", nil)

		require.NotNil(t, opErr)

		var target *OperationError
		assert.True(t, errors.As(opErr, &target))
		assert.Equal(t, "delete index", target.Op)
		assert.Nil(t, target.Err)
	})

	t.Run("ChainedOperationErrors", func(t *testing.T) {
		innerErr := NewOperationError("inner op", errors.New("root cause"))
		outerErr := NewOperationError("outer op", innerErr)

		// Should be able to unwrap to inner
		assert.True(t, errors.Is(outerErr, innerErr))

		// Should contain correct message
		assert.Contains(t, outerErr.Error(), "outer op")
		assert.Contains(t, outerErr.Error(), "inner op")
	})
}

// TestAllSentinelErrors verifies all sentinel errors are defined
func TestAllSentinelErrors(t *testing.T) {
	sentinelErrors := []struct {
		name string
		err  error
	}{
		{"ErrCapacityExceeded", ErrCapacityExceeded},
		{"ErrCertificateTooLarge", ErrCertificateTooLarge},
		{"ErrNotSupported", ErrNotSupported},
		{"ErrHardwareUnavailable", ErrHardwareUnavailable},
		{"ErrNVIndexUnavailable", ErrNVIndexUnavailable},
		{"ErrStorageClosed", ErrStorageClosed},
		{"ErrInvalidCertificate", ErrInvalidCertificate},
		{"ErrTokenFull", ErrTokenFull},
		{"ErrNilContext", ErrNilContext},
		{"ErrInvalidSession", ErrInvalidSession},
		{"ErrNilTPM", ErrNilTPM},
		{"ErrInvalidBaseIndex", ErrInvalidBaseIndex},
		{"ErrInvalidCertSize", ErrInvalidCertSize},
		{"ErrNilStorage", ErrNilStorage},
	}

	for _, se := range sentinelErrors {
		t.Run(se.name, func(t *testing.T) {
			assert.NotNil(t, se.err)
			assert.NotEmpty(t, se.err.Error())
		})
	}
}

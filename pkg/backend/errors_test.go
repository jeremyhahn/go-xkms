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

package backend

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestErrorVariables ensures all error variables are properly defined
// and have meaningful messages.
func TestErrorVariables(t *testing.T) {
	tests := []struct {
		name    string
		err     error
		wantMsg string
	}{
		{
			name:    "ErrFileAlreadyExists",
			err:     ErrFileAlreadyExists,
			wantMsg: "backend: file already exists",
		},
		{
			name:    "ErrFileNotFound",
			err:     ErrFileNotFound,
			wantMsg: "backend: file not found",
		},
		{
			name:    "ErrInvalidKeyType",
			err:     ErrInvalidKeyType,
			wantMsg: "backend: invalid key type",
		},
		{
			name:    "ErrInvalidKeyPartition",
			err:     ErrInvalidKeyPartition,
			wantMsg: "backend: invalid key partition",
		},
		{
			name:    "ErrInvalidExtension",
			err:     ErrInvalidExtension,
			wantMsg: "backend: invalid extension",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.NotNil(t, tt.err, "Error should not be nil")
			assert.Equal(t, tt.wantMsg, tt.err.Error(), "Error message should match")
		})
	}
}

// TestErrorComparison ensures errors can be compared using errors.Is
func TestErrorComparison(t *testing.T) {
	tests := []struct {
		name   string
		err1   error
		err2   error
		wantIs bool
	}{
		{
			name:   "Same error - ErrFileAlreadyExists",
			err1:   ErrFileAlreadyExists,
			err2:   ErrFileAlreadyExists,
			wantIs: true,
		},
		{
			name:   "Same error - ErrFileNotFound",
			err1:   ErrFileNotFound,
			err2:   ErrFileNotFound,
			wantIs: true,
		},
		{
			name:   "Different errors",
			err1:   ErrFileAlreadyExists,
			err2:   ErrFileNotFound,
			wantIs: false,
		},
		{
			name:   "ErrInvalidKeyType vs ErrInvalidKeyPartition",
			err1:   ErrInvalidKeyType,
			err2:   ErrInvalidKeyPartition,
			wantIs: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := errors.Is(tt.err1, tt.err2)
			assert.Equal(t, tt.wantIs, result, "errors.Is comparison should match expected result")
		})
	}
}

// TestErrorUniqueness ensures all error messages are unique
func TestErrorUniqueness(t *testing.T) {
	allErrors := []error{
		ErrFileAlreadyExists,
		ErrFileNotFound,
		ErrInvalidKeyType,
		ErrInvalidKeyPartition,
		ErrInvalidExtension,
	}

	messages := make(map[string]bool)
	for _, err := range allErrors {
		msg := err.Error()
		assert.False(t, messages[msg], "Error message should be unique: %s", msg)
		messages[msg] = true
	}

	assert.Equal(t, len(allErrors), len(messages), "All error messages should be unique")
}

// TestErrorWrapping tests that errors can be wrapped and unwrapped correctly
func TestErrorWrapping(t *testing.T) {
	tests := []struct {
		name      string
		baseErr   error
		wrapMsg   string
		checkWith error
	}{
		{
			name:      "Wrapped ErrFileNotFound",
			baseErr:   ErrFileNotFound,
			wrapMsg:   "failed to load key",
			checkWith: ErrFileNotFound,
		},
		{
			name:      "Wrapped ErrInvalidKeyType",
			baseErr:   ErrInvalidKeyType,
			wrapMsg:   "validation failed",
			checkWith: ErrInvalidKeyType,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wrappedErr := errors.Join(errors.New(tt.wrapMsg), tt.baseErr)
			assert.True(t, errors.Is(wrappedErr, tt.checkWith), "Wrapped error should be identifiable with errors.Is")
		})
	}
}

// TestErrorConstants verifies error constants maintain backward compatibility
func TestErrorConstants(t *testing.T) {
	// This test ensures error constants don't change accidentally,
	// which could break existing code that depends on exact error messages
	t.Run("Error messages have backend prefix", func(t *testing.T) {
		errors := []error{
			ErrFileAlreadyExists,
			ErrFileNotFound,
			ErrInvalidKeyType,
			ErrInvalidKeyPartition,
			ErrInvalidExtension,
		}

		for _, err := range errors {
			msg := err.Error()
			assert.Contains(t, msg, "backend:", "Error message should contain 'backend:' prefix")
		}
	})
}

// TestErrorInSwitch tests that errors can be used in switch statements
func TestErrorInSwitch(t *testing.T) {
	testCases := []struct {
		name     string
		err      error
		expected string
	}{
		{
			name:     "Handle ErrFileAlreadyExists",
			err:      ErrFileAlreadyExists,
			expected: "file_exists",
		},
		{
			name:     "Handle ErrFileNotFound",
			err:      ErrFileNotFound,
			expected: "not_found",
		},
		{
			name:     "Handle ErrInvalidKeyType",
			err:      ErrInvalidKeyType,
			expected: "invalid_type",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var result string
			switch {
			case errors.Is(tc.err, ErrFileAlreadyExists):
				result = "file_exists"
			case errors.Is(tc.err, ErrFileNotFound):
				result = "not_found"
			case errors.Is(tc.err, ErrInvalidKeyType):
				result = "invalid_type"
			case errors.Is(tc.err, ErrInvalidKeyPartition):
				result = "invalid_partition"
			case errors.Is(tc.err, ErrInvalidExtension):
				result = "invalid_extension"
			default:
				result = "unknown"
			}
			assert.Equal(t, tc.expected, result, "Error should be handled correctly in switch")
		})
	}
}

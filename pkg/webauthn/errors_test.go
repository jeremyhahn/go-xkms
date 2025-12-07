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

package webauthn

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestWebAuthnError_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      *WebAuthnError
		expected string
	}{
		{
			name:     "with operation",
			err:      &WebAuthnError{Op: "get user", Err: ErrUserNotFound},
			expected: "get user: user not found",
		},
		{
			name:     "without operation",
			err:      &WebAuthnError{Err: ErrUserNotFound},
			expected: "user not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.err.Error())
		})
	}
}

func TestWebAuthnError_Unwrap(t *testing.T) {
	err := &WebAuthnError{Op: "test", Err: ErrUserNotFound}
	assert.Equal(t, ErrUserNotFound, err.Unwrap())
}

func TestWebAuthnError_Is(t *testing.T) {
	err := &WebAuthnError{Op: "test", Err: ErrUserNotFound}

	assert.True(t, err.Is(ErrUserNotFound))
	assert.False(t, err.Is(ErrCredentialNotFound))
}

func TestNewError(t *testing.T) {
	err := NewError("operation", ErrSessionExpired)

	var waErr *WebAuthnError
	assert.True(t, errors.As(err, &waErr))
	assert.Equal(t, "operation", waErr.Op)
	assert.Equal(t, ErrSessionExpired, waErr.Err)
}

func TestWrapError(t *testing.T) {
	// Should return nil for nil error
	assert.Nil(t, WrapError("op", nil))

	// Should wrap non-nil error
	wrapped := WrapError("op", ErrInvalidRequest)
	assert.NotNil(t, wrapped)
	assert.Contains(t, wrapped.Error(), "op")
}

func TestIsHelpers(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		isFunc   func(error) bool
		expected bool
	}{
		{
			name:     "IsUserNotFound with ErrUserNotFound",
			err:      ErrUserNotFound,
			isFunc:   IsUserNotFound,
			expected: true,
		},
		{
			name:     "IsUserNotFound with wrapped ErrUserNotFound",
			err:      NewError("op", ErrUserNotFound),
			isFunc:   IsUserNotFound,
			expected: true,
		},
		{
			name:     "IsUserNotFound with different error",
			err:      ErrCredentialNotFound,
			isFunc:   IsUserNotFound,
			expected: false,
		},
		{
			name:     "IsCredentialNotFound with ErrCredentialNotFound",
			err:      ErrCredentialNotFound,
			isFunc:   IsCredentialNotFound,
			expected: true,
		},
		{
			name:     "IsCredentialNotFound with wrapped ErrCredentialNotFound",
			err:      NewError("op", ErrCredentialNotFound),
			isFunc:   IsCredentialNotFound,
			expected: true,
		},
		{
			name:     "IsSessionNotFound with ErrSessionNotFound",
			err:      ErrSessionNotFound,
			isFunc:   IsSessionNotFound,
			expected: true,
		},
		{
			name:     "IsSessionExpired with ErrSessionExpired",
			err:      ErrSessionExpired,
			isFunc:   IsSessionExpired,
			expected: true,
		},
		{
			name:     "IsVerificationFailed with ErrVerificationFailed",
			err:      ErrVerificationFailed,
			isFunc:   IsVerificationFailed,
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.isFunc(tt.err))
		})
	}
}

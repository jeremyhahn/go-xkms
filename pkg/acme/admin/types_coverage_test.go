//go:build codec_json

// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-ca.
//
// go-trusted-ca is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package admin

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsNotFoundError_AllErrors(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
		{
			name:     "certificate not found",
			err:      ErrCertificateNotFound,
			expected: true,
		},
		{
			name:     "account not found",
			err:      ErrAccountNotFound,
			expected: true,
		},
		{
			name:     "order not found",
			err:      ErrOrderNotFound,
			expected: true,
		},
		{
			name:     "tenant not found",
			err:      ErrTenantNotFound,
			expected: true,
		},
		{
			name:     "tenant root CA not found",
			err:      ErrTenantRootCANotFound,
			expected: true,
		},
		{
			name:     "tenant intermediate CA not found",
			err:      ErrTenantIntCANotFound,
			expected: true,
		},
		{
			name:     "EAB not found",
			err:      ErrEABNotFound,
			expected: true,
		},
		{
			name:     "unrelated error",
			err:      errors.New("some other error"),
			expected: false,
		},
		{
			name:     "unauthorized error is not not-found",
			err:      ErrUnauthorized,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsNotFoundError(tt.err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsValidationError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
		{
			name:     "invalid request",
			err:      ErrInvalidRequest,
			expected: true,
		},
		{
			name:     "invalid tenant ID",
			err:      ErrInvalidTenantID,
			expected: true,
		},
		{
			name:     "invalid EAB purpose",
			err:      ErrInvalidEABPurpose,
			expected: true,
		},
		{
			name:     "invalid key algorithm",
			err:      ErrInvalidKeyAlgorithm,
			expected: true,
		},
		{
			name:     "unrelated error",
			err:      errors.New("some other error"),
			expected: false,
		},
		{
			name:     "not found error is not validation error",
			err:      ErrTenantNotFound,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsValidationError(tt.err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsAlreadyExistsError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
		{
			name:     "tenant already exists",
			err:      ErrTenantAlreadyExists,
			expected: true,
		},
		{
			name:     "tenant root CA exists",
			err:      ErrTenantRootCAExists,
			expected: true,
		},
		{
			name:     "tenant intermediate CA exists",
			err:      ErrTenantIntCAExists,
			expected: true,
		},
		{
			name:     "unrelated error",
			err:      errors.New("some other error"),
			expected: false,
		},
		{
			name:     "not found error is not already exists",
			err:      ErrTenantNotFound,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsAlreadyExistsError(tt.err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsUnauthorizedError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
		{
			name:     "unauthorized",
			err:      ErrUnauthorized,
			expected: true,
		},
		{
			name:     "forbidden",
			err:      ErrForbidden,
			expected: true,
		},
		{
			name:     "invalid API key",
			err:      ErrInvalidAPIKey,
			expected: true,
		},
		{
			name:     "insufficient privileges",
			err:      ErrInsufficientPrivileges,
			expected: true,
		},
		{
			name:     "unrelated error",
			err:      errors.New("some other error"),
			expected: false,
		},
		{
			name:     "not found error is not unauthorized",
			err:      ErrTenantNotFound,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsUnauthorizedError(tt.err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

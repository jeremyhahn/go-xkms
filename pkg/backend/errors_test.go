// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
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

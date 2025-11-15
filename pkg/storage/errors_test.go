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

package storage

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestErrors(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{"ErrClosed", ErrClosed},
		{"ErrNotFound", ErrNotFound},
		{"ErrAlreadyExists", ErrAlreadyExists},
		{"ErrInvalidID", ErrInvalidID},
		{"ErrInvalidData", ErrInvalidData},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.NotNil(t, tt.err, "Error should not be nil")
			assert.NotEmpty(t, tt.err.Error(), "Error message should not be empty")
		})
	}
}

func TestErrors_Uniqueness(t *testing.T) {
	// Ensure all error messages are unique
	errs := []error{
		ErrClosed,
		ErrNotFound,
		ErrAlreadyExists,
		ErrInvalidID,
		ErrInvalidData,
	}

	seen := make(map[string]bool)
	for _, err := range errs {
		msg := err.Error()
		assert.False(t, seen[msg], "Error message should be unique: %s", msg)
		seen[msg] = true
	}
}

func TestErrors_Is(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		target error
		want   bool
	}{
		{"ErrClosed matches", ErrClosed, ErrClosed, true},
		{"ErrNotFound matches", ErrNotFound, ErrNotFound, true},
		{"ErrAlreadyExists matches", ErrAlreadyExists, ErrAlreadyExists, true},
		{"ErrInvalidID matches", ErrInvalidID, ErrInvalidID, true},
		{"ErrInvalidData matches", ErrInvalidData, ErrInvalidData, true},
		{"ErrClosed does not match ErrNotFound", ErrClosed, ErrNotFound, false},
		{"ErrNotFound does not match ErrAlreadyExists", ErrNotFound, ErrAlreadyExists, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, errors.Is(tt.err, tt.target))
		})
	}
}

func TestErrors_Wrapping(t *testing.T) {
	baseErr := errors.New("base error")

	wrappedClosed := errors.Join(ErrClosed, baseErr)
	assert.True(t, errors.Is(wrappedClosed, ErrClosed), "Should match ErrClosed when wrapped")
	assert.True(t, errors.Is(wrappedClosed, baseErr), "Should match base error when wrapped")

	wrappedNotFound := errors.Join(ErrNotFound, baseErr)
	assert.True(t, errors.Is(wrappedNotFound, ErrNotFound), "Should match ErrNotFound when wrapped")

	wrappedAlreadyExists := errors.Join(ErrAlreadyExists, baseErr)
	assert.True(t, errors.Is(wrappedAlreadyExists, ErrAlreadyExists), "Should match ErrAlreadyExists when wrapped")

	wrappedInvalidID := errors.Join(ErrInvalidID, baseErr)
	assert.True(t, errors.Is(wrappedInvalidID, ErrInvalidID), "Should match ErrInvalidID when wrapped")

	wrappedInvalidData := errors.Join(ErrInvalidData, baseErr)
	assert.True(t, errors.Is(wrappedInvalidData, ErrInvalidData), "Should match ErrInvalidData when wrapped")
}

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

//go:build awskms

package awskms

import (
	"errors"
	"testing"
)

// TestErrorConstants tests that all error constants are defined and unique.
func TestErrorConstants(t *testing.T) {
	errorList := []struct {
		name  string
		err   error
		match string
	}{
		{"ErrNotInitialized", ErrNotInitialized, "awskms: client not initialized"},
		{"ErrInvalidConfig", ErrInvalidConfig, "awskms: invalid configuration"},
		{"ErrKeyNotFound", ErrKeyNotFound, "awskms: key not found"},
		{"ErrUnsupportedKeyType", ErrUnsupportedKeyType, "awskms: unsupported key type"},
		{"ErrInvalidRegion", ErrInvalidRegion, "awskms: invalid region"},
		{"ErrInvalidKeySpec", ErrInvalidKeySpec, "awskms: invalid key spec"},
		{"ErrKeyAlreadyExists", ErrKeyAlreadyExists, "awskms: key already exists"},
		{"ErrInvalidAlgorithm", ErrInvalidAlgorithm, "awskms: invalid algorithm"},
		{"ErrSignatureFailed", ErrSignatureFailed, "awskms: signature verification failed"},
		{"ErrMetadataStorage", ErrMetadataStorage, "awskms: metadata storage failed"},
		{"ErrInvalidKeyID", ErrInvalidKeyID, "awskms: invalid key ID"},
	}

	// Check that all errors are defined
	for _, tt := range errorList {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err == nil {
				t.Errorf("%s is nil", tt.name)
			}
			if tt.err.Error() != tt.match {
				t.Errorf("%s message = %q, want %q", tt.name, tt.err.Error(), tt.match)
			}
		})
	}

	// Check that all errors are unique
	seen := make(map[error]string)
	for _, tt := range errorList {
		if prevName, ok := seen[tt.err]; ok {
			t.Errorf("Duplicate error: %s and %s are the same", tt.name, prevName)
		}
		seen[tt.err] = tt.name
	}
}

// TestErrorIs tests that errors can be checked with errors.Is.
func TestErrorIs(t *testing.T) {
	tests := []struct {
		name   string
		target error
		err    error
		want   bool
	}{
		{
			name:   "exact match",
			target: ErrInvalidConfig,
			err:    ErrInvalidConfig,
			want:   true,
		},
		{
			name:   "no match",
			target: ErrInvalidConfig,
			err:    ErrKeyNotFound,
			want:   false,
		},
		{
			name:   "wrapped error match",
			target: ErrInvalidRegion,
			err:    errors.New("wrapped: " + ErrInvalidRegion.Error()),
			want:   false, // errors.New creates a new error, not a wrapped one
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := errors.Is(tt.err, tt.target)
			if got != tt.want {
				t.Errorf("errors.Is(%v, %v) = %v, want %v", tt.err, tt.target, got, tt.want)
			}
		})
	}
}

// TestErrorMessages tests that error messages are descriptive.
func TestErrorMessages(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{"ErrNotInitialized", ErrNotInitialized},
		{"ErrInvalidConfig", ErrInvalidConfig},
		{"ErrKeyNotFound", ErrKeyNotFound},
		{"ErrUnsupportedKeyType", ErrUnsupportedKeyType},
		{"ErrInvalidRegion", ErrInvalidRegion},
		{"ErrInvalidKeySpec", ErrInvalidKeySpec},
		{"ErrKeyAlreadyExists", ErrKeyAlreadyExists},
		{"ErrInvalidAlgorithm", ErrInvalidAlgorithm},
		{"ErrSignatureFailed", ErrSignatureFailed},
		{"ErrMetadataStorage", ErrMetadataStorage},
		{"ErrInvalidKeyID", ErrInvalidKeyID},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := tt.err.Error()
			if msg == "" {
				t.Errorf("%s has empty error message", tt.name)
			}
			if len(msg) < 10 {
				t.Errorf("%s has very short error message: %q", tt.name, msg)
			}
		})
	}
}

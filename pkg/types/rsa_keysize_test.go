// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package types

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestValidateRSAKeySize_RefusesBelowMinimum proves every size under
// RSAKeySize2048 -- not just the specific 1024 the go-xkms#1204 report used
// as its example -- is refused with the typed *RSAKeySizeError, including
// zero and negative values a caller-assembled struct might carry.
func TestValidateRSAKeySize_RefusesBelowMinimum(t *testing.T) {
	for _, bits := range []int{-1, 0, 512, 1024, 2047} {
		err := ValidateRSAKeySize(bits)
		if !assert.Error(t, err, "bits=%d", bits) {
			continue
		}
		var sizeErr *RSAKeySizeError
		assert.True(t, errors.As(err, &sizeErr), "bits=%d: want *RSAKeySizeError, got %T", bits, err)
		assert.Equal(t, bits, sizeErr.Requested)
		assert.Contains(t, err.Error(), "RSA key size must be at least 2048")
	}
}

// TestValidateRSAKeySize_AcceptsMinimumAndAbove proves the floor is
// inclusive of RSAKeySize2048 and accepts the other documented sizes up to
// and including the RSAKeySize4096 ceiling.
func TestValidateRSAKeySize_AcceptsMinimumAndAbove(t *testing.T) {
	for _, bits := range []int{RSAKeySize2048, RSAKeySize3072, RSAKeySize4096} {
		assert.NoError(t, ValidateRSAKeySize(bits), "bits=%d", bits)
	}
}

// TestValidateRSAKeySize_RefusesAboveMaximum proves the go-xkms#1260 ceiling:
// a modulus above RSAKeySize4096 is refused with the typed *RSAKeySizeError
// rather than reaching rsa.GenerateKey, whose cost grows with the cube of
// the modulus size and cannot be cancelled. 65536 is the size the original
// report used to pin a CPU core for minutes to hours.
func TestValidateRSAKeySize_RefusesAboveMaximum(t *testing.T) {
	for _, bits := range []int{RSAKeySize4096 + 1, 8193, 16384, 65536} {
		err := ValidateRSAKeySize(bits)
		if !assert.Error(t, err, "bits=%d", bits) {
			continue
		}
		var sizeErr *RSAKeySizeError
		assert.True(t, errors.As(err, &sizeErr), "bits=%d: want *RSAKeySizeError, got %T", bits, err)
		assert.Equal(t, bits, sizeErr.Requested)
		assert.Contains(t, err.Error(), "RSA key size must be at most 4096")
	}
}

// TestValidateRSAKeySize_Table is the single table-driven pass over the
// whole boundary the go-xkms#1260 fix drew: refused just below the floor,
// accepted at the floor and ceiling, refused just above the ceiling, and
// refused at the sizes the vulnerability report and a naive "just raise it"
// fix (8192) both named.
func TestValidateRSAKeySize_Table(t *testing.T) {
	tests := []struct {
		name    string
		bits    int
		wantErr bool
	}{
		{"2047 refused", 2047, true},
		{"2048 ok", 2048, false},
		{"8192 refused", 8192, true},
		{"8193 refused", 8193, true},
		{"16384 refused", 16384, true},
		{"65536 refused", 65536, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateRSAKeySize(tt.bits)
			if tt.wantErr {
				assert.Error(t, err, "bits=%d", tt.bits)
				var sizeErr *RSAKeySizeError
				assert.True(t, errors.As(err, &sizeErr), "bits=%d: want *RSAKeySizeError, got %T", tt.bits, err)
				return
			}
			assert.NoError(t, err, "bits=%d", tt.bits)
		})
	}
}

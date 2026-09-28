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
// inclusive of RSAKeySize2048 and accepts the other two documented sizes.
func TestValidateRSAKeySize_AcceptsMinimumAndAbove(t *testing.T) {
	for _, bits := range []int{RSAKeySize2048, RSAKeySize3072, RSAKeySize4096, 8192} {
		assert.NoError(t, ValidateRSAKeySize(bits), "bits=%d", bits)
	}
}

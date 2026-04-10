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

package fips

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEnabled_ReturnsFalseWhenUnset(t *testing.T) {
	t.Setenv(EnvGOFIPS140, "")
	assert.False(t, Enabled(), "Enabled must return false when GOFIPS140 is empty")
}

func TestEnabled_ReturnsTrueWhenSet(t *testing.T) {
	values := []string{"v1.0.0", "1", "true", "on", "yes"}
	for _, v := range values {
		t.Run(v, func(t *testing.T) {
			t.Setenv(EnvGOFIPS140, v)
			require.True(t, Enabled(), "Enabled must return true when GOFIPS140=%q", v)
		})
	}
}

func TestDefaultKDF_ReturnsArgon2idWhenFIPSDisabled(t *testing.T) {
	t.Setenv(EnvGOFIPS140, "")
	assert.Equal(t, KDFArgon2id, DefaultKDF(), "DefaultKDF must return argon2id in standard mode")
}

func TestDefaultKDF_ReturnsPBKDF2WhenFIPSEnabled(t *testing.T) {
	t.Setenv(EnvGOFIPS140, "v1.0.0")
	assert.Equal(t, KDFPBKDF2, DefaultKDF(), "DefaultKDF must return pbkdf2 in FIPS mode")
}

func TestDefaultLUKSKDF_ReturnsArgon2idWhenFIPSDisabled(t *testing.T) {
	t.Setenv(EnvGOFIPS140, "")
	assert.Equal(t, KDFArgon2id, DefaultLUKSKDF(), "DefaultLUKSKDF must return argon2id in standard mode")
}

func TestDefaultLUKSKDF_ReturnsPBKDF2WhenFIPSEnabled(t *testing.T) {
	t.Setenv(EnvGOFIPS140, "1")
	assert.Equal(t, KDFPBKDF2, DefaultLUKSKDF(), "DefaultLUKSKDF must return pbkdf2 in FIPS mode")
}

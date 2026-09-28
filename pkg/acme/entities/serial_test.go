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

package entities

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNormalizeSerial_Valid(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"lowercase hex", "1a2b3c", "1a2b3c"},
		{"uppercase hex normalizes to lowercase", "1A2B3C", "1a2b3c"},
		{"0x prefix is stripped", "0x1a2b3c", "1a2b3c"},
		{"0X prefix is stripped", "0X1a2b3c", "1a2b3c"},
		{"leading zeros are dropped", "0001a2b3c", "1a2b3c"},
		{"single digit", "1", "1"},
		{
			name:     "128-bit serial round-trips at full precision",
			input:    "ff00000000000000ee00000000000000",
			expected: "ff00000000000000ee00000000000000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NormalizeSerial(tt.input)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestNormalizeSerial_Invalid(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"empty string", ""},
		{"only 0x prefix", "0x"},
		{"non-hex characters", "not-a-serial"},
		{"decimal-looking but invalid hex digit", "12g3"},
		{"zero is not a valid RFC 5280 serial", "0"},
		{"negative sign is not valid hex", "-1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NormalizeSerial(tt.input)
			require.Error(t, err)

			var invalidErr *InvalidSerialError
			require.ErrorAs(t, err, &invalidErr)
			assert.Equal(t, tt.input, invalidErr.Serial)
		})
	}
}

func TestNormalizeSerial_MatchesBigIntTextForm(t *testing.T) {
	serial, ok := new(big.Int).SetString("ffeeddccbbaa99887766554433221100", 16)
	require.True(t, ok)

	got, err := NormalizeSerial(serial.Text(16))
	require.NoError(t, err)
	assert.Equal(t, serial.Text(16), got)
}

func TestInvalidSerialError_Error(t *testing.T) {
	err := &InvalidSerialError{Serial: "zz"}
	assert.Contains(t, err.Error(), "zz")
	assert.Contains(t, err.Error(), "invalid certificate serial")
}

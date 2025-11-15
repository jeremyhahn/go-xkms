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
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/types"
	"github.com/stretchr/testify/assert"
)

func TestCapabilities_HasKeys(t *testing.T) {
	tests := []struct {
		name string
		caps types.Capabilities
		want bool
	}{
		{
			name: "Keys enabled",
			caps: types.Capabilities{Keys: true},
			want: true,
		},
		{
			name: "Keys disabled",
			caps: types.Capabilities{Keys: false},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.caps.HasKeys())
		})
	}
}

func TestCapabilities_IsHardwareBacked(t *testing.T) {
	tests := []struct {
		name string
		caps types.Capabilities
		want bool
	}{
		{
			name: "Hardware backed",
			caps: types.Capabilities{HardwareBacked: true},
			want: true,
		},
		{
			name: "Not hardware backed",
			caps: types.Capabilities{HardwareBacked: false},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.caps.IsHardwareBacked())
		})
	}
}

func TestCapabilities_SupportsSign(t *testing.T) {
	tests := []struct {
		name string
		caps types.Capabilities
		want bool
	}{
		{
			name: "Signing supported",
			caps: types.Capabilities{Signing: true},
			want: true,
		},
		{
			name: "Signing not supported",
			caps: types.Capabilities{Signing: false},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.caps.SupportsSign())
		})
	}
}

func TestCapabilities_SupportsDecrypt(t *testing.T) {
	tests := []struct {
		name string
		caps types.Capabilities
		want bool
	}{
		{
			name: "Decryption supported",
			caps: types.Capabilities{Decryption: true},
			want: true,
		},
		{
			name: "Decryption not supported",
			caps: types.Capabilities{Decryption: false},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.caps.SupportsDecrypt())
		})
	}
}

func TestCapabilities_SupportsKeyRotation(t *testing.T) {
	tests := []struct {
		name string
		caps types.Capabilities
		want bool
	}{
		{
			name: "Key rotation supported",
			caps: types.Capabilities{KeyRotation: true},
			want: true,
		},
		{
			name: "Key rotation not supported",
			caps: types.Capabilities{KeyRotation: false},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.caps.SupportsKeyRotation())
		})
	}
}

func TestCapabilities_String(t *testing.T) {
	tests := []struct {
		name string
		caps types.Capabilities
		want string
	}{
		{
			name: "All capabilities enabled",
			caps: types.Capabilities{
				Keys:           true,
				HardwareBacked: true,
				Signing:        true,
				Decryption:     true,
				KeyRotation:    true,
			},
			want: "Capabilities{Keys: true, HardwareBacked: true, Signing: true, Decryption: true, KeyRotation: true}",
		},
		{
			name: "All capabilities disabled",
			caps: types.Capabilities{
				Keys:           false,
				HardwareBacked: false,
				Signing:        false,
				Decryption:     false,
				KeyRotation:    false,
			},
			want: "Capabilities{Keys: false, HardwareBacked: false, Signing: false, Decryption: false, KeyRotation: false}",
		},
		{
			name: "Mixed capabilities",
			caps: types.Capabilities{
				Keys:           true,
				HardwareBacked: false,
				Signing:        true,
				Decryption:     false,
				KeyRotation:    true,
			},
			want: "Capabilities{Keys: true, HardwareBacked: false, Signing: true, Decryption: false, KeyRotation: true}",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.caps.String())
		})
	}
}

func TestNewSoftwareCapabilities(t *testing.T) {
	caps := types.NewSoftwareCapabilities()

	assert.True(t, caps.Keys, "Software backend should support keys")
	assert.False(t, caps.HardwareBacked, "Software backend should not be hardware backed")
	assert.True(t, caps.Signing, "Software backend should support signing")
	assert.True(t, caps.Decryption, "Software backend should support decryption")
	assert.False(t, caps.KeyRotation, "Software backend should not support key rotation by default")

	// Test using the helper methods
	assert.True(t, caps.HasKeys())
	assert.False(t, caps.IsHardwareBacked())
	assert.True(t, caps.SupportsSign())
	assert.True(t, caps.SupportsDecrypt())
	assert.False(t, caps.SupportsKeyRotation())
}

func TestNewHardwareCapabilities(t *testing.T) {
	caps := types.NewHardwareCapabilities()

	assert.True(t, caps.Keys, "Hardware backend should support keys")
	assert.True(t, caps.HardwareBacked, "Hardware backend should be hardware backed")
	assert.True(t, caps.Signing, "Hardware backend should support signing")
	assert.True(t, caps.Decryption, "Hardware backend should support decryption")
	assert.False(t, caps.KeyRotation, "Hardware backend should not support key rotation by default")

	// Test using the helper methods
	assert.True(t, caps.HasKeys())
	assert.True(t, caps.IsHardwareBacked())
	assert.True(t, caps.SupportsSign())
	assert.True(t, caps.SupportsDecrypt())
	assert.False(t, caps.SupportsKeyRotation())
}

// TestCapabilities_EdgeCases tests edge cases and boundary conditions
func TestCapabilities_EdgeCases(t *testing.T) {
	t.Run("Empty capabilities struct", func(t *testing.T) {
		caps := types.Capabilities{}
		assert.False(t, caps.HasKeys())
		assert.False(t, caps.IsHardwareBacked())
		assert.False(t, caps.SupportsSign())
		assert.False(t, caps.SupportsDecrypt())
		assert.False(t, caps.SupportsKeyRotation())
		assert.Equal(t, "Capabilities{Keys: false, HardwareBacked: false, Signing: false, Decryption: false, KeyRotation: false}", caps.String())
	})

	t.Run("Capabilities comparison", func(t *testing.T) {
		soft := types.NewSoftwareCapabilities()
		hard := types.NewHardwareCapabilities()

		assert.NotEqual(t, soft.HardwareBacked, hard.HardwareBacked, "Software and hardware capabilities should differ")
		assert.Equal(t, soft.Keys, hard.Keys, "Both should support keys")
		assert.Equal(t, soft.Signing, hard.Signing, "Both should support signing")
	})
}

// TestCapabilitiesSupportsImportExport tests the SupportsImportExport method
func TestCapabilitiesSupportsImportExport(t *testing.T) {
	tests := []struct {
		name string
		caps types.Capabilities
		want bool
	}{
		{
			name: "Supports import/export",
			caps: types.Capabilities{Import: true, Export: true},
			want: true,
		},
		{
			name: "Does not support import/export",
			caps: types.Capabilities{Import: false, Export: false},
			want: false,
		},
		{
			name: "Software capabilities without import/export",
			caps: types.NewSoftwareCapabilities(),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.caps.SupportsImportExport())
		})
	}
}

// TestNewUnifiedSoftwareCapabilities tests the unified software backend capabilities
func TestNewUnifiedSoftwareCapabilities(t *testing.T) {
	caps := types.NewUnifiedSoftwareCapabilities()

	assert.True(t, caps.Keys, "Unified software backend should support keys")
	assert.False(t, caps.HardwareBacked, "Unified software backend should not be hardware backed")
	assert.True(t, caps.Signing, "Unified software backend should support signing")
	assert.True(t, caps.Decryption, "Unified software backend should support decryption")
	assert.True(t, caps.KeyRotation, "Unified software backend should support key rotation")
	assert.True(t, caps.SymmetricEncryption, "Unified software backend should support symmetric encryption")

	// Test using the helper methods
	assert.True(t, caps.HasKeys())
	assert.False(t, caps.IsHardwareBacked())
	assert.True(t, caps.SupportsSign())
	assert.True(t, caps.SupportsDecrypt())
	assert.True(t, caps.SupportsKeyRotation())
	assert.True(t, caps.SupportsSymmetricEncryption())
}

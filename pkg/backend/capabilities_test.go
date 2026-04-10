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
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/types"
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
	}{
		{
			name: "All capabilities enabled",
			caps: types.Capabilities{
				Keys:           true,
				HardwareBacked: true,
				Signing:        true,
				Decryption:     true,
				KeyRotation:    true,
				SecurityLevel:  types.SecurityLevelHigh,
			},
		},
		{
			name: "All capabilities disabled",
			caps: types.Capabilities{
				Keys:           false,
				HardwareBacked: false,
				Signing:        false,
				Decryption:     false,
				KeyRotation:    false,
				SecurityLevel:  types.SecurityLevelLow,
			},
		},
		{
			name: "Mixed capabilities",
			caps: types.Capabilities{
				Keys:           true,
				HardwareBacked: false,
				Signing:        true,
				Decryption:     false,
				KeyRotation:    true,
				SecurityLevel:  types.SecurityLevelMedium,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			str := tt.caps.String()
			assert.Contains(t, str, "Keys:")
			assert.Contains(t, str, "HardwareBacked:")
			assert.Contains(t, str, "Signing:")
			assert.Contains(t, str, "Decryption:")
			assert.Contains(t, str, "KeyRotation:")
			assert.Contains(t, str, "SecurityLevel:")
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
	assert.Equal(t, types.SecurityLevelLow, caps.SecurityLevel, "Software backend should have Low security level")

	// Test using the helper methods
	assert.True(t, caps.HasKeys())
	assert.False(t, caps.IsHardwareBacked())
	assert.True(t, caps.SupportsSign())
	assert.True(t, caps.SupportsDecrypt())
	assert.False(t, caps.SupportsKeyRotation())
	assert.Equal(t, types.SecurityLevelLow, caps.GetSecurityLevel())
}

func TestNewHardwareCapabilities(t *testing.T) {
	caps := types.NewHardwareCapabilities()

	assert.True(t, caps.Keys, "Hardware backend should support keys")
	assert.True(t, caps.HardwareBacked, "Hardware backend should be hardware backed")
	assert.True(t, caps.Signing, "Hardware backend should support signing")
	assert.True(t, caps.Decryption, "Hardware backend should support decryption")
	assert.False(t, caps.KeyRotation, "Hardware backend should not support key rotation by default")
	assert.Equal(t, types.SecurityLevelHigh, caps.SecurityLevel, "Hardware backend should have High security level by default")

	// Test using the helper methods
	assert.True(t, caps.HasKeys())
	assert.True(t, caps.IsHardwareBacked())
	assert.True(t, caps.SupportsSign())
	assert.True(t, caps.SupportsDecrypt())
	assert.False(t, caps.SupportsKeyRotation())
	assert.Equal(t, types.SecurityLevelHigh, caps.GetSecurityLevel())
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
		assert.Equal(t, types.SecurityLevelLow, caps.GetSecurityLevel()) // Zero value is Low
		str := caps.String()
		assert.Contains(t, str, "Keys: false")
		assert.Contains(t, str, "SecurityLevel: Low")
	})

	t.Run("Capabilities comparison", func(t *testing.T) {
		soft := types.NewSoftwareCapabilities()
		hard := types.NewHardwareCapabilities()

		assert.NotEqual(t, soft.HardwareBacked, hard.HardwareBacked, "Software and hardware capabilities should differ")
		assert.Equal(t, soft.Keys, hard.Keys, "Both should support keys")
		assert.Equal(t, soft.Signing, hard.Signing, "Both should support signing")
		assert.Less(t, soft.SecurityLevel, hard.SecurityLevel, "Hardware should have higher security level")
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
	assert.Equal(t, types.SecurityLevelLow, caps.SecurityLevel, "Unified software backend should have Low security level")

	// Test using the helper methods
	assert.True(t, caps.HasKeys())
	assert.False(t, caps.IsHardwareBacked())
	assert.True(t, caps.SupportsSign())
	assert.True(t, caps.SupportsDecrypt())
	assert.True(t, caps.SupportsKeyRotation())
	assert.True(t, caps.SupportsSymmetricEncryption())
	assert.Equal(t, types.SecurityLevelLow, caps.GetSecurityLevel())
}

// TestSecurityLevel_ConstructorDefaults tests that capability constructors set appropriate security levels
func TestSecurityLevel_ConstructorDefaults(t *testing.T) {
	tests := []struct {
		name          string
		constructor   func() types.Capabilities
		expectedLevel types.SecurityLevel
	}{
		{
			name:          "Software capabilities have Low security",
			constructor:   types.NewSoftwareCapabilities,
			expectedLevel: types.SecurityLevelLow,
		},
		{
			name:          "Hardware capabilities have High security",
			constructor:   types.NewHardwareCapabilities,
			expectedLevel: types.SecurityLevelHigh,
		},
		{
			name:          "Unified software capabilities have Low security",
			constructor:   types.NewUnifiedSoftwareCapabilities,
			expectedLevel: types.SecurityLevelLow,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			caps := tt.constructor()
			assert.Equal(t, tt.expectedLevel, caps.GetSecurityLevel())
		})
	}
}

// TestSecurityLevel_Ordering verifies that security levels are properly ordered
func TestSecurityLevel_Ordering(t *testing.T) {
	// SecurityLevel should be: Low < Medium < High < VeryHigh
	assert.True(t, types.SecurityLevelLow < types.SecurityLevelMedium,
		"Low should be less than Medium")
	assert.True(t, types.SecurityLevelMedium < types.SecurityLevelHigh,
		"Medium should be less than High")
	assert.True(t, types.SecurityLevelHigh < types.SecurityLevelVeryHigh,
		"High should be less than VeryHigh")

	// Expected backend security level assignments:
	// - Software: Low (0) - keys on disk
	// - Cloud KMS (AWS/GCP/Azure/Vault): Medium (1) - network-dependent
	// - PKCS#11: High (2) - local HSM
	// - TPM 2.0: VeryHigh (3) - hardware-bound, non-exportable
}

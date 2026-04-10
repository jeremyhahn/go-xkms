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

package xkms

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBackendType_String(t *testing.T) {
	tests := []struct {
		name     string
		backend  BackendType
		expected string
	}{
		{
			name:     "software backend",
			backend:  BackendSoftware,
			expected: "software",
		},
		{
			name:     "tpm2 backend",
			backend:  BackendTPM2,
			expected: "tpm2",
		},
		{
			name:     "pkcs11 backend",
			backend:  BackendPKCS11,
			expected: "pkcs11",
		},
		{
			name:     "pkcs8 backend",
			backend:  BackendPKCS8,
			expected: "pkcs8",
		},
		{
			name:     "awskms backend",
			backend:  BackendAWSKMS,
			expected: "awskms",
		},
		{
			name:     "gcpkms backend",
			backend:  BackendGCPKMS,
			expected: "gcpkms",
		},
		{
			name:     "azurekv backend",
			backend:  BackendAzureKV,
			expected: "azurekv",
		},
		{
			name:     "vault backend",
			backend:  BackendVault,
			expected: "vault",
		},
		{
			name:     "quantum backend",
			backend:  BackendQuantum,
			expected: "quantum",
		},
		{
			name:     "frost backend",
			backend:  BackendFROST,
			expected: "frost",
		},
		{
			name:     "symmetric backend",
			backend:  BackendSymmetric,
			expected: "symmetric",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.backend.String()
			if result != tt.expected {
				t.Errorf("BackendType.String() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestBackendType_IsValid(t *testing.T) {
	tests := []struct {
		name     string
		backend  BackendType
		expected bool
	}{
		{
			name:     "software is valid",
			backend:  BackendSoftware,
			expected: true,
		},
		{
			name:     "tpm2 is valid",
			backend:  BackendTPM2,
			expected: true,
		},
		{
			name:     "pkcs11 is valid",
			backend:  BackendPKCS11,
			expected: true,
		},
		{
			name:     "pkcs8 is valid",
			backend:  BackendPKCS8,
			expected: true,
		},
		{
			name:     "awskms is valid",
			backend:  BackendAWSKMS,
			expected: true,
		},
		{
			name:     "gcpkms is valid",
			backend:  BackendGCPKMS,
			expected: true,
		},
		{
			name:     "azurekv is valid",
			backend:  BackendAzureKV,
			expected: true,
		},
		{
			name:     "vault is valid",
			backend:  BackendVault,
			expected: true,
		},
		{
			name:     "quantum is valid",
			backend:  BackendQuantum,
			expected: true,
		},
		{
			name:     "frost is valid",
			backend:  BackendFROST,
			expected: true,
		},
		{
			name:     "symmetric is valid",
			backend:  BackendSymmetric,
			expected: true,
		},
		{
			name:     "empty string is invalid",
			backend:  BackendType(""),
			expected: false,
		},
		{
			name:     "unknown backend is invalid",
			backend:  BackendType("unknown"),
			expected: false,
		},
		{
			name:     "similar but wrong name is invalid",
			backend:  BackendType("aws-kms"),
			expected: false,
		},
		{
			name:     "case sensitive mismatch is invalid",
			backend:  BackendType("Software"),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.backend.IsValid()
			if result != tt.expected {
				t.Errorf("BackendType.IsValid() = %v, want %v for backend %q",
					result, tt.expected, tt.backend)
			}
		})
	}
}

func TestSupportedBackends(t *testing.T) {
	backends := SupportedBackends()

	// Always-compiled backends should be present
	alwaysPresent := []BackendType{BackendSoftware, BackendPKCS8, BackendSymmetric, BackendTPM2}
	for _, expected := range alwaysPresent {
		found := false
		for _, b := range backends {
			if b == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("SupportedBackends() should always include %q", expected)
		}
	}

	// Verify all returned backends are valid types
	for _, b := range backends {
		if !b.IsValid() {
			t.Errorf("SupportedBackends() returned invalid backend type: %q", b)
		}
	}

	// Verify returned slice is sorted
	for i := 1; i < len(backends); i++ {
		if backends[i-1] > backends[i] {
			t.Errorf("SupportedBackends() not sorted: %q > %q at indices %d, %d",
				backends[i-1], backends[i], i-1, i)
		}
	}
}

func TestIsBackendSupported(t *testing.T) {
	// Software backend should always be supported
	if !IsBackendSupported(BackendSoftware) {
		t.Error("IsBackendSupported(BackendSoftware) should always return true")
	}

	// Unknown backend should never be supported
	if IsBackendSupported(BackendType("nonexistent")) {
		t.Error("IsBackendSupported() returned true for unknown backend")
	}

	// Empty string should not be supported
	if IsBackendSupported(BackendType("")) {
		t.Error("IsBackendSupported() returned true for empty string")
	}
}

func TestIsBackendSupported_ConsistentWithSupported(t *testing.T) {
	// All backends returned by SupportedBackends should return true from IsBackendSupported
	backends := SupportedBackends()
	for _, b := range backends {
		if !IsBackendSupported(b) {
			t.Errorf("IsBackendSupported(%q) = false, but backend is in SupportedBackends()", b)
		}
	}
}

func TestBackendCount(t *testing.T) {
	count := BackendCount()
	backends := SupportedBackends()

	if count != len(backends) {
		t.Errorf("BackendCount() = %d, want %d (length of SupportedBackends())",
			count, len(backends))
	}

	// Should be at least 4 (software, pkcs8, symmetric, tpm2)
	if count < 4 {
		t.Errorf("BackendCount() = %d, want at least 4 (software, pkcs8, symmetric, tpm2)", count)
	}
}

func TestSortBackends(t *testing.T) {
	tests := []struct {
		name     string
		input    []BackendType
		expected []BackendType
	}{
		{
			name:     "already sorted",
			input:    []BackendType{"a", "b", "c"},
			expected: []BackendType{"a", "b", "c"},
		},
		{
			name:     "reverse order",
			input:    []BackendType{"c", "b", "a"},
			expected: []BackendType{"a", "b", "c"},
		},
		{
			name:     "random order",
			input:    []BackendType{"b", "a", "c"},
			expected: []BackendType{"a", "b", "c"},
		},
		{
			name:     "single element",
			input:    []BackendType{"a"},
			expected: []BackendType{"a"},
		},
		{
			name:     "empty slice",
			input:    []BackendType{},
			expected: []BackendType{},
		},
		{
			name:     "real backend types",
			input:    []BackendType{BackendQuantum, BackendSoftware, BackendAWSKMS, BackendTPM2},
			expected: []BackendType{BackendAWSKMS, BackendQuantum, BackendSoftware, BackendTPM2},
		},
		{
			name:     "duplicates",
			input:    []BackendType{"b", "a", "b", "a"},
			expected: []BackendType{"a", "a", "b", "b"},
		},
		{
			name:     "all always-compiled backends",
			input:    []BackendType{BackendTPM2, BackendSymmetric, BackendSoftware, BackendPKCS8},
			expected: []BackendType{BackendPKCS8, BackendSoftware, BackendSymmetric, BackendTPM2},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Make a copy to avoid modifying test data
			input := make([]BackendType, len(tt.input))
			copy(input, tt.input)

			sortBackends(input)

			if len(input) != len(tt.expected) {
				t.Errorf("sortBackends() length = %d, want %d", len(input), len(tt.expected))
				return
			}

			for i, v := range input {
				if v != tt.expected[i] {
					t.Errorf("sortBackends()[%d] = %q, want %q", i, v, tt.expected[i])
				}
			}
		})
	}
}

func TestRegisterBackend_Idempotent(t *testing.T) {
	// Get initial count
	initialCount := BackendCount()

	// Register software again (already registered in init)
	RegisterBackend(BackendSoftware)

	// Count should remain the same since we're using a map
	afterCount := BackendCount()
	if afterCount != initialCount {
		t.Errorf("Re-registering backend changed count from %d to %d",
			initialCount, afterCount)
	}

	// Software should still be available
	if !IsBackendSupported(BackendSoftware) {
		t.Error("BackendSoftware not available after re-registration")
	}
}

func TestBackendTypeConstants(t *testing.T) {
	// Verify constant values match expected strings
	constants := map[BackendType]string{
		BackendSoftware:  "software",
		BackendTPM2:      "tpm2",
		BackendPKCS11:    "pkcs11",
		BackendPKCS8:     "pkcs8",
		BackendAWSKMS:    "awskms",
		BackendGCPKMS:    "gcpkms",
		BackendAzureKV:   "azurekv",
		BackendVault:     "vault",
		BackendQuantum:   "quantum",
		BackendFROST:     "frost",
		BackendSymmetric: "symmetric",
	}

	for backend, expected := range constants {
		if string(backend) != expected {
			t.Errorf("Backend constant %v has value %q, want %q",
				backend, string(backend), expected)
		}
	}
}

func TestSupportedBackends_ReturnsCopy(t *testing.T) {
	// Get two calls and verify they return independent slices
	first := SupportedBackends()
	second := SupportedBackends()

	if len(first) == 0 {
		t.Fatal("SupportedBackends() returned empty slice, expected at least 4 backends")
	}

	// Modify first slice
	original := first[0]
	first[0] = BackendType("modified")

	// Second slice should be unaffected
	if second[0] == BackendType("modified") {
		t.Error("SupportedBackends() returns shared slice instead of copy")
	}

	// Restore for cleanliness
	first[0] = original
}

func BenchmarkIsBackendSupported(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = IsBackendSupported(BackendSoftware)
	}
}

func BenchmarkSupportedBackends(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = SupportedBackends()
	}
}

func BenchmarkBackendCount(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = BackendCount()
	}
}

func TestIsKeyProviderType(t *testing.T) {
	// Key provider types
	assert.True(t, IsKeyProviderType(BackendPKCS8))
	assert.True(t, IsKeyProviderType(BackendSymmetric))
	assert.True(t, IsKeyProviderType(BackendQuantum))
	assert.True(t, IsKeyProviderType(BackendFROST))

	// Full-service backend types
	assert.False(t, IsKeyProviderType(BackendSoftware))
	assert.False(t, IsKeyProviderType(BackendTPM2))
	assert.False(t, IsKeyProviderType(BackendPKCS11))
	assert.False(t, IsKeyProviderType(BackendAWSKMS))
	assert.False(t, IsKeyProviderType(BackendGCPKMS))
	assert.False(t, IsKeyProviderType(BackendAzureKV))
	assert.False(t, IsKeyProviderType(BackendVault))
}

func BenchmarkBackendType_String(b *testing.B) {
	backend := BackendSoftware
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = backend.String()
	}
}

func BenchmarkBackendType_IsValid(b *testing.B) {
	backend := BackendSoftware
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = backend.IsValid()
	}
}

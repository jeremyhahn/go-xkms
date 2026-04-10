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

package module

import (
	"testing"
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
			name:     "quantum backend",
			backend:  BackendQuantum,
			expected: "quantum",
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
			name:     "quantum is valid",
			backend:  BackendQuantum,
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

func TestAvailableBackends(t *testing.T) {
	backends := AvailableBackends()

	// Software backend should always be available (no build tags required)
	found := false
	for _, b := range backends {
		if b == BackendSoftware {
			found = true
			break
		}
	}
	if !found {
		t.Error("AvailableBackends() should always include BackendSoftware")
	}

	// Verify all returned backends are valid types
	for _, b := range backends {
		if !b.IsValid() {
			t.Errorf("AvailableBackends() returned invalid backend type: %q", b)
		}
	}

	// Verify returned slice is sorted
	for i := 1; i < len(backends); i++ {
		if backends[i-1] > backends[i] {
			t.Errorf("AvailableBackends() not sorted: %q > %q at indices %d, %d",
				backends[i-1], backends[i], i-1, i)
		}
	}
}

func TestSupportedBackends(t *testing.T) {
	// SupportedBackends should return the same result as AvailableBackends
	available := AvailableBackends()
	supported := SupportedBackends()

	if len(available) != len(supported) {
		t.Errorf("SupportedBackends() length %d != AvailableBackends() length %d",
			len(supported), len(available))
		return
	}

	for i, b := range available {
		if supported[i] != b {
			t.Errorf("SupportedBackends()[%d] = %q, want %q",
				i, supported[i], b)
		}
	}
}

func TestIsBackendAvailable(t *testing.T) {
	// Software backend should always be available
	if !IsBackendAvailable(BackendSoftware) {
		t.Error("IsBackendAvailable(BackendSoftware) should always return true")
	}

	// Unknown backend should never be available
	if IsBackendAvailable(BackendType("nonexistent")) {
		t.Error("IsBackendAvailable() returned true for unknown backend")
	}

	// Empty string should not be available
	if IsBackendAvailable(BackendType("")) {
		t.Error("IsBackendAvailable() returned true for empty string")
	}
}

func TestIsBackendAvailable_ConsistentWithAvailable(t *testing.T) {
	// All backends returned by AvailableBackends should return true from IsBackendAvailable
	backends := AvailableBackends()
	for _, b := range backends {
		if !IsBackendAvailable(b) {
			t.Errorf("IsBackendAvailable(%q) = false, but backend is in AvailableBackends()", b)
		}
	}
}

func TestBackendCount(t *testing.T) {
	count := BackendCount()
	backends := AvailableBackends()

	if count != len(backends) {
		t.Errorf("BackendCount() = %d, want %d (length of AvailableBackends())",
			count, len(backends))
	}

	// Should be at least 1 (software backend)
	if count < 1 {
		t.Error("BackendCount() should be at least 1 (software backend)")
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
	if !IsBackendAvailable(BackendSoftware) {
		t.Error("BackendSoftware not available after re-registration")
	}
}

func TestBackendTypeConstants(t *testing.T) {
	// Verify constant values match expected strings
	constants := map[BackendType]string{
		BackendSoftware: "software",
		BackendTPM2:     "tpm2",
		BackendPKCS11:   "pkcs11",
		BackendQuantum:  "quantum",
		BackendAWSKMS:   "awskms",
		BackendGCPKMS:   "gcpkms",
		BackendAzureKV:  "azurekv",
	}

	for backend, expected := range constants {
		if string(backend) != expected {
			t.Errorf("Backend constant %v has value %q, want %q",
				backend, string(backend), expected)
		}
	}
}

func TestAvailableBackends_ReturnsCopy(t *testing.T) {
	// Get two calls and verify they return independent slices
	first := AvailableBackends()
	second := AvailableBackends()

	if len(first) == 0 {
		t.Skip("No backends available to test")
	}

	// Modify first slice
	original := first[0]
	first[0] = BackendType("modified")

	// Second slice should be unaffected
	if second[0] == BackendType("modified") {
		t.Error("AvailableBackends() returns shared slice instead of copy")
	}

	// Restore for cleanliness
	first[0] = original
}

func BenchmarkIsBackendAvailable(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = IsBackendAvailable(BackendSoftware)
	}
}

func BenchmarkAvailableBackends(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = AvailableBackends()
	}
}

func BenchmarkBackendCount(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = BackendCount()
	}
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

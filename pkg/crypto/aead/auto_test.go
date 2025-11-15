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

package aead

import (
	"runtime"
	"testing"

	"golang.org/x/sys/cpu"
)

func TestHasAESNI(t *testing.T) {
	// This test verifies the CPU detection logic works
	// The actual result depends on the test machine's CPU
	hasAES := HasAESNI()

	// Verify it matches the expected value for the architecture
	switch runtime.GOARCH {
	case "amd64":
		if hasAES != cpu.X86.HasAES {
			t.Errorf("HasAESNI() = %v, want %v (from cpu.X86.HasAES)", hasAES, cpu.X86.HasAES)
		}
	case "arm64":
		if hasAES != cpu.ARM64.HasAES {
			t.Errorf("HasAESNI() = %v, want %v (from cpu.ARM64.HasAES)", hasAES, cpu.ARM64.HasAES)
		}
	default:
		// Other architectures should return false
		if hasAES {
			t.Errorf("HasAESNI() = true on unsupported architecture %s, want false", runtime.GOARCH)
		}
	}

	// Log the result for informational purposes
	t.Logf("CPU architecture: %s, AES-NI support: %v", runtime.GOARCH, hasAES)
}

func TestSelectOptimal(t *testing.T) {
	tests := []struct {
		name              string
		isHardwareBacked  bool
		expectedIfAESNI   string
		expectedIfNoAESNI string
	}{
		{
			name:              "Hardware-backed key always uses AES-256-GCM",
			isHardwareBacked:  true,
			expectedIfAESNI:   AES256GCM,
			expectedIfNoAESNI: AES256GCM,
		},
		{
			name:              "Software key with AES-NI uses AES-256-GCM",
			isHardwareBacked:  false,
			expectedIfAESNI:   AES256GCM,
			expectedIfNoAESNI: ChaCha20Poly1305,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SelectOptimal(tt.isHardwareBacked)

			// Verify the result based on actual CPU capabilities
			var expected string
			if HasAESNI() {
				expected = tt.expectedIfAESNI
			} else {
				expected = tt.expectedIfNoAESNI
			}

			if result != expected {
				t.Errorf("SelectOptimal(%v) = %v, want %v (CPU has AES-NI: %v)",
					tt.isHardwareBacked, result, expected, HasAESNI())
			}

			t.Logf("SelectOptimal(isHardwareBacked=%v) = %s (CPU AES-NI: %v)",
				tt.isHardwareBacked, result, HasAESNI())
		})
	}
}

func TestSelectOptimal_HardwareBackedAlwaysAES(t *testing.T) {
	// Hardware-backed keys should ALWAYS use AES regardless of CPU
	result := SelectOptimal(true)
	if result != AES256GCM {
		t.Errorf("SelectOptimal(true) = %s, want %s (hardware-backed should always use AES)",
			result, AES256GCM)
	}
}

func TestSelectOptimalBackend(t *testing.T) {
	tests := []struct {
		name              string
		isHardwareBacked  bool
		expectedIfAESNI   string
		expectedIfNoAESNI string
	}{
		{
			name:              "Hardware-backed backend key uses aes256-gcm",
			isHardwareBacked:  true,
			expectedIfAESNI:   BackendAES256GCM,
			expectedIfNoAESNI: BackendAES256GCM,
		},
		{
			name:              "Software backend key adapts to CPU",
			isHardwareBacked:  false,
			expectedIfAESNI:   BackendAES256GCM,
			expectedIfNoAESNI: BackendChaCha20Poly1305,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SelectOptimalBackend(tt.isHardwareBacked)

			var expected string
			if HasAESNI() {
				expected = tt.expectedIfAESNI
			} else {
				expected = tt.expectedIfNoAESNI
			}

			if result != expected {
				t.Errorf("SelectOptimalBackend(%v) = %v, want %v (CPU has AES-NI: %v)",
					tt.isHardwareBacked, result, expected, HasAESNI())
			}
		})
	}
}

func TestIsAESGCM(t *testing.T) {
	tests := []struct {
		algorithm string
		want      bool
	}{
		// JWE format
		{AES128GCM, true},
		{AES192GCM, true},
		{AES256GCM, true},
		{ChaCha20Poly1305, false},
		{XChaCha20Poly1305, false},
		// Backend format
		{BackendAES128GCM, true},
		{BackendAES192GCM, true},
		{BackendAES256GCM, true},
		{BackendChaCha20Poly1305, false},
		{BackendXChaCha20Poly1305, false},
		// Unknown
		{"unknown", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.algorithm, func(t *testing.T) {
			if got := IsAESGCM(tt.algorithm); got != tt.want {
				t.Errorf("IsAESGCM(%q) = %v, want %v", tt.algorithm, got, tt.want)
			}
		})
	}
}

func TestIsChaCha(t *testing.T) {
	tests := []struct {
		algorithm string
		want      bool
	}{
		// JWE format
		{ChaCha20Poly1305, true},
		{XChaCha20Poly1305, true},
		{AES128GCM, false},
		{AES192GCM, false},
		{AES256GCM, false},
		// Backend format
		{BackendChaCha20Poly1305, true},
		{BackendXChaCha20Poly1305, true},
		{BackendAES128GCM, false},
		{BackendAES192GCM, false},
		{BackendAES256GCM, false},
		// Unknown
		{"unknown", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.algorithm, func(t *testing.T) {
			if got := IsChaCha(tt.algorithm); got != tt.want {
				t.Errorf("IsChaCha(%q) = %v, want %v", tt.algorithm, got, tt.want)
			}
		})
	}
}

func TestToJWE(t *testing.T) {
	tests := []struct {
		name     string
		backend  string
		expected string
	}{
		{"AES-128-GCM", BackendAES128GCM, AES128GCM},
		{"AES-192-GCM", BackendAES192GCM, AES192GCM},
		{"AES-256-GCM", BackendAES256GCM, AES256GCM},
		{"ChaCha20-Poly1305", BackendChaCha20Poly1305, ChaCha20Poly1305},
		{"XChaCha20-Poly1305", BackendXChaCha20Poly1305, XChaCha20Poly1305},
		{"Already JWE format", AES256GCM, AES256GCM},
		{"Unknown algorithm", "unknown", "unknown"},
		{"Empty string", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ToJWE(tt.backend)
			if result != tt.expected {
				t.Errorf("ToJWE(%q) = %q, want %q", tt.backend, result, tt.expected)
			}
		})
	}
}

func TestToBackend(t *testing.T) {
	tests := []struct {
		name     string
		jwe      string
		expected string
	}{
		{"A128GCM", AES128GCM, BackendAES128GCM},
		{"A192GCM", AES192GCM, BackendAES192GCM},
		{"A256GCM", AES256GCM, BackendAES256GCM},
		{"ChaCha20-Poly1305", ChaCha20Poly1305, BackendChaCha20Poly1305},
		{"XChaCha20-Poly1305", XChaCha20Poly1305, BackendXChaCha20Poly1305},
		{"Already backend format", BackendAES256GCM, BackendAES256GCM},
		{"Unknown algorithm", "unknown", "unknown"},
		{"Empty string", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ToBackend(tt.jwe)
			if result != tt.expected {
				t.Errorf("ToBackend(%q) = %q, want %q", tt.jwe, result, tt.expected)
			}
		})
	}
}

func TestRoundTripConversion(t *testing.T) {
	algorithms := []string{
		BackendAES128GCM,
		BackendAES192GCM,
		BackendAES256GCM,
		BackendChaCha20Poly1305,
		BackendXChaCha20Poly1305,
	}

	for _, alg := range algorithms {
		t.Run(alg, func(t *testing.T) {
			// Backend -> JWE -> Backend
			jwe := ToJWE(alg)
			backend := ToBackend(jwe)
			if backend != alg {
				t.Errorf("Round trip failed: %q -> %q -> %q", alg, jwe, backend)
			}
		})
	}
}

// TestConstantValues ensures the constant values match expected formats
func TestConstantValues(t *testing.T) {
	// JWE format constants
	jweTests := []struct {
		constant string
		expected string
	}{
		{AES128GCM, "A128GCM"},
		{AES192GCM, "A192GCM"},
		{AES256GCM, "A256GCM"},
		{ChaCha20Poly1305, "ChaCha20-Poly1305"},
		{XChaCha20Poly1305, "XChaCha20-Poly1305"},
	}

	for _, tt := range jweTests {
		if tt.constant != tt.expected {
			t.Errorf("JWE constant mismatch: got %q, want %q", tt.constant, tt.expected)
		}
	}

	// Backend format constants
	backendTests := []struct {
		constant string
		expected string
	}{
		{BackendAES128GCM, "aes128-gcm"},
		{BackendAES192GCM, "aes192-gcm"},
		{BackendAES256GCM, "aes256-gcm"},
		{BackendChaCha20Poly1305, "chacha20-poly1305"},
		{BackendXChaCha20Poly1305, "xchacha20-poly1305"},
	}

	for _, tt := range backendTests {
		if tt.constant != tt.expected {
			t.Errorf("Backend constant mismatch: got %q, want %q", tt.constant, tt.expected)
		}
	}
}

// Benchmark tests
func BenchmarkHasAESNI(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = HasAESNI()
	}
}

func BenchmarkSelectOptimal(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = SelectOptimal(false)
	}
}

func BenchmarkSelectOptimalBackend(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = SelectOptimalBackend(false)
	}
}

func BenchmarkIsAESGCM(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = IsAESGCM(AES256GCM)
	}
}

func BenchmarkToJWE(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = ToJWE(BackendAES256GCM)
	}
}

func BenchmarkToBackend(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = ToBackend(AES256GCM)
	}
}

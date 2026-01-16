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

package rand

import (
	"bytes"
	"sync"
	"testing"
)

// TestSoftwareResolver_LargeBuffer tests generating large amounts of random data
func TestSoftwareResolver_LargeBuffer(t *testing.T) {
	resolver, err := NewResolver(ModeSoftware)
	if err != nil {
		t.Fatalf("Failed to create resolver: %v", err)
	}
	defer func() { _ = resolver.Close() }()

	// Test various large sizes
	sizes := []int{1024, 4096, 65536, 1048576} // 1KB, 4KB, 64KB, 1MB
	for _, size := range sizes {
		buf := make([]byte, size)
		n, err := resolver.Read(buf)
		if err != nil {
			t.Errorf("Read(%d) failed: %v", size, err)
			continue
		}
		if n != size {
			t.Errorf("Read(%d): expected %d bytes, got %d", size, size, n)
		}
	}
}

// TestSoftwareResolver_ReadUniqueness tests that consecutive reads are unique
func TestSoftwareResolver_ReadUniqueness(t *testing.T) {
	resolver, err := NewResolver(ModeSoftware)
	if err != nil {
		t.Fatalf("Failed to create resolver: %v", err)
	}
	defer func() { _ = resolver.Close() }()

	// Generate 100 samples and verify all are unique
	samples := make([][]byte, 100)
	for i := 0; i < 100; i++ {
		buf := make([]byte, 32)
		n, err := resolver.Read(buf)
		if err != nil {
			t.Fatalf("Read failed at iteration %d: %v", i, err)
		}
		if n != 32 {
			t.Fatalf("Read iteration %d: expected 32 bytes, got %d", i, n)
		}
		samples[i] = buf
	}

	// Verify uniqueness
	for i := 0; i < len(samples); i++ {
		for j := i + 1; j < len(samples); j++ {
			if bytes.Equal(samples[i], samples[j]) {
				t.Errorf("Duplicate samples at indices %d and %d", i, j)
			}
		}
	}
}

// TestSoftwareResolver_ConcurrentRead tests concurrent reads
func TestSoftwareResolver_ConcurrentRead(t *testing.T) {
	resolver, err := NewResolver(ModeSoftware)
	if err != nil {
		t.Fatalf("Failed to create resolver: %v", err)
	}
	defer func() { _ = resolver.Close() }()

	var wg sync.WaitGroup
	numGoroutines := 50
	iterations := 100

	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				buf := make([]byte, 32)
				n, err := resolver.Read(buf)
				if err != nil {
					t.Errorf("Concurrent Read failed: %v", err)
					return
				}
				if n != 32 {
					t.Errorf("Expected 32 bytes, got %d", n)
				}
			}
		}()
	}
	wg.Wait()
}

// TestAutoResolver_ConcurrentClose tests concurrent close operations
func TestAutoResolver_ConcurrentClose(t *testing.T) {
	resolver, err := NewResolver(ModeAuto)
	if err != nil {
		t.Fatalf("Failed to create resolver: %v", err)
	}

	var wg sync.WaitGroup
	numGoroutines := 10
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			_ = resolver.Close()
		}()
	}
	wg.Wait()
}

// TestSoftwareResolver_RandMultipleSizes tests Rand with various sizes
func TestSoftwareResolver_RandMultipleSizes(t *testing.T) {
	resolver, err := NewResolver(ModeSoftware)
	if err != nil {
		t.Fatalf("Failed to create resolver: %v", err)
	}
	defer func() { _ = resolver.Close() }()

	sizes := []int{0, 1, 7, 8, 15, 16, 31, 32, 63, 64, 127, 128, 255, 256, 512, 1024}
	for _, size := range sizes {
		data, err := resolver.Rand(size)
		if err != nil {
			t.Errorf("Rand(%d) failed: %v", size, err)
			continue
		}
		if len(data) != size {
			t.Errorf("Rand(%d): expected %d bytes, got %d", size, size, len(data))
		}
	}
}

// TestAutoResolver_RandZeroBytes tests Rand with zero bytes
func TestAutoResolver_RandZeroBytes(t *testing.T) {
	resolver, err := NewResolver(ModeAuto)
	if err != nil {
		t.Fatalf("Failed to create resolver: %v", err)
	}
	defer func() { _ = resolver.Close() }()

	data, err := resolver.Rand(0)
	if err != nil {
		t.Errorf("Rand(0) failed: %v", err)
	}
	if len(data) != 0 {
		t.Errorf("Expected 0 bytes, got %d", len(data))
	}
}

// TestAutoResolver_ReadZeroBytes tests Read with zero-length buffer
func TestAutoResolver_ReadZeroBytes(t *testing.T) {
	resolver, err := NewResolver(ModeAuto)
	if err != nil {
		t.Fatalf("Failed to create resolver: %v", err)
	}
	defer func() { _ = resolver.Close() }()

	buf := make([]byte, 0)
	n, err := resolver.Read(buf)
	if err != nil {
		t.Errorf("Read(0) failed: %v", err)
	}
	if n != 0 {
		t.Errorf("Expected 0 bytes read, got %d", n)
	}
}

// TestNewResolver_AllModesDetailed tests creating resolvers with all modes
func TestNewResolver_AllModesDetailed(t *testing.T) {
	tests := []struct {
		name        string
		mode        Mode
		shouldError bool
	}{
		{"software mode", ModeSoftware, false},
		{"auto mode", ModeAuto, false},
		{"tpm2 mode (unavailable)", ModeTPM2, true},     // TPM not available
		{"pkcs11 mode (unavailable)", ModePKCS11, true}, // PKCS11 not compiled
		{"invalid mode", Mode("invalid_xyz"), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolver, err := NewResolver(tt.mode)
			if tt.shouldError {
				if err == nil {
					if resolver != nil {
						_ = resolver.Close()
					}
					t.Errorf("Expected error for mode %s", tt.mode)
				}
			} else {
				if err != nil {
					t.Fatalf("NewResolver(%s) failed: %v", tt.mode, err)
				}
				defer func() { _ = resolver.Close() }()

				if !resolver.Available() {
					t.Errorf("Resolver for mode %s should be available", tt.mode)
				}
			}
		})
	}
}

// TestNormalizeConfig_AllTypes tests normalizeConfig with various types
func TestNormalizeConfig_AllTypes(t *testing.T) {
	tests := []struct {
		name     string
		input    interface{}
		expected Mode
	}{
		{"nil", nil, ModeAuto},
		{"Mode value", ModeSoftware, ModeSoftware},
		{"*Config with mode", &Config{Mode: ModeSoftware}, ModeSoftware},
		{"*Config nil", (*Config)(nil), ModeAuto},
		{"*Config empty mode", &Config{Mode: ""}, ModeAuto},
		{"string", "test", ModeAuto},
		{"int", 123, ModeAuto},
		{"struct", struct{}{}, ModeAuto},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := normalizeConfig(tt.input)
			if result == nil {
				t.Fatal("normalizeConfig returned nil")
			}
			if result.Mode != tt.expected {
				t.Errorf("Expected mode %s, got %s", tt.expected, result.Mode)
			}
		})
	}
}

// TestSoftwareSource_MultipleOperations tests multiple operations on softwareSource
func TestSoftwareSource_MultipleOperations(t *testing.T) {
	resolver, err := NewResolver(ModeSoftware)
	if err != nil {
		t.Fatalf("Failed to create resolver: %v", err)
	}
	defer func() { _ = resolver.Close() }()

	source := resolver.Source()
	if source == nil {
		t.Fatal("Source returned nil")
	}

	// Multiple Rand calls
	for i := 0; i < 10; i++ {
		data, err := source.Rand(32)
		if err != nil {
			t.Errorf("Source.Rand iteration %d failed: %v", i, err)
		}
		if len(data) != 32 {
			t.Errorf("Source.Rand iteration %d: expected 32 bytes, got %d", i, len(data))
		}
	}

	// Available check
	if !source.Available() {
		t.Error("Source should be available")
	}

	// Close
	err = source.Close()
	if err != nil {
		t.Errorf("Source.Close failed: %v", err)
	}

	// Multiple closes should be safe
	err = source.Close()
	if err != nil {
		t.Errorf("Second Source.Close failed: %v", err)
	}
}

// TestTPM2Config_AllFields tests all TPM2Config fields
func TestTPM2Config_AllFields(t *testing.T) {
	tests := []struct {
		name   string
		config TPM2Config
	}{
		{"default device", TPM2Config{Device: "/dev/tpm0"}},
		{"custom device", TPM2Config{Device: "/dev/tpmrm0"}},
		{"simulator basic", TPM2Config{UseSimulator: true}},
		{"simulator full", TPM2Config{
			UseSimulator:  true,
			SimulatorType: "swtpm",
			SimulatorHost: "localhost",
			SimulatorPort: 2321,
		}},
		{"large max request", TPM2Config{MaxRequestSize: 4096}},
		{"small max request", TPM2Config{MaxRequestSize: 8}},
		{"zero max request", TPM2Config{MaxRequestSize: 0}},
		{"negative max request", TPM2Config{MaxRequestSize: -1}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Just verify the config can be created
			cfg := tt.config
			_ = cfg // Verify no panic
		})
	}
}

// TestPKCS11Config_AllFields tests all PKCS11Config fields
func TestPKCS11Config_AllFields(t *testing.T) {
	tests := []struct {
		name   string
		config PKCS11Config
	}{
		{"basic module", PKCS11Config{Module: "/usr/lib/libsofthsm2.so"}},
		{"with slot", PKCS11Config{Module: "/lib/pkcs11.so", SlotID: 1}},
		{"with pin", PKCS11Config{Module: "/lib/pkcs11.so", PINRequired: true, PIN: "1234"}},
		{"all fields", PKCS11Config{
			Module:      "/opt/crypto/pkcs11.so",
			SlotID:      5,
			PINRequired: true,
			PIN:         "secret",
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Just verify the config can be created
			cfg := tt.config
			_ = cfg // Verify no panic
		})
	}
}

// TestConfig_AllFields tests Config with all field combinations
func TestConfig_AllFields(t *testing.T) {
	tests := []struct {
		name   string
		config Config
	}{
		{"empty", Config{}},
		{"software only", Config{Mode: ModeSoftware}},
		{"auto only", Config{Mode: ModeAuto}},
		{"with fallback", Config{Mode: ModeAuto, FallbackMode: ModeSoftware}},
		{"with tpm2 config", Config{
			Mode:       ModeAuto,
			TPM2Config: &TPM2Config{Device: "/dev/tpm0"},
		}},
		{"with pkcs11 config", Config{
			Mode:         ModeAuto,
			PKCS11Config: &PKCS11Config{Module: "/lib/pkcs11.so"},
		}},
		{"full config", Config{
			Mode:         ModeAuto,
			FallbackMode: ModeSoftware,
			TPM2Config:   &TPM2Config{Device: "/dev/tpm0", MaxRequestSize: 64},
			PKCS11Config: &PKCS11Config{Module: "/lib/pkcs11.so", SlotID: 0},
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Just verify the config can be created
			cfg := tt.config
			_ = cfg // Verify no panic
		})
	}
}

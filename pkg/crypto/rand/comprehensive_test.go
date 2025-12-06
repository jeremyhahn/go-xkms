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

// TestComprehensive_AllResolverTypes tests all resolver configurations
func TestComprehensive_AllResolverTypes(t *testing.T) {
	tests := []struct {
		name   string
		config interface{}
	}{
		{"nil config", nil},
		{"empty Mode", Mode("")},
		{"software mode", ModeSoftware},
		{"auto mode", ModeAuto},
		{"config with software", &Config{Mode: ModeSoftware}},
		{"config with auto", &Config{Mode: ModeAuto}},
		{"config with nil mode", &Config{}},
		{"config with fallback", &Config{Mode: ModeSoftware, FallbackMode: ModeSoftware}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolver, err := NewResolver(tt.config)
			if err != nil {
				t.Fatalf("NewResolver failed: %v", err)
			}
			defer func() { _ = resolver.Close() }()

			// Test all methods
			if !resolver.Available() {
				t.Error("Resolver should be available")
			}

			source := resolver.Source()
			if source == nil {
				t.Error("Source should not be nil")
			}

			data, err := resolver.Rand(32)
			if err != nil {
				t.Errorf("Rand failed: %v", err)
			}
			if len(data) != 32 {
				t.Errorf("Expected 32 bytes, got %d", len(data))
			}
		})
	}
}

// TestComprehensive_RandomnessQuality tests the quality of generated random data
func TestComprehensive_RandomnessQuality(t *testing.T) {
	resolver, _ := NewResolver(ModeSoftware)
	defer func() { _ = resolver.Close() }()

	// Generate multiple samples and verify they're all different
	samples := make([][]byte, 100)
	for i := 0; i < 100; i++ {
		samples[i], _ = resolver.Rand(32)
	}

	// Check for duplicates (extremely unlikely with good RNG)
	for i := 0; i < len(samples); i++ {
		for j := i + 1; j < len(samples); j++ {
			if bytes.Equal(samples[i], samples[j]) {
				t.Errorf("Found duplicate samples at indices %d and %d", i, j)
			}
		}
	}
}

// TestComprehensive_ConcurrentAccess tests thread safety across all methods
func TestComprehensive_ConcurrentAccess(t *testing.T) {
	resolver, _ := NewResolver(ModeAuto)
	defer func() { _ = resolver.Close() }()

	var wg sync.WaitGroup
	numGoroutines := 50
	operationsPerGoroutine := 100

	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < operationsPerGoroutine; j++ {
				// Concurrent Rand calls
				data, err := resolver.Rand(16)
				if err != nil {
					t.Errorf("Concurrent Rand failed: %v", err)
				}
				if len(data) != 16 {
					t.Errorf("Expected 16 bytes, got %d", len(data))
				}

				// Concurrent Source calls
				_ = resolver.Source()

				// Concurrent Available calls
				_ = resolver.Available()
			}
		}()
	}

	wg.Wait()
}

// TestComprehensive_VariableSizes tests a wide range of byte sizes
func TestComprehensive_VariableSizes(t *testing.T) {
	resolver, _ := NewResolver(ModeSoftware)
	defer func() { _ = resolver.Close() }()

	// Test powers of 2
	for size := 0; size <= 16384; size = max(1, size*2) {
		data, err := resolver.Rand(size)
		if err != nil {
			t.Errorf("Rand(%d) failed: %v", size, err)
		}
		if len(data) != size {
			t.Errorf("Rand(%d) returned %d bytes", size, len(data))
		}
	}

	// Test prime numbers
	primes := []int{3, 7, 13, 31, 61, 127, 251, 509, 1021}
	for _, size := range primes {
		data, err := resolver.Rand(size)
		if err != nil {
			t.Errorf("Rand(%d) failed: %v", size, err)
		}
		if len(data) != size {
			t.Errorf("Rand(%d) returned %d bytes", size, len(data))
		}
	}
}

// TestComprehensive_SourceInterface tests the Source interface thoroughly
func TestComprehensive_SourceInterface(t *testing.T) {
	resolver, _ := NewResolver(ModeSoftware)
	defer func() { _ = resolver.Close() }()

	source := resolver.Source()

	// Test multiple operations
	for i := 0; i < 10; i++ {
		data, err := source.Rand(32)
		if err != nil {
			t.Errorf("Source.Rand() failed: %v", err)
		}
		if len(data) != 32 {
			t.Errorf("Expected 32 bytes, got %d", len(data))
		}

		if !source.Available() {
			t.Error("Source should be available")
		}
	}

	// Close should work
	if err := source.Close(); err != nil {
		t.Errorf("Source.Close() failed: %v", err)
	}
}

// TestComprehensive_NormalizeConfigVariants tests all normalizeConfig paths
func TestComprehensive_NormalizeConfigVariants(t *testing.T) {
	tests := []struct {
		name     string
		input    interface{}
		expected Mode
	}{
		{"nil", nil, ModeAuto},
		{"nil *Config", (*Config)(nil), ModeAuto},
		{"empty string", "", ModeAuto},
		{"software mode", ModeSoftware, ModeSoftware},
		{"auto mode", ModeAuto, ModeAuto},
		{"tpm2 mode", ModeTPM2, ModeTPM2},
		{"pkcs11 mode", ModePKCS11, ModePKCS11},
		{"empty config", &Config{}, ModeAuto},
		{"config with mode", &Config{Mode: ModeSoftware}, ModeSoftware},
		{"invalid type int", 42, ModeAuto},
		{"invalid type string", "invalid", ModeAuto},
		{"invalid type bool", true, ModeAuto},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := normalizeConfig(tt.input)
			if cfg == nil {
				t.Fatal("normalizeConfig returned nil")
				return
			}
			if cfg.Mode != tt.expected {
				t.Errorf("Expected mode %s, got %s", tt.expected, cfg.Mode)
			}
		})
	}
}

// TestComprehensive_ResolverLifecycle tests full lifecycle
func TestComprehensive_ResolverLifecycle(t *testing.T) {
	// Create
	resolver, err := NewResolver(ModeSoftware)
	if err != nil {
		t.Fatalf("NewResolver failed: %v", err)
	}

	// Use - Available
	if !resolver.Available() {
		t.Error("Resolver should be available after creation")
	}

	// Use - Source
	source := resolver.Source()
	if source == nil {
		t.Error("Source should not be nil")
	}

	// Use - Rand multiple times
	for i := 0; i < 10; i++ {
		data, err := resolver.Rand(32)
		if err != nil {
			t.Errorf("Rand() call %d failed: %v", i, err)
		}
		if len(data) != 32 {
			t.Errorf("Call %d: expected 32 bytes, got %d", i, len(data))
		}
	}

	// Close
	err = resolver.Close()
	if err != nil {
		t.Errorf("Close() failed: %v", err)
	}

	// Multiple close should be safe
	err = resolver.Close()
	if err != nil {
		t.Errorf("Second Close() failed: %v", err)
	}
}

// TestComprehensive_ErrorHandling tests error scenarios
func TestComprehensive_ErrorHandling(t *testing.T) {
	// Invalid mode should error
	_, err := newResolver(&Config{Mode: "invalid_mode"})
	if err == nil {
		t.Error("Expected error for invalid mode")
	}

	// TPM2 mode without hardware should error (without build tag)
	_, err = newResolver(&Config{Mode: ModeTPM2})
	if err == nil && !tpm2Available() {
		t.Error("Expected error for TPM2 mode without hardware")
	}

	// PKCS11 mode without hardware should error (without build tag)
	_, err = newResolver(&Config{Mode: ModePKCS11})
	if err == nil && !pkcs11Available() {
		t.Error("Expected error for PKCS11 mode without hardware")
	}
}

// TestComprehensive_ConfigPreservation tests that configs are properly preserved
func TestComprehensive_ConfigPreservation(t *testing.T) {
	cfg := &Config{
		Mode:         ModeSoftware,
		FallbackMode: ModeAuto,
		TPM2Config:   &TPM2Config{Device: "/test/tpm"},
		PKCS11Config: &PKCS11Config{Module: "/test/pkcs11.so"},
	}

	normalized := normalizeConfig(cfg)
	if normalized != cfg {
		t.Error("normalizeConfig should return same *Config instance")
	}
	if normalized.Mode != ModeSoftware {
		t.Error("Mode should be preserved")
	}
	if normalized.FallbackMode != ModeAuto {
		t.Error("FallbackMode should be preserved")
	}
	if normalized.TPM2Config == nil || normalized.TPM2Config.Device != "/test/tpm" {
		t.Error("TPM2Config should be preserved")
	}
	if normalized.PKCS11Config == nil || normalized.PKCS11Config.Module != "/test/pkcs11.so" {
		t.Error("PKCS11Config should be preserved")
	}
}

// Helper function for max (for Go versions < 1.21)
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

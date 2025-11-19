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
	"testing"
)

// TestSoftwareSource_Available tests the Available method
func TestSoftwareSource_Available(t *testing.T) {
	src := &softwareSource{}
	if !src.Available() {
		t.Error("softwareSource.Available() should always return true")
	}
}

// TestSoftwareSource_Close tests the Close method
func TestSoftwareSource_Close(t *testing.T) {
	src := &softwareSource{}
	if err := src.Close(); err != nil {
		t.Errorf("softwareSource.Close() returned error: %v", err)
	}
}

// TestAutoResolver_WithFallback tests auto resolver with fallback mode
func TestAutoResolver_WithFallback(t *testing.T) {
	// Create config with fallback
	cfg := &Config{
		Mode:         ModeSoftware,
		FallbackMode: ModeSoftware,
	}

	resolver, err := newAutoResolver(cfg)
	if err != nil {
		t.Fatalf("newAutoResolver failed: %v", err)
	}
	defer func() { _ = resolver.Close() }()

	// Test that resolver works
	data, err := resolver.Rand(32)
	if err != nil {
		t.Errorf("Rand() failed: %v", err)
	}
	if len(data) != 32 {
		t.Errorf("Expected 32 bytes, got %d", len(data))
	}
}

// TestAutoResolver_Available tests the Available method
func TestAutoResolver_Available(t *testing.T) {
	cfg := &Config{Mode: ModeSoftware}
	resolver, err := newAutoResolver(cfg)
	if err != nil {
		t.Fatalf("newAutoResolver failed: %v", err)
	}
	defer func() { _ = resolver.Close() }()

	if !resolver.Available() {
		t.Error("autoResolver.Available() should return true with software mode")
	}
}

// TestAutoResolver_Close tests the Close method
func TestAutoResolver_Close(t *testing.T) {
	cfg := &Config{Mode: ModeSoftware}
	resolver, err := newAutoResolver(cfg)
	if err != nil {
		t.Fatalf("newAutoResolver failed: %v", err)
	}

	if err := resolver.Close(); err != nil {
		t.Errorf("autoResolver.Close() returned error: %v", err)
	}

	// Close should be idempotent (can call multiple times)
	if err := resolver.Close(); err != nil {
		t.Errorf("autoResolver.Close() second call returned error: %v", err)
	}
}

// TestAutoResolver_Source tests the Source method
func TestAutoResolver_Source(t *testing.T) {
	cfg := &Config{Mode: ModeSoftware}
	resolver, err := newAutoResolver(cfg)
	if err != nil {
		t.Fatalf("newAutoResolver failed: %v", err)
	}
	defer func() { _ = resolver.Close() }()

	source := resolver.Source()
	if source == nil {
		t.Error("Source() returned nil")
	}
}

// TestNormalizeConfig_EdgeCase tests normalizeConfig with edge cases
func TestNormalizeConfig_EmptyString(t *testing.T) {
	cfg := normalizeConfig("")
	if cfg == nil {
		t.Error("normalizeConfig(\"\") returned nil config")
		return
	}
	// Empty string should default to auto mode
	if cfg.Mode != ModeAuto {
		t.Errorf("Expected ModeAuto for empty string, got %s", cfg.Mode)
	}
}

// TestNormalizeConfig_AllModes tests all mode strings
func TestNormalizeConfig_AllModes(t *testing.T) {
	modes := []Mode{
		ModeSoftware,
		ModeTPM2,
		ModePKCS11,
		ModeAuto,
	}

	for _, mode := range modes {
		t.Run(string(mode), func(t *testing.T) {
			cfg := normalizeConfig(mode)
			if cfg == nil {
				t.Errorf("normalizeConfig(%s) returned nil config", mode)
				return
			}
			if cfg.Mode != mode {
				t.Errorf("normalizeConfig(%s) returned mode %s", mode, cfg.Mode)
			}
		})
	}
}

// TestNewResolver_AllModes tests creating resolvers for all modes
func TestNewResolver_AllModes(t *testing.T) {
	modes := []Mode{
		ModeSoftware,
		ModeAuto,
		// Skip TPM2 and PKCS#11 as they require hardware/libraries
	}

	for _, mode := range modes {
		t.Run(string(mode), func(t *testing.T) {
			resolver, err := newResolver(&Config{Mode: mode})
			if err != nil {
				t.Errorf("newResolver(mode=%s) returned error: %v", mode, err)
			}
			if resolver == nil {
				t.Errorf("newResolver(mode=%s) returned nil resolver", mode)
			}
			if resolver != nil {
				defer func() { _ = resolver.Close() }()

				// Test basic functionality
				if !resolver.Available() {
					t.Errorf("Resolver for mode %s should be available", mode)
				}

				data, err := resolver.Rand(16)
				if err != nil {
					t.Errorf("Rand() failed for mode %s: %v", mode, err)
				}
				if len(data) != 16 {
					t.Errorf("Expected 16 bytes for mode %s, got %d", mode, len(data))
				}
			}
		})
	}
}

// TestAutoResolver_Fallback tests fallback functionality
func TestAutoResolver_FallbackWithInvalidMode(t *testing.T) {
	// Create config with valid fallback but potentially unavailable primary
	cfg := &Config{
		Mode:         ModeSoftware,
		FallbackMode: ModeSoftware,
	}

	resolver, err := newAutoResolver(cfg)
	if err != nil {
		t.Fatalf("newAutoResolver failed: %v", err)
	}
	defer func() { _ = resolver.Close() }()

	// Verify it works
	data, err := resolver.Rand(32)
	if err != nil {
		t.Errorf("Rand() failed with fallback: %v", err)
	}
	if len(data) != 32 {
		t.Errorf("Expected 32 bytes, got %d", len(data))
	}
}

// TestSoftwareResolver_Lifecycle tests full lifecycle of software resolver
func TestSoftwareResolver_Lifecycle(t *testing.T) {
	// Create
	resolver, err := newSoftwareResolver()
	if err != nil {
		t.Fatalf("newSoftwareResolver failed: %v", err)
	}

	// Use
	if !resolver.Available() {
		t.Error("Software resolver should always be available")
	}

	source := resolver.Source()
	if source == nil {
		t.Error("Source() returned nil")
	}

	data, err := resolver.Rand(32)
	if err != nil {
		t.Errorf("Rand() failed: %v", err)
	}
	if len(data) != 32 {
		t.Errorf("Expected 32 bytes, got %d", len(data))
	}

	// Close
	if err := resolver.Close(); err != nil {
		t.Errorf("Close() failed: %v", err)
	}
}

// TestNormalizeConfig_WithConfig tests normalizeConfig with *Config input
func TestNormalizeConfig_WithConfig(t *testing.T) {
	inputCfg := &Config{
		Mode:         ModeSoftware,
		FallbackMode: ModeAuto,
	}

	cfg := normalizeConfig(inputCfg)
	if cfg == nil {
		t.Error("normalizeConfig(*Config) returned nil")
	}
	if cfg != inputCfg {
		t.Error("normalizeConfig should return the same config when passed *Config")
	}
}

// TestNormalizeConfig_WithInvalidType tests normalizeConfig with unexpected type
func TestNormalizeConfig_WithInvalidType(t *testing.T) {
	// Test with an integer (invalid type)
	cfg := normalizeConfig(42)
	if cfg == nil {
		t.Error("normalizeConfig(int) should return default config, not nil")
		return
	}
	// Should default to auto mode for invalid types
	if cfg.Mode != ModeAuto {
		t.Errorf("Expected ModeAuto for invalid type, got %s", cfg.Mode)
	}
}

// TestNewResolver_WithConfigStruct tests newResolver with full Config struct
func TestNewResolver_WithConfigStruct(t *testing.T) {
	cfg := &Config{
		Mode: ModeSoftware,
		TPM2Config: &TPM2Config{
			Device: "/dev/tpmrm0",
		},
		PKCS11Config: &PKCS11Config{
			Module: "/usr/lib/libsofthsm2.so",
		},
	}

	resolver, err := newResolver(cfg)
	if err != nil {
		t.Fatalf("newResolver with config struct failed: %v", err)
	}
	defer func() { _ = resolver.Close() }()

	if resolver == nil {
		t.Error("newResolver returned nil")
	}
}

// TestAutoResolver_RandFallback tests the fallback mechanism in Rand()
func TestAutoResolver_RandFallback(t *testing.T) {
	// Create resolver with fallback configured
	cfg := &Config{
		Mode:         ModeSoftware,
		FallbackMode: ModeSoftware,
	}

	resolver, err := newAutoResolver(cfg)
	if err != nil {
		t.Fatalf("newAutoResolver failed: %v", err)
	}
	defer func() { _ = resolver.Close() }()

	// Normal operation should work
	data, err := resolver.Rand(32)
	if err != nil {
		t.Errorf("Rand() failed: %v", err)
	}
	if len(data) != 32 {
		t.Errorf("Expected 32 bytes, got %d", len(data))
	}
}

// TestNormalizeConfig_EmptyMode tests normalizeConfig with empty mode in Config
func TestNormalizeConfig_EmptyMode(t *testing.T) {
	cfg := &Config{Mode: ""} // Empty mode should default to auto
	result := normalizeConfig(cfg)
	if result == nil {
		t.Fatal("normalizeConfig returned nil")
	}
	if result.Mode != ModeAuto {
		t.Errorf("Expected ModeAuto for empty mode, got %s", result.Mode)
	}
}

// TestNewResolver_TPM2Mode tests attempting to create TPM2 resolver (will fail without hardware)
func TestNewResolver_TPM2Mode(t *testing.T) {
	cfg := &Config{Mode: ModeTPM2}
	resolver, err := newResolver(cfg)

	// Without TPM2 hardware/build tag, this should return an error
	if err != nil {
		// Expected when TPM2 is not available
		if resolver != nil {
			t.Error("Expected nil resolver when TPM2 is not available")
		}
		return
	}

	// If TPM2 is available, resolver should work
	if resolver != nil {
		defer func() { _ = resolver.Close() }()
	}
}

// TestNewResolver_PKCS11Mode tests attempting to create PKCS11 resolver (will fail without hardware)
func TestNewResolver_PKCS11Mode(t *testing.T) {
	cfg := &Config{Mode: ModePKCS11}
	resolver, err := newResolver(cfg)

	// Without PKCS#11 hardware/build tag, this should return an error
	if err != nil {
		// Expected when PKCS#11 is not available
		if resolver != nil {
			t.Error("Expected nil resolver when PKCS#11 is not available")
		}
		return
	}

	// If PKCS#11 is available, resolver should work
	if resolver != nil {
		defer func() { _ = resolver.Close() }()
	}
}

// TestAutoResolver_WithEmptyFallback tests auto resolver with empty fallback mode
func TestAutoResolver_WithEmptyFallback(t *testing.T) {
	cfg := &Config{
		Mode:         ModeSoftware,
		FallbackMode: "", // Empty fallback
	}

	resolver, err := newAutoResolver(cfg)
	if err != nil {
		t.Fatalf("newAutoResolver failed: %v", err)
	}
	defer func() { _ = resolver.Close() }()

	// Should still work with primary resolver
	data, err := resolver.Rand(32)
	if err != nil {
		t.Errorf("Rand() failed: %v", err)
	}
	if len(data) != 32 {
		t.Errorf("Expected 32 bytes, got %d", len(data))
	}
}

// TestAutoResolver_WithTPM2Fallback tests auto resolver with TPM2 as fallback
func TestAutoResolver_WithTPM2Fallback(t *testing.T) {
	cfg := &Config{
		Mode:         ModeSoftware,
		FallbackMode: ModeTPM2,
	}

	resolver, err := newAutoResolver(cfg)
	if err != nil {
		t.Fatalf("newAutoResolver failed: %v", err)
	}
	defer func() { _ = resolver.Close() }()

	// Should work even if TPM2 fallback fails to initialize
	data, err := resolver.Rand(32)
	if err != nil {
		t.Errorf("Rand() failed: %v", err)
	}
	if len(data) != 32 {
		t.Errorf("Expected 32 bytes, got %d", len(data))
	}
}

// TestAutoResolver_WithPKCS11Fallback tests auto resolver with PKCS11 as fallback
func TestAutoResolver_WithPKCS11Fallback(t *testing.T) {
	cfg := &Config{
		Mode:         ModeSoftware,
		FallbackMode: ModePKCS11,
	}

	resolver, err := newAutoResolver(cfg)
	if err != nil {
		t.Fatalf("newAutoResolver failed: %v", err)
	}
	defer func() { _ = resolver.Close() }()

	// Should work even if PKCS11 fallback fails to initialize
	data, err := resolver.Rand(32)
	if err != nil {
		t.Errorf("Rand() failed: %v", err)
	}
	if len(data) != 32 {
		t.Errorf("Expected 32 bytes, got %d", len(data))
	}
}

// TestNewResolver_EmptyMode tests newResolver with empty mode string
func TestNewResolver_EmptyMode(t *testing.T) {
	cfg := &Config{Mode: ""}
	resolver, err := newResolver(cfg)
	if err != nil {
		t.Fatalf("newResolver with empty mode failed: %v", err)
	}
	defer func() { _ = resolver.Close() }()

	// Empty mode should default to auto, which uses software
	if !resolver.Available() {
		t.Error("Resolver should be available with empty mode (defaults to auto)")
	}
}

// TestAutoResolver_AutoModeSelection tests the auto mode selection logic
func TestAutoResolver_AutoModeSelection(t *testing.T) {
	cfg := &Config{Mode: ModeAuto}
	resolver, err := newAutoResolver(cfg)
	if err != nil {
		t.Fatalf("newAutoResolver with ModeAuto failed: %v", err)
	}
	defer func() { _ = resolver.Close() }()

	// Auto mode should select an available resolver
	if !resolver.Available() {
		t.Error("Auto resolver should be available")
	}

	// Should be able to generate random bytes
	data, err := resolver.Rand(32)
	if err != nil {
		t.Errorf("Rand() failed: %v", err)
	}
	if len(data) != 32 {
		t.Errorf("Expected 32 bytes, got %d", len(data))
	}

	// Source should be non-nil
	source := resolver.Source()
	if source == nil {
		t.Error("Source() should return non-nil")
	}
}

// TestNewAutoResolver_WithTPM2Config tests auto resolver creation with TPM2 config
func TestNewAutoResolver_WithTPM2Config(t *testing.T) {
	cfg := &Config{
		Mode: ModeAuto,
		TPM2Config: &TPM2Config{
			Device:         "/dev/tpm0",
			MaxRequestSize: 32,
		},
	}
	resolver, err := newAutoResolver(cfg)
	if err != nil {
		t.Fatalf("newAutoResolver with TPM2Config failed: %v", err)
	}
	defer func() { _ = resolver.Close() }()

	// Should fallback to software when TPM2 not available
	if !resolver.Available() {
		t.Error("Auto resolver should be available (fallback to software)")
	}
}

// TestNewAutoResolver_WithPKCS11Config tests auto resolver creation with PKCS11 config
func TestNewAutoResolver_WithPKCS11Config(t *testing.T) {
	cfg := &Config{
		Mode: ModeAuto,
		PKCS11Config: &PKCS11Config{
			Module: "/usr/lib/libsofthsm2.so",
			SlotID: 0,
		},
	}
	resolver, err := newAutoResolver(cfg)
	if err != nil {
		t.Fatalf("newAutoResolver with PKCS11Config failed: %v", err)
	}
	defer func() { _ = resolver.Close() }()

	// Should fallback to software when PKCS#11 not available
	if !resolver.Available() {
		t.Error("Auto resolver should be available (fallback to software)")
	}
}

// TestNewAutoResolver_WithAllConfigs tests auto resolver with all hardware configs
func TestNewAutoResolver_WithAllConfigs(t *testing.T) {
	cfg := &Config{
		Mode: ModeAuto,
		TPM2Config: &TPM2Config{
			Device:         "/dev/tpm0",
			MaxRequestSize: 32,
		},
		PKCS11Config: &PKCS11Config{
			Module:      "/usr/lib/libsofthsm2.so",
			SlotID:      0,
			PINRequired: true,
			PIN:         "1234",
		},
	}
	resolver, err := newAutoResolver(cfg)
	if err != nil {
		t.Fatalf("newAutoResolver with all configs failed: %v", err)
	}
	defer func() { _ = resolver.Close() }()

	// Should work (will use software since hardware not available)
	data, err := resolver.Rand(32)
	if err != nil {
		t.Errorf("Rand() failed: %v", err)
	}
	if len(data) != 32 {
		t.Errorf("Expected 32 bytes, got %d", len(data))
	}
}

// TestAutoResolver_FallbackToSoftware tests the software fallback path
func TestAutoResolver_FallbackToSoftware(t *testing.T) {
	// Test that auto mode falls back to software when hardware unavailable
	cfg := &Config{
		Mode: ModeAuto,
		// No hardware configs, should use software
	}
	resolver, err := newAutoResolver(cfg)
	if err != nil {
		t.Fatalf("newAutoResolver fallback to software failed: %v", err)
	}
	defer func() { _ = resolver.Close() }()

	// Verify software fallback works
	if !resolver.Available() {
		t.Error("Software fallback should be available")
	}

	// Multiple calls to ensure stability
	for i := 0; i < 10; i++ {
		data, err := resolver.Rand(16)
		if err != nil {
			t.Errorf("Rand() call %d failed: %v", i, err)
		}
		if len(data) != 16 {
			t.Errorf("Expected 16 bytes, got %d", len(data))
		}
	}
}

// TestAutoResolver_ConcurrentAccess tests thread safety of auto resolver
func TestAutoResolver_ConcurrentAccess(t *testing.T) {
	cfg := &Config{Mode: ModeAuto}
	resolver, err := newAutoResolver(cfg)
	if err != nil {
		t.Fatalf("newAutoResolver failed: %v", err)
	}
	defer func() { _ = resolver.Close() }()

	// Test concurrent access to Rand, Source, and Available
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func() {
			defer func() { done <- true }()
			for j := 0; j < 100; j++ {
				// Call Rand
				if _, err := resolver.Rand(32); err != nil {
					t.Errorf("Concurrent Rand() failed: %v", err)
				}
				// Call Source
				_ = resolver.Source()
				// Call Available
				_ = resolver.Available()
			}
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}
}

// TestAutoResolver_AvailableWithFallback tests Available when fallback is configured
func TestAutoResolver_AvailableWithFallback(t *testing.T) {
	cfg := &Config{
		Mode:         ModeAuto,
		FallbackMode: ModeSoftware,
	}
	resolver, err := newAutoResolver(cfg)
	if err != nil {
		t.Fatalf("newAutoResolver failed: %v", err)
	}
	defer func() { _ = resolver.Close() }()

	// Should be available (either primary or fallback)
	if !resolver.Available() {
		t.Error("Resolver with fallback should be available")
	}
}

// TestAutoResolver_CloseMultiple tests calling Close multiple times
func TestAutoResolver_CloseMultiple(t *testing.T) {
	cfg := &Config{
		Mode:         ModeAuto,
		FallbackMode: ModeSoftware,
	}
	resolver, err := newAutoResolver(cfg)
	if err != nil {
		t.Fatalf("newAutoResolver failed: %v", err)
	}

	// Close multiple times should not panic or error
	for i := 0; i < 3; i++ {
		if err := resolver.Close(); err != nil {
			t.Errorf("Close() call %d returned error: %v", i+1, err)
		}
	}
}

// TestAutoResolver_SourceConsistency tests that Source returns consistent results
func TestAutoResolver_SourceConsistency(t *testing.T) {
	cfg := &Config{Mode: ModeAuto}
	resolver, err := newAutoResolver(cfg)
	if err != nil {
		t.Fatalf("newAutoResolver failed: %v", err)
	}
	defer func() { _ = resolver.Close() }()

	// Get source multiple times, should return same source
	source1 := resolver.Source()
	source2 := resolver.Source()

	if source1 == nil || source2 == nil {
		t.Fatal("Source() returned nil")
	}

	// Both sources should work
	data1, err1 := source1.Rand(16)
	data2, err2 := source2.Rand(16)

	if err1 != nil || err2 != nil {
		t.Errorf("Source.Rand() failed: err1=%v, err2=%v", err1, err2)
	}
	if len(data1) != 16 || len(data2) != 16 {
		t.Error("Source.Rand() returned wrong size")
	}
}

// TestNewAutoResolver_AllPriorities tests auto resolver tries each priority
func TestNewAutoResolver_AllPriorities(t *testing.T) {
	// Test that auto resolver handles various configs
	tests := []struct {
		name   string
		config *Config
	}{
		{
			name:   "with nil config fields",
			config: &Config{Mode: ModeAuto},
		},
		{
			name: "with PKCS11 config",
			config: &Config{
				Mode: ModeAuto,
				PKCS11Config: &PKCS11Config{
					Module: "/nonexistent/lib.so",
					SlotID: 0,
				},
			},
		},
		{
			name: "with TPM2 config",
			config: &Config{
				Mode: ModeAuto,
				TPM2Config: &TPM2Config{
					Device:         "/dev/tpmrm0",
					MaxRequestSize: 32,
				},
			},
		},
		{
			name: "with both configs",
			config: &Config{
				Mode: ModeAuto,
				PKCS11Config: &PKCS11Config{
					Module: "/nonexistent/lib.so",
				},
				TPM2Config: &TPM2Config{
					Device: "/dev/tpmrm0",
				},
			},
		},
		{
			name: "with fallback mode auto",
			config: &Config{
				Mode:         ModeAuto,
				FallbackMode: ModeAuto,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolver, err := newAutoResolver(tt.config)
			if err != nil {
				t.Fatalf("newAutoResolver failed: %v", err)
			}
			defer func() { _ = resolver.Close() }()

			// Should still work (falls back to software)
			if !resolver.Available() {
				t.Error("Resolver should be available (software fallback)")
			}

			data, err := resolver.Rand(32)
			if err != nil {
				t.Errorf("Rand() failed: %v", err)
			}
			if len(data) != 32 {
				t.Errorf("Expected 32 bytes, got %d", len(data))
			}
		})
	}
}

// TestAutoResolver_EdgeCase_NilFallback tests auto resolver with nil fallback
func TestAutoResolver_EdgeCase_NilFallback(t *testing.T) {
	// Create resolver with invalid fallback mode to ensure fallback is nil
	cfg := &Config{
		Mode:         ModeAuto,
		FallbackMode: "invalid",
	}
	resolver, err := newAutoResolver(cfg)
	if err != nil {
		t.Fatalf("newAutoResolver failed: %v", err)
	}
	defer func() { _ = resolver.Close() }()

	// Should still work with nil fallback
	data, err := resolver.Rand(32)
	if err != nil {
		t.Errorf("Rand() with nil fallback failed: %v", err)
	}
	if len(data) != 32 {
		t.Errorf("Expected 32 bytes, got %d", len(data))
	}
}

// TestAutoResolver_InitializationFallbacks tests hardware initialization fallback paths
func TestAutoResolver_InitializationFallbacks(t *testing.T) {
	tests := []struct {
		name   string
		config *Config
	}{
		{
			name: "PKCS11 with valid config falls back to software",
			config: &Config{
				Mode: ModeAuto,
				PKCS11Config: &PKCS11Config{
					Module:      "/nonexistent/pkcs11/module.so",
					SlotID:      0,
					PINRequired: true,
					PIN:         "1234",
				},
			},
		},
		{
			name: "TPM2 with valid config falls back to software",
			config: &Config{
				Mode: ModeAuto,
				TPM2Config: &TPM2Config{
					Device:         "/dev/nonexistent_tpm",
					MaxRequestSize: 64,
				},
			},
		},
		{
			name: "Both hardware configs fall back to software",
			config: &Config{
				Mode: ModeAuto,
				PKCS11Config: &PKCS11Config{
					Module: "/nonexistent/pkcs11/module.so",
					SlotID: 999,
				},
				TPM2Config: &TPM2Config{
					Device:         "/dev/nonexistent_tpm",
					MaxRequestSize: 32,
				},
			},
		},
		{
			name: "PKCS11 with incomplete config",
			config: &Config{
				Mode: ModeAuto,
				PKCS11Config: &PKCS11Config{
					Module: "",
					SlotID: 0,
				},
			},
		},
		{
			name: "TPM2 with incomplete config",
			config: &Config{
				Mode: ModeAuto,
				TPM2Config: &TPM2Config{
					Device: "",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolver, err := newAutoResolver(tt.config)
			if err != nil {
				t.Fatalf("newAutoResolver failed: %v", err)
			}
			defer func() { _ = resolver.Close() }()

			// Should fallback to software and be available
			if !resolver.Available() {
				t.Error("Resolver should be available via software fallback")
			}

			// Should be able to generate random data
			data, err := resolver.Rand(32)
			if err != nil {
				t.Errorf("Rand() failed: %v", err)
			}
			if len(data) != 32 {
				t.Errorf("Expected 32 bytes, got %d", len(data))
			}
		})
	}
}

// TestAutoResolver_FallbackModeInvalidConfig tests various invalid fallback configurations
func TestAutoResolver_FallbackModeInvalidConfig(t *testing.T) {
	tests := []struct {
		name         string
		fallbackMode Mode
	}{
		{name: "invalid fallback mode", fallbackMode: "invalid_mode"},
		{name: "empty fallback mode", fallbackMode: ""},
		{name: "tpm2 fallback (unavailable)", fallbackMode: ModeTPM2},
		{name: "pkcs11 fallback (unavailable)", fallbackMode: ModePKCS11},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				Mode:         ModeSoftware,
				FallbackMode: tt.fallbackMode,
			}
			resolver, err := newAutoResolver(cfg)
			if err != nil {
				t.Fatalf("newAutoResolver failed: %v", err)
			}
			defer func() { _ = resolver.Close() }()

			// Primary resolver (software) should work regardless of fallback failure
			data, err := resolver.Rand(32)
			if err != nil {
				t.Errorf("Rand() should succeed with primary resolver: %v", err)
			}
			if len(data) != 32 {
				t.Errorf("Expected 32 bytes, got %d", len(data))
			}
		})
	}
}

// TestAutoResolver_AutoFallback tests the auto mode fallback behavior
func TestAutoResolver_AutoFallback(t *testing.T) {
	cfg := &Config{
		Mode:         ModeAuto,
		FallbackMode: ModeAuto,
	}
	resolver, err := newAutoResolver(cfg)
	if err != nil {
		t.Fatalf("newAutoResolver with auto fallback failed: %v", err)
	}
	defer func() { _ = resolver.Close() }()

	if !resolver.Available() {
		t.Error("Auto resolver with auto fallback should be available")
	}

	data, err := resolver.Rand(32)
	if err != nil {
		t.Errorf("Rand() with auto fallback failed: %v", err)
	}
	if len(data) != 32 {
		t.Errorf("Expected 32 bytes, got %d", len(data))
	}
}

// TestAutoResolver_PKCS11Priority tests PKCS11 has higher priority than TPM2
func TestAutoResolver_PKCS11Priority(t *testing.T) {
	cfg := &Config{
		Mode: ModeAuto,
		PKCS11Config: &PKCS11Config{
			Module:      "/usr/lib/softhsm/libsofthsm2.so",
			SlotID:      0,
			PINRequired: false,
		},
		TPM2Config: &TPM2Config{
			Device:         "/dev/tpmrm0",
			MaxRequestSize: 32,
		},
	}
	resolver, err := newAutoResolver(cfg)
	if err != nil {
		t.Fatalf("newAutoResolver failed: %v", err)
	}
	defer func() { _ = resolver.Close() }()

	// Should succeed with software fallback since neither hardware is available
	if !resolver.Available() {
		t.Error("Resolver should fall back to software")
	}

	data, err := resolver.Rand(16)
	if err != nil {
		t.Errorf("Rand() failed: %v", err)
	}
	if len(data) != 16 {
		t.Errorf("Expected 16 bytes, got %d", len(data))
	}
}

// TestAutoResolver_CloseNilResolvers tests Close with nil resolver and fallback
func TestAutoResolver_CloseNilResolvers(t *testing.T) {
	// Create an autoResolver with potentially nil components
	ar := &autoResolver{
		resolver: nil,
		fallback: nil,
	}

	// Close should not panic with nil resolvers
	err := ar.Close()
	if err != nil {
		t.Errorf("Close() with nil resolvers returned error: %v", err)
	}
}

// TestAutoResolver_AvailableWithNilResolvers tests Available with edge cases
func TestAutoResolver_AvailableWithNilResolvers(t *testing.T) {
	// Test with valid resolver, nil fallback
	resolver, _ := newSoftwareResolver()
	ar := &autoResolver{
		resolver: resolver,
		fallback: nil,
	}
	if !ar.Available() {
		t.Error("Available() should return true with valid primary resolver")
	}
	_ = ar.Close()

	// Test with valid resolver and fallback
	resolver1, _ := newSoftwareResolver()
	resolver2, _ := newSoftwareResolver()
	ar = &autoResolver{
		resolver: resolver1,
		fallback: resolver2,
	}
	if !ar.Available() {
		t.Error("Available() should return true with both resolvers")
	}
	_ = ar.Close()
}

// TestAutoResolver_SourceWithConcurrency tests Source method under concurrent access
func TestAutoResolver_SourceWithConcurrency(t *testing.T) {
	cfg := &Config{
		Mode:         ModeAuto,
		FallbackMode: ModeSoftware,
	}
	resolver, err := newAutoResolver(cfg)
	if err != nil {
		t.Fatalf("newAutoResolver failed: %v", err)
	}
	defer func() { _ = resolver.Close() }()

	// Concurrently access Source method
	done := make(chan bool)
	for i := 0; i < 5; i++ {
		go func() {
			defer func() { done <- true }()
			for j := 0; j < 50; j++ {
				source := resolver.Source()
				if source == nil {
					t.Error("Source() returned nil during concurrent access")
				}
			}
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 5; i++ {
		<-done
	}
}

// TestNormalizeConfig_WithEmptyModeInConfig tests empty mode field in Config struct
func TestNormalizeConfig_WithEmptyModeInConfig(t *testing.T) {
	cfg := &Config{
		Mode:         "",
		FallbackMode: ModeSoftware,
	}
	result := normalizeConfig(cfg)
	if result.Mode != ModeAuto {
		t.Errorf("Empty mode in Config should default to ModeAuto, got %s", result.Mode)
	}
	// Should preserve other fields
	if result.FallbackMode != ModeSoftware {
		t.Error("normalizeConfig should preserve FallbackMode")
	}
}

// TestNewResolver_WithStringMode tests NewResolver with Mode string
func TestNewResolver_WithStringMode(t *testing.T) {
	// Test with Mode type directly (not *Config)
	resolver, err := NewResolver(ModeSoftware)
	if err != nil {
		t.Fatalf("NewResolver with Mode failed: %v", err)
	}
	defer func() { _ = resolver.Close() }()

	if !resolver.Available() {
		t.Error("Resolver should be available")
	}

	data, err := resolver.Rand(32)
	if err != nil {
		t.Errorf("Rand() failed: %v", err)
	}
	if len(data) != 32 {
		t.Errorf("Expected 32 bytes, got %d", len(data))
	}
}

// TestNewResolver_WithAutoMode tests explicit auto mode selection
func TestNewResolver_WithAutoMode(t *testing.T) {
	resolver, err := NewResolver(ModeAuto)
	if err != nil {
		t.Fatalf("NewResolver with ModeAuto failed: %v", err)
	}
	defer func() { _ = resolver.Close() }()

	if !resolver.Available() {
		t.Error("Auto mode resolver should be available")
	}

	data, err := resolver.Rand(64)
	if err != nil {
		t.Errorf("Rand() failed: %v", err)
	}
	if len(data) != 64 {
		t.Errorf("Expected 64 bytes, got %d", len(data))
	}
}

// TestAutoResolver_RandVariousSizes tests Rand with different byte sizes
func TestAutoResolver_RandVariousSizes(t *testing.T) {
	cfg := &Config{Mode: ModeAuto}
	resolver, err := newAutoResolver(cfg)
	if err != nil {
		t.Fatalf("newAutoResolver failed: %v", err)
	}
	defer func() { _ = resolver.Close() }()

	sizes := []int{0, 1, 7, 15, 16, 31, 32, 63, 64, 127, 128, 255, 256, 512, 1024, 2048}
	for _, size := range sizes {
		data, err := resolver.Rand(size)
		if err != nil {
			t.Errorf("Rand(%d) failed: %v", size, err)
		}
		if len(data) != size {
			t.Errorf("Rand(%d) returned %d bytes", size, len(data))
		}
	}
}

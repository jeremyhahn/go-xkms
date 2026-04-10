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

package rand

import (
	"testing"
)

// TestAutoResolver_FallbackModeInvalid tests fallback to an invalid mode
// This exercises the error path in newAutoResolver when fallback creation fails
func TestAutoResolver_FallbackModeInvalid(t *testing.T) {
	cfg := &Config{
		Mode:         ModeAuto,
		FallbackMode: Mode("invalid_mode_xyz"),
	}

	// newAutoResolver should succeed even with invalid fallback
	// (fallback failures are non-fatal according to the code)
	resolver, err := newAutoResolver(cfg)
	if err != nil {
		t.Fatalf("newAutoResolver should not fail with invalid fallback: %v", err)
	}
	defer func() { _ = resolver.Close() }()

	// Primary should work
	data, err := resolver.Rand(32)
	if err != nil {
		t.Errorf("Rand failed: %v", err)
	}
	if len(data) != 32 {
		t.Errorf("Expected 32 bytes, got %d", len(data))
	}

	// Verify fallback was set to nil due to creation failure
	ar, ok := resolver.(*autoResolver)
	if !ok {
		t.Fatal("Expected autoResolver type")
	}
	if ar.fallback != nil {
		t.Error("Fallback should be nil due to invalid mode")
	}
}

// TestAutoResolver_FallbackModeTPM2Unavailable_VerbosePath tests TPM2 fallback path
func TestAutoResolver_FallbackModeTPM2Unavailable_VerbosePath(t *testing.T) {
	// When fallback mode is TPM2 but TPM is unavailable,
	// the fallback should fail to initialize but primary should work
	cfg := &Config{
		Mode:         ModeAuto,
		FallbackMode: ModeTPM2,
		TPM2Config: &TPM2Config{
			Device: "/dev/nonexistent_tpm_device",
		},
	}

	resolver, err := newAutoResolver(cfg)
	if err != nil {
		t.Fatalf("newAutoResolver should not fail: %v", err)
	}
	defer func() { _ = resolver.Close() }()

	// Primary works via software
	if !resolver.Available() {
		t.Error("Resolver should be available")
	}

	// Verify data generation works
	data, err := resolver.Rand(64)
	if err != nil {
		t.Errorf("Rand failed: %v", err)
	}
	if len(data) != 64 {
		t.Errorf("Expected 64 bytes, got %d", len(data))
	}
}

// TestAutoResolver_FallbackModePKCS11Unavailable_VerbosePath tests PKCS11 fallback path
func TestAutoResolver_FallbackModePKCS11Unavailable_VerbosePath(t *testing.T) {
	cfg := &Config{
		Mode:         ModeAuto,
		FallbackMode: ModePKCS11,
		PKCS11Config: &PKCS11Config{
			Module: "/nonexistent/pkcs11/module.so",
		},
	}

	resolver, err := newAutoResolver(cfg)
	if err != nil {
		t.Fatalf("newAutoResolver should not fail: %v", err)
	}
	defer func() { _ = resolver.Close() }()

	// Primary works via software
	if !resolver.Available() {
		t.Error("Resolver should be available")
	}
}

// TestAutoResolver_AllFallbackModes tests all fallback mode combinations
func TestAutoResolver_AllFallbackModes(t *testing.T) {
	fallbackModes := []Mode{
		ModeSoftware,
		ModeAuto,
		ModeTPM2,
		ModePKCS11,
		Mode("invalid"),
		Mode(""),
	}

	for _, fallbackMode := range fallbackModes {
		t.Run(string(fallbackMode), func(t *testing.T) {
			cfg := &Config{
				Mode:         ModeAuto,
				FallbackMode: fallbackMode,
			}

			resolver, err := newAutoResolver(cfg)
			if err != nil {
				t.Fatalf("newAutoResolver failed for fallback %s: %v", fallbackMode, err)
			}
			defer func() { _ = resolver.Close() }()

			// All should have available primary
			if !resolver.Available() {
				t.Errorf("Resolver should be available for fallback mode %s", fallbackMode)
			}

			// All should generate data
			data, err := resolver.Rand(16)
			if err != nil {
				t.Errorf("Rand failed for fallback mode %s: %v", fallbackMode, err)
			}
			if len(data) != 16 {
				t.Errorf("Expected 16 bytes for fallback mode %s, got %d", fallbackMode, len(data))
			}
		})
	}
}

// TestAutoResolver_PrimaryAvailable_NoFallbackUsed tests that fallback is not used when primary succeeds
func TestAutoResolver_PrimaryAvailable_NoFallbackUsed(t *testing.T) {
	cfg := &Config{
		Mode:         ModeAuto,
		FallbackMode: ModeSoftware,
	}

	resolver, err := newAutoResolver(cfg)
	if err != nil {
		t.Fatalf("newAutoResolver failed: %v", err)
	}
	defer func() { _ = resolver.Close() }()

	ar, ok := resolver.(*autoResolver)
	if !ok {
		t.Fatal("Expected autoResolver type")
	}

	// Both should be configured
	if ar.resolver == nil {
		t.Error("Primary resolver should be set")
	}
	if ar.fallback == nil {
		t.Error("Fallback should be set when FallbackMode is specified")
	}

	// Generate data multiple times - primary should always be used
	for i := 0; i < 10; i++ {
		data, err := resolver.Rand(32)
		if err != nil {
			t.Errorf("Rand iteration %d failed: %v", i, err)
		}
		if len(data) != 32 {
			t.Errorf("Rand iteration %d: expected 32 bytes, got %d", i, len(data))
		}
	}
}

// TestAutoResolver_SourceMethodWithFallback tests Source with fallback configured
func TestAutoResolver_SourceMethodWithFallback(t *testing.T) {
	cfg := &Config{
		Mode:         ModeAuto,
		FallbackMode: ModeSoftware,
	}

	resolver, err := newAutoResolver(cfg)
	if err != nil {
		t.Fatalf("newAutoResolver failed: %v", err)
	}
	defer func() { _ = resolver.Close() }()

	source := resolver.Source()
	if source == nil {
		t.Fatal("Source should not return nil")
	}

	// Source should work
	data, err := source.Rand(32)
	if err != nil {
		t.Errorf("Source.Rand failed: %v", err)
	}
	if len(data) != 32 {
		t.Errorf("Expected 32 bytes, got %d", len(data))
	}

	if !source.Available() {
		t.Error("Source should be available")
	}

	err = source.Close()
	if err != nil {
		t.Errorf("Source.Close failed: %v", err)
	}
}

// TestAutoResolver_ReadMethodWithFallback tests Read with fallback configured
func TestAutoResolver_ReadMethodWithFallback(t *testing.T) {
	cfg := &Config{
		Mode:         ModeAuto,
		FallbackMode: ModeSoftware,
	}

	resolver, err := newAutoResolver(cfg)
	if err != nil {
		t.Fatalf("newAutoResolver failed: %v", err)
	}
	defer func() { _ = resolver.Close() }()

	buf := make([]byte, 64)
	n, err := resolver.Read(buf)
	if err != nil {
		t.Errorf("Read failed: %v", err)
	}
	if n != 64 {
		t.Errorf("Expected 64 bytes, got %d", n)
	}

	// Verify data is not all zeros
	allZeros := true
	for _, b := range buf {
		if b != 0 {
			allZeros = false
			break
		}
	}
	if allZeros {
		t.Error("Read should produce non-zero data")
	}
}

// TestAutoResolver_CloseWithFallbackSuccess tests Close with successful fallback close
func TestAutoResolver_CloseWithFallbackSuccess(t *testing.T) {
	cfg := &Config{
		Mode:         ModeAuto,
		FallbackMode: ModeSoftware,
	}

	resolver, err := newAutoResolver(cfg)
	if err != nil {
		t.Fatalf("newAutoResolver failed: %v", err)
	}

	// Close should succeed
	err = resolver.Close()
	if err != nil {
		t.Errorf("Close failed: %v", err)
	}

	// Double close should be safe
	err = resolver.Close()
	if err != nil {
		t.Errorf("Double close failed: %v", err)
	}
}

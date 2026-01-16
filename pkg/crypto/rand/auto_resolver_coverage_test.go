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
	"errors"
	"sync"
	"testing"
)

// TestAutoResolver_FallbackModeAutoRecursive tests fallback to auto mode (recursive)
func TestAutoResolver_FallbackModeAutoRecursive(t *testing.T) {
	cfg := &Config{
		Mode:         ModeAuto,
		FallbackMode: ModeAuto, // This creates an auto resolver as fallback
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

	// Verify fallback was created
	if ar.fallback == nil {
		t.Error("Fallback should be configured")
	}
}

// TestAutoResolver_FallbackModeTPM2Unavailable tests fallback to TPM2 mode when unavailable
func TestAutoResolver_FallbackModeTPM2Unavailable(t *testing.T) {
	cfg := &Config{
		Mode:         ModeAuto,
		FallbackMode: ModeTPM2,
	}

	resolver, err := newAutoResolver(cfg)
	if err != nil {
		t.Fatalf("newAutoResolver should not fail even with TPM2 fallback: %v", err)
	}
	defer func() { _ = resolver.Close() }()

	// Primary should work via software
	data, err := resolver.Rand(32)
	if err != nil {
		t.Errorf("Rand failed: %v", err)
	}
	if len(data) != 32 {
		t.Errorf("Expected 32 bytes, got %d", len(data))
	}
}

// TestAutoResolver_FallbackModePKCS11Unavailable tests fallback to PKCS11 mode when unavailable
func TestAutoResolver_FallbackModePKCS11Unavailable(t *testing.T) {
	cfg := &Config{
		Mode:         ModeAuto,
		FallbackMode: ModePKCS11,
	}

	resolver, err := newAutoResolver(cfg)
	if err != nil {
		t.Fatalf("newAutoResolver should not fail: %v", err)
	}
	defer func() { _ = resolver.Close() }()

	// Primary should work via software
	if !resolver.Available() {
		t.Error("Resolver should be available")
	}
}

// TestAutoResolver_ReadSuccessWithFallback tests successful Read operation with fallback
func TestAutoResolver_ReadSuccessWithFallback(t *testing.T) {
	resolver, _ := newSoftwareResolver()
	fallback, _ := newSoftwareResolver()
	ar := &autoResolver{
		resolver: resolver,
		fallback: fallback,
	}
	defer func() { _ = ar.Close() }()

	buf := make([]byte, 64)
	n, err := ar.Read(buf)
	if err != nil {
		t.Errorf("Read failed: %v", err)
	}
	if n != 64 {
		t.Errorf("Expected 64 bytes, got %d", n)
	}

	// Verify not all zeros
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

// TestAutoResolver_ReadWithFallbackOnPrimaryFail tests Read with fallback on primary failure
func TestAutoResolver_ReadWithFallbackOnPrimaryFail(t *testing.T) {
	failingPrimary := &mockResolver{
		randFunc: func(n int) ([]byte, error) {
			return nil, errors.New("primary failed")
		},
	}
	workingFallback, _ := newSoftwareResolver()

	ar := &autoResolver{
		resolver: failingPrimary,
		fallback: workingFallback,
	}
	defer func() { _ = ar.Close() }()

	buf := make([]byte, 32)
	n, err := ar.Read(buf)
	if err != nil {
		t.Errorf("Read should succeed with fallback: %v", err)
	}
	if n != 32 {
		t.Errorf("Expected 32 bytes, got %d", n)
	}
}

// TestAutoResolver_SourceFromPrimaryResolver tests Source returns primary's source
func TestAutoResolver_SourceFromPrimaryResolver(t *testing.T) {
	resolver, _ := newSoftwareResolver()
	ar := &autoResolver{
		resolver: resolver,
		fallback: nil,
	}
	defer func() { _ = ar.Close() }()

	source := ar.Source()
	if source == nil {
		t.Fatal("Source should not be nil")
	}

	// Source should work
	data, err := source.Rand(16)
	if err != nil {
		t.Errorf("Source.Rand failed: %v", err)
	}
	if len(data) != 16 {
		t.Errorf("Expected 16 bytes, got %d", len(data))
	}
}

// TestAutoResolver_AvailableWithBothResolversTrue tests Available when both are true
func TestAutoResolver_AvailableWithBothResolversTrue(t *testing.T) {
	primary, _ := newSoftwareResolver()
	fallback, _ := newSoftwareResolver()

	ar := &autoResolver{
		resolver: primary,
		fallback: fallback,
	}
	defer func() { _ = ar.Close() }()

	if !ar.Available() {
		t.Error("Should be available when both are available")
	}
}

// TestAutoResolver_AvailableWithPrimaryResolverFalse tests Available when primary is false
func TestAutoResolver_AvailableWithPrimaryResolverFalse(t *testing.T) {
	primary := &mockResolver{
		availableFunc: func() bool { return false },
	}
	fallback := &mockResolver{
		availableFunc: func() bool { return true },
	}

	ar := &autoResolver{
		resolver: primary,
		fallback: fallback,
	}

	if !ar.Available() {
		t.Error("Should be available when fallback is available")
	}
}

// TestAutoResolver_CloseWithNilFallback tests Close with nil fallback
func TestAutoResolver_CloseWithNilFallback(t *testing.T) {
	primary, _ := newSoftwareResolver()

	ar := &autoResolver{
		resolver: primary,
		fallback: nil,
	}

	err := ar.Close()
	if err != nil {
		t.Errorf("Close should not fail: %v", err)
	}
}

// TestAutoResolver_CloseErrorFromPrimary tests Close error propagation from primary
func TestAutoResolver_CloseErrorFromPrimary(t *testing.T) {
	expectedErr := errors.New("close error")
	primary := &mockResolver{
		closeFunc: func() error { return expectedErr },
	}

	ar := &autoResolver{
		resolver: primary,
		fallback: nil,
	}

	err := ar.Close()
	if err == nil {
		t.Error("Expected error from Close")
	}
}

// TestAutoResolver_CloseErrorFromFallback tests Close error propagation from fallback
func TestAutoResolver_CloseErrorFromFallback(t *testing.T) {
	primary, _ := newSoftwareResolver()
	expectedErr := errors.New("fallback close error")
	fallback := &mockResolver{
		closeFunc: func() error { return expectedErr },
	}

	ar := &autoResolver{
		resolver: primary,
		fallback: fallback,
	}

	err := ar.Close()
	if err == nil {
		t.Error("Expected error from Close")
	}
}

// TestAutoResolver_CloseWithNilPrimaryResolver tests Close with nil primary
func TestAutoResolver_CloseWithNilPrimaryResolver(t *testing.T) {
	ar := &autoResolver{
		resolver: nil,
		fallback: nil,
	}

	err := ar.Close()
	if err != nil {
		t.Errorf("Close with nil resolver should not fail: %v", err)
	}
}

// TestAutoResolver_RandWithNoFallback tests Rand error without fallback
func TestAutoResolver_RandWithNoFallback(t *testing.T) {
	expectedErr := errors.New("rand error")
	primary := &mockResolver{
		randFunc: func(n int) ([]byte, error) { return nil, expectedErr },
	}

	ar := &autoResolver{
		resolver: primary,
		fallback: nil,
	}

	_, err := ar.Rand(32)
	if err != expectedErr {
		t.Errorf("Expected error %v, got %v", expectedErr, err)
	}
}

// TestAutoResolver_RandWithFallbackSuccess tests Rand fallback on primary error
func TestAutoResolver_RandWithFallbackSuccess(t *testing.T) {
	primary := &mockResolver{
		randFunc: func(n int) ([]byte, error) { return nil, errors.New("primary error") },
	}
	fallback, _ := newSoftwareResolver()

	ar := &autoResolver{
		resolver: primary,
		fallback: fallback,
	}
	defer func() { _ = ar.Close() }()

	data, err := ar.Rand(32)
	if err != nil {
		t.Errorf("Rand should succeed with fallback: %v", err)
	}
	if len(data) != 32 {
		t.Errorf("Expected 32 bytes, got %d", len(data))
	}
}

// TestAutoResolver_RandWithFallbackError tests Rand when both fail
func TestAutoResolver_RandWithFallbackError(t *testing.T) {
	primary := &mockResolver{
		randFunc: func(n int) ([]byte, error) { return nil, errors.New("primary error") },
	}
	fallback := &mockResolver{
		randFunc: func(n int) ([]byte, error) { return nil, errors.New("fallback error") },
	}

	ar := &autoResolver{
		resolver: primary,
		fallback: fallback,
	}

	_, err := ar.Rand(32)
	if err == nil {
		t.Error("Expected error when both fail")
	}
}

// TestAutoResolver_ConcurrentRandOperations tests concurrent Rand calls
func TestAutoResolver_ConcurrentRandOperations(t *testing.T) {
	resolver, _ := newSoftwareResolver()
	ar := &autoResolver{
		resolver: resolver,
		fallback: nil,
	}
	defer func() { _ = ar.Close() }()

	var wg sync.WaitGroup
	numGoroutines := 50
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				data, err := ar.Rand(32)
				if err != nil {
					t.Errorf("Concurrent Rand failed: %v", err)
					return
				}
				if len(data) != 32 {
					t.Errorf("Expected 32 bytes, got %d", len(data))
				}
			}
		}()
	}

	wg.Wait()
}

// TestAutoResolver_ConcurrentReadOperations tests concurrent Read calls
func TestAutoResolver_ConcurrentReadOperations(t *testing.T) {
	resolver, _ := newSoftwareResolver()
	ar := &autoResolver{
		resolver: resolver,
		fallback: nil,
	}
	defer func() { _ = ar.Close() }()

	var wg sync.WaitGroup
	numGoroutines := 50
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				buf := make([]byte, 32)
				n, err := ar.Read(buf)
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

// TestAutoResolver_ConcurrentMixedOperations tests concurrent mixed operations
func TestAutoResolver_ConcurrentMixedOperations(t *testing.T) {
	resolver, _ := newSoftwareResolver()
	fallback, _ := newSoftwareResolver()
	ar := &autoResolver{
		resolver: resolver,
		fallback: fallback,
	}
	defer func() { _ = ar.Close() }()

	var wg sync.WaitGroup
	numGoroutines := 20
	wg.Add(numGoroutines * 4)

	// Concurrent Rand
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			_, _ = ar.Rand(16)
		}()
	}

	// Concurrent Read
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			buf := make([]byte, 16)
			_, _ = ar.Read(buf)
		}()
	}

	// Concurrent Source
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			_ = ar.Source()
		}()
	}

	// Concurrent Available
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			_ = ar.Available()
		}()
	}

	wg.Wait()
}

// TestAutoResolver_ReadRandomnessVerification tests that Read produces random data
func TestAutoResolver_ReadRandomnessVerification(t *testing.T) {
	resolver, _ := NewResolver(ModeAuto)
	defer func() { _ = resolver.Close() }()

	samples := make([][]byte, 20)
	for i := 0; i < 20; i++ {
		buf := make([]byte, 32)
		n, err := resolver.Read(buf)
		if err != nil {
			t.Fatalf("Read failed: %v", err)
		}
		if n != 32 {
			t.Fatalf("Expected 32 bytes, got %d", n)
		}
		samples[i] = buf
	}

	// Check uniqueness
	for i := 0; i < len(samples); i++ {
		for j := i + 1; j < len(samples); j++ {
			if bytes.Equal(samples[i], samples[j]) {
				t.Errorf("Duplicate samples at %d and %d", i, j)
			}
		}
	}
}

// TestNormalizeConfig_PreservesAllFields tests normalizeConfig preserves other fields
func TestNormalizeConfig_PreservesAllFields(t *testing.T) {
	cfg := &Config{
		Mode:         ModeSoftware,
		FallbackMode: ModeAuto,
		TPM2Config:   &TPM2Config{Device: "/dev/tpm0"},
		PKCS11Config: &PKCS11Config{Module: "/test.so"},
	}

	result := normalizeConfig(cfg)
	if result != cfg {
		t.Error("normalizeConfig should return same config pointer")
	}
	if result.FallbackMode != ModeAuto {
		t.Errorf("FallbackMode not preserved")
	}
	if result.TPM2Config == nil || result.TPM2Config.Device != "/dev/tpm0" {
		t.Error("TPM2Config not preserved")
	}
	if result.PKCS11Config == nil || result.PKCS11Config.Module != "/test.so" {
		t.Error("PKCS11Config not preserved")
	}
}

// TestNewResolver_EmptyConfigStruct tests NewResolver with zero-value Config
func TestNewResolver_EmptyConfigStruct(t *testing.T) {
	cfg := &Config{} // All zero values

	resolver, err := NewResolver(cfg)
	if err != nil {
		t.Fatalf("NewResolver failed: %v", err)
	}
	defer func() { _ = resolver.Close() }()

	// Should default to auto mode
	if !resolver.Available() {
		t.Error("Resolver should be available")
	}
}

// TestNewResolver_UnknownConfigType tests NewResolver with unknown type
func TestNewResolver_UnknownConfigType(t *testing.T) {
	resolver, err := NewResolver(12345) // Random integer

	if err != nil {
		t.Fatalf("NewResolver should handle unknown type: %v", err)
	}
	defer func() { _ = resolver.Close() }()

	// Should default to auto
	if !resolver.Available() {
		t.Error("Resolver should be available")
	}
}

// TestAutoResolver_BothConfigsWithNonexistentPaths tests with both configs pointing to nonexistent paths
func TestAutoResolver_BothConfigsWithNonexistentPaths(t *testing.T) {
	cfg := &Config{
		Mode: ModeAuto,
		PKCS11Config: &PKCS11Config{
			Module: "/nonexistent/path/to/pkcs11.so",
		},
		TPM2Config: &TPM2Config{
			Device: "/nonexistent/tpm/device",
		},
	}

	resolver, err := newAutoResolver(cfg)
	if err != nil {
		t.Fatalf("newAutoResolver should not fail: %v", err)
	}
	defer func() { _ = resolver.Close() }()

	// Should fall back to software
	if !resolver.Available() {
		t.Error("Resolver should be available via software fallback")
	}

	data, err := resolver.Rand(32)
	if err != nil {
		t.Errorf("Rand failed: %v", err)
	}
	if len(data) != 32 {
		t.Errorf("Expected 32 bytes, got %d", len(data))
	}
}

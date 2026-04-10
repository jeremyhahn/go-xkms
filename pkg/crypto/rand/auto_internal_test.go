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
	"errors"
	"testing"
)

// These tests use package-internal access to test code paths that are
// normally only exercised when build tags (pkcs11, tpm2) are enabled.

// mockResolver is a test double for testing auto resolver logic
type mockResolver struct {
	randFunc      func(int) ([]byte, error)
	availableFunc func() bool
	sourceFunc    func() Source
	closeFunc     func() error
}

func (m *mockResolver) Rand(n int) ([]byte, error) {
	if m.randFunc != nil {
		return m.randFunc(n)
	}
	return make([]byte, n), nil
}

func (m *mockResolver) Source() Source {
	if m.sourceFunc != nil {
		return m.sourceFunc()
	}
	return &softwareSource{}
}

func (m *mockResolver) Available() bool {
	if m.availableFunc != nil {
		return m.availableFunc()
	}
	return true
}

func (m *mockResolver) Close() error {
	if m.closeFunc != nil {
		return m.closeFunc()
	}
	return nil
}

func (m *mockResolver) Read(p []byte) (n int, err error) {
	data, err := m.Rand(len(p))
	if err != nil {
		return 0, err
	}
	copy(p, data)
	return len(data), nil
}

// TestAutoResolver_InitWithSoftwareFallback tests initialization fallback to software
func TestAutoResolver_InitWithSoftwareFallback(t *testing.T) {
	// Test that newAutoResolver falls back to software when no hardware available
	// This is what happens when pkcs11Available() and tpm2Available() return false
	cfg := &Config{
		Mode: ModeAuto,
		// Both PKCS11 and TPM2 configs provided but unavailable
		PKCS11Config: &PKCS11Config{Module: "/nonexistent"},
		TPM2Config:   &TPM2Config{Device: "/nonexistent"},
	}

	resolver, err := newAutoResolver(cfg)
	if err != nil {
		t.Fatalf("newAutoResolver should not fail with unavailable hardware: %v", err)
	}
	defer func() { _ = resolver.Close() }()

	// Verify it fell back to software
	if !resolver.Available() {
		t.Error("Resolver should be available via software fallback")
	}

	// Verify it works
	data, err := resolver.Rand(32)
	if err != nil {
		t.Errorf("Rand() should work with software fallback: %v", err)
	}
	if len(data) != 32 {
		t.Errorf("Expected 32 bytes, got %d", len(data))
	}
}

// TestAutoResolver_ManualConstruction tests manually constructed autoResolver
func TestAutoResolver_ManualConstruction(t *testing.T) {
	// Manually construct an autoResolver to test internal behavior
	swResolver, _ := newSoftwareResolver()

	ar := &autoResolver{
		resolver: swResolver,
		fallback: nil,
	}
	defer func() { _ = ar.Close() }()

	// Test basic operations
	if !ar.Available() {
		t.Error("Manually constructed autoResolver should be available")
	}

	data, err := ar.Rand(16)
	if err != nil {
		t.Errorf("Rand() failed: %v", err)
	}
	if len(data) != 16 {
		t.Errorf("Expected 16 bytes, got %d", len(data))
	}

	source := ar.Source()
	if source == nil {
		t.Error("Source() should return non-nil")
	}
}

// TestAutoResolver_FallbackModeSoftware tests explicit software fallback
func TestAutoResolver_FallbackModeSoftware(t *testing.T) {
	cfg := &Config{
		Mode:         ModeAuto,
		FallbackMode: ModeSoftware,
	}

	resolver, err := newAutoResolver(cfg)
	if err != nil {
		t.Fatalf("newAutoResolver failed: %v", err)
	}
	defer func() { _ = resolver.Close() }()

	// Cast to autoResolver to check internal state
	ar, ok := resolver.(*autoResolver)
	if !ok {
		t.Fatal("Expected autoResolver type")
	}

	// Verify fallback was created
	if ar.fallback == nil {
		t.Error("Fallback should be configured when FallbackMode is set")
	}
}

// TestAutoResolver_NoFallbackMode tests without fallback configured
func TestAutoResolver_NoFallbackMode(t *testing.T) {
	cfg := &Config{
		Mode:         ModeAuto,
		FallbackMode: "", // No fallback
	}

	resolver, err := newAutoResolver(cfg)
	if err != nil {
		t.Fatalf("newAutoResolver failed: %v", err)
	}
	defer func() { _ = resolver.Close() }()

	// Cast to autoResolver to check internal state
	ar, ok := resolver.(*autoResolver)
	if !ok {
		t.Fatal("Expected autoResolver type")
	}

	// Verify no fallback was created
	if ar.fallback != nil {
		t.Error("Fallback should be nil when FallbackMode is empty")
	}
}

// TestAutoResolver_RandErrorPropagation tests error propagation
func TestAutoResolver_RandErrorPropagation(t *testing.T) {
	expectedErr := errors.New("test error")

	mock := &mockResolver{
		randFunc: func(n int) ([]byte, error) {
			return nil, expectedErr
		},
	}

	ar := &autoResolver{
		resolver: mock,
		fallback: nil,
	}

	_, err := ar.Rand(32)
	if err == nil {
		t.Error("Expected error to be propagated")
	}
	if err != expectedErr {
		t.Errorf("Expected error %v, got %v", expectedErr, err)
	}
}

// TestAutoResolver_SourcePropagation tests Source method propagation
func TestAutoResolver_SourcePropagation(t *testing.T) {
	expectedSource := &softwareSource{}

	mock := &mockResolver{
		sourceFunc: func() Source {
			return expectedSource
		},
	}

	ar := &autoResolver{
		resolver: mock,
		fallback: nil,
	}

	source := ar.Source()
	if source != expectedSource {
		t.Error("Source should be propagated from underlying resolver")
	}
}

// TestAutoResolver_AvailableOnlyFallback tests Available when only fallback works
func TestAutoResolver_AvailableOnlyFallback(t *testing.T) {
	primaryUnavailable := &mockResolver{
		availableFunc: func() bool {
			return false
		},
	}

	fallbackAvailable := &mockResolver{
		availableFunc: func() bool {
			return true
		},
	}

	ar := &autoResolver{
		resolver: primaryUnavailable,
		fallback: fallbackAvailable,
	}

	if !ar.Available() {
		t.Error("Should be available when fallback is available")
	}
}

// TestAutoResolver_CloseCalledOnBoth tests Close is called on both resolvers
func TestAutoResolver_CloseCalledOnBoth(t *testing.T) {
	primaryClosed := false
	fallbackClosed := false

	primary := &mockResolver{
		closeFunc: func() error {
			primaryClosed = true
			return nil
		},
	}

	fallback := &mockResolver{
		closeFunc: func() error {
			fallbackClosed = true
			return nil
		},
	}

	ar := &autoResolver{
		resolver: primary,
		fallback: fallback,
	}

	err := ar.Close()
	if err != nil {
		t.Errorf("Close() returned error: %v", err)
	}

	if !primaryClosed {
		t.Error("Primary resolver Close() was not called")
	}

	if !fallbackClosed {
		t.Error("Fallback resolver Close() was not called")
	}
}

// TestAutoResolver_CloseErrorFromPrimaryOnly tests Close error propagation
// when only the primary resolver returns an error
func TestAutoResolver_CloseErrorFromPrimaryOnly(t *testing.T) {
	expectedErr := errors.New("primary close error")
	primary := &mockResolver{
		closeFunc: func() error { return expectedErr },
	}
	fallback := &mockResolver{}

	ar := &autoResolver{
		resolver: primary,
		fallback: fallback,
	}

	err := ar.Close()
	if err == nil {
		t.Error("Expected error from Close when primary fails")
	}
	if !errors.Is(err, expectedErr) {
		t.Errorf("Expected wrapped primary error, got: %v", err)
	}
}

// TestAutoResolver_CloseErrorFromFallbackOnly tests Close error propagation
// when only the fallback resolver returns an error
func TestAutoResolver_CloseErrorFromFallbackOnly(t *testing.T) {
	primary := &mockResolver{}
	fallbackErr := errors.New("fallback close error")
	fallback := &mockResolver{
		closeFunc: func() error { return fallbackErr },
	}

	ar := &autoResolver{
		resolver: primary,
		fallback: fallback,
	}

	err := ar.Close()
	if err == nil {
		t.Error("Expected error from Close when fallback fails")
	}
	if !errors.Is(err, fallbackErr) {
		t.Errorf("Expected wrapped fallback error, got: %v", err)
	}
}

// TestAutoResolver_CloseErrorFromBoth tests Close error propagation
// when both primary and fallback resolvers return errors. The primary
// error should take precedence per the implementation.
func TestAutoResolver_CloseErrorFromBoth(t *testing.T) {
	primaryErr := errors.New("primary close error")
	fallbackErr := errors.New("fallback close error")
	primary := &mockResolver{
		closeFunc: func() error { return primaryErr },
	}
	fallback := &mockResolver{
		closeFunc: func() error { return fallbackErr },
	}

	ar := &autoResolver{
		resolver: primary,
		fallback: fallback,
	}

	err := ar.Close()
	if err == nil {
		t.Error("Expected error from Close when both fail")
	}
	// Primary error should be returned first per the implementation
	if !errors.Is(err, primaryErr) {
		t.Errorf("Expected primary error to take precedence, got: %v", err)
	}
}

// TestAutoResolver_ReadErrorWithoutFallback tests Read error handling
// when the primary resolver fails and no fallback is configured
func TestAutoResolver_ReadErrorWithoutFallback(t *testing.T) {
	expectedErr := errors.New("read error from rand")
	primary := &mockResolver{
		randFunc: func(n int) ([]byte, error) {
			return nil, expectedErr
		},
	}

	ar := &autoResolver{
		resolver: primary,
		fallback: nil,
	}

	buf := make([]byte, 32)
	n, err := ar.Read(buf)
	if err == nil {
		t.Error("Expected error from Read when primary fails and no fallback")
	}
	if n != 0 {
		t.Errorf("Expected 0 bytes read on error, got %d", n)
	}
}

// TestAutoResolver_ReadFallbackOnPrimaryError tests Read uses fallback
// when primary resolver fails
func TestAutoResolver_ReadFallbackOnPrimaryError(t *testing.T) {
	primary := &mockResolver{
		randFunc: func(n int) ([]byte, error) {
			return nil, errors.New("primary failed")
		},
	}
	fallback, _ := newSoftwareResolver()

	ar := &autoResolver{
		resolver: primary,
		fallback: fallback,
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

// TestAutoResolver_ThreadSafety tests concurrent access to all methods
func TestAutoResolver_ThreadSafety(t *testing.T) {
	resolver, _ := newSoftwareResolver()
	fallback, _ := newSoftwareResolver()

	ar := &autoResolver{
		resolver: resolver,
		fallback: fallback,
	}
	defer func() { _ = ar.Close() }()

	// Spawn multiple goroutines accessing all methods concurrently
	done := make(chan bool)
	numGoroutines := 20

	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer func() { done <- true }()
			for j := 0; j < 100; j++ {
				// Test all methods
				_, _ = ar.Rand(16)
				ar.Source()
				ar.Available()
			}
		}()
	}

	// Wait for all goroutines
	for i := 0; i < numGoroutines; i++ {
		<-done
	}
}

// TestAutoResolver_NilChecks tests nil safety
func TestAutoResolver_NilChecks(t *testing.T) {
	// Test with nil resolver (should not panic)
	ar := &autoResolver{
		resolver: nil,
		fallback: nil,
	}

	// Close should handle nil gracefully
	err := ar.Close()
	if err != nil {
		t.Errorf("Close() with nil resolvers should not error: %v", err)
	}
}

// TestAutoResolver_FallbackSuccess tests successful fallback on primary failure
func TestAutoResolver_FallbackSuccess(t *testing.T) {
	failingPrimary := &mockResolver{
		randFunc: func(n int) ([]byte, error) {
			return nil, errors.New("primary failed")
		},
	}

	workingFallback := &mockResolver{
		randFunc: func(n int) ([]byte, error) {
			return make([]byte, n), nil
		},
	}

	ar := &autoResolver{
		resolver: failingPrimary,
		fallback: workingFallback,
	}

	data, err := ar.Rand(32)
	if err != nil {
		t.Errorf("Should succeed with fallback: %v", err)
	}
	if len(data) != 32 {
		t.Errorf("Expected 32 bytes, got %d", len(data))
	}
}

// TestAutoResolver_PrimarySuccessNoFallback tests primary success without using fallback
func TestAutoResolver_PrimarySuccessNoFallback(t *testing.T) {
	workingPrimary := &mockResolver{
		randFunc: func(n int) ([]byte, error) {
			return make([]byte, n), nil
		},
	}

	// Fallback that would fail if called
	failingFallback := &mockResolver{
		randFunc: func(n int) ([]byte, error) {
			t.Error("Fallback should not be called when primary succeeds")
			return nil, errors.New("fallback called")
		},
	}

	ar := &autoResolver{
		resolver: workingPrimary,
		fallback: failingFallback,
	}

	data, err := ar.Rand(32)
	if err != nil {
		t.Errorf("Primary should succeed without calling fallback: %v", err)
	}
	if len(data) != 32 {
		t.Errorf("Expected 32 bytes, got %d", len(data))
	}
}

// TestNewResolver_DirectModeSelection tests direct mode usage
func TestNewResolver_DirectModeSelection(t *testing.T) {
	tests := []struct {
		name string
		mode Mode
	}{
		{"software mode", ModeSoftware},
		{"auto mode", ModeAuto},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolver, err := newResolver(&Config{Mode: tt.mode})
			if err != nil {
				t.Fatalf("newResolver(%s) failed: %v", tt.mode, err)
			}
			defer func() { _ = resolver.Close() }()

			if !resolver.Available() {
				t.Errorf("Resolver for mode %s should be available", tt.mode)
			}
		})
	}
}

// TestSoftwareResolver_EdgeCases tests software resolver edge cases
func TestSoftwareResolver_EdgeCases(t *testing.T) {
	resolver, err := newSoftwareResolver()
	if err != nil {
		t.Fatalf("newSoftwareResolver failed: %v", err)
	}
	defer func() { _ = resolver.Close() }()

	// Test zero bytes
	data, err := resolver.Rand(0)
	if err != nil {
		t.Errorf("Rand(0) failed: %v", err)
	}
	if len(data) != 0 {
		t.Errorf("Rand(0) should return 0 bytes, got %d", len(data))
	}

	// Test large request
	data, err = resolver.Rand(65536)
	if err != nil {
		t.Errorf("Rand(65536) failed: %v", err)
	}
	if len(data) != 65536 {
		t.Errorf("Rand(65536) should return 65536 bytes, got %d", len(data))
	}
}

// TestSoftwareSource_DirectUsage tests using softwareSource directly
func TestSoftwareSource_DirectUsage(t *testing.T) {
	source := &softwareSource{}

	// Test Rand
	data, err := source.Rand(32)
	if err != nil {
		t.Errorf("softwareSource.Rand() failed: %v", err)
	}
	if len(data) != 32 {
		t.Errorf("Expected 32 bytes, got %d", len(data))
	}

	// Test Available
	if !source.Available() {
		t.Error("softwareSource.Available() should always return true")
	}

	// Test Close
	if err := source.Close(); err != nil {
		t.Errorf("softwareSource.Close() failed: %v", err)
	}

	// Test multiple sizes
	sizes := []int{0, 1, 16, 32, 64, 128, 256, 1024}
	for _, size := range sizes {
		data, err := source.Rand(size)
		if err != nil {
			t.Errorf("softwareSource.Rand(%d) failed: %v", size, err)
		}
		if len(data) != size {
			t.Errorf("Expected %d bytes, got %d", size, len(data))
		}
	}
}

// TestAutoResolver_InitializationSequence tests the initialization order
func TestAutoResolver_InitializationSequence(t *testing.T) {
	// Test that auto resolver properly initializes with various configs
	configs := []*Config{
		{Mode: ModeAuto},
		{Mode: ModeAuto, FallbackMode: ModeSoftware},
		{Mode: ModeAuto, PKCS11Config: &PKCS11Config{Module: "/test"}},
		{Mode: ModeAuto, TPM2Config: &TPM2Config{Device: "/test"}},
		{Mode: ModeAuto, PKCS11Config: &PKCS11Config{Module: "/test"}, TPM2Config: &TPM2Config{Device: "/test"}},
	}

	for i, cfg := range configs {
		t.Run("config_"+string(rune('A'+i)), func(t *testing.T) {
			resolver, err := newAutoResolver(cfg)
			if err != nil {
				t.Fatalf("newAutoResolver failed for config %d: %v", i, err)
			}
			defer func() { _ = resolver.Close() }()

			// All should succeed by falling back to software
			if !resolver.Available() {
				t.Errorf("Resolver %d should be available", i)
			}

			data, err := resolver.Rand(16)
			if err != nil {
				t.Errorf("Resolver %d Rand() failed: %v", i, err)
			}
			if len(data) != 16 {
				t.Errorf("Resolver %d: expected 16 bytes, got %d", i, len(data))
			}
		})
	}
}

// TestAutoResolver_MultipleFallbackLevels tests nested fallback scenarios
func TestAutoResolver_MultipleFallbackLevels(t *testing.T) {
	// Primary that fails
	primary := &mockResolver{
		randFunc: func(n int) ([]byte, error) {
			return nil, errors.New("primary error")
		},
	}

	// Fallback that succeeds
	fallback := &mockResolver{
		randFunc: func(n int) ([]byte, error) {
			return make([]byte, n), nil
		},
	}

	ar := &autoResolver{
		resolver: primary,
		fallback: fallback,
	}
	defer func() { _ = ar.Close() }()

	// Multiple calls should consistently use fallback
	for i := 0; i < 10; i++ {
		data, err := ar.Rand(32)
		if err != nil {
			t.Errorf("Call %d: Rand() should succeed via fallback: %v", i, err)
		}
		if len(data) != 32 {
			t.Errorf("Call %d: Expected 32 bytes, got %d", i, len(data))
		}
	}
}

// TestNewTPM2Resolver_NilConfig tests that nil config gets defaults applied
func TestNewTPM2Resolver_NilConfig(t *testing.T) {
	// newTPM2Resolver with nil config should set defaults and attempt connection.
	// The connection will fail because /dev/tpm0 likely doesn't exist,
	// but we exercise the config-defaulting code path.
	_, err := newTPM2Resolver(nil)
	// We expect an error because no real TPM device exists
	if err == nil {
		t.Log("TPM2 device was actually available (unexpected in CI)")
	}
}

// TestNewTPM2Resolver_SimulatorDefaults tests simulator config defaults
func TestNewTPM2Resolver_SimulatorDefaults(t *testing.T) {
	cfg := &TPM2Config{
		UseSimulator: true,
		// Leave host, port, type empty to exercise defaults
	}
	_, err := newTPM2Resolver(cfg)
	// Will fail to connect to localhost:2321 but exercises the default logic
	if err != nil {
		// Expected: simulator not running
		if cfg.SimulatorHost != "localhost" {
			t.Errorf("Expected SimulatorHost default 'localhost', got %q", cfg.SimulatorHost)
		}
		if cfg.SimulatorPort != 2321 {
			t.Errorf("Expected SimulatorPort default 2321, got %d", cfg.SimulatorPort)
		}
		if cfg.SimulatorType != "swtpm" {
			t.Errorf("Expected SimulatorType default 'swtpm', got %q", cfg.SimulatorType)
		}
	}
}

// TestNewTPM2Resolver_SimulatorWithPartialConfig tests partial simulator config
func TestNewTPM2Resolver_SimulatorWithPartialConfig(t *testing.T) {
	cfg := &TPM2Config{
		UseSimulator:  true,
		SimulatorHost: "127.0.0.1",
		SimulatorPort: 9999,
		SimulatorType: "custom",
	}
	_, err := newTPM2Resolver(cfg)
	// Connection to 127.0.0.1:9999 will fail
	if err == nil {
		t.Log("Unexpectedly connected to simulator")
	} else {
		// Verify the custom config was preserved (not overwritten by defaults)
		if cfg.SimulatorHost != "127.0.0.1" {
			t.Errorf("SimulatorHost should remain '127.0.0.1', got %q", cfg.SimulatorHost)
		}
		if cfg.SimulatorPort != 9999 {
			t.Errorf("SimulatorPort should remain 9999, got %d", cfg.SimulatorPort)
		}
		if cfg.SimulatorType != "custom" {
			t.Errorf("SimulatorType should remain 'custom', got %q", cfg.SimulatorType)
		}
	}
}

// TestNewTPM2Resolver_DeviceDefault tests that Device gets defaulted
func TestNewTPM2Resolver_DeviceDefault(t *testing.T) {
	cfg := &TPM2Config{
		UseSimulator: false,
		Device:       "", // Should default to /dev/tpm0
	}
	_, err := newTPM2Resolver(cfg)
	if err != nil {
		// Expected: /dev/tpm0 not available
		if cfg.Device != "/dev/tpm0" {
			t.Errorf("Expected Device default '/dev/tpm0', got %q", cfg.Device)
		}
	}
}

// TestNewTPM2Resolver_MaxRequestSizeDefault tests MaxRequestSize defaulting
func TestNewTPM2Resolver_MaxRequestSizeDefault(t *testing.T) {
	cfg := &TPM2Config{
		UseSimulator:   false,
		Device:         "/dev/nonexistent_tpm",
		MaxRequestSize: 0, // Should default to 32
	}
	_, err := newTPM2Resolver(cfg)
	if err != nil {
		// Expected: device not available
		if cfg.MaxRequestSize != 32 {
			t.Errorf("Expected MaxRequestSize default 32, got %d", cfg.MaxRequestSize)
		}
	}
}

// TestNewTPM2Resolver_NegativeMaxRequestSize tests negative MaxRequestSize
func TestNewTPM2Resolver_NegativeMaxRequestSize(t *testing.T) {
	cfg := &TPM2Config{
		UseSimulator:   false,
		Device:         "/dev/nonexistent_tpm",
		MaxRequestSize: -5, // Should default to 32
	}
	_, err := newTPM2Resolver(cfg)
	if err != nil {
		if cfg.MaxRequestSize != 32 {
			t.Errorf("Expected MaxRequestSize default 32, got %d", cfg.MaxRequestSize)
		}
	}
}

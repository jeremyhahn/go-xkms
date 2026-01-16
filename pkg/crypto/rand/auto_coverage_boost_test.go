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
	"io"
	"sync"
	"testing"
)

// errorResolver is a resolver that returns errors for testing error paths
type errorResolver struct {
	randErr     error
	closeErr    error
	available   bool
	closeCalled bool
	randCalled  bool
	sourceValue Source
	closeCount  int
	mu          sync.Mutex
}

func newErrorResolver(randErr, closeErr error, available bool) *errorResolver {
	return &errorResolver{
		randErr:   randErr,
		closeErr:  closeErr,
		available: available,
	}
}

func (e *errorResolver) Rand(n int) ([]byte, error) {
	e.mu.Lock()
	e.randCalled = true
	e.mu.Unlock()
	if e.randErr != nil {
		return nil, e.randErr
	}
	return make([]byte, n), nil
}

func (e *errorResolver) Read(p []byte) (int, error) {
	data, err := e.Rand(len(p))
	if err != nil {
		return 0, err
	}
	copy(p, data)
	return len(data), nil
}

func (e *errorResolver) Source() Source {
	if e.sourceValue != nil {
		return e.sourceValue
	}
	return &softwareSource{}
}

func (e *errorResolver) Available() bool {
	return e.available
}

func (e *errorResolver) Close() error {
	e.mu.Lock()
	e.closeCalled = true
	e.closeCount++
	e.mu.Unlock()
	return e.closeErr
}

// TestAutoResolver_ReadErrorPath tests the Read method error handling
func TestAutoResolver_ReadErrorPath(t *testing.T) {
	expectedErr := errors.New("read error from rand")
	primary := newErrorResolver(expectedErr, nil, true)

	ar := &autoResolver{
		resolver: primary,
		fallback: nil,
	}

	buf := make([]byte, 32)
	n, err := ar.Read(buf)

	if err == nil {
		t.Error("Expected error from Read")
	}
	if n != 0 {
		t.Errorf("Expected 0 bytes read on error, got %d", n)
	}
}

// TestAutoResolver_ReadWithFallbackOnError tests Read uses fallback when primary fails
func TestAutoResolver_ReadWithFallbackOnError(t *testing.T) {
	primaryErr := errors.New("primary read failed")
	primary := newErrorResolver(primaryErr, nil, true)
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

// TestAutoResolver_CloseWithPrimaryError tests Close when primary returns error
func TestAutoResolver_CloseWithPrimaryError(t *testing.T) {
	expectedErr := errors.New("primary close error")
	primary := newErrorResolver(nil, expectedErr, true)
	fallback, _ := newSoftwareResolver()

	ar := &autoResolver{
		resolver: primary,
		fallback: fallback,
	}

	err := ar.Close()
	if err == nil {
		t.Error("Expected error from Close when primary fails")
	}
	if !errors.Is(err, expectedErr) {
		t.Errorf("Expected wrapped error containing primary error")
	}
}

// TestAutoResolver_CloseWithFallbackError tests Close when fallback returns error
func TestAutoResolver_CloseWithFallbackError(t *testing.T) {
	fallbackErr := errors.New("fallback close error")
	primary, _ := newSoftwareResolver()
	fallback := newErrorResolver(nil, fallbackErr, true)

	ar := &autoResolver{
		resolver: primary,
		fallback: fallback,
	}

	err := ar.Close()
	if err == nil {
		t.Error("Expected error from Close when fallback fails")
	}
}

// TestAutoResolver_CloseWithBothErrors tests Close when both return errors
func TestAutoResolver_CloseWithBothErrors(t *testing.T) {
	primaryErr := errors.New("primary close error")
	fallbackErr := errors.New("fallback close error")
	primary := newErrorResolver(nil, primaryErr, true)
	fallback := newErrorResolver(nil, fallbackErr, true)

	ar := &autoResolver{
		resolver: primary,
		fallback: fallback,
	}

	err := ar.Close()
	if err == nil {
		t.Error("Expected error from Close when both fail")
	}
	// Primary error should be returned first
	if !errors.Is(err, primaryErr) {
		t.Errorf("Expected primary error to be returned first")
	}
}

// TestAutoResolver_AvailablePrimaryOnly tests Available with only primary
func TestAutoResolver_AvailablePrimaryOnly(t *testing.T) {
	primary, _ := newSoftwareResolver()

	ar := &autoResolver{
		resolver: primary,
		fallback: nil,
	}
	defer func() { _ = ar.Close() }()

	if !ar.Available() {
		t.Error("Should be available when primary is available")
	}
}

// TestAutoResolver_AvailableViaFallbackOnly tests Available when only fallback works
func TestAutoResolver_AvailableViaFallbackOnly(t *testing.T) {
	primary := newErrorResolver(nil, nil, false) // Not available
	fallback := newErrorResolver(nil, nil, true) // Available

	ar := &autoResolver{
		resolver: primary,
		fallback: fallback,
	}
	defer func() { _ = ar.Close() }()

	if !ar.Available() {
		t.Error("Should be available when fallback is available")
	}
}

// TestAutoResolver_NotAvailable tests Available when neither is available
func TestAutoResolver_NotAvailable(t *testing.T) {
	primary := newErrorResolver(nil, nil, false)  // Not available
	fallback := newErrorResolver(nil, nil, false) // Not available

	ar := &autoResolver{
		resolver: primary,
		fallback: fallback,
	}
	defer func() { _ = ar.Close() }()

	if ar.Available() {
		t.Error("Should not be available when neither resolver is available")
	}
}

// TestAutoResolver_RandWithFallbackBothFail tests when both resolvers fail
func TestAutoResolver_RandWithFallbackBothFail(t *testing.T) {
	primaryErr := errors.New("primary rand error")
	fallbackErr := errors.New("fallback rand error")
	primary := newErrorResolver(primaryErr, nil, true)
	fallback := newErrorResolver(fallbackErr, nil, true)

	ar := &autoResolver{
		resolver: primary,
		fallback: fallback,
	}
	defer func() { _ = ar.Close() }()

	_, err := ar.Rand(32)
	if err == nil {
		t.Error("Expected error when both resolvers fail")
	}
	// Should get fallback error since primary fails first, then fallback is tried
	if !errors.Is(err, fallbackErr) {
		t.Errorf("Expected fallback error, got: %v", err)
	}
}

// TestAutoResolver_RandSucceedsDoesNotUseFallback verifies fallback not used when primary works
func TestAutoResolver_RandSucceedsDoesNotUseFallback(t *testing.T) {
	primary := newErrorResolver(nil, nil, true)
	fallback := newErrorResolver(errors.New("should not be called"), nil, true)

	ar := &autoResolver{
		resolver: primary,
		fallback: fallback,
	}
	defer func() { _ = ar.Close() }()

	data, err := ar.Rand(32)
	if err != nil {
		t.Errorf("Rand should succeed with primary: %v", err)
	}
	if len(data) != 32 {
		t.Errorf("Expected 32 bytes, got %d", len(data))
	}

	// Verify fallback was not called
	fallback.mu.Lock()
	called := fallback.randCalled
	fallback.mu.Unlock()
	if called {
		t.Error("Fallback should not be called when primary succeeds")
	}
}

// TestAutoResolver_SourceReturnsPrimarySource tests Source delegation
func TestAutoResolver_SourceReturnsPrimarySource(t *testing.T) {
	expectedSource := &softwareSource{}
	primary := &errorResolver{
		sourceValue: expectedSource,
		available:   true,
	}

	ar := &autoResolver{
		resolver: primary,
		fallback: nil,
	}
	defer func() { _ = ar.Close() }()

	source := ar.Source()
	if source != expectedSource {
		t.Error("Source should return primary resolver's source")
	}
}

// TestAutoResolver_ConcurrentReadAndRand tests concurrent Read and Rand calls
func TestAutoResolver_ConcurrentReadAndRand(t *testing.T) {
	resolver, _ := newSoftwareResolver()
	ar := &autoResolver{
		resolver: resolver,
		fallback: nil,
	}
	defer func() { _ = ar.Close() }()

	var wg sync.WaitGroup
	numOps := 100

	// Concurrent Rand calls
	wg.Add(numOps)
	for i := 0; i < numOps; i++ {
		go func() {
			defer wg.Done()
			_, err := ar.Rand(16)
			if err != nil {
				t.Errorf("Concurrent Rand failed: %v", err)
			}
		}()
	}

	// Concurrent Read calls
	wg.Add(numOps)
	for i := 0; i < numOps; i++ {
		go func() {
			defer wg.Done()
			buf := make([]byte, 16)
			_, err := ar.Read(buf)
			if err != nil {
				t.Errorf("Concurrent Read failed: %v", err)
			}
		}()
	}

	wg.Wait()
}

// TestAutoResolver_ReadImplementsIOReader verifies Read satisfies io.Reader
func TestAutoResolver_ReadImplementsIOReader(t *testing.T) {
	resolver, _ := NewResolver(ModeAuto)
	defer func() { _ = resolver.Close() }()

	// Verify it satisfies io.Reader
	var reader io.Reader = resolver
	buf := make([]byte, 64)
	n, err := reader.Read(buf)
	if err != nil {
		t.Errorf("io.Reader Read failed: %v", err)
	}
	if n != 64 {
		t.Errorf("Expected 64 bytes, got %d", n)
	}

	// Verify bytes are not all zeros
	allZeros := true
	for _, b := range buf {
		if b != 0 {
			allZeros = false
			break
		}
	}
	if allZeros {
		t.Error("Read should return random data, not zeros")
	}
}

// TestAutoResolver_ReadCopiesCorrectly tests Read copies data correctly
func TestAutoResolver_ReadCopiesCorrectly(t *testing.T) {
	resolver, _ := NewResolver(ModeSoftware)
	defer func() { _ = resolver.Close() }()

	buf1 := make([]byte, 32)
	n, err := resolver.Read(buf1)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	if n != 32 {
		t.Fatalf("Expected 32 bytes, got %d", n)
	}

	buf2 := make([]byte, 32)
	n, err = resolver.Read(buf2)
	if err != nil {
		t.Fatalf("Second Read failed: %v", err)
	}
	if n != 32 {
		t.Fatalf("Expected 32 bytes, got %d", n)
	}

	// Buffers should be different
	if bytes.Equal(buf1, buf2) {
		t.Error("Two consecutive reads should produce different data")
	}
}

// TestAutoResolver_CloseIsIdempotent tests that Close can be called multiple times
func TestAutoResolver_CloseIsIdempotent(t *testing.T) {
	resolver, _ := NewResolver(ModeAuto)

	// Close multiple times
	for i := 0; i < 5; i++ {
		err := resolver.Close()
		if err != nil {
			t.Errorf("Close call %d returned error: %v", i+1, err)
		}
	}
}

// TestAutoResolver_RandWithZeroBytes tests Rand(0) behavior
func TestAutoResolver_RandWithZeroBytes(t *testing.T) {
	resolver, _ := NewResolver(ModeAuto)
	defer func() { _ = resolver.Close() }()

	data, err := resolver.Rand(0)
	if err != nil {
		t.Errorf("Rand(0) failed: %v", err)
	}
	if len(data) != 0 {
		t.Errorf("Expected 0 bytes, got %d", len(data))
	}
}

// TestAutoResolver_ReadWithZeroBuffer tests Read with zero-length buffer
func TestAutoResolver_ReadWithZeroBuffer(t *testing.T) {
	resolver, _ := NewResolver(ModeAuto)
	defer func() { _ = resolver.Close() }()

	buf := make([]byte, 0)
	n, err := resolver.Read(buf)
	if err != nil {
		t.Errorf("Read(empty) failed: %v", err)
	}
	if n != 0 {
		t.Errorf("Expected 0 bytes read, got %d", n)
	}
}

// TestAutoResolver_LargeRead tests Read with large buffer
func TestAutoResolver_LargeRead(t *testing.T) {
	resolver, _ := NewResolver(ModeAuto)
	defer func() { _ = resolver.Close() }()

	buf := make([]byte, 65536)
	n, err := resolver.Read(buf)
	if err != nil {
		t.Errorf("Large Read failed: %v", err)
	}
	if n != 65536 {
		t.Errorf("Expected 65536 bytes, got %d", n)
	}
}

// TestNewAutoResolver_WithInvalidFallback tests auto resolver with invalid fallback mode
func TestNewAutoResolver_WithInvalidFallback(t *testing.T) {
	cfg := &Config{
		Mode:         ModeAuto,
		FallbackMode: "nonexistent_mode",
	}

	resolver, err := newAutoResolver(cfg)
	if err != nil {
		t.Fatalf("newAutoResolver should not fail even with invalid fallback: %v", err)
	}
	defer func() { _ = resolver.Close() }()

	// Should still work with primary
	data, err := resolver.Rand(32)
	if err != nil {
		t.Errorf("Rand should work with primary resolver: %v", err)
	}
	if len(data) != 32 {
		t.Errorf("Expected 32 bytes, got %d", len(data))
	}
}

// TestNewAutoResolver_SoftwareFallback tests auto resolver falls back to software
func TestNewAutoResolver_SoftwareFallback(t *testing.T) {
	// Since no PKCS11 or TPM2 hardware is available, auto should use software
	cfg := &Config{Mode: ModeAuto}

	resolver, err := newAutoResolver(cfg)
	if err != nil {
		t.Fatalf("newAutoResolver failed: %v", err)
	}
	defer func() { _ = resolver.Close() }()

	// Verify it works
	if !resolver.Available() {
		t.Error("Resolver should be available")
	}

	data, err := resolver.Rand(32)
	if err != nil {
		t.Errorf("Rand failed: %v", err)
	}
	if len(data) != 32 {
		t.Errorf("Expected 32 bytes, got %d", len(data))
	}

	// Verify source is not nil
	source := resolver.Source()
	if source == nil {
		t.Error("Source should not be nil")
	}
}

// TestAutoResolver_MultipleConcurrentClose tests concurrent Close calls
func TestAutoResolver_MultipleConcurrentClose(t *testing.T) {
	resolver, _ := NewResolver(ModeAuto)

	var wg sync.WaitGroup
	numClose := 10
	wg.Add(numClose)

	for i := 0; i < numClose; i++ {
		go func() {
			defer wg.Done()
			// Should not panic
			_ = resolver.Close()
		}()
	}

	wg.Wait()
}

// TestAutoResolver_SourceAfterClose tests Source after Close
func TestAutoResolver_SourceAfterClose(t *testing.T) {
	resolver, _ := NewResolver(ModeAuto)
	_ = resolver.Close()

	// Should still return a source (software resolver doesn't track closed state)
	source := resolver.Source()
	if source == nil {
		t.Error("Source should not be nil even after Close")
	}
}

// TestAutoResolver_AvailableAfterClose tests Available after Close
func TestAutoResolver_AvailableAfterClose(t *testing.T) {
	resolver, _ := NewResolver(ModeSoftware)
	_ = resolver.Close()

	// Software resolver remains "available" as it has no resources
	available := resolver.Available()
	if !available {
		t.Log("Software resolver reports not available after close (acceptable)")
	}
}

// TestAutoResolver_ReadVaryingSizes tests Read with various buffer sizes
func TestAutoResolver_ReadVaryingSizes(t *testing.T) {
	resolver, _ := NewResolver(ModeAuto)
	defer func() { _ = resolver.Close() }()

	sizes := []int{1, 7, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 255, 256, 257, 511, 512, 513, 1023, 1024}
	for _, size := range sizes {
		buf := make([]byte, size)
		n, err := resolver.Read(buf)
		if err != nil {
			t.Errorf("Read(%d) failed: %v", size, err)
		}
		if n != size {
			t.Errorf("Read(%d) returned %d bytes", size, n)
		}
	}
}

// TestAutoResolver_RandVaryingSizes tests Rand with various sizes
func TestAutoResolver_RandVaryingSizes(t *testing.T) {
	resolver, _ := NewResolver(ModeAuto)
	defer func() { _ = resolver.Close() }()

	sizes := []int{1, 7, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 255, 256, 257, 511, 512, 513, 1023, 1024}
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

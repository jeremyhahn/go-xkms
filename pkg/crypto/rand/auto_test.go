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
	"errors"
	"testing"
)

// mockFailingResolver is a mock resolver that always fails
type mockFailingResolver struct {
	failRand      bool
	failAvailable bool
}

func (m *mockFailingResolver) Rand(n int) ([]byte, error) {
	if m.failRand {
		return nil, errors.New("mock rand failure")
	}
	return make([]byte, n), nil
}

func (m *mockFailingResolver) Source() Source {
	return &mockFailingSource{failRand: m.failRand}
}

func (m *mockFailingResolver) Available() bool {
	return !m.failAvailable
}

func (m *mockFailingResolver) Close() error {
	return nil
}

func (m *mockFailingResolver) Read(p []byte) (n int, err error) {
	data, err := m.Rand(len(p))
	if err != nil {
		return 0, err
	}
	copy(p, data)
	return len(data), nil
}

type mockFailingSource struct {
	failRand bool
}

func (m *mockFailingSource) Rand(n int) ([]byte, error) {
	if m.failRand {
		return nil, errors.New("mock source rand failure")
	}
	return make([]byte, n), nil
}

func (m *mockFailingSource) Available() bool {
	return !m.failRand
}

func (m *mockFailingSource) Close() error {
	return nil
}

// TestAutoResolver_RandFallbackOnError tests fallback when primary resolver fails
func TestAutoResolver_RandFallbackOnError(t *testing.T) {
	// Create a primary resolver that fails and a working fallback
	primary := &mockFailingResolver{failRand: true}
	fallback, _ := newSoftwareResolver()

	ar := &autoResolver{
		resolver: primary,
		fallback: fallback,
	}
	defer func() { _ = ar.Close() }()

	// Should succeed using fallback
	data, err := ar.Rand(32)
	if err != nil {
		t.Errorf("Rand() should succeed with fallback: %v", err)
	}
	if len(data) != 32 {
		t.Errorf("Expected 32 bytes, got %d", len(data))
	}
}

// TestAutoResolver_RandFailureWithoutFallback tests error when no fallback
func TestAutoResolver_RandFailureWithoutFallback(t *testing.T) {
	// Create a primary resolver that fails with no fallback
	primary := &mockFailingResolver{failRand: true}

	ar := &autoResolver{
		resolver: primary,
		fallback: nil,
	}
	defer func() { _ = ar.Close() }()

	// Should fail since there's no fallback
	_, err := ar.Rand(32)
	if err == nil {
		t.Error("Rand() should fail when primary fails and no fallback")
	}
}

// TestAutoResolver_RandBothFail tests when both primary and fallback fail
func TestAutoResolver_RandBothFail(t *testing.T) {
	// Create resolvers that both fail
	primary := &mockFailingResolver{failRand: true}
	fallback := &mockFailingResolver{failRand: true}

	ar := &autoResolver{
		resolver: primary,
		fallback: fallback,
	}
	defer func() { _ = ar.Close() }()

	// Should fail since both fail
	_, err := ar.Rand(32)
	if err == nil {
		t.Error("Rand() should fail when both primary and fallback fail")
	}
}

// TestAutoResolver_AvailableWithFailedPrimaryButWorkingFallback tests Available
func TestAutoResolver_AvailableWithFailedPrimaryButWorkingFallback(t *testing.T) {
	// Create a primary that's not available but fallback is
	primary := &mockFailingResolver{failAvailable: true}
	fallback, _ := newSoftwareResolver()

	ar := &autoResolver{
		resolver: primary,
		fallback: fallback,
	}
	defer func() { _ = ar.Close() }()

	// Should be available via fallback
	if !ar.Available() {
		t.Error("Available() should return true when fallback is available")
	}
}

// TestAutoResolver_AvailableBothUnavailable tests when both are unavailable
func TestAutoResolver_AvailableBothUnavailable(t *testing.T) {
	// Create resolvers that are both unavailable
	primary := &mockFailingResolver{failAvailable: true}
	fallback := &mockFailingResolver{failAvailable: true}

	ar := &autoResolver{
		resolver: primary,
		fallback: fallback,
	}
	defer func() { _ = ar.Close() }()

	// Should not be available
	if ar.Available() {
		t.Error("Available() should return false when both resolvers are unavailable")
	}
}

// TestAutoResolver_CloseWithFallback tests closing both resolvers
func TestAutoResolver_CloseWithFallback(t *testing.T) {
	primary, _ := newSoftwareResolver()
	fallback, _ := newSoftwareResolver()

	ar := &autoResolver{
		resolver: primary,
		fallback: fallback,
	}

	err := ar.Close()
	if err != nil {
		t.Errorf("Close() should not error: %v", err)
	}
}

// TestAutoResolver_SourceReturnsUnderlyingSource tests Source method
func TestAutoResolver_SourceReturnsUnderlyingSource(t *testing.T) {
	resolver, _ := newSoftwareResolver()
	ar := &autoResolver{
		resolver: resolver,
		fallback: nil,
	}
	defer func() { _ = ar.Close() }()

	source := ar.Source()
	if source == nil {
		t.Error("Source() should return non-nil source")
	}

	// Verify the source works
	data, err := source.Rand(16)
	if err != nil {
		t.Errorf("Source.Rand() failed: %v", err)
	}
	if len(data) != 16 {
		t.Errorf("Expected 16 bytes, got %d", len(data))
	}
}

// TestAutoResolver_ConcurrentRandWithFallback tests concurrent access to fallback
func TestAutoResolver_ConcurrentRandWithFallback(t *testing.T) {
	// Primary that sometimes fails
	primary := &mockFailingResolver{failRand: true}
	fallback, _ := newSoftwareResolver()

	ar := &autoResolver{
		resolver: primary,
		fallback: fallback,
	}
	defer func() { _ = ar.Close() }()

	// Concurrent Rand calls should all succeed via fallback
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func() {
			defer func() { done <- true }()
			for j := 0; j < 50; j++ {
				data, err := ar.Rand(32)
				if err != nil {
					t.Errorf("Concurrent Rand() failed: %v", err)
				}
				if len(data) != 32 {
					t.Errorf("Expected 32 bytes, got %d", len(data))
				}
			}
		}()
	}

	for i := 0; i < 10; i++ {
		<-done
	}
}

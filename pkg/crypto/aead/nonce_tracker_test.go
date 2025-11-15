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
	"crypto/rand"
	"sync"
	"testing"
)

// TestNewNonceTracker tests the creation of a new nonce tracker.
func TestNewNonceTracker(t *testing.T) {
	tests := []struct {
		name    string
		enabled bool
	}{
		{
			name:    "enabled tracker",
			enabled: true,
		},
		{
			name:    "disabled tracker",
			enabled: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tracker := NewNonceTracker(tt.enabled)
			if tracker == nil {
				t.Fatal("NewNonceTracker() returned nil")
			}
			if tracker.enabled != tt.enabled {
				t.Errorf("enabled = %v, want %v", tracker.enabled, tt.enabled)
			}
			if tracker.nonces == nil {
				t.Error("nonces map is nil")
			}
			if tracker.Count() != 0 {
				t.Errorf("Count() = %d, want 0", tracker.Count())
			}
		})
	}
}

// TestCheckAndRecordNonce_Enabled tests nonce tracking when enabled.
func TestCheckAndRecordNonce_Enabled(t *testing.T) {
	tracker := NewNonceTracker(true)

	// First use should succeed
	nonce := make([]byte, 12)
	rand.Read(nonce)

	err := tracker.CheckAndRecordNonce(nonce)
	if err != nil {
		t.Errorf("CheckAndRecordNonce() first use failed: %v", err)
	}

	// Second use of same nonce should fail
	err = tracker.CheckAndRecordNonce(nonce)
	if err == nil {
		t.Error("CheckAndRecordNonce() second use should have failed")
	}
	if err != ErrNonceReuse {
		t.Errorf("CheckAndRecordNonce() error = %v, want %v", err, ErrNonceReuse)
	}

	// Different nonce should succeed
	nonce2 := make([]byte, 12)
	rand.Read(nonce2)

	err = tracker.CheckAndRecordNonce(nonce2)
	if err != nil {
		t.Errorf("CheckAndRecordNonce() different nonce failed: %v", err)
	}

	// Verify count
	if tracker.Count() != 2 {
		t.Errorf("Count() = %d, want 2", tracker.Count())
	}
}

// TestCheckAndRecordNonce_Disabled tests that tracking is bypassed when disabled.
func TestCheckAndRecordNonce_Disabled(t *testing.T) {
	tracker := NewNonceTracker(false)

	nonce := make([]byte, 12)
	rand.Read(nonce)

	// First use
	err := tracker.CheckAndRecordNonce(nonce)
	if err != nil {
		t.Errorf("CheckAndRecordNonce() with disabled tracker failed: %v", err)
	}

	// Second use should also succeed when disabled
	err = tracker.CheckAndRecordNonce(nonce)
	if err != nil {
		t.Errorf("CheckAndRecordNonce() second use with disabled tracker failed: %v", err)
	}

	// Count should be 0 when disabled
	if tracker.Count() != 0 {
		t.Errorf("Count() = %d, want 0 (disabled)", tracker.Count())
	}
}

// TestContains tests the Contains method.
func TestContains(t *testing.T) {
	tracker := NewNonceTracker(true)

	nonce := make([]byte, 12)
	rand.Read(nonce)

	// Should not contain before recording
	if tracker.Contains(nonce) {
		t.Error("Contains() returned true for unrecorded nonce")
	}

	// Record the nonce
	tracker.CheckAndRecordNonce(nonce)

	// Should contain after recording
	if !tracker.Contains(nonce) {
		t.Error("Contains() returned false for recorded nonce")
	}

	// Different nonce should not be contained
	nonce2 := make([]byte, 12)
	rand.Read(nonce2)
	if tracker.Contains(nonce2) {
		t.Error("Contains() returned true for different nonce")
	}
}

// TestContains_Disabled tests Contains when tracking is disabled.
func TestContains_Disabled(t *testing.T) {
	tracker := NewNonceTracker(false)

	nonce := make([]byte, 12)
	rand.Read(nonce)

	tracker.CheckAndRecordNonce(nonce)

	// Should always return false when disabled
	if tracker.Contains(nonce) {
		t.Error("Contains() returned true when tracker is disabled")
	}
}

// TestCount tests the Count method.
func TestCount(t *testing.T) {
	tracker := NewNonceTracker(true)

	if tracker.Count() != 0 {
		t.Errorf("Count() = %d, want 0", tracker.Count())
	}

	// Add multiple nonces
	for i := 0; i < 5; i++ {
		nonce := make([]byte, 12)
		rand.Read(nonce)
		tracker.CheckAndRecordNonce(nonce)
	}

	if tracker.Count() != 5 {
		t.Errorf("Count() = %d, want 5", tracker.Count())
	}
}

// TestClear tests the Clear method.
func TestClear(t *testing.T) {
	tracker := NewNonceTracker(true)

	// Add some nonces
	nonce1 := make([]byte, 12)
	rand.Read(nonce1)
	tracker.CheckAndRecordNonce(nonce1)

	nonce2 := make([]byte, 12)
	rand.Read(nonce2)
	tracker.CheckAndRecordNonce(nonce2)

	if tracker.Count() != 2 {
		t.Errorf("Count() = %d, want 2", tracker.Count())
	}

	// Clear all nonces
	tracker.Clear()

	if tracker.Count() != 0 {
		t.Errorf("Count() after Clear() = %d, want 0", tracker.Count())
	}

	// Nonces should be usable again after clear
	err := tracker.CheckAndRecordNonce(nonce1)
	if err != nil {
		t.Errorf("CheckAndRecordNonce() after Clear() failed: %v", err)
	}
}

// TestIsEnabled tests the IsEnabled method.
func TestIsEnabled(t *testing.T) {
	tracker := NewNonceTracker(true)
	if !tracker.IsEnabled() {
		t.Error("IsEnabled() = false, want true")
	}

	tracker2 := NewNonceTracker(false)
	if tracker2.IsEnabled() {
		t.Error("IsEnabled() = true, want false")
	}
}

// TestSetEnabled tests enabling and disabling tracking.
func TestSetEnabled(t *testing.T) {
	tracker := NewNonceTracker(true)

	nonce := make([]byte, 12)
	rand.Read(nonce)

	// Record a nonce while enabled
	tracker.CheckAndRecordNonce(nonce)

	// Disable tracking
	tracker.SetEnabled(false)
	if tracker.IsEnabled() {
		t.Error("IsEnabled() = true after SetEnabled(false)")
	}

	// Should allow reuse when disabled
	err := tracker.CheckAndRecordNonce(nonce)
	if err != nil {
		t.Errorf("CheckAndRecordNonce() with disabled tracker failed: %v", err)
	}

	// Re-enable tracking
	tracker.SetEnabled(true)
	if !tracker.IsEnabled() {
		t.Error("IsEnabled() = false after SetEnabled(true)")
	}

	// Should detect reuse again (nonce still in map)
	err = tracker.CheckAndRecordNonce(nonce)
	if err == nil {
		t.Error("CheckAndRecordNonce() should have failed after re-enabling")
	}
}

// TestConcurrentAccess tests thread safety with concurrent operations.
func TestConcurrentAccess(t *testing.T) {
	tracker := NewNonceTracker(true)
	const numGoroutines = 100
	const noncesPerGoroutine = 100

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	// Launch multiple goroutines that add nonces concurrently
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < noncesPerGoroutine; j++ {
				nonce := make([]byte, 12)
				rand.Read(nonce)
				tracker.CheckAndRecordNonce(nonce)
			}
		}()
	}

	wg.Wait()

	expectedCount := numGoroutines * noncesPerGoroutine
	actualCount := tracker.Count()

	if actualCount != expectedCount {
		t.Errorf("Count() = %d, want %d", actualCount, expectedCount)
	}
}

// TestConcurrentReuseDetection tests that nonce reuse is properly detected under concurrent load.
func TestConcurrentReuseDetection(t *testing.T) {
	tracker := NewNonceTracker(true)

	// Create a nonce that will be reused
	sharedNonce := make([]byte, 12)
	rand.Read(sharedNonce)

	const numGoroutines = 10
	successCount := 0
	failureCount := 0
	var mu sync.Mutex
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	// Multiple goroutines try to use the same nonce
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			err := tracker.CheckAndRecordNonce(sharedNonce)
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				successCount++
			} else {
				failureCount++
			}
		}()
	}

	wg.Wait()

	// Exactly one should succeed, the rest should fail
	if successCount != 1 {
		t.Errorf("successCount = %d, want 1", successCount)
	}
	if failureCount != numGoroutines-1 {
		t.Errorf("failureCount = %d, want %d", failureCount, numGoroutines-1)
	}
}

// TestDifferentNonceSizes tests tracking with different nonce sizes.
func TestDifferentNonceSizes(t *testing.T) {
	tracker := NewNonceTracker(true)

	sizes := []int{12, 16, 24, 32} // Common nonce sizes

	for _, size := range sizes {
		nonce := make([]byte, size)
		rand.Read(nonce)

		err := tracker.CheckAndRecordNonce(nonce)
		if err != nil {
			t.Errorf("CheckAndRecordNonce() with size %d failed: %v", size, err)
		}

		// Verify reuse detection for this size
		err = tracker.CheckAndRecordNonce(nonce)
		if err == nil {
			t.Errorf("CheckAndRecordNonce() should have detected reuse for size %d", size)
		}
	}

	if tracker.Count() != len(sizes) {
		t.Errorf("Count() = %d, want %d", tracker.Count(), len(sizes))
	}
}

// TestEmptyNonce tests handling of empty nonces.
func TestEmptyNonce(t *testing.T) {
	tracker := NewNonceTracker(true)

	emptyNonce := []byte{}

	// First use
	err := tracker.CheckAndRecordNonce(emptyNonce)
	if err != nil {
		t.Errorf("CheckAndRecordNonce() with empty nonce failed: %v", err)
	}

	// Reuse should be detected
	err = tracker.CheckAndRecordNonce(emptyNonce)
	if err == nil {
		t.Error("CheckAndRecordNonce() should have detected empty nonce reuse")
	}
}

// BenchmarkCheckAndRecordNonce benchmarks the performance of nonce tracking.
func BenchmarkCheckAndRecordNonce(b *testing.B) {
	tracker := NewNonceTracker(true)
	nonces := make([][]byte, b.N)

	// Pre-generate nonces to isolate tracking performance
	for i := 0; i < b.N; i++ {
		nonces[i] = make([]byte, 12)
		rand.Read(nonces[i])
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		tracker.CheckAndRecordNonce(nonces[i])
	}
}

// BenchmarkCheckAndRecordNonce_Disabled benchmarks performance when disabled.
func BenchmarkCheckAndRecordNonce_Disabled(b *testing.B) {
	tracker := NewNonceTracker(false)
	nonce := make([]byte, 12)
	rand.Read(nonce)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		tracker.CheckAndRecordNonce(nonce)
	}
}

// BenchmarkContains benchmarks the Contains method.
func BenchmarkContains(b *testing.B) {
	tracker := NewNonceTracker(true)

	// Add 10000 nonces
	nonces := make([][]byte, 10000)
	for i := 0; i < len(nonces); i++ {
		nonces[i] = make([]byte, 12)
		rand.Read(nonces[i])
		tracker.CheckAndRecordNonce(nonces[i])
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		tracker.Contains(nonces[i%len(nonces)])
	}
}

// BenchmarkConcurrentCheckAndRecord benchmarks concurrent nonce tracking.
func BenchmarkConcurrentCheckAndRecord(b *testing.B) {
	tracker := NewNonceTracker(true)
	nonces := make([][]byte, b.N)

	for i := 0; i < b.N; i++ {
		nonces[i] = make([]byte, 12)
		rand.Read(nonces[i])
	}

	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			tracker.CheckAndRecordNonce(nonces[i])
			i++
		}
	})
}

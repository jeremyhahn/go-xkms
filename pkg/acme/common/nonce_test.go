// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-ca.
//
// go-trusted-ca is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package common

import (
	"encoding/base64"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// GenerateNonce Tests
// =============================================================================

func TestGenerateNonce(t *testing.T) {
	nonce, err := GenerateNonce(32)
	if err != nil {
		t.Fatalf("GenerateNonce() returned error: %v", err)
	}

	if nonce == "" {
		t.Error("GenerateNonce() should return a non-empty string")
	}

	// Nonce should be URL-safe base64 without padding
	if strings.Contains(nonce, "+") || strings.Contains(nonce, "/") || strings.Contains(nonce, "=") {
		t.Errorf("Nonce should be URL-safe base64 without padding, got: %s", nonce)
	}
}

func TestGenerateNonce_Uniqueness(t *testing.T) {
	// Generate multiple nonces and ensure they're unique
	nonces := make(map[string]bool)
	iterations := 1000

	for i := 0; i < iterations; i++ {
		nonce, err := GenerateNonce(32)
		if err != nil {
			t.Fatalf("GenerateNonce() returned error: %v", err)
		}
		if nonces[nonce] {
			t.Errorf("GenerateNonce() generated duplicate nonce: %s", nonce)
		}
		nonces[nonce] = true
	}

	if len(nonces) != iterations {
		t.Errorf("Expected %d unique nonces, got %d", iterations, len(nonces))
	}
}

func TestGenerateNonce_Length(t *testing.T) {
	tests := []struct {
		bytes          int
		expectedLength int
	}{
		{16, 22}, // 16 bytes = 22 base64 chars (ceil(16*8/6))
		{32, 43}, // 32 bytes = 43 base64 chars
		{64, 86}, // 64 bytes = 86 base64 chars
	}

	for _, tt := range tests {
		nonce, err := GenerateNonce(tt.bytes)
		if err != nil {
			t.Fatalf("GenerateNonce(%d) returned error: %v", tt.bytes, err)
		}

		if len(nonce) != tt.expectedLength {
			t.Errorf("GenerateNonce(%d): expected length %d, got %d",
				tt.bytes, tt.expectedLength, len(nonce))
		}
	}
}

func TestGenerateNonce_InvalidLength(t *testing.T) {
	// Test with zero length
	nonce, err := GenerateNonce(0)
	if err != nil {
		t.Errorf("GenerateNonce(0) should not error, got: %v", err)
	}
	if nonce != "" {
		t.Errorf("GenerateNonce(0) should return empty string, got: %s", nonce)
	}
}

func TestGenerateNonce_OutputFormat(t *testing.T) {
	nonce, err := GenerateNonce(32)
	require.NoError(t, err)

	// Should be URL-safe base64 without padding
	for _, ch := range nonce {
		isValid := (ch >= 'a' && ch <= 'z') ||
			(ch >= 'A' && ch <= 'Z') ||
			(ch >= '0' && ch <= '9') ||
			ch == '-' || ch == '_'
		assert.True(t, isValid, "Character %c should be URL-safe base64", ch)
	}

	// Should not contain standard base64 characters
	assert.NotContains(t, nonce, "+")
	assert.NotContains(t, nonce, "/")
	assert.NotContains(t, nonce, "=")
}

func TestGenerateNonce_Decodable(t *testing.T) {
	lengths := []int{16, 32, 64}

	for _, length := range lengths {
		nonce, err := GenerateNonce(length)
		require.NoError(t, err)

		decoded, err := base64.RawURLEncoding.DecodeString(nonce)
		require.NoError(t, err)
		assert.Equal(t, length, len(decoded))
	}
}

func TestGenerateNonce_MassUniqueness(t *testing.T) {
	const count = 10000
	nonces := make(map[string]bool, count)

	for i := 0; i < count; i++ {
		nonce, err := GenerateNonce(32)
		require.NoError(t, err)

		if nonces[nonce] {
			t.Fatalf("Duplicate nonce found at iteration %d: %s", i, nonce)
		}
		nonces[nonce] = true
	}

	assert.Equal(t, count, len(nonces))
}

func TestGenerateNonce_ConcurrentUniqueness(t *testing.T) {
	const goroutines = 10
	const perGoroutine = 1000

	var mu sync.Mutex
	nonces := make(map[string]bool, goroutines*perGoroutine)
	var wg sync.WaitGroup

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < perGoroutine; j++ {
				nonce, err := GenerateNonce(32)
				require.NoError(t, err)

				mu.Lock()
				if nonces[nonce] {
					t.Errorf("Duplicate nonce: %s", nonce)
				}
				nonces[nonce] = true
				mu.Unlock()
			}
		}()
	}

	wg.Wait()
	assert.Equal(t, goroutines*perGoroutine, len(nonces))
}

func TestGenerateNonce_SmallLengths(t *testing.T) {
	tests := []int{1, 2, 3, 4, 5, 6, 7, 8}

	for _, length := range tests {
		nonce, err := GenerateNonce(length)
		require.NoError(t, err)
		assert.NotEmpty(t, nonce)

		// Verify decoding works
		decoded, err := base64.RawURLEncoding.DecodeString(nonce)
		require.NoError(t, err)
		assert.Equal(t, length, len(decoded))
	}
}

func TestGenerateNonce_VeryLargeLengths(t *testing.T) {
	tests := []int{256, 512, 1024}

	for _, length := range tests {
		nonce, err := GenerateNonce(length)
		require.NoError(t, err)
		assert.NotEmpty(t, nonce)

		decoded, err := base64.RawURLEncoding.DecodeString(nonce)
		require.NoError(t, err)
		assert.Equal(t, length, len(decoded))
	}
}

// =============================================================================
// NonceStore Tests
// =============================================================================

func TestNonceStore(t *testing.T) {
	ttl := 500 * time.Millisecond
	store := NewNonceStore(ttl)

	nonce, err := GenerateNonce(32)
	if err != nil {
		t.Fatalf("Failed to generate nonce: %v", err)
	}

	// Add nonce to store
	store.Add(nonce)

	// Verify it exists
	if !store.Exists(nonce) {
		t.Error("Nonce should exist after being added")
	}

	// Verify single-use: nonce should not exist after first check
	if store.Exists(nonce) {
		t.Error("Nonce should not exist after first use (single-use requirement)")
	}
}

func TestNonceStore_Expiration(t *testing.T) {
	ttl := 100 * time.Millisecond
	store := NewNonceStore(ttl)

	nonce, _ := GenerateNonce(32)
	store.Add(nonce)

	// Wait for expiration
	time.Sleep(150 * time.Millisecond)

	// Nonce should be expired
	if store.Exists(nonce) {
		t.Error("Nonce should have expired")
	}
}

func TestNonceStore_NonExistent(t *testing.T) {
	store := NewNonceStore(time.Minute)

	// Check for nonce that was never added
	if store.Exists("non-existent-nonce") {
		t.Error("Non-existent nonce should return false")
	}
}

func TestNonceStore_Sweep(t *testing.T) {
	// Use a short TTL for faster testing
	ttl := 100 * time.Millisecond
	store := NewNonceStore(ttl)

	// Add multiple nonces
	nonces := make([]string, 5)
	for i := 0; i < 5; i++ {
		nonce, _ := GenerateNonce(32)
		store.Add(nonce)
		nonces[i] = nonce
	}

	// Verify all nonces exist
	store.mu.Lock()
	initialCount := len(store.nonces)
	store.mu.Unlock()

	if initialCount != 5 {
		t.Errorf("Expected 5 nonces in store, got %d", initialCount)
	}

	// Wait for nonces to expire
	time.Sleep(150 * time.Millisecond)

	// Manually trigger sweep
	store.sweep()

	// Check that expired nonces were removed
	store.mu.Lock()
	afterSweepCount := len(store.nonces)
	store.mu.Unlock()

	if afterSweepCount != 0 {
		t.Errorf("Expected 0 nonces after sweep, got %d", afterSweepCount)
	}
}

func TestNonceStore_SweepPartial(t *testing.T) {
	ttl := 200 * time.Millisecond
	store := NewNonceStore(ttl)

	// Add first batch of nonces
	for i := 0; i < 3; i++ {
		nonce, _ := GenerateNonce(32)
		store.Add(nonce)
	}

	// Wait for half the TTL
	time.Sleep(100 * time.Millisecond)

	// Add second batch of nonces
	for i := 0; i < 3; i++ {
		nonce, _ := GenerateNonce(32)
		store.Add(nonce)
	}

	// Wait for first batch to expire but not second
	time.Sleep(150 * time.Millisecond)

	// Trigger sweep
	store.sweep()

	// Should have ~3 nonces remaining (second batch)
	store.mu.Lock()
	remainingCount := len(store.nonces)
	store.mu.Unlock()

	if remainingCount != 3 {
		t.Errorf("Expected 3 nonces after partial sweep, got %d", remainingCount)
	}
}

func TestNonceStore_ConcurrentAccess(t *testing.T) {
	store := NewNonceStore(time.Minute)
	done := make(chan bool)

	// Concurrent adds
	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 100; j++ {
				nonce, _ := GenerateNonce(32)
				store.Add(nonce)
			}
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	store.mu.Lock()
	count := len(store.nonces)
	store.mu.Unlock()

	if count != 1000 {
		t.Errorf("Expected 1000 nonces after concurrent adds, got %d", count)
	}
}

func TestNonceStore_ExpirationPrecision(t *testing.T) {
	ttl := 100 * time.Millisecond
	store := NewNonceStore(ttl)

	nonce := "test-nonce-expiration"
	store.Add(nonce)

	// Should exist immediately
	store.mu.Lock()
	_, exists := store.nonces[nonce]
	store.mu.Unlock()
	assert.True(t, exists, "Nonce should exist immediately after Add")

	// Wait just under TTL
	time.Sleep(80 * time.Millisecond)

	// Should still be valid
	assert.True(t, store.Exists(nonce), "Nonce should be valid before TTL")

	// Add again for next test
	store.Add(nonce)

	// Wait past TTL
	time.Sleep(120 * time.Millisecond)

	// Should be expired now
	assert.False(t, store.Exists(nonce), "Nonce should be expired after TTL")
}

func TestNonceStore_SweepTiming(t *testing.T) {
	ttl := 200 * time.Millisecond
	store := NewNonceStore(ttl)

	// Add first batch
	batch1 := []string{"old1", "old2", "old3"}
	for _, n := range batch1 {
		store.Add(n)
	}

	// Wait 150ms
	time.Sleep(150 * time.Millisecond)

	// Add second batch
	batch2 := []string{"new1", "new2", "new3"}
	for _, n := range batch2 {
		store.Add(n)
	}

	// Verify all are present
	store.mu.Lock()
	assert.Equal(t, 6, len(store.nonces))
	store.mu.Unlock()

	// Wait 100ms more (batch1 now 250ms old, batch2 is 100ms old)
	time.Sleep(100 * time.Millisecond)

	// Sweep should remove batch1
	store.sweep()

	// Verify only batch2 remains
	store.mu.Lock()
	assert.Equal(t, 3, len(store.nonces))
	for _, n := range batch2 {
		_, exists := store.nonces[n]
		assert.True(t, exists, "New nonce %s should still exist", n)
	}
	for _, n := range batch1 {
		_, exists := store.nonces[n]
		assert.False(t, exists, "Old nonce %s should be swept", n)
	}
	store.mu.Unlock()
}

func TestNonceStore_ConcurrentAddAndExists(t *testing.T) {
	store := NewNonceStore(time.Minute)
	const ops = 1000
	var wg sync.WaitGroup

	// Concurrent adds
	for i := 0; i < ops; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			nonce, _ := GenerateNonce(16)
			store.Add(nonce)
		}(i)
	}

	wg.Wait()

	// Verify count
	store.mu.Lock()
	count := len(store.nonces)
	store.mu.Unlock()

	assert.Equal(t, ops, count)
}

func TestNonceStore_SweepConcurrency(t *testing.T) {
	ttl := 50 * time.Millisecond
	store := NewNonceStore(ttl)
	var wg sync.WaitGroup

	// Concurrent adds while sweep runs
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				nonce, _ := GenerateNonce(16)
				store.Add(nonce)
				time.Sleep(10 * time.Millisecond)
			}
		}()
	}

	// Concurrent sweeps
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				store.sweep()
				time.Sleep(15 * time.Millisecond)
			}
		}()
	}

	wg.Wait()
	// No deadlock or race = success
}

func TestNonceStore_EmptyNonce(t *testing.T) {
	store := NewNonceStore(time.Minute)

	// Empty nonce should work but is unusual
	store.Add("")

	store.mu.Lock()
	_, exists := store.nonces[""]
	store.mu.Unlock()

	assert.True(t, exists)

	// Exists should consume it
	assert.True(t, store.Exists(""))
	assert.False(t, store.Exists(""))
}

func TestNonceStore_VeryLongNonce(t *testing.T) {
	store := NewNonceStore(time.Minute)

	// Generate a very long nonce
	longNonce, err := GenerateNonce(1024)
	require.NoError(t, err)

	store.Add(longNonce)

	store.mu.Lock()
	_, exists := store.nonces[longNonce]
	store.mu.Unlock()

	assert.True(t, exists)
	assert.True(t, store.Exists(longNonce))
	assert.False(t, store.Exists(longNonce))
}

func TestNonceStore_SpecialCharacters(t *testing.T) {
	store := NewNonceStore(100 * time.Millisecond)
	specialNonce := "nonce-with-special-chars-!@#$%^&*()_+{}|:<>?"
	store.Add(specialNonce)

	if !store.Exists(specialNonce) {
		t.Error("Special character nonce should exist after being added")
	}
}

func TestNonceStore_SingleUseEnforcement(t *testing.T) {
	store := NewNonceStore(time.Minute)

	nonce, err := GenerateNonce(32)
	require.NoError(t, err)

	store.Add(nonce)

	// First use should succeed
	require.True(t, store.Exists(nonce))

	// Second use should fail (nonce consumed)
	require.False(t, store.Exists(nonce))
}

func TestNonceStore_ConcurrentSweepAndAdd(t *testing.T) {
	store := NewNonceStore(100 * time.Millisecond)
	done := make(chan bool)

	// Concurrent adds and sweep operations
	for i := 0; i < 5; i++ {
		go func() {
			for j := 0; j < 50; j++ {
				nonce, _ := GenerateNonce(16)
				store.Add(nonce)
			}
			done <- true
		}()
	}

	// Concurrent sweep operations
	for i := 0; i < 3; i++ {
		go func() {
			for j := 0; j < 20; j++ {
				store.sweep()
				time.Sleep(10 * time.Millisecond)
			}
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 8; i++ {
		<-done
	}

	// Should complete without panic
	require.True(t, true)
}

func TestNonceStore_ExpiredNonceNotExists(t *testing.T) {
	ttl := 50 * time.Millisecond
	store := NewNonceStore(ttl)

	nonce, _ := GenerateNonce(32)
	store.Add(nonce)

	// Verify it exists immediately
	require.True(t, store.Exists(nonce))

	// Re-add it (since it was consumed)
	store.Add(nonce)

	// Wait for expiration
	time.Sleep(100 * time.Millisecond)

	// Now it should not exist
	require.False(t, store.Exists(nonce))
}

func TestNonceStore_NonceConsumption(t *testing.T) {
	store := NewNonceStore(time.Minute)

	nonce, _ := GenerateNonce(32)
	store.Add(nonce)

	// First check should consume the nonce
	exists1 := store.Exists(nonce)
	require.True(t, exists1)

	// Second check should fail (nonce consumed)
	exists2 := store.Exists(nonce)
	require.False(t, exists2)

	// Third check should also fail
	exists3 := store.Exists(nonce)
	require.False(t, exists3)
}

// =============================================================================
// Benchmarks
// =============================================================================

func BenchmarkGenerateNonce(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = GenerateNonce(32)
	}
}

func BenchmarkNonceStore_Add(b *testing.B) {
	store := NewNonceStore(time.Minute)
	for i := 0; i < b.N; i++ {
		nonce, _ := GenerateNonce(32)
		store.Add(nonce)
	}
}

func BenchmarkNonceStore_Exists(b *testing.B) {
	store := NewNonceStore(time.Minute)
	nonce, _ := GenerateNonce(32)
	store.Add(nonce)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		store.Exists(nonce)
		// Re-add for next iteration
		if i < b.N-1 {
			store.Add(nonce)
		}
	}
}

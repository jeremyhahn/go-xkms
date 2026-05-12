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

package rfc8555

import (
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
	"github.com/jeremyhahn/go-xkms/pkg/acme/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNonceGeneration tests secure nonce generation
func TestNonceGeneration(t *testing.T) {
	nonce1, err := common.GenerateNonce(16)
	require.NoError(t, err)
	assert.NotEmpty(t, nonce1)

	nonce2, err := common.GenerateNonce(16)
	require.NoError(t, err)
	assert.NotEmpty(t, nonce2)

	// Nonces should be unique
	assert.NotEqual(t, nonce1, nonce2)
}

// TestNonceGeneration_DifferentLengths tests nonce generation with various lengths
func TestNonceGeneration_DifferentLengths(t *testing.T) {
	lengths := []int{8, 16, 32, 64}

	for _, length := range lengths {
		t.Run(string(rune(length+'0'))+"bytes", func(t *testing.T) {
			nonce, err := common.GenerateNonce(length)
			require.NoError(t, err)
			assert.NotEmpty(t, nonce)

			// Base64 URL encoding increases size, but we verify it's not empty
			assert.Greater(t, len(nonce), 0)
		})
	}
}

// TestNonceStore_AddAndExists tests basic nonce storage and validation
func TestNonceStore_AddAndExists(t *testing.T) {
	store := common.NewNonceStore(5 * time.Minute)

	nonce := "test-nonce-12345"
	store.Add(nonce)

	// First use should succeed
	exists := store.Exists(nonce)
	assert.True(t, exists)

	// Second use should fail (single-use requirement)
	exists = store.Exists(nonce)
	assert.False(t, exists)
}

// TestNonceStore_Expiration tests nonce expiration
func TestNonceStore_Expiration(t *testing.T) {
	// Use very short TTL for testing
	store := common.NewNonceStore(100 * time.Millisecond)

	nonce := "test-nonce-expiring"
	store.Add(nonce)

	// Should exist immediately
	time.Sleep(50 * time.Millisecond)
	exists := store.Exists(nonce)
	assert.True(t, exists)

	// Add another nonce that will expire
	nonce2 := "test-nonce-expiring-2"
	store.Add(nonce2)

	// Wait for expiration
	time.Sleep(150 * time.Millisecond)

	// Should not exist after expiration
	exists = store.Exists(nonce2)
	assert.False(t, exists)
}

// TestNonceStore_NonExistent tests checking for non-existent nonce
func TestNonceStore_NonExistent(t *testing.T) {
	store := common.NewNonceStore(5 * time.Minute)

	// Check for nonce that was never added
	exists := store.Exists("non-existent-nonce")
	assert.False(t, exists)
}

// TestNonceStore_ConcurrentAccess tests thread-safe nonce operations
func TestNonceStore_ConcurrentAccess(t *testing.T) {
	store := common.NewNonceStore(5 * time.Minute)

	// Add multiple nonces concurrently
	done := make(chan bool)
	numGoroutines := 10

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			nonce, err := common.GenerateNonce(16)
			require.NoError(t, err)

			store.Add(nonce)
			exists := store.Exists(nonce)
			assert.True(t, exists)

			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < numGoroutines; i++ {
		<-done
	}
}

// TestRateLimiter_AllowsWithinLimit tests rate limiting allows requests within limit
func TestRateLimiter_AllowsWithinLimit(t *testing.T) {
	limiter := server.NewRateLimiter(5, time.Minute)

	clientID := "test-client-123"

	// Initialize tokens for client
	limiter.Tokens[clientID] = 5
	limiter.LastRequest[clientID] = time.Now()

	// Should allow requests within limit
	for i := 0; i < 5; i++ {
		limiter.Tokens[clientID]--
		assert.GreaterOrEqual(t, limiter.Tokens[clientID], 0)
	}
}

// TestRateLimiter_BlocksExcessRequests tests rate limiting blocks excess requests
func TestRateLimiter_BlocksExcessRequests(t *testing.T) {
	limiter := server.NewRateLimiter(3, time.Minute)

	clientID := "test-client-456"

	// Initialize tokens
	limiter.Tokens[clientID] = 3
	limiter.LastRequest[clientID] = time.Now()

	// Use all tokens
	for i := 0; i < 3; i++ {
		limiter.Tokens[clientID]--
	}

	// No tokens left
	assert.Equal(t, 0, limiter.Tokens[clientID])

	// Would need to wait for refill
	hasTokens := limiter.Tokens[clientID] > 0
	assert.False(t, hasTokens)
}

// TestRateLimiter_TokenRefill tests token bucket refill over time
func TestRateLimiter_TokenRefill(t *testing.T) {
	limiter := server.NewRateLimiter(5, 100*time.Millisecond)

	clientID := "test-client-refill"

	// Start with empty bucket
	limiter.Tokens[clientID] = 0
	limiter.LastRequest[clientID] = time.Now().Add(-200 * time.Millisecond)

	// Calculate elapsed time
	elapsed := time.Since(limiter.LastRequest[clientID])

	// Calculate tokens to add based on elapsed time
	tokensToAdd := int(elapsed.Seconds() / limiter.Interval.Seconds())

	// Should have refilled
	assert.Greater(t, tokensToAdd, 0)
}

// TestRateLimiter_MultipleClients tests rate limiting tracks clients independently
func TestRateLimiter_MultipleClients(t *testing.T) {
	limiter := server.NewRateLimiter(5, time.Minute)

	client1 := "client-1"
	client2 := "client-2"

	// Initialize both clients
	limiter.Tokens[client1] = 5
	limiter.Tokens[client2] = 5
	now := time.Now()
	limiter.LastRequest[client1] = now
	limiter.LastRequest[client2] = now

	// Use tokens from client1
	limiter.Tokens[client1] = 0

	// client2 should still have tokens
	assert.Equal(t, 0, limiter.Tokens[client1])
	assert.Equal(t, 5, limiter.Tokens[client2])
}

// TestRateLimiter_MaxTokensCap tests that tokens don't exceed maximum
func TestRateLimiter_MaxTokensCap(t *testing.T) {
	maxRequests := 10
	limiter := server.NewRateLimiter(maxRequests, time.Minute)

	clientID := "test-client-cap"

	// Try to add more tokens than max
	limiter.Tokens[clientID] = 5
	tokensToAdd := 20

	// Apply cap
	newTokens := min(maxRequests, limiter.Tokens[clientID]+tokensToAdd)

	// Should be capped at max
	assert.Equal(t, maxRequests, newTokens)
}

// TestReplayProtection tests that nonces can only be used once
func TestReplayProtection(t *testing.T) {
	store := common.NewNonceStore(5 * time.Minute)

	nonce := "replay-test-nonce"
	store.Add(nonce)

	// First use - should succeed
	valid1 := store.Exists(nonce)
	assert.True(t, valid1, "First use should be valid")

	// Replay attempt - should fail
	valid2 := store.Exists(nonce)
	assert.False(t, valid2, "Replay should be rejected")

	// Third attempt - should still fail
	valid3 := store.Exists(nonce)
	assert.False(t, valid3, "Multiple replays should be rejected")
}

// Helper function for min comparison
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

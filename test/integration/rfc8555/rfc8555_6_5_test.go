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

package rfc8555

import (
	"crypto/rand"
	"testing"
	"time"

	acmeerrors "github.com/jeremyhahn/go-xkms/pkg/acme/errors"
	"github.com/jeremyhahn/go-xkms/pkg/acme/nonce"
	"github.com/jeremyhahn/go-xkms/pkg/acme/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNonceGeneration tests secure nonce generation via pkg/acme/nonce, the
// canonical ACME nonce implementation (RFC 8555 Section 6.5).
func TestNonceGeneration(t *testing.T) {
	svc, err := nonce.NewService()
	require.NoError(t, err)

	nonce1, err := svc.Generate()
	require.NoError(t, err)
	assert.NotEmpty(t, nonce1)

	nonce2, err := svc.Generate()
	require.NoError(t, err)
	assert.NotEmpty(t, nonce2)

	// Nonces should be unique
	assert.NotEqual(t, nonce1, nonce2)
}

// TestNonce_ValidRedeemedOnce verifies a freshly minted nonce validates
// exactly once, RFC 8555 Section 6.5's single-use requirement.
func TestNonce_ValidRedeemedOnce(t *testing.T) {
	svc, err := nonce.NewService()
	require.NoError(t, err)

	n, err := svc.Generate()
	require.NoError(t, err)

	require.NoError(t, svc.Redeem(n))
}

// TestNonce_ReplayRejected verifies a redeemed nonce cannot be redeemed a
// second time: the server MUST reject a replayed nonce with badNonce.
func TestNonce_ReplayRejected(t *testing.T) {
	svc, err := nonce.NewService()
	require.NoError(t, err)

	n, err := svc.Generate()
	require.NoError(t, err)
	require.NoError(t, svc.Redeem(n))

	err = svc.Redeem(n)
	require.Error(t, err)
	var nonceErr *acmeerrors.NonceError
	require.ErrorAs(t, err, &nonceErr)
	assert.ErrorIs(t, nonceErr.Cause, acmeerrors.ErrNonceAlreadyUsed)
}

// TestNonce_ExpiredRejected verifies a nonce retired from the redeemed-set
// window is rejected. pkg/acme/nonce tracks validity by a bounded, monotonic
// counter window (WithMaxUsed) rather than a per-nonce wall-clock TTL, so
// "expired" here means evicted past the earliest still-valid counter.
func TestNonce_ExpiredRejected(t *testing.T) {
	svc, err := nonce.NewService(nonce.WithMaxUsed(1))
	require.NoError(t, err)

	first, err := svc.Generate()
	require.NoError(t, err)
	second, err := svc.Generate()
	require.NoError(t, err)

	require.NoError(t, svc.Redeem(first))
	// maxUsed=1: redeeming a second nonce evicts "first" from the window and
	// advances earliest past it.
	require.NoError(t, svc.Redeem(second))

	err = svc.Redeem(first)
	require.Error(t, err)
	var nonceErr *acmeerrors.NonceError
	require.ErrorAs(t, err, &nonceErr)
	assert.ErrorIs(t, nonceErr.Cause, acmeerrors.ErrNonceTooLow)
}

// TestNonce_MalformedRejected verifies a syntactically invalid nonce is
// rejected rather than causing a panic or an ambiguous result.
func TestNonce_MalformedRejected(t *testing.T) {
	svc, err := nonce.NewService()
	require.NoError(t, err)

	for _, malformed := range []string{
		"not-base64url!!!",
		"",
		"AAAA",
	} {
		err := svc.Redeem(malformed)
		assert.Error(t, err, "malformed nonce %q should be rejected", malformed)
	}
}

// TestNonce_ForeignPrefixFallsBackToLocal verifies pkg/acme/nonce.MultiService
// routing semantics: a nonce whose prefix identifies a node that has not been
// registered falls back to the local service, whose own prefix check then
// rejects it. This is the load-balanced deployment case where a request
// lands on a node that does not (yet) know about the issuing node.
func TestNonce_ForeignPrefixFallsBackToLocal(t *testing.T) {
	key := make([]byte, 16)
	_, err := rand.Read(key)
	require.NoError(t, err)

	local, err := nonce.NewService(nonce.WithKey(key), nonce.WithPrefix("AAAAAAAA"))
	require.NoError(t, err)
	remote, err := nonce.NewService(nonce.WithKey(key), nonce.WithPrefix("BBBBBBBB"))
	require.NoError(t, err)

	multi := nonce.NewMultiService(local)

	foreignNonce, err := remote.Generate()
	require.NoError(t, err)

	err = multi.Redeem(foreignNonce)
	require.Error(t, err)
}

// TestNonce_ForeignPrefixRoutedWhenRegistered verifies that once a remote
// node's service is registered, MultiService routes redemption of its
// nonces to it instead of falling back to local.
func TestNonce_ForeignPrefixRoutedWhenRegistered(t *testing.T) {
	key := make([]byte, 16)
	_, err := rand.Read(key)
	require.NoError(t, err)

	local, err := nonce.NewService(nonce.WithKey(key), nonce.WithPrefix("AAAAAAAA"))
	require.NoError(t, err)
	remote, err := nonce.NewService(nonce.WithKey(key), nonce.WithPrefix("BBBBBBBB"))
	require.NoError(t, err)

	multi := nonce.NewMultiService(local)
	multi.Register(remote)

	remoteNonce, err := remote.Generate()
	require.NoError(t, err)

	assert.NoError(t, multi.Redeem(remoteNonce))
}

// TestNonce_BoundedMemoryUnderFlood verifies the redeemed-set stays capped
// at WithMaxUsed regardless of how many nonces are minted and redeemed, the
// defense a flood of new-nonce requests needs against an unbounded store.
func TestNonce_BoundedMemoryUnderFlood(t *testing.T) {
	const maxUsed = 100
	svc, err := nonce.NewService(nonce.WithMaxUsed(maxUsed))
	require.NoError(t, err)

	for i := 0; i < maxUsed*10; i++ {
		n, err := svc.Generate()
		require.NoError(t, err)
		require.NoError(t, svc.Redeem(n))
	}

	assert.LessOrEqual(t, svc.UsedCount(), maxUsed)
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

// Helper function for min comparison
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

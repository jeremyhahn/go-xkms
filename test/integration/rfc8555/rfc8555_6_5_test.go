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
	"fmt"
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

// TestRateLimiter_AllowsWithinLimit verifies every request within the
// budget is admitted.
func TestRateLimiter_AllowsWithinLimit(t *testing.T) {
	limiter := server.NewRateLimiter(5, time.Minute)

	for i := 0; i < 5; i++ {
		assert.True(t, limiter.Allow("test-client-123"), "request %d is within the limit", i+1)
	}
}

// TestRateLimiter_BlocksExcessRequests verifies the request after the budget
// is exhausted is refused.
func TestRateLimiter_BlocksExcessRequests(t *testing.T) {
	limiter := server.NewRateLimiter(3, time.Minute)

	for i := 0; i < 3; i++ {
		require.True(t, limiter.Allow("test-client-456"))
	}
	assert.False(t, limiter.Allow("test-client-456"))
}

// TestRateLimiter_TokenRefill verifies an exhausted bucket refills once an
// interval has elapsed.
func TestRateLimiter_TokenRefill(t *testing.T) {
	limiter := server.NewRateLimiter(1, 50*time.Millisecond)

	require.True(t, limiter.Allow("test-client-refill"))
	require.False(t, limiter.Allow("test-client-refill"))

	assert.Eventually(t, func() bool {
		return limiter.Allow("test-client-refill")
	}, 2*time.Second, 60*time.Millisecond)
}

// TestRateLimiter_MultipleClients verifies clients are tracked independently.
func TestRateLimiter_MultipleClients(t *testing.T) {
	limiter := server.NewRateLimiter(1, time.Minute)

	require.True(t, limiter.Allow("client-1"))
	require.False(t, limiter.Allow("client-1"))
	assert.True(t, limiter.Allow("client-2"), "client-2 has its own bucket")
	assert.Equal(t, 2, limiter.Len())
}

// TestRateLimiter_BoundedUnderKeyFlood verifies the limiter's state stays
// capped however many distinct keys it sees.
func TestRateLimiter_BoundedUnderKeyFlood(t *testing.T) {
	limiter := server.NewRateLimiter(10, time.Minute)

	for i := 0; i < server.DefaultMaxEntries*2; i++ {
		limiter.Allow(fmt.Sprintf("client-%d", i))
	}
	assert.Equal(t, server.DefaultMaxEntries, limiter.Len())
}

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

package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"
)

// fakeClock is a manually advanced clock for RateLimiter.now.
type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time          { return c.t }
func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }

// newClockedLimiter returns a limiter driven by a fake clock.
func newClockedLimiter(maxRequests int, interval time.Duration) (*RateLimiter, *fakeClock) {
	clock := &fakeClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	rl := NewRateLimiter(maxRequests, interval)
	rl.now = clock.now
	rl.lastSweep = clock.t
	return rl, clock
}

// signedJWSWithKID returns a genuinely signed flattened JWS whose protected
// header names kid, the shape of a real ACME POST.
func signedJWSWithKID(t *testing.T, key *ecdsa.PrivateKey, kid string) string {
	t.Helper()
	opts := (&jose.SignerOptions{}).WithHeader(jose.HeaderKey("kid"), kid)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, opts)
	require.NoError(t, err)
	jws, err := signer.Sign([]byte(`{}`))
	require.NoError(t, err)
	return jws.FullSerialize()
}

// TestClientRateLimiter_RandomKIDFloodIsLimitedByIP is the #1171 regression
// for the unverified-kid bypass: one IP sending a fresh, validly signed kid
// on every request must still be limited, and must occupy a single bucket.
func TestClientRateLimiter_RandomKIDFloodIsLimitedByIP(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	const limit = 5
	rl := NewRateLimiter(limit, time.Minute)
	chains := map[string]http.Handler{
		"NewClientRateLimiterMiddleware": NewClientRateLimiterMiddleware(limit, time.Minute, nil)(okHandler()),
		"MiddlewareFunc(ClientID)":       rl.MiddlewareFunc(ClientID)(okHandler()),
	}

	for name, handler := range chains {
		t.Run(name, func(t *testing.T) {
			admitted := 0
			for i := 0; i < 4*limit; i++ {
				body := signedJWSWithKID(t, key, fmt.Sprintf("https://kms.example.com/acme/account/%d", i))
				req := httptest.NewRequest(http.MethodPost, "/acme/new-order", strings.NewReader(body))
				req.RemoteAddr = "198.51.100.7:40000"
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, req)
				if rec.Code == http.StatusOK {
					admitted++
				} else {
					require.Equal(t, http.StatusTooManyRequests, rec.Code)
				}
			}
			require.Equal(t, limit, admitted, "a kid flood from one IP must share that IP's budget")
		})
	}
	require.Equal(t, 1, rl.Len(), "unverified kids must never create buckets")
}

// TestRateLimiter_EntriesAreBounded proves the limiter never tracks more than
// its entry cap: once full, a new key is refused while known keys are still
// served from their existing buckets.
func TestRateLimiter_EntriesAreBounded(t *testing.T) {
	rl, _ := newClockedLimiter(10, time.Minute)
	rl.maxEntries = 50

	for i := 0; i < 500; i++ {
		rl.Allow(fmt.Sprintf("198.51.100.%d", i))
	}

	require.Equal(t, 50, rl.Len())
	require.False(t, rl.Allow("203.0.113.1"), "a new key must be refused once the limiter is full")
	require.True(t, rl.Allow("198.51.100.0"), "a tracked key keeps its bucket when the limiter is full")
	require.Equal(t, 50, rl.Len())
}

// TestRateLimiter_EvictsIdleBucketsAfterTTL proves an idle bucket is evicted
// once it has been idle for the TTL (MaxRequests intervals) and that
// eviction frees capacity for new keys, while a bucket younger than the TTL
// survives the same sweep.
func TestRateLimiter_EvictsIdleBucketsAfterTTL(t *testing.T) {
	rl, clock := newClockedLimiter(3, 10*time.Second)
	rl.maxEntries = 4
	ttl := rl.ttl()
	require.Equal(t, 30*time.Second, ttl)

	for i := 0; i < 3; i++ {
		require.True(t, rl.Allow(fmt.Sprintf("old-%d", i)))
	}
	clock.advance(ttl / 2)
	require.True(t, rl.Allow("young"))
	require.False(t, rl.Allow("refused"), "the limiter is full")

	clock.advance(ttl/2 + time.Second)
	require.True(t, rl.Allow("new"), "expired buckets must be evicted to admit a new key")
	require.Equal(t, 2, rl.Len(), "only the young and new buckets remain")
}

// TestRateLimiter_EvictionNeverChangesAdmission proves eviction is invisible
// to a client: after sitting idle for the TTL a drained bucket is evicted and
// the client gets exactly the full budget it would have refilled to anyway.
func TestRateLimiter_EvictionNeverChangesAdmission(t *testing.T) {
	rl, clock := newClockedLimiter(2, time.Second)

	require.True(t, rl.Allow("client"))
	require.True(t, rl.Allow("client"))
	require.False(t, rl.Allow("client"))

	clock.advance(rl.ttl())
	require.True(t, rl.Allow("client"))
	require.True(t, rl.Allow("client"))
	require.False(t, rl.Allow("client"))
}

// TestRateLimiter_RefillWithClock proves the token-bucket refill (one token
// per interval, capped at MaxRequests) without sleeping.
func TestRateLimiter_RefillWithClock(t *testing.T) {
	rl, clock := newClockedLimiter(3, time.Second)

	for i := 0; i < 3; i++ {
		require.True(t, rl.Allow("c"))
	}
	require.False(t, rl.Allow("c"))

	clock.advance(time.Second)
	require.True(t, rl.Allow("c"), "one interval refills one token")
	require.False(t, rl.Allow("c"))

	clock.advance(time.Hour)
	for i := 0; i < 3; i++ {
		require.True(t, rl.Allow("c"))
	}
	require.False(t, rl.Allow("c"), "refill is capped at MaxRequests")
}

// TestRateLimiter_TTL covers the TTL edge cases: overflow saturates, a
// non-positive interval never expires, and a zero budget keeps one interval.
func TestRateLimiter_TTL(t *testing.T) {
	require.Equal(t, time.Duration(math.MaxInt64), NewRateLimiter(math.MaxInt32, time.Duration(math.MaxInt64/2)).ttl())
	require.Equal(t, time.Duration(math.MaxInt64), NewRateLimiter(5, 0).ttl())
	require.Equal(t, time.Minute, NewRateLimiter(0, time.Minute).ttl())
	require.Equal(t, 10*time.Hour, NewRateLimiter(10, time.Hour).ttl())
}

// TestRateLimiter_ZeroIntervalNeverRefills proves a limiter with no positive
// interval admits its initial budget and then nothing, rather than dividing
// by zero or refilling unboundedly.
func TestRateLimiter_ZeroIntervalNeverRefills(t *testing.T) {
	rl, clock := newClockedLimiter(1, 0)

	require.True(t, rl.Allow("c"))
	clock.advance(time.Hour)
	require.False(t, rl.Allow("c"))
}

// TestRateLimiter_HandlerRunsOutsideLock is the #1171 regression for the
// global mutex: while one request is parked inside the next handler (a slow
// synchronous challenge validation, say), another request through the same
// limiter must still be admitted and served before a deadline.
func TestRateLimiter_HandlerRunsOutsideLock(t *testing.T) {
	rl := NewRateLimiter(100, time.Minute)
	entered := make(chan struct{})
	release := make(chan struct{})
	handler := rl.MiddlewareFunc(ClientIP)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/slow" {
			close(entered)
			<-release
		}
		w.WriteHeader(http.StatusOK)
	}))

	slowDone := make(chan struct{})
	go func() {
		defer close(slowDone)
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/slow", nil))
	}()
	<-entered

	fastDone := make(chan int, 1)
	go func() {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/directory", nil))
		fastDone <- rec.Code
	}()

	select {
	case code := <-fastDone:
		require.Equal(t, http.StatusOK, code)
	case <-time.After(5 * time.Second):
		t.Fatal("a request was blocked by another request still inside the handler")
	}
	close(release)
	<-slowDone
}

// okHandler answers 200 to every request.
func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

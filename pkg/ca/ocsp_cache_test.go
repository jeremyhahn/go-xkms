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

package ca

import (
	"math/big"
	"testing"
	"time"
)

// newTestOCSPCache builds an OCSPResponder with no backing CA: the tests in
// this file exercise only the cache/eviction machinery (cacheResponse,
// getCachedResponse, evictLocked), none of which touch o.ca.
func newTestOCSPCache(maxEntries int, cacheTTL time.Duration) *OCSPResponder {
	return &OCSPResponder{
		config: OCSPResponderConfig{
			CacheTTL:        cacheTTL,
			MaxCacheEntries: maxEntries,
		},
		cache: make(map[string]*cachedOCSPResponse),
	}
}

// TestOCSPResponder_CacheCapHolds is the regression guard for go-xkms#1263:
// an OCSP request names any serial number the caller chooses, so before this
// fix a client probing distinct serials grew the response cache without
// bound. Caching more entries than MaxCacheEntries must evict down to the
// cap rather than growing past it.
func TestOCSPResponder_CacheCapHolds(t *testing.T) {
	const maxEntries = 5
	o := newTestOCSPCache(maxEntries, time.Hour)
	farFuture := time.Now().Add(time.Hour)

	for i := 0; i < 4*maxEntries; i++ {
		key := ocspCacheKey(big.NewInt(int64(i)))
		o.cacheResponse(key, []byte("resp"), farFuture)
	}

	if got := len(o.cache); got > maxEntries {
		t.Fatalf("cache grew to %d entries, want at most the %d-entry cap", got, maxEntries)
	}
}

// TestOCSPResponder_CacheCapLeavesRecentEntryServable checks that eviction
// makes room rather than refusing new entries outright: the most recently
// cached response must still be servable after the cap is exceeded.
func TestOCSPResponder_CacheCapLeavesRecentEntryServable(t *testing.T) {
	const maxEntries = 5
	o := newTestOCSPCache(maxEntries, time.Hour)
	farFuture := time.Now().Add(time.Hour)

	var lastKey string
	for i := 0; i < 4*maxEntries; i++ {
		lastKey = ocspCacheKey(big.NewInt(int64(i)))
		o.cacheResponse(lastKey, []byte("resp"), farFuture)
	}

	if got := o.getCachedResponse(lastKey); string(got) != "resp" {
		t.Fatalf("expected the most recently cached entry to be servable, got %q", got)
	}
}

// TestOCSPResponder_ExpiredEntryNotServed proves the cache honors a
// response's own NextUpdate as its TTL even when CacheTTL is configured
// longer: RFC 6960 tells relying parties a response past NextUpdate is
// stale, so the cache must not keep serving it just because CacheTTL alone
// has not elapsed (go-xkms#1263).
func TestOCSPResponder_ExpiredEntryNotServed(t *testing.T) {
	o := newTestOCSPCache(10, time.Hour) // CacheTTL alone would keep this fresh for an hour.
	key := ocspCacheKey(big.NewInt(1))

	o.cacheResponse(key, []byte("resp"), time.Now().Add(-time.Second)) // NextUpdate already in the past.

	if got := o.getCachedResponse(key); got != nil {
		t.Fatalf("expected an entry past its NextUpdate to not be served, got %q", got)
	}
}

// TestOCSPResponder_FreshEntryIsServed is the passing counterpart: an entry
// whose NextUpdate and CacheTTL have not elapsed is returned as-is.
func TestOCSPResponder_FreshEntryIsServed(t *testing.T) {
	o := newTestOCSPCache(10, time.Hour)
	key := ocspCacheKey(big.NewInt(1))

	o.cacheResponse(key, []byte("resp"), time.Now().Add(time.Hour))

	if got := o.getCachedResponse(key); string(got) != "resp" {
		t.Fatalf("expected a fresh entry to be served, got %q", got)
	}
}

// TestNewOCSPResponder_DefaultsMaxCacheEntries verifies a caller that
// customizes CacheTTL/NextUpdate but leaves MaxCacheEntries unset still gets
// the hardened default cap, not an unbounded (zero) cache.
func TestNewOCSPResponder_DefaultsMaxCacheEntries(t *testing.T) {
	responder := NewOCSPResponder(nil, OCSPResponderConfig{
		CacheTTL:   time.Minute,
		NextUpdate: time.Hour,
	})

	want := DefaultOCSPResponderConfig().MaxCacheEntries
	if responder.config.MaxCacheEntries != want {
		t.Fatalf("MaxCacheEntries = %d, want the default %d", responder.config.MaxCacheEntries, want)
	}
}

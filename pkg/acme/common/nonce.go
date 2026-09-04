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

package common

import (
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"
)

// Clock reports the current time. It is the seam that lets a test advance time
// instead of sleeping for it.
//
// Every expiry decision in this file goes through one, because the alternative
// -- sleeping and hoping -- is not a test of the TTL, it is a test of the
// scheduler. time.Sleep guarantees a MINIMUM duration and no maximum, so a test
// that sleeps 80ms expecting to stay inside a 100ms TTL asserts that the
// machine was not busy. Under -race on a shared runner it regularly is, and
// go-xkms#243 is the bill for that: these tests failed on three PRs that did
// not touch this package.
type Clock func() time.Time

// NonceStoreOption configures a NonceStore.
type NonceStoreOption func(*NonceStore)

// WithClock replaces the store's time source. Production never calls it; it
// exists so tests can make expiry deterministic rather than probabilistic.
func WithClock(now Clock) NonceStoreOption {
	return func(s *NonceStore) {
		if now != nil {
			s.now = now
		}
	}
}

// NonceStore is a thread-safe store for nonces.
// It provides replay protection for ACME protocol by ensuring each nonce
// can only be used once and expires after a configurable TTL.
type NonceStore struct {
	nonces map[string]time.Time
	mu     sync.Mutex
	ttl    time.Duration
	// now is the store's time source. Never nil: the constructor defaults it
	// to time.Now, so a NonceStore built by any path has a working clock.
	now Clock
}

// NewNonceStore initializes a new NonceStore with a specified TTL (Time-To-Live).
// It starts a background goroutine to periodically clean up expired nonces.
//
// The options are a test seam and are empty in production; see WithClock.
func NewNonceStore(ttl time.Duration, opts ...NonceStoreOption) *NonceStore {
	store := &NonceStore{
		nonces: make(map[string]time.Time),
		ttl:    ttl,
		now:    time.Now,
	}
	for _, opt := range opts {
		opt(store)
	}

	// Start a background goroutine to clean up expired nonces periodically
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			<-ticker.C
			store.sweep()
		}
	}()

	return store
}

// Add inserts a new nonce into the store with the current timestamp.
func (s *NonceStore) Add(nonce string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nonces[nonce] = s.now()
}

// Exists checks if a nonce exists and is still valid (not expired).
// Returns true if valid, false otherwise.
// Note: The nonce is consumed (deleted) after successful validation
// to enforce single-use requirement per RFC 8555.
func (s *NonceStore) Exists(nonce string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	ts, exists := s.nonces[nonce]
	if !exists {
		return false
	}
	if s.now().Sub(ts) > s.ttl {
		delete(s.nonces, nonce)
		return false
	}
	// Delete the nonce after it's used to enforce single use
	delete(s.nonces, nonce)
	return true
}

// sweep removes expired nonces from the store.
func (s *NonceStore) sweep() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	for nonce, ts := range s.nonces {
		if now.Sub(ts) > s.ttl {
			delete(s.nonces, nonce)
		}
	}
}

// GenerateNonce creates a new secure random nonce encoded in URL-safe Base64 without padding.
// The length parameter specifies the number of random bytes to generate.
func GenerateNonce(length int) (string, error) {
	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	// ACME nonces are URL-safe base64 without padding per RFC 8555
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

// Package importtoken provides a bounded, TTL-enforced, single-use store for
// the ephemeral wrapping-key material an ImportBackend generates in
// GetImportParameters and consumes once in UnwrapKey (see
// pkg/backend.ImportBackend). Every backend that implements the import
// ceremony -- software, symmetric, azurekv, and any added later -- needs the
// same three properties for that per-request state, so they live here once
// instead of once per backend:
//
//   - bounded: a hard cap refuses new tokens once the store is full, rather
//     than growing without limit for as long as callers keep starting
//     ceremonies they never finish (go-xkms#1261).
//   - swept: every insert first drops expired entries, so an abandoned
//     ceremony's token is gone within one TTL of the next insert even if no
//     caller ever asks for it again.
//   - destroyed: eviction -- by sweep, by Take, or by Close -- always runs
//     the caller-supplied destroy callback, so key material does not
//     outlive the token that names it.
package importtoken

import (
	"sync"
	"time"
)

// DefaultTTL is how long a token remains valid after Put, matching the
// 24-hour wrapping-key validity every current caller of this package already
// documents in its ImportParameters.ExpiresAt.
const DefaultTTL = 24 * time.Hour

// DefaultMaxTokens caps how many in-flight import ceremonies a Store holds
// at once when the caller does not choose its own limit.
const DefaultMaxTokens = 10_000

// Store is a bounded, TTL-enforced, single-use holder for per-token values,
// keyed by the import token string a backend hands its caller. T is
// typically a sealed value (see SealedRSAKey) or, when the token never
// carries key material back out, a plain byte slice destroyed with
// secure.Wipe; Store never inspects T itself, so the destroy callback
// supplied to New fully determines how eviction is handled.
//
// A Store is safe for concurrent use.
type Store[T any] struct {
	mu      sync.Mutex
	ttl     time.Duration
	max     int
	destroy func(T)
	entries map[string]entry[T]
}

type entry[T any] struct {
	value     T
	expiresAt time.Time
}

// New constructs a Store. ttl <= 0 defaults to DefaultTTL; max <= 0 defaults
// to DefaultMaxTokens. destroy is called exactly once for every value that
// enters the store, at the moment it is evicted -- by expiry sweep, by
// Take, by Delete, or by Close -- and nil is treated as a no-op.
func New[T any](ttl time.Duration, max int, destroy func(T)) *Store[T] {
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	if max <= 0 {
		max = DefaultMaxTokens
	}
	if destroy == nil {
		destroy = func(T) {}
	}
	return &Store[T]{
		ttl:     ttl,
		max:     max,
		destroy: destroy,
		entries: make(map[string]entry[T]),
	}
}

// Put inserts value under token, valid for the Store's TTL, and returns its
// expiry. Expired entries are swept first, so a store that is only ever
// written to (never read back, as happens when every caller abandons its
// ceremony) still cannot grow past its cap. If the store remains at
// capacity after the sweep, Put destroys value and returns
// *LimitExceededError instead of evicting a live ceremony to make room --
// see LimitExceededError's doc comment for why eviction is not the answer
// here. Put on an existing token replaces it, destroying the old value.
func (s *Store[T]) Put(token string, value T) (time.Time, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.sweepLocked()

	if old, exists := s.entries[token]; exists {
		s.destroy(old.value)
		delete(s.entries, token)
	} else if len(s.entries) >= s.max {
		s.destroy(value)
		return time.Time{}, &LimitExceededError{Limit: s.max}
	}

	expiresAt := time.Now().Add(s.ttl)
	s.entries[token] = entry[T]{value: value, expiresAt: expiresAt}
	return expiresAt, nil
}

// Take removes and returns the value for token. Ownership of the value
// passes to the caller, who becomes responsible for destroying it -- Take
// does not call the Store's destroy callback on the entry it successfully
// returns, only on ones it finds already expired. This makes every token
// single-use: a second Take (or a Peek after a Take) reports
// *NotFoundError, exactly as it would for a token that was never issued.
func (s *Store[T]) Take(token string) (T, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	e, ok := s.entries[token]
	if !ok {
		var zero T
		return zero, &NotFoundError{Token: token}
	}
	delete(s.entries, token)
	if time.Now().After(e.expiresAt) {
		s.destroy(e.value)
		var zero T
		return zero, &NotFoundError{Token: token}
	}
	return e.value, nil
}

// Peek returns the value for token without consuming it, for a caller that
// needs to read metadata carried in T (for example, the wrapping public
// key) before performing the single-use Take. Peek still enforces expiry:
// an expired entry is swept and destroyed exactly as Take would, and
// reported the same way.
func (s *Store[T]) Peek(token string) (T, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	e, ok := s.entries[token]
	if !ok {
		var zero T
		return zero, &NotFoundError{Token: token}
	}
	if time.Now().After(e.expiresAt) {
		s.destroy(e.value)
		delete(s.entries, token)
		var zero T
		return zero, &NotFoundError{Token: token}
	}
	return e.value, nil
}

// Delete removes and destroys the entry for token, if present. It reports
// no error when the token is already absent, so callers can use it
// unconditionally to release a ceremony's token once its value has been
// consumed through some path other than Take (for example, a backend that
// re-derives its unwrapping key from the caller-supplied WrappedKeyMaterial
// and only keeps the Store entry as bookkeeping for the token's lifetime).
func (s *Store[T]) Delete(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if e, ok := s.entries[token]; ok {
		s.destroy(e.value)
		delete(s.entries, token)
	}
}

// Len reports how many tokens the Store currently holds, including any not
// yet removed by a sweep. It is intended for tests and metrics, not for
// capacity decisions -- Put already enforces the cap atomically.
func (s *Store[T]) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.entries)
}

// Close destroys every remaining entry and empties the Store. Safe to call
// more than once.
func (s *Store[T]) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()

	for token, e := range s.entries {
		s.destroy(e.value)
		delete(s.entries, token)
	}
}

// sweepLocked removes and destroys every expired entry. Callers must hold
// s.mu.
func (s *Store[T]) sweepLocked() {
	now := time.Now()
	for token, e := range s.entries {
		if now.After(e.expiresAt) {
			s.destroy(e.value)
			delete(s.entries, token)
		}
	}
}

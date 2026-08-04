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
	"context"
	"hash/fnv"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
)

// NonceStoreInterface defines the interface for nonce storage operations.
// Both in-memory and persistent implementations satisfy this interface.
type NonceStoreInterface interface {
	// Add inserts a new nonce into the store
	Add(nonce string)

	// Exists checks if a nonce exists and is still valid.
	// The nonce is consumed (deleted) after successful validation
	// to enforce single-use requirement per RFC 8555.
	Exists(nonce string) bool
}

// PersistentNonceStore implements NonceStoreInterface using a NonceDAO backend.
// This provides persistent storage for nonces across server restarts and
// supports horizontal scaling in clustered deployments.
type PersistentNonceStore struct {
	dao qrdbsdk.GenericDAO[*entities.ACMENonce]
	ttl time.Duration
}

// NewPersistentNonceStore creates a new PersistentNonceStore backed by a NonceDAO.
// It starts a background goroutine to periodically clean up expired nonces.
//
// Parameters:
//   - dao: The NonceDAO implementation for persistent storage
//   - ttl: Time-to-live for nonces before expiration
//
// Returns:
//   - *PersistentNonceStore: Configured persistent nonce store
func NewPersistentNonceStore(dao qrdbsdk.GenericDAO[*entities.ACMENonce], ttl time.Duration) *PersistentNonceStore {
	store := &PersistentNonceStore{
		dao: dao,
		ttl: ttl,
	}

	// Start background cleanup goroutine
	go store.sweepLoop()

	return store
}

// Add inserts a new nonce into the persistent store with expiration time.
func (s *PersistentNonceStore) Add(nonce string) {
	id := s.hashNonce(nonce)
	expiresAt := time.Now().Add(s.ttl).Unix()

	acmeNonce := &entities.ACMENonce{
		ID:        id,
		Value:     []byte(nonce),
		ExpiresAt: expiresAt,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Best effort - if save fails, nonce won't be usable
	// This is acceptable as the client will get a badNonce error and retry
	_ = s.dao.Save(ctx, acmeNonce)
}

// Exists checks if a nonce exists and is still valid (not expired).
// Returns true if valid, false otherwise.
// Note: The nonce is consumed (deleted) after successful validation
// to enforce single-use requirement per RFC 8555.
func (s *PersistentNonceStore) Exists(nonce string) bool {
	id := s.hashNonce(nonce)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	acmeNonce, err := s.dao.Get(ctx, id)
	if err != nil {
		return false
	}

	// Check if expired
	if time.Unix(acmeNonce.ExpiresAt, 0).Before(time.Now()) {
		// Delete expired nonce
		_ = s.dao.Delete(ctx, acmeNonce)
		return false
	}

	// Verify the nonce value matches (hash collision protection)
	if string(acmeNonce.Value) != nonce {
		return false
	}

	// Delete the nonce after it's used to enforce single use
	_ = s.dao.Delete(ctx, acmeNonce)
	return true
}

// hashNonce generates a deterministic uint64 ID from a nonce string.
// Uses FNV-1a hash which provides good distribution with low collision rate.
func (s *PersistentNonceStore) hashNonce(nonce string) uint64 {
	h := fnv.New64a()
	// hash.Hash.Write never returns an error per Go documentation
	_, _ = h.Write([]byte(nonce))
	return h.Sum64()
}

// sweepLoop periodically cleans up expired nonces from storage.
func (s *PersistentNonceStore) sweepLoop() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		s.sweep()
	}
}

// sweep removes expired nonces from the store.
func (s *PersistentNonceStore) sweep() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	now := time.Now()
	_ = s.dao.ForEachPage(ctx, qrdbsdk.PageQuery{PageSize: 1000}, func(page qrdbsdk.PageResult[*entities.ACMENonce]) error {
		for _, nonce := range page.Entities {
			if time.Unix(nonce.ExpiresAt, 0).Before(now) {
				_ = s.dao.Delete(ctx, nonce)
			}
		}
		return nil
	})
}

// PersistentNonceStoreWithFallback wraps a PersistentNonceStore with
// an in-memory cache for improved performance. Reads check memory first,
// writes go to both memory and persistent storage.
type PersistentNonceStoreWithFallback struct {
	persistent *PersistentNonceStore
	memory     *NonceStore
}

// NewPersistentNonceStoreWithFallback creates a hybrid nonce store with
// in-memory caching backed by persistent storage.
func NewPersistentNonceStoreWithFallback(dao qrdbsdk.GenericDAO[*entities.ACMENonce], ttl time.Duration) *PersistentNonceStoreWithFallback {
	return &PersistentNonceStoreWithFallback{
		persistent: NewPersistentNonceStore(dao, ttl),
		memory:     NewNonceStore(ttl),
	}
}

// Add inserts a nonce into both memory and persistent storage.
func (s *PersistentNonceStoreWithFallback) Add(nonce string) {
	s.memory.Add(nonce)
	s.persistent.Add(nonce)
}

// Exists checks memory first, then falls back to persistent storage.
// This optimizes for the common case where nonces are used within the same
// server instance that created them.
func (s *PersistentNonceStoreWithFallback) Exists(nonce string) bool {
	// Check memory first (fast path)
	if s.memory.Exists(nonce) {
		// Also delete from persistent to maintain consistency
		id := s.persistent.hashNonce(nonce)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = s.persistent.dao.Delete(ctx, &entities.ACMENonce{ID: id})
		cancel()
		return true
	}

	// Fall back to persistent storage (for clustered deployments)
	return s.persistent.Exists(nonce)
}

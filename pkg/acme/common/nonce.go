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
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"
)

// NonceStore is a thread-safe store for nonces.
// It provides replay protection for ACME protocol by ensuring each nonce
// can only be used once and expires after a configurable TTL.
type NonceStore struct {
	nonces map[string]time.Time
	mu     sync.Mutex
	ttl    time.Duration
}

// NewNonceStore initializes a new NonceStore with a specified TTL (Time-To-Live).
// It starts a background goroutine to periodically clean up expired nonces.
func NewNonceStore(ttl time.Duration) *NonceStore {
	store := &NonceStore{
		nonces: make(map[string]time.Time),
		ttl:    ttl,
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
	s.nonces[nonce] = time.Now()
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
	if time.Since(ts) > s.ttl {
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
	now := time.Now()
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

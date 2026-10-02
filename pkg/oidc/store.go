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

package oidc

import (
	"sort"
	"strings"
	"sync"
)

// TokenStore defines the interface for persistent token storage.
//
// The GUI's production implementations are DAOStore (dao_store.go, a
// go-qrdb DAO/entity-backed store -- barrier-encrypted when its KVStore is
// adapted from a barrier backend) and MemoryTokenStore below (no-barrier
// fallback, go-xkms#1203): there is no file-backed implementation in this
// package. A key compiled into the binary gives a file on disk no real
// confidentiality, so no in-between "encrypted with a fixed key" option
// exists here for a caller to reach for -- with a barrier, use DAOStore;
// without one, tokens stay in memory only.
type TokenStore interface {
	// Save stores tokens for the given issuer.
	Save(issuer string, tokens *TokenResponse) error

	// Load retrieves tokens for the given issuer.
	Load(issuer string) (*TokenResponse, error)

	// Delete removes tokens for the given issuer.
	Delete(issuer string) error

	// List returns all issuers with stored tokens.
	List() ([]string, error)

	// Close closes the store and releases resources.
	Close() error
}

// normalizeIssuer normalizes an issuer URL for consistent storage.
func normalizeIssuer(issuer string) string {
	return strings.TrimSuffix(strings.ToLower(issuer), "/")
}

// MemoryTokenStore implements TokenStore using in-memory storage.
type MemoryTokenStore struct {
	mu     sync.RWMutex
	tokens map[string]*TokenResponse
	closed bool
}

// NewMemoryTokenStore creates a new in-memory token store.
func NewMemoryTokenStore() *MemoryTokenStore {
	return &MemoryTokenStore{
		tokens: make(map[string]*TokenResponse),
	}
}

// Save stores tokens for the given issuer.
func (s *MemoryTokenStore) Save(issuer string, tokens *TokenResponse) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return ErrStoreClosed
	}

	if issuer == "" {
		return ErrInvalidIssuer
	}

	if tokens == nil {
		return ErrTokenNotFound
	}

	issuer = normalizeIssuer(issuer)
	s.tokens[issuer] = tokens
	return nil
}

// Load retrieves tokens for the given issuer.
func (s *MemoryTokenStore) Load(issuer string) (*TokenResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return nil, ErrStoreClosed
	}

	if issuer == "" {
		return nil, ErrInvalidIssuer
	}

	issuer = normalizeIssuer(issuer)
	tokens, exists := s.tokens[issuer]
	if !exists {
		return nil, ErrTokenNotFound
	}

	return tokens, nil
}

// Delete removes tokens for the given issuer.
func (s *MemoryTokenStore) Delete(issuer string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return ErrStoreClosed
	}

	if issuer == "" {
		return ErrInvalidIssuer
	}

	issuer = normalizeIssuer(issuer)
	if _, exists := s.tokens[issuer]; !exists {
		return ErrTokenNotFound
	}

	delete(s.tokens, issuer)
	return nil
}

// List returns all issuers with stored tokens.
func (s *MemoryTokenStore) List() ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return nil, ErrStoreClosed
	}

	issuers := make([]string, 0, len(s.tokens))
	for issuer := range s.tokens {
		issuers = append(issuers, issuer)
	}

	sort.Strings(issuers)
	return issuers, nil
}

// Close closes the store.
func (s *MemoryTokenStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil
	}

	s.closed = true
	for k := range s.tokens {
		delete(s.tokens, k)
	}
	s.tokens = nil

	return nil
}

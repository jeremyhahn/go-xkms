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

package tokenstore

import (
	"context"
	"encoding/json"
	"sort"
	"sync"
)

// MemoryTokenStore implements TokenStore using in-memory storage.
// This is useful for testing and ephemeral token needs.
type MemoryTokenStore struct {
	mu     sync.RWMutex
	tokens map[string]*TokenEntry
	closed bool
}

// Compile-time interface compliance check.
var _ TokenStore = (*MemoryTokenStore)(nil)

// NewMemoryTokenStore creates a new in-memory token store.
func NewMemoryTokenStore() *MemoryTokenStore {
	return &MemoryTokenStore{
		tokens: make(map[string]*TokenEntry),
	}
}

// Save persists a token entry keyed by its server URL.
func (s *MemoryTokenStore) Save(_ context.Context, entry *TokenEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return ErrStoreClosed
	}

	if entry == nil {
		return ErrNilEntry
	}

	if entry.ServerURL == "" {
		return ErrInvalidServer
	}

	normalized := normalizeServer(entry.ServerURL)
	entry.ServerURL = normalized

	// Store a deep copy to prevent external mutation.
	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}

	var copy TokenEntry
	if err := json.Unmarshal(data, &copy); err != nil {
		return err
	}

	s.tokens[normalized] = &copy
	return nil
}

// Load retrieves the token entry for the given server URL.
func (s *MemoryTokenStore) Load(_ context.Context, serverURL string) (*TokenEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return nil, ErrStoreClosed
	}

	if serverURL == "" {
		return nil, ErrInvalidServer
	}

	normalized := normalizeServer(serverURL)

	entry, exists := s.tokens[normalized]
	if !exists {
		return nil, ErrTokenNotFound
	}

	// Return a deep copy to prevent external mutation.
	data, err := json.Marshal(entry)
	if err != nil {
		return nil, err
	}

	var copy TokenEntry
	if err := json.Unmarshal(data, &copy); err != nil {
		return nil, err
	}

	return &copy, nil
}

// Delete removes the token entry for the given server URL.
func (s *MemoryTokenStore) Delete(_ context.Context, serverURL string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return ErrStoreClosed
	}

	if serverURL == "" {
		return ErrInvalidServer
	}

	normalized := normalizeServer(serverURL)

	if _, exists := s.tokens[normalized]; !exists {
		return ErrTokenNotFound
	}

	delete(s.tokens, normalized)
	return nil
}

// List returns all stored token entries sorted by server URL.
func (s *MemoryTokenStore) List(_ context.Context) ([]*TokenEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return nil, ErrStoreClosed
	}

	entries := make([]*TokenEntry, 0, len(s.tokens))
	for _, entry := range s.tokens {
		// Return deep copies.
		data, err := json.Marshal(entry)
		if err != nil {
			continue
		}

		var copy TokenEntry
		if err := json.Unmarshal(data, &copy); err != nil {
			continue
		}
		entries = append(entries, &copy)
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].ServerURL < entries[j].ServerURL
	})

	return entries, nil
}

// Close marks the store as closed and releases stored tokens.
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

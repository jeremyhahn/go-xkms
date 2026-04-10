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

package sharestore

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"
)

// MemoryShareStore provides an in-memory ShareStore implementation
// suitable for testing and ephemeral use. Thread-safe using a
// read-write mutex.
type MemoryShareStore struct {
	mu     sync.RWMutex
	shares map[string]*ShareEntry // key = serverURL/groupID/shareIndex
	closed bool
}

// Compile-time interface compliance check.
var _ ShareStore = (*MemoryShareStore)(nil)

// NewMemoryShareStore creates a new in-memory share store.
func NewMemoryShareStore() *MemoryShareStore {
	return &MemoryShareStore{
		shares: make(map[string]*ShareEntry),
	}
}

// Save stores a share entry. Returns ErrShareExists if a share for
// the same server+group+shareIndex already exists.
func (m *MemoryShareStore) Save(_ context.Context, entry *ShareEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return ErrStoreClosed
	}

	if entry == nil {
		return ErrNilEntry
	}

	if err := entry.Validate(); err != nil {
		return err
	}

	key := entry.Key()
	if _, exists := m.shares[key]; exists {
		return ErrShareExists
	}

	if entry.ReceivedAt.IsZero() {
		entry.ReceivedAt = time.Now().UTC()
	}

	// Store a deep copy to prevent external mutation.
	stored := *entry
	stored.ShareData = make([]byte, len(entry.ShareData))
	copy(stored.ShareData, entry.ShareData)
	m.shares[key] = &stored

	return nil
}

// Load retrieves a share by server URL, group ID, and share index.
func (m *MemoryShareStore) Load(_ context.Context, serverURL, groupID string, shareIndex int) (*ShareEntry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return nil, ErrStoreClosed
	}

	if serverURL == "" {
		return nil, ErrInvalidServerURL
	}

	if groupID == "" {
		return nil, ErrInvalidGroupID
	}

	key := fmt.Sprintf("%s/%s/%d", serverURL, groupID, shareIndex)
	entry, exists := m.shares[key]
	if !exists {
		return nil, ErrShareNotFound
	}

	// Return a deep copy to prevent external mutation.
	result := *entry
	result.ShareData = make([]byte, len(entry.ShareData))
	copy(result.ShareData, entry.ShareData)

	return &result, nil
}

// Delete removes a share by server URL, group ID, and share index.
func (m *MemoryShareStore) Delete(_ context.Context, serverURL, groupID string, shareIndex int) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return ErrStoreClosed
	}

	if serverURL == "" {
		return ErrInvalidServerURL
	}

	if groupID == "" {
		return ErrInvalidGroupID
	}

	key := fmt.Sprintf("%s/%s/%d", serverURL, groupID, shareIndex)
	if _, exists := m.shares[key]; !exists {
		return ErrShareNotFound
	}

	delete(m.shares, key)
	return nil
}

// List returns all stored shares sorted by composite key.
func (m *MemoryShareStore) List(_ context.Context) ([]*ShareEntry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return nil, ErrStoreClosed
	}

	entries := make([]*ShareEntry, 0, len(m.shares))
	for _, entry := range m.shares {
		// Return deep copies.
		copied := *entry
		copied.ShareData = make([]byte, len(entry.ShareData))
		copy(copied.ShareData, entry.ShareData)
		entries = append(entries, &copied)
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Key() < entries[j].Key()
	})

	return entries, nil
}

// ListByServer returns all shares for a specific server URL.
func (m *MemoryShareStore) ListByServer(ctx context.Context, serverURL string) ([]*ShareEntry, error) {
	if serverURL == "" {
		return nil, ErrInvalidServerURL
	}

	all, err := m.List(ctx)
	if err != nil {
		return nil, err
	}

	filtered := make([]*ShareEntry, 0)
	for _, entry := range all {
		if entry.ServerURL == serverURL {
			filtered = append(filtered, entry)
		}
	}

	return filtered, nil
}

// ListByGroup returns all shares for a specific group ID.
func (m *MemoryShareStore) ListByGroup(ctx context.Context, groupID string) ([]*ShareEntry, error) {
	if groupID == "" {
		return nil, ErrInvalidGroupID
	}

	all, err := m.List(ctx)
	if err != nil {
		return nil, err
	}

	filtered := make([]*ShareEntry, 0)
	for _, entry := range all {
		if entry.GroupID == groupID {
			filtered = append(filtered, entry)
		}
	}

	return filtered, nil
}

// Close closes the store and marks it as closed.
func (m *MemoryShareStore) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.closed = true
	m.shares = nil
	return nil
}

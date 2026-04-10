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

package serverregistry

import (
	"context"
	"sort"
	"sync"
	"time"
)

// MemoryServerRegistry implements ServerRegistry with an in-memory map.
// Primarily intended for testing and ephemeral use cases.
type MemoryServerRegistry struct {
	mu      sync.RWMutex
	servers map[string]*ServerEntry
	closed  bool
}

// Compile-time interface compliance check.
var _ ServerRegistry = (*MemoryServerRegistry)(nil)

// NewMemoryServerRegistry creates a new in-memory server registry.
func NewMemoryServerRegistry() *MemoryServerRegistry {
	return &MemoryServerRegistry{
		servers: make(map[string]*ServerEntry),
	}
}

// Register stores a new server entry. Returns ErrServerExists if the URL
// is already registered.
func (m *MemoryServerRegistry) Register(_ context.Context, entry *ServerEntry) error {
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

	if _, exists := m.servers[entry.URL]; exists {
		return ErrServerExists
	}

	entry.RegisteredAt = time.Now()

	// Store a copy to prevent external mutation.
	stored := *entry
	m.servers[entry.URL] = &stored

	return nil
}

// Lookup retrieves a server entry by URL.
func (m *MemoryServerRegistry) Lookup(_ context.Context, url string) (*ServerEntry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return nil, ErrStoreClosed
	}

	if url == "" {
		return nil, ErrInvalidURL
	}

	entry, exists := m.servers[url]
	if !exists {
		return nil, ErrServerNotFound
	}

	// Return a copy to prevent external mutation.
	result := *entry
	return &result, nil
}

// Update modifies an existing server entry. The entry must already exist.
// LastConnectedAt is automatically set to the current time.
func (m *MemoryServerRegistry) Update(_ context.Context, entry *ServerEntry) error {
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

	if _, exists := m.servers[entry.URL]; !exists {
		return ErrServerNotFound
	}

	entry.LastConnectedAt = time.Now()

	// Store a copy to prevent external mutation.
	stored := *entry
	m.servers[entry.URL] = &stored

	return nil
}

// List returns all registered server entries sorted by URL.
func (m *MemoryServerRegistry) List(_ context.Context) ([]*ServerEntry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return nil, ErrStoreClosed
	}

	entries := make([]*ServerEntry, 0, len(m.servers))
	for _, entry := range m.servers {
		copied := *entry
		entries = append(entries, &copied)
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].URL < entries[j].URL
	})

	return entries, nil
}

// Delete removes a server entry by URL.
func (m *MemoryServerRegistry) Delete(_ context.Context, url string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return ErrStoreClosed
	}

	if url == "" {
		return ErrInvalidURL
	}

	if _, exists := m.servers[url]; !exists {
		return ErrServerNotFound
	}

	delete(m.servers, url)
	return nil
}

// Close marks the registry as closed.
func (m *MemoryServerRegistry) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.closed = true
	m.servers = nil
	return nil
}

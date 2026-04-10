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

package storage

import (
	"context"
	"sort"
	"strings"
	"sync"
)

// MemoryBackend provides an in-memory storage implementation.
// This is useful for testing and ephemeral storage needs.
// Thread-safe using a read-write mutex.
type MemoryBackend struct {
	data   map[string][]byte
	mu     sync.RWMutex
	closed bool
}

// NewMemoryBackend creates a new in-memory storage backend.
func NewMemoryBackend() (Backend, error) {
	return &MemoryBackend{
		data: make(map[string][]byte),
	}, nil
}

// NewMemory creates a new in-memory storage backend.
// This is a convenience function that panics on error (which should never happen).
func NewMemory() Backend {
	backend, err := NewMemoryBackend()
	if err != nil {
		panic("failed to create memory backend: " + err.Error())
	}
	return backend
}

// Get retrieves the value for the given key.
func (m *MemoryBackend) Get(_ context.Context, key string) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return nil, ErrClosed
	}

	value, exists := m.data[key]
	if !exists {
		return nil, ErrNotFound
	}

	// Return a copy to prevent modification
	result := make([]byte, len(value))
	copy(result, value)
	return result, nil
}

// Put stores the value for the given key.
func (m *MemoryBackend) Put(_ context.Context, key string, value []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return ErrClosed
	}

	// Store a copy to prevent modification
	data := make([]byte, len(value))
	copy(data, value)
	m.data[key] = data
	return nil
}

// Delete removes the key and its value from storage.
func (m *MemoryBackend) Delete(_ context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return ErrClosed
	}

	if _, exists := m.data[key]; !exists {
		return ErrNotFound
	}

	delete(m.data, key)
	return nil
}

// List returns all keys with the given prefix in sorted order.
// Keys are sorted to ensure deterministic ordering since Go map
// iteration order is not guaranteed.
func (m *MemoryBackend) List(_ context.Context, prefix string) ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return nil, ErrClosed
	}

	var keys []string
	for key := range m.data {
		if prefix == "" || strings.HasPrefix(key, prefix) {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	return keys, nil
}

// Scan iterates over all key-value pairs matching the given prefix,
// calling fn for each pair. Return a non-nil error from fn to stop early.
func (m *MemoryBackend) Scan(_ context.Context, prefix string, fn func(key string, value []byte) error) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return ErrClosed
	}

	for key, value := range m.data {
		if prefix == "" || strings.HasPrefix(key, prefix) {
			// Pass a copy to prevent modification
			valueCopy := make([]byte, len(value))
			copy(valueCopy, value)
			if err := fn(key, valueCopy); err != nil {
				return err
			}
		}
	}
	return nil
}

// Exists checks if a key exists in storage.
func (m *MemoryBackend) Exists(_ context.Context, key string) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return false, ErrClosed
	}

	_, exists := m.data[key]
	return exists, nil
}

// Close releases any resources held by the backend.
func (m *MemoryBackend) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return nil
	}

	m.closed = true
	m.data = nil
	return nil
}

// New creates a new in-memory storage backend.
// This is a convenience function for testing and development.
func New() Backend {
	return NewMemory()
}

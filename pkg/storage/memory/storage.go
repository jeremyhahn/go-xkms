// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

// Package memory provides an in-memory implementation of the storage.Backend interface.
// It uses a map with RWMutex for thread-safe operations and makes defensive copies
// of all byte slices to prevent external modification.
package memory

import (
	"sort"
	"strings"
	"sync"

	"github.com/jeremyhahn/go-keychain/pkg/storage"
)

// Storage is an in-memory implementation of storage.Backend.
// It uses a map to store key-value pairs and is fully thread-safe.
// All byte slices are defensively copied to prevent external modification.
type Storage struct {
	mu     sync.RWMutex
	data   map[string][]byte
	closed bool
}

// New creates a new in-memory storage backend.
// The returned storage is ready to use and implements storage.Backend.
func New() storage.Backend {
	return &Storage{
		data: make(map[string][]byte),
	}
}

// Get retrieves the value for the given key.
// Returns storage.ErrNotFound if the key does not exist.
// Returns storage.ErrClosed if the storage has been closed.
// The returned byte slice is a defensive copy and safe to modify.
func (s *Storage) Get(key string) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return nil, storage.ErrClosed
	}

	value, exists := s.data[key]
	if !exists {
		return nil, storage.ErrNotFound
	}

	// Return a defensive copy to prevent external modification
	result := make([]byte, len(value))
	copy(result, value)
	return result, nil
}

// Put stores the value for the given key with optional metadata.
// If the key already exists, it will be overwritten.
// The Options parameter is accepted for interface compatibility but metadata is not persisted.
// Returns storage.ErrClosed if the storage has been closed.
// The value byte slice is defensively copied to prevent external modification.
func (s *Storage) Put(key string, value []byte, opts *storage.Options) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return storage.ErrClosed
	}

	// Store a defensive copy to prevent external modification
	valueCopy := make([]byte, len(value))
	copy(valueCopy, value)
	s.data[key] = valueCopy

	return nil
}

// Delete removes the key and its value from storage.
// Returns storage.ErrNotFound if the key does not exist.
// Returns storage.ErrClosed if the storage has been closed.
func (s *Storage) Delete(key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return storage.ErrClosed
	}

	if _, exists := s.data[key]; !exists {
		return storage.ErrNotFound
	}

	delete(s.data, key)
	return nil
}

// List returns all keys with the given prefix.
// If prefix is empty, all keys are returned.
// Keys are returned in sorted order for consistent results.
// Returns storage.ErrClosed if the storage has been closed.
func (s *Storage) List(prefix string) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return nil, storage.ErrClosed
	}

	var keys []string
	for key := range s.data {
		if prefix == "" || strings.HasPrefix(key, prefix) {
			keys = append(keys, key)
		}
	}

	// Sort for consistent ordering
	sort.Strings(keys)
	return keys, nil
}

// Exists checks if a key exists in storage.
// Returns storage.ErrClosed if the storage has been closed.
func (s *Storage) Exists(key string) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return false, storage.ErrClosed
	}

	_, exists := s.data[key]
	return exists, nil
}

// Close releases any resources held by the backend and marks it as closed.
// After calling Close, all other operations will return storage.ErrClosed.
// Multiple calls to Close are safe and will return nil.
func (s *Storage) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.closed = true
	// Clear the data map to help with garbage collection
	s.data = nil

	return nil
}

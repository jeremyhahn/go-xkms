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

package qrdb

import (
	"context"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	db "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
)

// MemoryKVClient is an in-memory implementation of db.KVClient
// for unit testing. It uses sync.Map for lock-free concurrent access
// and atomic operations for revision tracking.
type MemoryKVClient struct {
	data     sync.Map
	revision atomic.Uint64
}

// NewMemoryKVClient creates a new in-memory KVClient.
func NewMemoryKVClient() *MemoryKVClient {
	return &MemoryKVClient{}
}

// Put stores a key-value pair in memory.
func (m *MemoryKVClient) Put(ctx context.Context, key string, value []byte, opts ...db.WriteOption) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if key == "" {
		return &db.KeyNotFoundError{Key: key}
	}
	// Copy the value to prevent aliasing.
	stored := make([]byte, len(value))
	copy(stored, value)
	m.data.Store(key, stored)
	m.revision.Add(1)
	return nil
}

// Get retrieves a value by key from memory. Returns KeyNotFoundError
// when the key does not exist.
func (m *MemoryKVClient) Get(ctx context.Context, key string, opts ...db.ReadOption) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	v, ok := m.data.Load(key)
	if !ok {
		return nil, &db.KeyNotFoundError{Key: key}
	}
	src := v.([]byte)
	result := make([]byte, len(src))
	copy(result, src)
	return result, nil
}

// Delete removes a key from memory.
func (m *MemoryKVClient) Delete(ctx context.Context, key string, opts ...db.WriteOption) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.data.Delete(key)
	m.revision.Add(1)
	return nil
}

// List returns sorted keys matching the given prefix.
func (m *MemoryKVClient) List(ctx context.Context, prefix string, opts ...db.ReadOption) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var keys []string
	m.data.Range(func(k, v interface{}) bool {
		key := k.(string)
		if strings.HasPrefix(key, prefix) {
			keys = append(keys, key)
		}
		return true
	})
	sort.Strings(keys)
	return keys, nil
}

// Scan returns all key-value pairs matching the given prefix.
func (m *MemoryKVClient) Scan(ctx context.Context, prefix string, opts ...db.ReadOption) (map[string][]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	result := make(map[string][]byte)
	m.data.Range(func(k, v interface{}) bool {
		key := k.(string)
		if strings.HasPrefix(key, prefix) {
			src := v.([]byte)
			dst := make([]byte, len(src))
			copy(dst, src)
			result[key] = dst
		}
		return true
	})
	return result, nil
}

// Exists checks whether a key exists in memory.
func (m *MemoryKVClient) Exists(ctx context.Context, key string, opts ...db.ReadOption) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	_, ok := m.data.Load(key)
	return ok, nil
}

// Revision returns the current revision counter for testing purposes.
func (m *MemoryKVClient) Revision() uint64 {
	return m.revision.Load()
}

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

package versioning

import (
	"context"
	"sort"
	"sync"
	"time"
)

// MemoryVersionStore is an in-memory implementation of VersionStore.
// It is thread-safe and suitable for unit testing.
// Data is not persisted and will be lost when the store is closed.
type MemoryVersionStore struct {
	mu     sync.RWMutex
	keys   map[string]*KeyVersions
	closed bool
}

// NewMemoryVersionStore creates a new in-memory version store.
func NewMemoryVersionStore() *MemoryVersionStore {
	return &MemoryVersionStore{
		keys: make(map[string]*KeyVersions),
	}
}

// GetCurrentVersion returns the current version number for a key.
func (m *MemoryVersionStore) GetCurrentVersion(ctx context.Context, keyID string) (uint64, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return 0, ErrStoreClosed
	}

	kv, ok := m.keys[keyID]
	if !ok {
		return 0, ErrKeyNotFound
	}

	return kv.CurrentVersion, nil
}

// GetVersionInfo returns metadata for a specific version of a key.
func (m *MemoryVersionStore) GetVersionInfo(ctx context.Context, keyID string, version uint64) (*VersionInfo, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return nil, ErrStoreClosed
	}

	kv, ok := m.keys[keyID]
	if !ok {
		return nil, ErrKeyNotFound
	}

	// Version 0 means current version
	if version == 0 {
		version = kv.CurrentVersion
	}

	info, ok := kv.Versions[version]
	if !ok {
		return nil, ErrVersionNotFound
	}

	// Return a copy to prevent mutation
	infoCopy := *info
	if info.Metadata != nil {
		infoCopy.Metadata = make(map[string]string, len(info.Metadata))
		for k, v := range info.Metadata {
			infoCopy.Metadata[k] = v
		}
	}

	return &infoCopy, nil
}

// GetKeyVersions returns all version information for a key.
func (m *MemoryVersionStore) GetKeyVersions(ctx context.Context, keyID string) (*KeyVersions, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return nil, ErrStoreClosed
	}

	kv, ok := m.keys[keyID]
	if !ok {
		return nil, ErrKeyNotFound
	}

	// Return a deep copy
	kvCopy := &KeyVersions{
		KeyID:          kv.KeyID,
		CurrentVersion: kv.CurrentVersion,
		Versions:       make(map[uint64]*VersionInfo, len(kv.Versions)),
		Created:        kv.Created,
		Updated:        kv.Updated,
	}

	for v, info := range kv.Versions {
		infoCopy := *info
		if info.Metadata != nil {
			infoCopy.Metadata = make(map[string]string, len(info.Metadata))
			for k, val := range info.Metadata {
				infoCopy.Metadata[k] = val
			}
		}
		kvCopy.Versions[v] = &infoCopy
	}

	return kvCopy, nil
}

// ListVersions returns all versions of a key, ordered by version number.
func (m *MemoryVersionStore) ListVersions(ctx context.Context, keyID string) ([]*VersionInfo, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return nil, ErrStoreClosed
	}

	kv, ok := m.keys[keyID]
	if !ok {
		return nil, ErrKeyNotFound
	}

	versions := make([]*VersionInfo, 0, len(kv.Versions))
	for _, info := range kv.Versions {
		infoCopy := *info
		if info.Metadata != nil {
			infoCopy.Metadata = make(map[string]string, len(info.Metadata))
			for k, v := range info.Metadata {
				infoCopy.Metadata[k] = v
			}
		}
		versions = append(versions, &infoCopy)
	}

	// Sort by version number
	sort.Slice(versions, func(i, j int) bool {
		return versions[i].Version < versions[j].Version
	})

	return versions, nil
}

// CreateVersion registers a new version for a key.
func (m *MemoryVersionStore) CreateVersion(ctx context.Context, keyID string, info *VersionInfo) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return ErrStoreClosed
	}

	now := time.Now()

	kv, ok := m.keys[keyID]
	if !ok {
		// Create new key entry
		kv = &KeyVersions{
			KeyID:          keyID,
			CurrentVersion: info.Version,
			Versions:       make(map[uint64]*VersionInfo),
			Created:        now,
			Updated:        now,
		}
		m.keys[keyID] = kv
	}

	// Check if version already exists
	if _, exists := kv.Versions[info.Version]; exists {
		return ErrVersionExists
	}

	// Store version info (make a copy)
	infoCopy := *info
	if info.Metadata != nil {
		infoCopy.Metadata = make(map[string]string, len(info.Metadata))
		for k, v := range info.Metadata {
			infoCopy.Metadata[k] = v
		}
	}
	if infoCopy.Created.IsZero() {
		infoCopy.Created = now
	}
	infoCopy.Updated = now

	kv.Versions[info.Version] = &infoCopy
	kv.Updated = now

	// Update current version if this is newer
	if info.Version > kv.CurrentVersion {
		kv.CurrentVersion = info.Version
	}

	return nil
}

// SetCurrentVersion updates which version is the current/active version.
func (m *MemoryVersionStore) SetCurrentVersion(ctx context.Context, keyID string, version uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return ErrStoreClosed
	}

	kv, ok := m.keys[keyID]
	if !ok {
		return ErrKeyNotFound
	}

	if _, exists := kv.Versions[version]; !exists {
		return ErrVersionNotFound
	}

	kv.CurrentVersion = version
	kv.Updated = time.Now()

	return nil
}

// UpdateVersionState changes the state of a specific version.
func (m *MemoryVersionStore) UpdateVersionState(ctx context.Context, keyID string, version uint64, state KeyState) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return ErrStoreClosed
	}

	kv, ok := m.keys[keyID]
	if !ok {
		return ErrKeyNotFound
	}

	info, exists := kv.Versions[version]
	if !exists {
		return ErrVersionNotFound
	}

	info.State = state
	info.Updated = time.Now()
	kv.Updated = info.Updated

	return nil
}

// DeleteVersion removes a version's metadata.
func (m *MemoryVersionStore) DeleteVersion(ctx context.Context, keyID string, version uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return ErrStoreClosed
	}

	kv, ok := m.keys[keyID]
	if !ok {
		return ErrKeyNotFound
	}

	if _, exists := kv.Versions[version]; !exists {
		return ErrVersionNotFound
	}

	delete(kv.Versions, version)
	kv.Updated = time.Now()

	// If we deleted the current version, update to highest remaining version
	if kv.CurrentVersion == version {
		kv.CurrentVersion = 0
		for v := range kv.Versions {
			if v > kv.CurrentVersion {
				kv.CurrentVersion = v
			}
		}
	}

	// If no versions left, remove the key entirely
	if len(kv.Versions) == 0 {
		delete(m.keys, keyID)
	}

	return nil
}

// DeleteKey removes all version metadata for a key.
func (m *MemoryVersionStore) DeleteKey(ctx context.Context, keyID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return ErrStoreClosed
	}

	if _, ok := m.keys[keyID]; !ok {
		return ErrKeyNotFound
	}

	delete(m.keys, keyID)
	return nil
}

// ListKeys returns all key IDs in the store.
func (m *MemoryVersionStore) ListKeys(ctx context.Context) ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return nil, ErrStoreClosed
	}

	keys := make([]string, 0, len(m.keys))
	for k := range m.keys {
		keys = append(keys, k)
	}

	sort.Strings(keys)
	return keys, nil
}

// Close releases any resources held by the store.
func (m *MemoryVersionStore) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.closed = true
	m.keys = nil
	return nil
}

// Ensure MemoryVersionStore implements VersionStore.
var _ VersionStore = (*MemoryVersionStore)(nil)

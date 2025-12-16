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
	"encoding/json"
	"sort"
	"sync"
	"time"

	"github.com/jeremyhahn/go-keychain/pkg/storage"
)

const (
	// keyPrefix is the prefix used for all version metadata keys in storage.
	keyPrefix = "keychain:versions:"
)

// BackendVersionStore implements VersionStore using the storage.Backend interface.
// This allows version metadata to be stored in any storage backend (file, database, etc.)
// without directly depending on the os filesystem package.
//
// Keys are stored with the prefix "keychain:versions:{keyID}" and contain
// JSON-serialized KeyVersions data.
type BackendVersionStore struct {
	mu      sync.RWMutex
	backend storage.Backend
	closed  bool
}

// NewBackendVersionStore creates a new version store backed by a storage.Backend.
// The backend must be initialized and ready for use.
func NewBackendVersionStore(backend storage.Backend) *BackendVersionStore {
	return &BackendVersionStore{
		backend: backend,
	}
}

// storageKey returns the storage key for a given key ID.
func storageKey(keyID string) string {
	return keyPrefix + keyID
}

// loadKeyVersions loads KeyVersions from storage.
func (b *BackendVersionStore) loadKeyVersions(keyID string) (*KeyVersions, error) {
	data, err := b.backend.Get(storageKey(keyID))
	if err != nil {
		if err == storage.ErrNotFound {
			return nil, ErrKeyNotFound
		}
		return nil, err
	}

	var kv KeyVersions
	if err := json.Unmarshal(data, &kv); err != nil {
		return nil, err
	}

	return &kv, nil
}

// saveKeyVersions saves KeyVersions to storage.
func (b *BackendVersionStore) saveKeyVersions(kv *KeyVersions) error {
	data, err := json.Marshal(kv)
	if err != nil {
		return err
	}

	return b.backend.Put(storageKey(kv.KeyID), data, nil)
}

// GetCurrentVersion returns the current version number for a key.
func (b *BackendVersionStore) GetCurrentVersion(ctx context.Context, keyID string) (uint64, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return 0, ErrStoreClosed
	}

	kv, err := b.loadKeyVersions(keyID)
	if err != nil {
		return 0, err
	}

	return kv.CurrentVersion, nil
}

// GetVersionInfo returns metadata for a specific version of a key.
func (b *BackendVersionStore) GetVersionInfo(ctx context.Context, keyID string, version uint64) (*VersionInfo, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return nil, ErrStoreClosed
	}

	kv, err := b.loadKeyVersions(keyID)
	if err != nil {
		return nil, err
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
func (b *BackendVersionStore) GetKeyVersions(ctx context.Context, keyID string) (*KeyVersions, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return nil, ErrStoreClosed
	}

	kv, err := b.loadKeyVersions(keyID)
	if err != nil {
		return nil, err
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
func (b *BackendVersionStore) ListVersions(ctx context.Context, keyID string) ([]*VersionInfo, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return nil, ErrStoreClosed
	}

	kv, err := b.loadKeyVersions(keyID)
	if err != nil {
		return nil, err
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
func (b *BackendVersionStore) CreateVersion(ctx context.Context, keyID string, info *VersionInfo) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return ErrStoreClosed
	}

	now := time.Now()

	kv, err := b.loadKeyVersions(keyID)
	if err != nil {
		if err != ErrKeyNotFound {
			return err
		}
		// Create new key entry
		kv = &KeyVersions{
			KeyID:          keyID,
			CurrentVersion: info.Version,
			Versions:       make(map[uint64]*VersionInfo),
			Created:        now,
			Updated:        now,
		}
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

	return b.saveKeyVersions(kv)
}

// SetCurrentVersion updates which version is the current/active version.
func (b *BackendVersionStore) SetCurrentVersion(ctx context.Context, keyID string, version uint64) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return ErrStoreClosed
	}

	kv, err := b.loadKeyVersions(keyID)
	if err != nil {
		return err
	}

	if _, exists := kv.Versions[version]; !exists {
		return ErrVersionNotFound
	}

	kv.CurrentVersion = version
	kv.Updated = time.Now()

	return b.saveKeyVersions(kv)
}

// UpdateVersionState changes the state of a specific version.
func (b *BackendVersionStore) UpdateVersionState(ctx context.Context, keyID string, version uint64, state KeyState) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return ErrStoreClosed
	}

	kv, err := b.loadKeyVersions(keyID)
	if err != nil {
		return err
	}

	info, exists := kv.Versions[version]
	if !exists {
		return ErrVersionNotFound
	}

	info.State = state
	info.Updated = time.Now()
	kv.Updated = info.Updated

	return b.saveKeyVersions(kv)
}

// DeleteVersion removes a version's metadata.
func (b *BackendVersionStore) DeleteVersion(ctx context.Context, keyID string, version uint64) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return ErrStoreClosed
	}

	kv, err := b.loadKeyVersions(keyID)
	if err != nil {
		return err
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
		return b.backend.Delete(storageKey(keyID))
	}

	return b.saveKeyVersions(kv)
}

// DeleteKey removes all version metadata for a key.
func (b *BackendVersionStore) DeleteKey(ctx context.Context, keyID string) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return ErrStoreClosed
	}

	// Check if key exists
	exists, err := b.backend.Exists(storageKey(keyID))
	if err != nil {
		return err
	}
	if !exists {
		return ErrKeyNotFound
	}

	return b.backend.Delete(storageKey(keyID))
}

// ListKeys returns all key IDs in the store.
func (b *BackendVersionStore) ListKeys(ctx context.Context) ([]string, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return nil, ErrStoreClosed
	}

	storageKeys, err := b.backend.List(keyPrefix)
	if err != nil {
		return nil, err
	}

	// Strip prefix to get key IDs
	prefixLen := len(keyPrefix)
	keyIDs := make([]string, 0, len(storageKeys))
	for _, sk := range storageKeys {
		if len(sk) > prefixLen {
			keyIDs = append(keyIDs, sk[prefixLen:])
		}
	}

	sort.Strings(keyIDs)
	return keyIDs, nil
}

// Close releases any resources held by the store.
func (b *BackendVersionStore) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.closed = true
	return nil
}

// Ensure BackendVersionStore implements VersionStore.
var _ VersionStore = (*BackendVersionStore)(nil)

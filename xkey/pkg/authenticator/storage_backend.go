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

package authenticator

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

const (
	// defaultCredentialPrefix is the default key prefix for credential storage.
	defaultCredentialPrefix = "credentials/"

	// stateKey is the key suffix for authenticator state storage.
	stateKey = "state"
)

// credentialMeta holds non-sensitive lookup metadata for a single credential.
// Only credential ID and discoverable flag are stored — no private keys or
// sensitive data touch the index.
type credentialMeta struct {
	credentialID []byte
	discoverable bool
}

// BackendStorage adapts storage.Backend to StatefulCredentialStorage.
// This allows the FIDO2 authenticator to use any go-xkms storage backend
// for credential persistence, including file-based and cloud storage.
//
// An in-memory rpIndex maps RPID → credential metadata for O(1) existence
// checks and O(k) targeted loads (where k = credentials for the target RP).
// The index is built asynchronously in a goroutine so construction does not
// block on storage I/O. Methods fall back to full scans until the index is ready.
//
// Thread-safe using a read-write mutex.
type BackendStorage struct {
	backend    storage.Backend
	prefix     string // key prefix, e.g., "fido2/authenticator/"
	rpIndex    map[string][]credentialMeta
	indexReady atomic.Bool
	indexDone  chan struct{} // closed when buildIndexAsync completes
	mu         sync.RWMutex
	closed     bool
}

// NewBackendStorage creates a new BackendStorage using the given storage backend.
// The prefix is prepended to all storage keys to namespace the authenticator data.
// If prefix is empty, "fido2/authenticator/" is used as the default.
//
// Example prefixes:
//   - "fido2/authenticator/" (default)
//   - "myapp/fido2/"
//   - "tenant-123/authenticator/"
func NewBackendStorage(backend storage.Backend, prefix string) (*BackendStorage, error) {
	if backend == nil {
		return nil, ErrNilStorage
	}

	if prefix == "" {
		prefix = "fido2/authenticator/"
	}

	// Ensure prefix ends with /
	if !strings.HasSuffix(prefix, "/") {
		prefix = prefix + "/"
	}

	bs := &BackendStorage{
		backend:   backend,
		prefix:    prefix,
		rpIndex:   make(map[string][]credentialMeta),
		indexDone: make(chan struct{}),
	}

	// Build the in-memory RP index asynchronously so construction
	// does not block on storage I/O. Methods fall back to full scans
	// until indexReady is set.
	go bs.buildIndexAsync()

	return bs, nil
}

// Store persists a credential to the backend storage.
// The credential is serialized to JSON and stored with a key based on its ID.
// Returns ErrInvalidCredentialID if the credential ID is nil or empty.
// Returns ErrStorageClosed if the storage has been closed.
func (b *BackendStorage) Store(credential *StoredCredential) error {
	if credential == nil || len(credential.CredentialID) == 0 {
		return ErrInvalidCredentialID
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return ErrStorageClosed
	}

	// Serialize credential to JSON
	data, err := json.Marshal(credential)
	if err != nil {
		return ErrSerializationFailed
	}

	// Build the storage key
	key := b.credentialKey(credential.CredentialID)

	// Store in backend
	if err := b.backend.Put(context.Background(), key, data); err != nil {
		return wrapStorageError(err)
	}

	// Update the RP index
	b.indexUpsert(credential.RPID, credential.CredentialID, credential.Discoverable)

	return nil
}

// Load retrieves a credential by its ID from the backend storage.
// Returns ErrCredentialNotFound if the credential does not exist.
// Returns ErrInvalidCredentialID if the credential ID is nil or empty.
// Returns ErrStorageClosed if the storage has been closed.
func (b *BackendStorage) Load(credentialID []byte) (*StoredCredential, error) {
	if len(credentialID) == 0 {
		return nil, ErrInvalidCredentialID
	}

	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return nil, ErrStorageClosed
	}

	key := b.credentialKey(credentialID)

	data, err := b.backend.Get(context.Background(), key)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, ErrCredentialNotFound
		}
		return nil, wrapStorageError(err)
	}

	var credential StoredCredential
	if err := json.Unmarshal(data, &credential); err != nil {
		return nil, ErrDeserializationFailed
	}

	return &credential, nil
}

// LoadByRPID retrieves all credentials for a relying party.
// When the RP index is ready, only matching credentials are loaded (O(k)).
// Before the index is ready, falls back to a full scan (O(n)).
// Returns an empty slice if no credentials exist for the given RPID.
// Returns ErrInvalidRPIDEmpty if the rpID is empty.
// Returns ErrStorageClosed if the storage has been closed.
func (b *BackendStorage) LoadByRPID(rpID string) ([]*StoredCredential, error) {
	if rpID == "" {
		return nil, ErrInvalidRPIDEmpty
	}

	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return nil, ErrStorageClosed
	}

	// When the index is ready, do O(k) targeted loads.
	if b.indexReady.Load() {
		metas := b.rpIndex[rpID]
		if len(metas) == 0 {
			return nil, nil
		}

		result := make([]*StoredCredential, 0, len(metas))
		for _, meta := range metas {
			key := b.credentialKey(meta.credentialID)
			data, err := b.backend.Get(context.Background(), key)
			if err != nil {
				continue
			}

			var credential StoredCredential
			if err := json.Unmarshal(data, &credential); err != nil {
				continue
			}

			result = append(result, &credential)
		}

		return result, nil
	}

	// Fallback: full scan when index is not yet ready.
	return b.loadByRPIDFullScan(rpID)
}

// loadByRPIDFullScan lists all credentials and filters by RPID.
// Must be called with at least a read lock held.
func (b *BackendStorage) loadByRPIDFullScan(rpID string) ([]*StoredCredential, error) {
	credPrefix := b.prefix + defaultCredentialPrefix

	keys, err := b.backend.List(context.Background(), credPrefix)
	if err != nil {
		return nil, wrapStorageError(err)
	}

	var result []*StoredCredential
	for _, key := range keys {
		data, err := b.backend.Get(context.Background(), key)
		if err != nil {
			continue
		}

		var credential StoredCredential
		if err := json.Unmarshal(data, &credential); err != nil {
			continue
		}

		if credential.RPID == rpID {
			result = append(result, &credential)
		}
	}

	return result, nil
}

// Delete removes a credential by its ID from the backend storage.
// Returns ErrCredentialNotFound if the credential does not exist.
// Returns ErrInvalidCredentialID if the credential ID is nil or empty.
// Returns ErrStorageClosed if the storage has been closed.
func (b *BackendStorage) Delete(credentialID []byte) error {
	if len(credentialID) == 0 {
		return ErrInvalidCredentialID
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return ErrStorageClosed
	}

	key := b.credentialKey(credentialID)

	// Load the credential before deleting to get its RPID for index removal.
	data, getErr := b.backend.Get(context.Background(), key)
	var rpID string
	if getErr == nil {
		var cred StoredCredential
		if jsonErr := json.Unmarshal(data, &cred); jsonErr == nil {
			rpID = cred.RPID
		}
	}

	if err := b.backend.Delete(context.Background(), key); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return ErrCredentialNotFound
		}
		return wrapStorageError(err)
	}

	// Remove from RP index
	if rpID != "" {
		b.indexRemove(rpID, credentialID)
	}

	return nil
}

// Count returns the total number of stored credentials.
// Returns ErrStorageClosed if the storage has been closed.
func (b *BackendStorage) Count() (int, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return 0, ErrStorageClosed
	}

	credPrefix := b.prefix + defaultCredentialPrefix

	keys, err := b.backend.List(context.Background(), credPrefix)
	if err != nil {
		return 0, wrapStorageError(err)
	}

	return len(keys), nil
}

// CountDiscoverable returns the number of discoverable (resident) credentials.
// This operation requires loading all credentials to check the Discoverable flag.
// Returns ErrStorageClosed if the storage has been closed.
func (b *BackendStorage) CountDiscoverable() (int, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return 0, ErrStorageClosed
	}

	credPrefix := b.prefix + defaultCredentialPrefix

	keys, err := b.backend.List(context.Background(), credPrefix)
	if err != nil {
		return 0, wrapStorageError(err)
	}

	count := 0
	for _, key := range keys {
		data, err := b.backend.Get(context.Background(), key)
		if err != nil {
			continue
		}

		var credential StoredCredential
		if err := json.Unmarshal(data, &credential); err != nil {
			continue
		}

		if credential.Discoverable {
			count++
		}
	}

	return count, nil
}

// SaveState persists the authenticator state to the backend storage.
// The state is serialized to JSON using SerializableState.
// Returns ErrStorageClosed if the storage has been closed.
func (b *BackendStorage) SaveState(state *AuthenticatorState) error {
	if state == nil {
		return ErrInvalidParameter
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return ErrStorageClosed
	}

	// Convert to serializable form
	serializable, err := stateToSerializable(state)
	if err != nil {
		return err
	}

	// Serialize to JSON
	data, err := json.Marshal(serializable)
	if err != nil {
		return ErrSerializationFailed
	}

	// Store in backend
	key := b.prefix + stateKey
	if err := b.backend.Put(context.Background(), key, data); err != nil {
		return wrapStorageError(err)
	}

	return nil
}

// LoadState retrieves the persisted authenticator state from the backend storage.
// Returns ErrStateNotFound if no state has been saved.
// Returns ErrStorageClosed if the storage has been closed.
func (b *BackendStorage) LoadState() (*AuthenticatorState, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return nil, ErrStorageClosed
	}

	key := b.prefix + stateKey

	data, err := b.backend.Get(context.Background(), key)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, ErrStateNotFound
		}
		return nil, wrapStorageError(err)
	}

	var serializable SerializableState
	if err := json.Unmarshal(data, &serializable); err != nil {
		return nil, ErrDeserializationFailed
	}

	return serializableToState(&serializable)
}

// Close releases resources and marks the storage as closed.
// Note: This does NOT close the underlying backend, as it may be shared.
// After Close is called, all other methods return ErrStorageClosed.
// Close is idempotent and may be called multiple times safely.
func (b *BackendStorage) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return nil
	}

	b.closed = true

	return nil
}

// Clear removes all stored credentials from the backend storage.
// This implements the ClearableStorage interface for efficient reset operations.
// Returns ErrStorageClosed if the storage has been closed.
func (b *BackendStorage) Clear() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return ErrStorageClosed
	}

	credPrefix := b.prefix + defaultCredentialPrefix

	// List all credential keys
	keys, err := b.backend.List(context.Background(), credPrefix)
	if err != nil {
		return wrapStorageError(err)
	}

	// Delete each credential
	for _, key := range keys {
		if err := b.backend.Delete(context.Background(), key); err != nil {
			// Continue deleting even if individual deletions fail
			// to ensure maximum cleanup
			continue
		}
	}

	// Reset the RP index
	b.rpIndex = make(map[string][]credentialMeta)

	return nil
}

// ListAll returns all credential IDs in storage.
// This implements the ListableStorage interface.
// Returns ErrStorageClosed if the storage has been closed.
func (b *BackendStorage) ListAll() ([][]byte, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return nil, ErrStorageClosed
	}

	credPrefix := b.prefix + defaultCredentialPrefix

	// List all credential keys
	keys, err := b.backend.List(context.Background(), credPrefix)
	if err != nil {
		return nil, wrapStorageError(err)
	}

	result := make([][]byte, 0, len(keys))
	for _, key := range keys {
		// Extract credential ID from key (remove prefix)
		hexID := strings.TrimPrefix(key, credPrefix)
		if hexID == key {
			// Key didn't have expected prefix, skip
			continue
		}

		// Decode hex credential ID
		credID, err := hex.DecodeString(hexID)
		if err != nil {
			// Invalid hex encoding, skip
			continue
		}

		result = append(result, credID)
	}

	return result, nil
}

// credentialKey builds the storage key for a credential.
func (b *BackendStorage) credentialKey(credentialID []byte) string {
	return b.prefix + defaultCredentialPrefix + hex.EncodeToString(credentialID)
}

// IndexReady returns true when the background index build has completed.
func (b *BackendStorage) IndexReady() bool {
	return b.indexReady.Load()
}

// WaitForIndex blocks until the background index build has completed.
func (b *BackendStorage) WaitForIndex() {
	<-b.indexDone
}

// HasCredentialsForRP returns true if any credentials exist for the given RPID.
// This is an O(1) index lookup with zero storage I/O.
// Returns false if the index is not yet ready.
func (b *BackendStorage) HasCredentialsForRP(rpID string) bool {
	if !b.indexReady.Load() {
		return false
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.rpIndex[rpID]) > 0
}

// HasDiscoverableForRP returns true if any discoverable (resident) credentials
// exist for the given RPID. This is an O(k) scan of the RP's index entries
// (typically 1-3 credentials per RP) with zero storage I/O.
// Returns false if the index is not yet ready.
func (b *BackendStorage) HasDiscoverableForRP(rpID string) bool {
	if !b.indexReady.Load() {
		return false
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	for _, meta := range b.rpIndex[rpID] {
		if meta.discoverable {
			return true
		}
	}
	return false
}

// buildIndexAsync scans all existing credentials and populates the rpIndex.
// Runs in a goroutine launched by NewBackendStorage. Storage I/O is performed
// without holding locks, then the results are merged under the write lock
// (preserving any Store/Delete updates that arrived concurrently).
func (b *BackendStorage) buildIndexAsync() {
	defer close(b.indexDone)

	credPrefix := b.prefix + defaultCredentialPrefix

	keys, err := b.backend.List(context.Background(), credPrefix)
	if err != nil {
		// Empty storage or transient error — mark index ready with whatever
		// Store/Delete have accumulated so far.
		b.indexReady.Store(true)
		return
	}

	// Build the index entries without holding any lock.
	scanned := make(map[string][]credentialMeta, len(keys))
	for _, key := range keys {
		data, err := b.backend.Get(context.Background(), key)
		if err != nil {
			continue
		}

		var cred StoredCredential
		if err := json.Unmarshal(data, &cred); err != nil {
			continue
		}

		if cred.RPID == "" || len(cred.CredentialID) == 0 {
			continue
		}

		scanned[cred.RPID] = append(scanned[cred.RPID], credentialMeta{
			credentialID: cred.CredentialID,
			discoverable: cred.Discoverable,
		})
	}

	// Merge scanned entries into rpIndex under the write lock.
	// Concurrent Store/Delete calls may have already added entries, so
	// we only insert entries that are not yet present.
	b.mu.Lock()
	for rpID, metas := range scanned {
		for _, meta := range metas {
			if !b.indexHasCredential(rpID, meta.credentialID) {
				b.rpIndex[rpID] = append(b.rpIndex[rpID], meta)
			}
		}
	}
	b.mu.Unlock()

	b.indexReady.Store(true)
}

// indexHasCredential checks if a credential ID already exists in the rpIndex
// for the given RPID. Must be called with at least a read lock held.
func (b *BackendStorage) indexHasCredential(rpID string, credentialID []byte) bool {
	for _, meta := range b.rpIndex[rpID] {
		if bytes.Equal(meta.credentialID, credentialID) {
			return true
		}
	}
	return false
}

// indexUpsert adds or updates a credential entry in the rpIndex.
// Must be called with the write lock held.
func (b *BackendStorage) indexUpsert(rpID string, credentialID []byte, discoverable bool) {
	metas := b.rpIndex[rpID]

	// Check if entry already exists (update case, e.g., signCount increment)
	for i, meta := range metas {
		if bytes.Equal(meta.credentialID, credentialID) {
			metas[i].discoverable = discoverable
			return
		}
	}

	// New entry
	idCopy := make([]byte, len(credentialID))
	copy(idCopy, credentialID)
	b.rpIndex[rpID] = append(metas, credentialMeta{
		credentialID: idCopy,
		discoverable: discoverable,
	})
}

// indexRemove removes a credential entry from the rpIndex.
// Must be called with the write lock held.
func (b *BackendStorage) indexRemove(rpID string, credentialID []byte) {
	metas := b.rpIndex[rpID]
	for i, meta := range metas {
		if bytes.Equal(meta.credentialID, credentialID) {
			// Remove by swapping with last element (order doesn't matter)
			metas[i] = metas[len(metas)-1]
			metas = metas[:len(metas)-1]
			if len(metas) == 0 {
				delete(b.rpIndex, rpID)
			} else {
				b.rpIndex[rpID] = metas
			}
			return
		}
	}
}

// wrapStorageError wraps a storage backend error with ErrStorageError.
func wrapStorageError(err error) error {
	if err == nil {
		return nil
	}
	return errors.Join(ErrStorageError, err)
}

// Ensure BackendStorage implements StatefulCredentialStorage.
var _ StatefulCredentialStorage = (*BackendStorage)(nil)

// Ensure BackendStorage implements CredentialStorage.
var _ CredentialStorage = (*BackendStorage)(nil)

// Ensure BackendStorage implements ClearableStorage.
var _ ClearableStorage = (*BackendStorage)(nil)

// Ensure BackendStorage implements ListableStorage.
var _ ListableStorage = (*BackendStorage)(nil)

// Ensure BackendStorage implements CredentialIndexer.
var _ CredentialIndexer = (*BackendStorage)(nil)

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

package authenticator

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"sync"

	"github.com/jeremyhahn/go-keychain/pkg/storage"
)

const (
	// defaultCredentialPrefix is the default key prefix for credential storage.
	defaultCredentialPrefix = "credentials/"

	// stateKey is the key suffix for authenticator state storage.
	stateKey = "state"
)

// BackendStorage adapts storage.Backend to StatefulCredentialStorage.
// This allows the FIDO2 authenticator to use any go-keychain storage backend
// for credential persistence, including file-based and cloud storage.
//
// Thread-safe using a read-write mutex.
type BackendStorage struct {
	backend storage.Backend
	prefix  string // key prefix, e.g., "fido2/authenticator/"
	mu      sync.RWMutex
	closed  bool
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

	return &BackendStorage{
		backend: backend,
		prefix:  prefix,
	}, nil
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
	if err := b.backend.Put(key, data, nil); err != nil {
		return wrapStorageError(err)
	}

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

	data, err := b.backend.Get(key)
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
// This operation requires listing all credentials and filtering by RPID.
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

	credPrefix := b.prefix + defaultCredentialPrefix

	// List all credential keys
	keys, err := b.backend.List(credPrefix)
	if err != nil {
		return nil, wrapStorageError(err)
	}

	var result []*StoredCredential
	for _, key := range keys {
		data, err := b.backend.Get(key)
		if err != nil {
			// Skip credentials that can't be read
			continue
		}

		var credential StoredCredential
		if err := json.Unmarshal(data, &credential); err != nil {
			// Skip malformed credentials
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

	if err := b.backend.Delete(key); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return ErrCredentialNotFound
		}
		return wrapStorageError(err)
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

	keys, err := b.backend.List(credPrefix)
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

	keys, err := b.backend.List(credPrefix)
	if err != nil {
		return 0, wrapStorageError(err)
	}

	count := 0
	for _, key := range keys {
		data, err := b.backend.Get(key)
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
	if err := b.backend.Put(key, data, nil); err != nil {
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

	data, err := b.backend.Get(key)
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
	keys, err := b.backend.List(credPrefix)
	if err != nil {
		return wrapStorageError(err)
	}

	// Delete each credential
	for _, key := range keys {
		if err := b.backend.Delete(key); err != nil {
			// Continue deleting even if individual deletions fail
			// to ensure maximum cleanup
			continue
		}
	}

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
	keys, err := b.backend.List(credPrefix)
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

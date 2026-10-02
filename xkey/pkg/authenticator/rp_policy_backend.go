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
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

// BackendRPPolicyStore implements RPPolicyStore using a xkms.StorageBackend.
// This is the production implementation, designed to work with barrier-encrypted
// storage backends. It follows the same pattern as BackendStorage for credential
// persistence and BackendStore for OATH token storage (OIDC's own token store,
// oidc.DAOStore, moved onto go-qrdb's DAO/entity pattern over a KVStore
// adapted from the same kind of backend -- see oidc_service.go's SetBackend).
//
// Thread-safe using a read-write mutex.
type BackendRPPolicyStore struct {
	backend xkms.StorageBackend
	prefix  string // e.g., "fido2/authenticator/rp-policies/"
	mu      sync.RWMutex
	closed  bool
}

// NewBackendRPPolicyStore creates a new BackendRPPolicyStore using the given
// storage backend. The prefix is prepended to all storage keys to namespace
// the RP policy data. If prefix is empty, "fido2/authenticator/rp-policies/"
// is used as the default.
func NewBackendRPPolicyStore(backend xkms.StorageBackend, prefix string) (*BackendRPPolicyStore, error) {
	if backend == nil {
		return nil, ErrNilStorage
	}

	if prefix == "" {
		prefix = "fido2/authenticator/rp-policies/"
	}

	// Ensure prefix ends with /
	if !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}

	return &BackendRPPolicyStore{
		backend: backend,
		prefix:  prefix,
	}, nil
}

// SetPolicy creates or updates a per-RP policy in the backend storage.
func (b *BackendRPPolicyStore) SetPolicy(policy *RPPolicy) error {
	if err := policy.Validate(); err != nil {
		return err
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return ErrRPPolicyStoreClosed
	}

	data, err := json.Marshal(policy)
	if err != nil {
		return ErrSerializationFailed
	}

	key := b.policyKey(policy.RPID)
	if err := b.backend.Put(context.Background(), key, data); err != nil {
		return wrapStorageError(err)
	}

	return nil
}

// UpdatePolicy applies a partial update onto the stored policy for
// update.RPID, creating the policy if none exists. Fields the update does not
// carry keep their stored values. The read-modify-write runs under the write
// lock, which is this store's concurrency guarantee for all writers sharing
// the instance.
func (b *BackendRPPolicyStore) UpdatePolicy(update *RPPolicyUpdate) error {
	if err := update.Validate(); err != nil {
		return err
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return ErrRPPolicyStoreClosed
	}

	var existing *RPPolicy
	key := b.policyKey(update.RPID)
	data, err := b.backend.Get(context.Background(), key)
	switch {
	case err == nil:
		var stored RPPolicy
		if err := json.Unmarshal(data, &stored); err != nil {
			return ErrDeserializationFailed
		}
		existing = &stored
	case !errors.Is(err, xkms.ErrStorageNotFound):
		return wrapStorageError(err)
	}

	merged, err := json.Marshal(applyRPPolicyUpdate(existing, update))
	if err != nil {
		return ErrSerializationFailed
	}

	if err := b.backend.Put(context.Background(), key, merged); err != nil {
		return wrapStorageError(err)
	}

	return nil
}

// GetPolicy retrieves the policy for a specific RPID from the backend storage.
func (b *BackendRPPolicyStore) GetPolicy(rpID string) (*RPPolicy, error) {
	if rpID == "" {
		return nil, ErrRPPolicyInvalidRPID
	}

	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return nil, ErrRPPolicyStoreClosed
	}

	key := b.policyKey(rpID)
	data, err := b.backend.Get(context.Background(), key)
	if err != nil {
		if errors.Is(err, xkms.ErrStorageNotFound) {
			return nil, ErrRPPolicyNotFound
		}
		return nil, wrapStorageError(err)
	}

	var policy RPPolicy
	if err := json.Unmarshal(data, &policy); err != nil {
		return nil, ErrDeserializationFailed
	}

	return &policy, nil
}

// DeletePolicy removes the policy for a specific RPID from the backend storage.
func (b *BackendRPPolicyStore) DeletePolicy(rpID string) error {
	if rpID == "" {
		return ErrRPPolicyInvalidRPID
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return ErrRPPolicyStoreClosed
	}

	key := b.policyKey(rpID)
	if err := b.backend.Delete(context.Background(), key); err != nil {
		if errors.Is(err, xkms.ErrStorageNotFound) {
			return ErrRPPolicyNotFound
		}
		return wrapStorageError(err)
	}

	return nil
}

// ListPolicies returns all stored RP policies from the backend storage.
func (b *BackendRPPolicyStore) ListPolicies() ([]*RPPolicy, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return nil, ErrRPPolicyStoreClosed
	}

	keys, err := b.backend.List(context.Background(), b.prefix)
	if err != nil {
		return nil, wrapStorageError(err)
	}

	result := make([]*RPPolicy, 0, len(keys))
	for _, key := range keys {
		data, err := b.backend.Get(context.Background(), key)
		if err != nil {
			// Skip policies that can't be read
			continue
		}

		var policy RPPolicy
		if err := json.Unmarshal(data, &policy); err != nil {
			// Skip malformed policies
			continue
		}

		result = append(result, &policy)
	}

	return result, nil
}

// Close marks the store as closed. Does NOT close the underlying backend,
// as it may be shared with other components.
func (b *BackendRPPolicyStore) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return nil
	}

	b.closed = true
	return nil
}

// policyKey builds the storage key for an RP policy.
// The RPID is sanitized to be URL-safe for storage key compatibility.
func (b *BackendRPPolicyStore) policyKey(rpID string) string {
	return b.prefix + sanitizeRPID(rpID)
}

// sanitizeRPID converts an RPID to a URL-safe storage key component.
// Replaces characters that may conflict with storage key separators.
func sanitizeRPID(rpID string) string {
	replacer := strings.NewReplacer(
		"/", "_",
		"\\", "_",
		":", "_",
		" ", "_",
	)
	return replacer.Replace(rpID)
}

// Compile-time interface check.
var _ RPPolicyStore = (*BackendRPPolicyStore)(nil)

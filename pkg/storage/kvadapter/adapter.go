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

// Package kvadapter bridges storage.Backend to go-qrdb's kvstore.KVStore
// interface. This enables go-xkms to use go-qrdb's DAO layer for typed
// entity persistence on top of any storage.Backend implementation.
//
// The adapter translates storage.Backend errors to go-qrdb DragonError
// types so that the DAO layer can correctly identify not-found conditions
// and other error classes.
package kvadapter

import (
	"context"
	"errors"
	"sort"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// KVStoreAdapter adapts a storage.Backend to the kvstore.KVStore interface
// required by go-qrdb's DAO layer. This allows any go-xkms storage backend
// (memory, file, QRDB, LUKS, sealed) to be used with the DAO for typed
// entity persistence.
type KVStoreAdapter struct {
	backend storage.Backend
}

// Compile-time interface compliance check.
var _ qrdbsdk.KVStore = (*KVStoreAdapter)(nil)

// New creates a new KVStoreAdapter wrapping the given storage.Backend.
// Returns NilBackendError if backend is nil.
func New(backend storage.Backend) (*KVStoreAdapter, error) {
	if backend == nil {
		return nil, NilBackendError{}
	}
	return &KVStoreAdapter{backend: backend}, nil
}

// Put stores a key-value pair by delegating to the underlying storage.Backend.
func (a *KVStoreAdapter) Put(ctx context.Context, key string, value []byte) error {
	if err := a.backend.Put(ctx, key, value); err != nil {
		return &PutError{Key: key, Err: err}
	}
	return nil
}

// Get retrieves a value by key. When the key does not exist, returns a
// DragonDB NotFound error so the DAO layer can correctly identify the
// not-found condition via errors.As.
func (a *KVStoreAdapter) Get(ctx context.Context, key string) ([]byte, error) {
	data, err := a.backend.Get(ctx, key)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, &qrdbsdk.DragonError{
				Code: qrdbsdk.ErrNotFound,
				Op:   "kvadapter.Get",
				Err:  err,
			}
		}
		return nil, &GetError{Key: key, Err: err}
	}
	return data, nil
}

// Delete removes a key from storage. This operation is idempotent: deleting
// a non-existent key does not return an error, matching kvstore.KVStore
// semantics. storage.Backend returns ErrNotFound for missing keys, which
// this adapter swallows.
func (a *KVStoreAdapter) Delete(ctx context.Context, key string) error {
	if err := a.backend.Delete(ctx, key); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil
		}
		return &DeleteError{Key: key, Err: err}
	}
	return nil
}

// Scan iterates over all key-value pairs matching the given prefix,
// calling fn for each pair. Iteration proceeds in sorted key order for
// deterministic behavior. Return a non-nil error from fn to stop iteration.
func (a *KVStoreAdapter) Scan(ctx context.Context, prefix string, fn func(key string, value []byte) error) error {
	// Collect pairs via callback, then sort for deterministic order.
	pairs := make(map[string][]byte)
	if err := a.backend.Scan(ctx, prefix, func(key string, value []byte) error {
		pairs[key] = value
		return nil
	}); err != nil {
		return &ScanError{Prefix: prefix, Err: err}
	}

	keys := make([]string, 0, len(pairs))
	for k := range pairs {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		if err := fn(k, pairs[k]); err != nil {
			return err
		}
	}
	return nil
}

// List returns all keys matching the given prefix by delegating to the
// underlying storage.Backend.
func (a *KVStoreAdapter) List(ctx context.Context, prefix string) ([]string, error) {
	keys, err := a.backend.List(ctx, prefix)
	if err != nil {
		return nil, &ListError{Prefix: prefix, Err: err}
	}
	return keys, nil
}

// Exists checks whether a key exists in the underlying storage.Backend.
func (a *KVStoreAdapter) Exists(ctx context.Context, key string) (bool, error) {
	exists, err := a.backend.Exists(ctx, key)
	if err != nil {
		return false, &ExistsError{Key: key, Err: err}
	}
	return exists, nil
}

// RegisterEntityIndexes registers index definitions for an entity type.
// The KVStoreAdapter does not support indexing; this is a no-op.
func (a *KVStoreAdapter) RegisterEntityIndexes(_ string, _ []qrdbsdk.EntityIndex) error {
	return nil
}

// QueryIndex performs an exact-match query on the named index.
// The KVStoreAdapter does not support indexing; returns nil.
func (a *KVStoreAdapter) QueryIndex(_ context.Context, _ string, _ []byte) ([][]byte, error) {
	return nil, nil
}

// ScanIndex performs a range scan on the named index.
// The KVStoreAdapter does not support indexing; returns nil.
func (a *KVStoreAdapter) ScanIndex(_ context.Context, _ string, _, _ []byte) (map[string][][]byte, error) {
	return nil, nil
}

// QueryCompoundIndex performs an exact-match query on a compound index.
// The KVStoreAdapter does not support indexing; returns nil.
func (a *KVStoreAdapter) QueryCompoundIndex(_ context.Context, _ string, _ [][]byte) ([][]byte, error) {
	return nil, nil
}

// ScanCompoundIndex performs a prefix and range scan on a compound index.
// The KVStoreAdapter does not support indexing; returns nil.
func (a *KVStoreAdapter) ScanCompoundIndex(_ context.Context, _ string, _ [][]byte, _, _ []byte) (map[string][][]byte, error) {
	return nil, nil
}

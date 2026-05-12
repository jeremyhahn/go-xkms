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

package objstore

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"

	"github.com/jeremyhahn/go-objstore/pkg/common"
	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
)

// kvStoreAdapter implements xkmssdk.QRDBKVStore using go-objstore's common.Storage.
// This allows qrdb's built-in GenericDAO (with its internal codec handling)
// to use go-objstore as the storage backend.
type kvStoreAdapter struct {
	store common.Storage
}

// Compile-time interface check.
var _ xkmssdk.QRDBKVStore = (*kvStoreAdapter)(nil)

// NewKVStoreAdapter creates a new KVStore adapter backed by the given object store.
func NewKVStoreAdapter(store common.Storage) xkmssdk.QRDBKVStore {
	return &kvStoreAdapter{store: store}
}

// Put stores a key-value pair in the object store.
func (a *kvStoreAdapter) Put(ctx context.Context, key string, value []byte) error {
	return a.store.PutWithContext(ctx, key, bytes.NewReader(value))
}

// Get retrieves a value by key. Returns nil, nil when the key does not exist,
// following the qrdb KVStore convention.
func (a *kvStoreAdapter) Get(ctx context.Context, key string) ([]byte, error) {
	reader, err := a.store.GetWithContext(ctx, key)
	if err != nil {
		if isObjStoreNotFound(err) {
			return nil, xkmssdk.QRDBNewError(xkmssdk.QRDBErrCodeNotFound, "objstore.Get", "key not found: "+key)
		}
		return nil, err
	}
	defer func() { _ = reader.Close() }()

	return io.ReadAll(reader)
}

// Delete removes a key from the object store. Not-found errors are ignored,
// making delete idempotent.
func (a *kvStoreAdapter) Delete(ctx context.Context, key string) error {
	if err := a.store.DeleteWithContext(ctx, key); err != nil {
		if isObjStoreNotFound(err) {
			return nil
		}
		return err
	}
	return nil
}

// Scan iterates over keys with the given prefix, calling fn for each
// key-value pair.
func (a *kvStoreAdapter) Scan(ctx context.Context, prefix string, fn func(key string, value []byte) error) error {
	keys, err := a.store.ListWithContext(ctx, prefix)
	if err != nil {
		return err
	}

	for _, key := range keys {
		value, err := a.Get(ctx, key)
		if err != nil {
			return err
		}
		if value == nil {
			continue
		}
		if err := fn(key, value); err != nil {
			return err
		}
	}

	return nil
}

// List returns all keys matching the given prefix.
func (a *kvStoreAdapter) List(ctx context.Context, prefix string) ([]string, error) {
	return a.store.ListWithContext(ctx, prefix)
}

// Exists checks whether a key exists in the object store.
func (a *kvStoreAdapter) Exists(ctx context.Context, key string) (bool, error) {
	return a.store.Exists(ctx, key)
}

// RegisterEntityIndexes is a no-op for the objstore backend.
// Object storage does not support native indexes.
func (a *kvStoreAdapter) RegisterEntityIndexes(_ string, _ []xkmssdk.QRDBEntityIndex) error {
	return nil
}

// QueryIndex returns an error because objstore does not support index queries.
// The qrdb GenericDAO falls back to scan-based queries when indexes are not available.
func (a *kvStoreAdapter) QueryIndex(_ context.Context, _ string, _ []byte) ([][]byte, error) {
	return nil, ErrIndexNotSupported
}

// ScanIndex returns an error because objstore does not support index queries.
func (a *kvStoreAdapter) ScanIndex(_ context.Context, _ string, _, _ []byte) (map[string][][]byte, error) {
	return nil, ErrIndexNotSupported
}

// QueryCompoundIndex returns an error because objstore does not support compound index queries.
func (a *kvStoreAdapter) QueryCompoundIndex(_ context.Context, _ string, _ [][]byte) ([][]byte, error) {
	return nil, ErrIndexNotSupported
}

// ScanCompoundIndex returns an error because objstore does not support compound index scans.
func (a *kvStoreAdapter) ScanCompoundIndex(_ context.Context, _ string, _ [][]byte, _, _ []byte) (map[string][][]byte, error) {
	return nil, ErrIndexNotSupported
}

// isObjStoreNotFound returns true if the error indicates a key was not found
// in the object store.
func isObjStoreNotFound(err error) bool {
	return errors.Is(err, common.ErrKeyNotFound) || errors.Is(err, os.ErrNotExist)
}

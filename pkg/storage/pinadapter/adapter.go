// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

// Package pinadapter bridges storage.Backend to go-qrdb's qrdbsdk.PINStorage
// interface. This enables go-xkms to use go-qrdb's SoftwareBackend for
// PIN persistence on top of any storage.Backend implementation.
//
// The adapter translates storage.ErrNotFound (go-xkms) into qrdbsdk.ErrPINStorageNotFound
// (go-qrdb) so that the SoftwareBackend correctly recognises a fresh
// install (no prior PIN record) instead of treating it as a load failure.
package pinadapter

import (
	"context"
	"errors"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// PINStoreAdapter adapts a storage.Backend to the qrdbsdk.PINStorage interface
// required by go-qrdb's SoftwareBackend. The adapter is intentionally
// narrow: only Get, Put and Delete are exposed, matching that contract.
type PINStoreAdapter struct {
	backend storage.Backend
}

// Compile-time interface compliance check.
var _ qrdbsdk.PINStorage = (*PINStoreAdapter)(nil)

// New creates a new PINStoreAdapter wrapping the given storage.Backend.
// Returns NilBackendError when backend is nil so callers can detect the
// misuse explicitly.
func New(backend storage.Backend) (*PINStoreAdapter, error) {
	if backend == nil {
		return nil, NilBackendError{}
	}
	return &PINStoreAdapter{backend: backend}, nil
}

// Get retrieves the value stored under key. A missing key is reported as
// qrdbsdk.ErrPINStorageNotFound so SoftwareBackend can treat it as a fresh-install
// signal rather than a load failure.
func (a *PINStoreAdapter) Get(ctx context.Context, key string) ([]byte, error) {
	data, err := a.backend.Get(ctx, key)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, qrdbsdk.ErrPINStorageNotFound
		}
		return nil, &GetError{Key: key, Err: err}
	}
	return data, nil
}

// Put writes value under key, overwriting any prior value. Errors from
// the underlying backend are wrapped in a typed PutError so callers can
// inspect the failing key without parsing string messages.
func (a *PINStoreAdapter) Put(ctx context.Context, key string, value []byte) error {
	if err := a.backend.Put(ctx, key, value); err != nil {
		return &PutError{Key: key, Err: err}
	}
	return nil
}

// Delete removes the record stored under key. Deleting an absent key is not
// an error: the record is already gone, which is what SoftwareBackend's
// provisioning rollback wants either way.
func (a *PINStoreAdapter) Delete(ctx context.Context, key string) error {
	if err := a.backend.Delete(ctx, key); err != nil && !errors.Is(err, storage.ErrNotFound) {
		return &DeleteError{Key: key, Err: err}
	}
	return nil
}

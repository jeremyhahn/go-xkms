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

package qrdb

import (
	"context"
	"errors"
	"io"

	"github.com/jeremyhahn/go-qrdb/sdk/go/transport"
)

// Backend wraps a go-qrdb KVClient to satisfy storage.Backend.
// Error translation maps QRDB transport errors to storage sentinel errors.
// When created via factory constructors, Close() tears down the underlying
// SDK client and engine resources.
type Backend struct {
	client transport.KVClient
	closer io.Closer // nil when backend doesn't own client lifecycle
}

// NewBackend creates a new QRDB storage backend that delegates all
// operations to the given KVClient. The backend does not own the client;
// callers are responsible for managing the client lifecycle.
func NewBackend(client transport.KVClient) *Backend {
	return &Backend{client: client}
}

// newOwnedBackend creates a backend that owns the client lifecycle.
// Close() will close the closer, tearing down the SDK client and any
// embedded engine resources.
func newOwnedBackend(client transport.KVClient, closer io.Closer) *Backend {
	return &Backend{client: client, closer: closer}
}

// ErrNotFound is returned when a key is not found in the QRDB cluster.
// By default this is a standalone sentinel. The parent storage package
// overwrites this with storage.ErrNotFound via SetNotFoundError to ensure
// errors.Is compatibility without circular imports.
var ErrNotFound = errors.New("storage: not found")

// SetNotFoundError allows the parent storage package to inject its
// ErrNotFound sentinel, ensuring errors.Is compatibility across packages.
func SetNotFoundError(err error) {
	ErrNotFound = err
}

// Get retrieves the value for the given key from the QRDB cluster.
// Returns ErrNotFound when the key does not exist.
func (b *Backend) Get(ctx context.Context, key string) ([]byte, error) {
	value, err := b.client.Get(ctx, key)
	if err != nil {
		var knf *transport.KeyNotFoundError
		if errors.As(err, &knf) {
			return nil, ErrNotFound
		}
		return nil, &BackendError{Op: "get", Key: key, Err: err}
	}
	return value, nil
}

// Put stores a key-value pair in the QRDB cluster through Raft consensus.
func (b *Backend) Put(ctx context.Context, key string, value []byte) error {
	if err := b.client.Put(ctx, key, value); err != nil {
		return &BackendError{Op: "put", Key: key, Err: err}
	}
	return nil
}

// Delete removes the key from the QRDB cluster. QRDB delete is
// idempotent, so a missing key is not treated as an error.
func (b *Backend) Delete(ctx context.Context, key string) error {
	err := b.client.Delete(ctx, key)
	if err != nil {
		// QRDB delete is idempotent; ignore key-not-found.
		var knf *transport.KeyNotFoundError
		if errors.As(err, &knf) {
			return nil
		}
		return &BackendError{Op: "delete", Key: key, Err: err}
	}
	return nil
}

// List returns all keys matching the given prefix from the QRDB cluster.
// An empty prefix returns all keys.
func (b *Backend) List(ctx context.Context, prefix string) ([]string, error) {
	keys, err := b.client.List(ctx, prefix)
	if err != nil {
		return nil, &BackendError{Op: "list", Key: prefix, Err: err}
	}
	return keys, nil
}

// Scan iterates over all key-value pairs matching the given prefix from the
// QRDB cluster. An empty prefix visits all pairs. Return a non-nil error
// from fn to stop iteration early.
func (b *Backend) Scan(ctx context.Context, prefix string, fn func(key string, value []byte) error) error {
	pairs, err := b.client.Scan(ctx, prefix)
	if err != nil {
		return &BackendError{Op: "scan", Key: prefix, Err: err}
	}
	for k, v := range pairs {
		if err := fn(k, v); err != nil {
			return err
		}
	}
	return nil
}

// Exists checks whether the given key exists in the QRDB cluster.
// Delegates directly to the client's Exists method.
func (b *Backend) Exists(ctx context.Context, key string) (bool, error) {
	exists, err := b.client.Exists(ctx, key)
	if err != nil {
		return false, &BackendError{Op: "exists", Key: key, Err: err}
	}
	return exists, nil
}

// Close releases resources held by the backend. When the backend owns the
// underlying client lifecycle (created via factory constructors), Close
// tears down the SDK client and any embedded engine resources. When the
// backend wraps an externally-provided KVClient, Close is a no-op.
func (b *Backend) Close() error {
	if b.closer != nil {
		return b.closer.Close()
	}
	return nil
}

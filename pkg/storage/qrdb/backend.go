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

// followerRead requests follower-read consistency: every replica serves the
// read from its local state machine once it has applied up to its committed
// index, without a leader ReadIndex round-trip. This is the correct level for a
// replicated key store read on any node — it reflects all committed entries
// (read-your-committed-writes) yet, unlike linearizable reads, never blocks a
// follower on leader confirmation. Linearizable reads on a follower can stall
// indefinitely when the leader's ReadIndex confirmation does not return, which
// would hang every key-existence check and health probe on non-leader nodes.
var followerRead = transport.WithConsistency(transport.ConsistencyFollower)

// Backend wraps a go-qrdb KVClient to satisfy storage.Backend.
// Error translation maps QRDB transport errors to storage sentinel errors.
// When created via factory constructors, Close() tears down the underlying
// SDK client and engine resources.
type Backend struct {
	client transport.KVClient
	closer io.Closer // nil when backend doesn't own client lifecycle

	// guardedWrites records whether PutIfAbsent, CompareAndSwap and
	// CompareAndDelete can execute against this client. It is set by the
	// constructor rather than derived on each call, because the answer is a
	// property of how the backend was built.
	//
	// The zero value is false, so a Backend assembled as a struct literal
	// claims nothing: a capability claim that defaults to "yes" is the defect
	// this field exists to report.
	guardedWrites bool
}

// NewBackend creates a new QRDB storage backend that delegates all
// operations to the given KVClient. The backend does not own the client;
// callers are responsible for managing the client lifecycle.
func NewBackend(client transport.KVClient) *Backend {
	// A caller-supplied client is taken at the only signal that exists before
	// a write: whether it can carry a guarded write at all, either through the
	// SDK's native guarded-write capability or through a transaction. That is
	// the same pair of assertions PutIfAbsent, CompareAndSwap and
	// CompareAndDelete make, hoisted to construction so a caller can ask
	// instead of discovering. Either capability alone is sufficient — the
	// guarded methods themselves prefer GuardedKVClient and fall back to
	// TransactionClient (#125) — so this is an OR, not an AND.
	_, guarded := client.(transport.GuardedKVClient)
	_, transactional := client.(transport.TransactionClient)
	return &Backend{client: client, guardedWrites: guarded || transactional}
}

// newOwnedBackend creates a backend that owns the client lifecycle.
// Close() will close the closer, tearing down the SDK client and any
// embedded engine resources.
func newOwnedBackend(client transport.KVClient, closer io.Closer, guardedWrites bool) *Backend {
	return &Backend{client: client, closer: closer, guardedWrites: guardedWrites}
}

// GuardedWritesAvailable reports whether this backend's PutIfAbsent,
// CompareAndSwap and CompareAndDelete can execute.
//
// It is true for every backend the embedded constructors in factory.go build:
// newEmbedded's transport (embedded.New(kvSvc, adminSvc)) implements
// transport.GuardedKVClient by delegating straight to the KV service, so all
// three guarded verbs execute without a transaction service — measured through
// the constructors for memory, file and pebble alike (#125, fixed by
// preferring GuardedKVClient in the guarded methods over the transaction
// fallback). It is also true for a caller-supplied client that can only carry
// a transaction, since the guarded methods fall back to that when
// GuardedKVClient is absent or refuses on capability.
//
// It is false only for a client offering neither capability — a hand-rolled
// KVClient a caller injects, since every concrete QRDB transport implements at
// least one.
func (b *Backend) GuardedWritesAvailable() bool {
	return b.guardedWrites
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
	value, err := b.client.Get(ctx, key, followerRead)
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
	keys, err := b.client.List(ctx, prefix, followerRead)
	if err != nil {
		return nil, &BackendError{Op: "list", Key: prefix, Err: err}
	}
	return keys, nil
}

// Scan iterates over all key-value pairs matching the given prefix from the
// QRDB cluster. An empty prefix visits all pairs. Return a non-nil error
// from fn to stop iteration early.
func (b *Backend) Scan(ctx context.Context, prefix string, fn func(key string, value []byte) error) error {
	pairs, err := b.client.Scan(ctx, prefix, followerRead)
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
	exists, err := b.client.Exists(ctx, key, followerRead)
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

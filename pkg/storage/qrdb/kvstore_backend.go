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

package qrdb

import (
	"context"
	"errors"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-qrdb/sdk/go/transport"
)

// ErrNilKVStore is returned by NewKVStoreBackend when it is given no store.
var ErrNilKVStore = errors.New("qrdb: kvstore backend requires a non-nil KVStore")

// KVStoreBackend adapts a go-qrdb KVStore -- the store a DAO factory hands
// out -- to storage.Backend, so a feature that has not moved to a DAO yet
// persists through the same injected factory as one that has.
//
// PutIfAbsent, CompareAndSwap and CompareAndDelete run on the store's
// qrdbsdk.AtomicKVStore capability. A store without it reports
// GuardedWritesAvailable false and refuses all three with
// qrdbsdk.ErrKVAtomicWriteUnsupported.
//
// It offers no fenced create (storage.FencedCreator). The go-qrdb SDK
// re-exports no multi-key guarded batch, so a fenced create cannot be built
// on a KVStore without importing go-qrdb's pkg/kvstore. A caller that needs
// one keeps a Backend over the client (NewBackend).
//
// Reads use the store's own consistency, which for the SDK's
// Client.KVStore is linearizable. Backend reads at follower consistency
// because it holds the KVClient and can pass a read option. A KVStore takes
// no read options.
type KVStoreBackend struct {
	store  qrdbsdk.KVStore
	atomic qrdbsdk.AtomicKVStore // nil when the store has no guarded writes
}

// NewKVStoreBackend wraps store as a storage.Backend. The backend does not
// own the store: Close is a no-op, and the store's owner (the datastore)
// releases it.
func NewKVStoreBackend(store qrdbsdk.KVStore) (*KVStoreBackend, error) {
	if store == nil {
		return nil, ErrNilKVStore
	}
	b := &KVStoreBackend{store: store}
	if atomic, ok := store.(qrdbsdk.AtomicKVStore); ok {
		b.atomic = atomic
	}
	return b, nil
}

// GuardedWritesAvailable reports whether the store carries the guarded
// writes PutIfAbsent, CompareAndSwap and CompareAndDelete run on.
func (b *KVStoreBackend) GuardedWritesAvailable() bool {
	return b.atomic != nil
}

// Get returns the value stored under key, or ErrNotFound when key is
// absent. A KVStore reports absence as a nil value, which a stored empty
// value can also read back as, so a nil value is confirmed with Exists.
func (b *KVStoreBackend) Get(ctx context.Context, key string) ([]byte, error) {
	value, err := b.store.Get(ctx, key)
	if err != nil {
		return nil, &BackendError{Op: "get", Key: key, Err: err}
	}
	if value != nil {
		return value, nil
	}
	exists, err := b.store.Exists(ctx, key)
	if err != nil {
		return nil, &BackendError{Op: "get", Key: key, Err: err}
	}
	if !exists {
		return nil, ErrNotFound
	}
	return []byte{}, nil
}

// Put stores value under key.
func (b *KVStoreBackend) Put(ctx context.Context, key string, value []byte) error {
	if err := b.store.Put(ctx, key, value); err != nil {
		return &BackendError{Op: "put", Key: key, Err: err}
	}
	return nil
}

// PutIfAbsent stores value under key only when key is absent, reporting
// whether it stored.
func (b *KVStoreBackend) PutIfAbsent(ctx context.Context, key string, value []byte) (bool, error) {
	if b.atomic == nil {
		return false, &BackendError{Op: "put-if-absent", Key: key, Err: qrdbsdk.ErrKVAtomicWriteUnsupported}
	}
	stored, err := b.atomic.PutIfAbsent(ctx, key, value)
	if err != nil {
		return false, &BackendError{Op: "put-if-absent", Key: key, Err: err}
	}
	return stored, nil
}

// CompareAndSwap stores newValue under key only when key exists and holds
// expected. On a refusal current is the value present after it (nil when
// key is absent), with the same advisory window as Backend.CompareAndSwap.
func (b *KVStoreBackend) CompareAndSwap(ctx context.Context, key string, expected, newValue []byte) (bool, []byte, error) {
	if b.atomic == nil {
		return false, nil, &BackendError{Op: "compare-and-swap", Key: key, Err: qrdbsdk.ErrKVAtomicWriteUnsupported}
	}
	swapped, current, err := qrdbsdk.CompareAndSwapWithCurrent(ctx, b.atomic, key, expected, newValue)
	if err != nil {
		return false, nil, &BackendError{Op: "compare-and-swap", Key: key, Err: err}
	}
	return swapped, current, nil
}

// CompareAndDelete removes key only when it holds expected, reporting
// whether it deleted.
func (b *KVStoreBackend) CompareAndDelete(ctx context.Context, key string, expected []byte) (bool, error) {
	if b.atomic == nil {
		return false, &BackendError{Op: "compare-and-delete", Key: key, Err: qrdbsdk.ErrKVAtomicWriteUnsupported}
	}
	deleted, err := b.atomic.CompareAndDelete(ctx, key, expected)
	if err != nil {
		return false, &BackendError{Op: "compare-and-delete", Key: key, Err: err}
	}
	return deleted, nil
}

// Delete removes key. Like Backend.Delete it is idempotent: a key that is
// already absent is not an error.
func (b *KVStoreBackend) Delete(ctx context.Context, key string) error {
	err := b.store.Delete(ctx, key)
	if err == nil {
		return nil
	}
	var notFound *transport.KeyNotFoundError
	if errors.As(err, &notFound) {
		return nil
	}
	return &BackendError{Op: "delete", Key: key, Err: err}
}

// List returns every key under prefix.
func (b *KVStoreBackend) List(ctx context.Context, prefix string) ([]string, error) {
	keys, err := b.store.List(ctx, prefix)
	if err != nil {
		return nil, &BackendError{Op: "list", Key: prefix, Err: err}
	}
	return keys, nil
}

// Scan calls fn for every pair under prefix and stops at fn's first error,
// which it returns unwrapped.
func (b *KVStoreBackend) Scan(ctx context.Context, prefix string, fn func(key string, value []byte) error) error {
	var fnErr error
	err := b.store.Scan(ctx, prefix, func(key string, value []byte) error {
		fnErr = fn(key, value)
		return fnErr
	})
	if fnErr != nil {
		return fnErr
	}
	if err != nil {
		return &BackendError{Op: "scan", Key: prefix, Err: err}
	}
	return nil
}

// Exists reports whether key is present.
func (b *KVStoreBackend) Exists(ctx context.Context, key string) (bool, error) {
	exists, err := b.store.Exists(ctx, key)
	if err != nil {
		return false, &BackendError{Op: "exists", Key: key, Err: err}
	}
	return exists, nil
}

// Close is a no-op: the backend does not own the store.
func (b *KVStoreBackend) Close() error {
	return nil
}

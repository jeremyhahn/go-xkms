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

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	db "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
)

// kvStoreAdapter adapts a db.KVClient to the qrdbsdk.KVStore
// interface, enabling DAO access through remote QRDB transports.
type kvStoreAdapter struct {
	kv db.KVClient
}

// NewKVStoreAdapter creates a qrdbsdk.KVStore from a db.KVClient.
// This is used in remote mode to bridge the transport KVClient with
// the DAO layer that expects a KVStore.
func NewKVStoreAdapter(kv db.KVClient) qrdbsdk.KVStore {
	return &kvStoreAdapter{kv: kv}
}

// Put stores a key-value pair via the transport KVClient.
func (a *kvStoreAdapter) Put(ctx context.Context, key string, value []byte) error {
	return a.kv.Put(ctx, key, value)
}

// Get retrieves a value by key via the transport KVClient.
// Returns a database error with ErrNotFound code when the key does not exist,
// matching the behavior expected by QRDB's DAO layer.
func (a *kvStoreAdapter) Get(ctx context.Context, key string) ([]byte, error) {
	val, err := a.kv.Get(ctx, key)
	if err != nil {
		var knf *db.KeyNotFoundError
		if errors.As(err, &knf) {
			return nil, &qrdbsdk.DatabaseError{Code: qrdbsdk.ErrNotFound, Op: "kv.get"}
		}
		return nil, err
	}
	return val, nil
}

// Delete removes a key via the transport KVClient.
func (a *kvStoreAdapter) Delete(ctx context.Context, key string) error {
	return a.kv.Delete(ctx, key)
}

// Scan iterates over keys matching the given prefix, calling fn for
// each key-value pair. Uses the transport KVClient's Scan method
// and iterates the returned map.
func (a *kvStoreAdapter) Scan(ctx context.Context, prefix string, fn func(key string, value []byte) error) error {
	pairs, err := a.kv.Scan(ctx, prefix)
	if err != nil {
		return err
	}
	for k, v := range pairs {
		if err := fn(k, v); err != nil {
			return err
		}
	}
	return nil
}

// List returns all keys matching the given prefix via the transport KVClient.
func (a *kvStoreAdapter) List(ctx context.Context, prefix string) ([]string, error) {
	return a.kv.List(ctx, prefix)
}

// Exists checks whether a key exists via the transport KVClient.
func (a *kvStoreAdapter) Exists(ctx context.Context, key string) (bool, error) {
	return a.kv.Exists(ctx, key)
}

// remoteIndexUnsupportedError reports a secondary-index operation attempted
// against the remote-transport adapter, which fronts a bare KVServicer with
// no index subsystem behind it.
//
// It matches go-qrdb's ErrKVIndexUnsupported, and that match is load-bearing
// rather than cosmetic. Since go-qrdb v0.8.0-alpha, pkg/dao NEGOTIATES index
// capability: it registers indexes at DAO construction and reads the reply.
// An error matching the sentinel means "no index subsystem, plan full scans";
// ANY OTHER error aborts construction. This adapter previously returned a
// bare errs.Message, which go-qrdb does not recognise -- so under v0.9.0-alpha
// every DAO built over it failed to construct.
//
// That path is the DEFAULT one, not an exotic one: NewProvider(svc, nil)
// installs exactly this adapter. It was initially mis-triaged as latent on
// the grounds that no test exercises it, which is not the same thing as
// nothing reaching it.
// Deliberately unexported: callers detect this condition with
// errors.Is(err, qrdbsdk.ErrKVIndexUnsupported), never by asserting the
// concrete type, so exporting it would widen the public API for no caller --
// and a dependency bump is the wrong place to widen an API.
type remoteIndexUnsupportedError struct {
	// Op is the adapter method that was called, such as "QueryIndex".
	Op string

	// Name is the index name, or the entity type for RegisterEntityIndexes.
	Name string
}

// Error returns a human-readable description of the unsupported operation.
func (e *remoteIndexUnsupportedError) Error() string {
	return "kvstore adapter: remote transport does not support " + e.Op + " for " + e.Name
}

// Unwrap returns go-qrdb's capability sentinel so errors.Is identifies the
// class through the standard chain as well as through Is.
func (e *remoteIndexUnsupportedError) Unwrap() error {
	return qrdbsdk.ErrKVIndexUnsupported
}

// Is matches go-qrdb's index-capability sentinel.
func (e *remoteIndexUnsupportedError) Is(target error) bool {
	return target == qrdbsdk.ErrKVIndexUnsupported
}

// RegisterEntityIndexes registers index definitions for an entity type.
// Remote transports do not currently support index registration; this returns
// an error if called, indicating the caller should use a local KVStore.
func (a *kvStoreAdapter) RegisterEntityIndexes(entityType string, indexes []xkmssdk.QRDBEntityIndex) error {
	return &remoteIndexUnsupportedError{Op: "RegisterEntityIndexes", Name: entityType}
}

// QueryIndex performs an exact-match query on a named index.
// Remote transports do not currently support index queries.
func (a *kvStoreAdapter) QueryIndex(ctx context.Context, indexName string, value []byte) ([][]byte, error) {
	return nil, &remoteIndexUnsupportedError{Op: "QueryIndex", Name: indexName}
}

// ScanIndex performs a range scan on a named index.
// Remote transports do not currently support index scans.
func (a *kvStoreAdapter) ScanIndex(ctx context.Context, indexName string, start, end []byte) (map[string][][]byte, error) {
	return nil, &remoteIndexUnsupportedError{Op: "ScanIndex", Name: indexName}
}

// QueryCompoundIndex performs an exact-match query on a compound index.
// Remote transports do not currently support compound index queries.
func (a *kvStoreAdapter) QueryCompoundIndex(ctx context.Context, indexName string, values [][]byte) ([][]byte, error) {
	return nil, &remoteIndexUnsupportedError{Op: "QueryCompoundIndex", Name: indexName}
}

// ScanCompoundIndex performs a range scan on a compound index.
// Remote transports do not currently support compound index scans.
func (a *kvStoreAdapter) ScanCompoundIndex(ctx context.Context, indexName string, prefixValues [][]byte, rangeStart, rangeEnd []byte) (map[string][][]byte, error) {
	return nil, &remoteIndexUnsupportedError{Op: "ScanCompoundIndex", Name: indexName}
}

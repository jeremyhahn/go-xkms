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

package datastore

import (
	"context"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-qrdb/sdk/go/transport"

	qrdbstorage "github.com/jeremyhahn/go-xkms/pkg/storage/qrdb"
)

// Option configures a Datastore built by New.
type Option func(*Datastore)

// WithCallContext runs every call the datastore makes into go-qrdb -- the
// database ensure DatabaseKVStore makes and every operation of a store its
// DAO factory serves -- on the context bind derives from the caller's. A
// feature's persistence is xkms's own, so over an embedded node the server
// passes Node.ServiceContext: the DAOs then run as the node's service
// principal, as xkms's storage backend does (qrdbstorage.WithCallContext).
// A bind error fails the call with ErrCallContext before it reaches go-qrdb.
func WithCallContext(bind qrdbstorage.CallContext) Option {
	return func(d *Datastore) {
		d.bind = bind
	}
}

// callContext derives the context a call into go-qrdb runs on from ctx.
func (d *Datastore) callContext(ctx context.Context) (context.Context, error) {
	if d.bind == nil {
		return ctx, nil
	}
	bound, err := d.bind(ctx)
	if err != nil {
		return nil, &ErrCallContext{Err: err}
	}
	return bound, nil
}

// kvStore returns the DAO store over client: the SDK's own adapter, built
// over transport clients that run on the bound context when the datastore
// has one.
func (d *Datastore) kvStore(client *qrdbsdk.Client) (qrdbsdk.KVStore, error) {
	if d.bind == nil {
		return client.KVStore(), nil
	}
	return qrdbsdk.NewKVStoreAdapter(
		&boundKV{kv: client.KV(), bind: d.callContext},
		&boundIndex{index: client.Index(), bind: d.callContext},
	)
}

// boundKV is a transport KV client that runs every call on the context bind
// derives. It also carries the guarded and transaction verbs the SDK's
// KVStore adapter asserts for, refusing them as the adapter does when the
// inner client lacks them.
type boundKV struct {
	kv   transport.KVClient
	bind func(context.Context) (context.Context, error)
}

var (
	_ transport.GuardedKVClient   = (*boundKV)(nil)
	_ transport.TransactionClient = (*boundKV)(nil)
)

// Put stores a key-value pair on the bound context.
func (b *boundKV) Put(ctx context.Context, key string, value []byte, opts ...transport.WriteOption) error {
	ctx, err := b.bind(ctx)
	if err != nil {
		return err
	}
	return b.kv.Put(ctx, key, value, opts...)
}

// Get retrieves a value on the bound context.
func (b *boundKV) Get(ctx context.Context, key string, opts ...transport.ReadOption) ([]byte, error) {
	ctx, err := b.bind(ctx)
	if err != nil {
		return nil, err
	}
	return b.kv.Get(ctx, key, opts...)
}

// Delete removes a key on the bound context.
func (b *boundKV) Delete(ctx context.Context, key string, opts ...transport.WriteOption) error {
	ctx, err := b.bind(ctx)
	if err != nil {
		return err
	}
	return b.kv.Delete(ctx, key, opts...)
}

// List returns the keys under prefix on the bound context.
func (b *boundKV) List(ctx context.Context, prefix string, opts ...transport.ReadOption) ([]string, error) {
	ctx, err := b.bind(ctx)
	if err != nil {
		return nil, err
	}
	return b.kv.List(ctx, prefix, opts...)
}

// Scan returns the pairs under prefix on the bound context.
func (b *boundKV) Scan(ctx context.Context, prefix string, opts ...transport.ReadOption) (map[string][]byte, error) {
	ctx, err := b.bind(ctx)
	if err != nil {
		return nil, err
	}
	return b.kv.Scan(ctx, prefix, opts...)
}

// Exists reports whether key exists, on the bound context.
func (b *boundKV) Exists(ctx context.Context, key string, opts ...transport.ReadOption) (bool, error) {
	ctx, err := b.bind(ctx)
	if err != nil {
		return false, err
	}
	return b.kv.Exists(ctx, key, opts...)
}

// PutIfAbsent forwards the guarded create on the bound context.
func (b *boundKV) PutIfAbsent(ctx context.Context, key string, value []byte) (bool, error) {
	guarded, ok := b.kv.(transport.GuardedKVClient)
	if !ok {
		return false, qrdbsdk.ErrKVAtomicWriteUnsupported
	}
	ctx, err := b.bind(ctx)
	if err != nil {
		return false, err
	}
	return guarded.PutIfAbsent(ctx, key, value)
}

// CompareAndDelete forwards the guarded delete on the bound context.
func (b *boundKV) CompareAndDelete(ctx context.Context, key string, expected []byte) (bool, error) {
	guarded, ok := b.kv.(transport.GuardedKVClient)
	if !ok {
		return false, qrdbsdk.ErrKVAtomicWriteUnsupported
	}
	ctx, err := b.bind(ctx)
	if err != nil {
		return false, err
	}
	return guarded.CompareAndDelete(ctx, key, expected)
}

// CompareAndSwap forwards the guarded edit on the bound context.
func (b *boundKV) CompareAndSwap(ctx context.Context, key string, expected, next []byte) (bool, error) {
	guarded, ok := b.kv.(transport.GuardedKVClient)
	if !ok {
		return false, qrdbsdk.ErrKVAtomicWriteUnsupported
	}
	ctx, err := b.bind(ctx)
	if err != nil {
		return false, err
	}
	return guarded.CompareAndSwap(ctx, key, expected, next)
}

// ExecuteTransaction forwards the transaction on the bound context.
func (b *boundKV) ExecuteTransaction(ctx context.Context, req *transport.TransactionRequest, opts ...transport.WriteOption) (*transport.TransactionResponse, error) {
	tx, ok := b.kv.(transport.TransactionClient)
	if !ok {
		return nil, qrdbsdk.ErrKVAtomicWriteUnsupported
	}
	ctx, err := b.bind(ctx)
	if err != nil {
		return nil, err
	}
	return tx.ExecuteTransaction(ctx, req, opts...)
}

// boundIndex is a transport index client that runs every call on the
// context bind derives. The SDK's adapter registers a DAO's indexes on a
// background context, so the binding has to sit beneath it, here.
type boundIndex struct {
	index transport.IndexClient
	bind  func(context.Context) (context.Context, error)
}

var _ transport.IndexClient = (*boundIndex)(nil)

// IndexCreate creates an index on the bound context.
func (b *boundIndex) IndexCreate(ctx context.Context, name, fieldName string, config transport.IndexConfig) error {
	ctx, err := b.bind(ctx)
	if err != nil {
		return err
	}
	return b.index.IndexCreate(ctx, name, fieldName, config)
}

// IndexDrop drops an index on the bound context.
func (b *boundIndex) IndexDrop(ctx context.Context, name string) error {
	ctx, err := b.bind(ctx)
	if err != nil {
		return err
	}
	return b.index.IndexDrop(ctx, name)
}

// IndexQuery queries an index on the bound context.
func (b *boundIndex) IndexQuery(ctx context.Context, indexName, value string) (*transport.IndexQueryResponse, error) {
	ctx, err := b.bind(ctx)
	if err != nil {
		return nil, err
	}
	return b.index.IndexQuery(ctx, indexName, value)
}

// IndexScan scans an index on the bound context.
func (b *boundIndex) IndexScan(ctx context.Context, indexName string, start, end *string) (*transport.IndexScanResponse, error) {
	ctx, err := b.bind(ctx)
	if err != nil {
		return nil, err
	}
	return b.index.IndexScan(ctx, indexName, start, end)
}

// IndexList lists the indexes on the bound context.
func (b *boundIndex) IndexList(ctx context.Context) (*transport.IndexListResponse, error) {
	ctx, err := b.bind(ctx)
	if err != nil {
		return nil, err
	}
	return b.index.IndexList(ctx)
}

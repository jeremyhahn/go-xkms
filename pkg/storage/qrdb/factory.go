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
	"io"
	"sync/atomic"

	"github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/jeremyhahn/go-qrdb/sdk/go/transport/embedded"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
)

// GUARDED WRITES (PutIfAbsent, CompareAndSwap, CompareAndDelete) ARE
// AVAILABLE FROM EVERY CONSTRUCTOR BELOW.
//
// They were not, uniformly, and the fix -- landed for issue #125 -- did not
// need a transaction service, a different storage layout, or a different
// package boundary. It needed this package's own guarded methods
// (backend_putifabsent.go, backend_compareandswap.go) to try
// transport.GuardedKVClient before transport.TransactionClient, which is the
// dispatch order backend_compareanddelete.go already used. newEmbedded's
// transport, built by embedded.New(kvSvc, adminSvc) below, implements
// GuardedKVClient by delegating straight to the KV service -- no transaction
// service required -- and always has; the SDK carried PutIfAbsent and
// CompareAndDelete on that interface since go-qrdb#119 and CompareAndSwap
// since go-qrdb#121 (v0.12.0-alpha). PutIfAbsent and CompareAndSwap in this
// package simply never asked for it, so they took the transaction path alone,
// which newEmbedded genuinely does not wire, and failed identically to the
// "embedded: TransactionServicer must not be nil" this note used to
// characterize. CompareAndDelete had already been fixed the same way once its
// own blocker (a missing FastStateMachine opcode handler, go-qrdb#175) was
// cleared in go-qrdb v0.16.3-alpha; see backend_compareanddelete.go's history
// and factory_cas_characterization_test.go's current assertions for both
// verbs.
//
// The issue's discussion considered rebasing these constructors on
// storage.OpenEngine (pkg/storage/engine.go), which already produces a
// guarded-write-capable Backend for file/pebble/memory. That path was not
// taken: pkg/storage already imports pkg/storage/qrdb (constructors.go
// delegates NewFile/NewPebble here), so this package importing pkg/storage
// back would be a compile-time cycle -- the same constraint
// backend_compareanddelete_test.go documents for why it cannot import
// pkg/storage/storagetest directly. OpenEngine's mechanism is also a
// different one: engineBackend wraps go-qrdb's raw Storage engine and
// arbitrates guarded writes with a process-local mutex, never touching a
// transaction service or the embedded transport at all. Reaching the SAME
// outcome (guarded writes, on the SAME on-disk layout, with no data move) by
// fixing the dispatch order here is smaller, avoids the cycle, and leaves
// newEmbedded's storage engines -- and therefore the on-disk format every
// existing NewFile/NewPebble directory was written in -- untouched.
//
// A caller cannot currently ask a Backend which operations it supports; that
// needs a capability on the interface and is an owner decision (#29). Backend
// implements GuardedWriteReporter (backend.go's GuardedWritesAvailable) for
// exactly this, and now answers true for everything built below.

// NewMemory creates an embedded in-memory backend. The entire QRDB stack
// (storage, state machine, services, transport, and SDK client) is
// initialized in-process. Close() tears down all resources.
//
// Supports PutIfAbsent, CompareAndSwap and CompareAndDelete; see the note
// above these constructors.
func NewMemory() (*Backend, error) {
	store := qrdbsdk.NewMemoryStorage()
	return newEmbedded(store, "memory")
}

// NewFile creates an embedded file-based backend at the given path. Each
// key-value pair is stored as a separate file under the directory -- the
// same on-disk layout NewFile has always written, unchanged by #125. The
// entire QRDB stack is initialized in-process. Close() tears down all
// resources.
//
// Supports PutIfAbsent, CompareAndSwap and CompareAndDelete; see the note
// above these constructors.
func NewFile(path string) (*Backend, error) {
	store, err := qrdbsdk.NewFileStorage(path)
	if err != nil {
		return nil, &FactoryError{Engine: "file", Err: err}
	}
	return newEmbedded(store, "file")
}

// NewPebble creates an embedded PebbleDB backend at the given path. Uses
// a test-optimized PebbleDB configuration suitable for lightweight embedded
// usage. The entire QRDB stack is initialized in-process. Close() tears
// down all resources.
//
// Supports PutIfAbsent, CompareAndSwap and CompareAndDelete; see the note
// above these constructors.
func NewPebble(path string) (*Backend, error) {
	cfg := qrdbsdk.TestPebbleConfig(path)
	store, err := qrdbsdk.NewPebbleStorage(cfg)
	if err != nil {
		return nil, &FactoryError{Engine: "pebble", Err: err}
	}
	return newEmbedded(store, "pebble")
}

// newEmbedded builds the full QRDB embedded stack from a storage engine:
//
//	Storage -> FastStateMachine -> LocalBackend -> KVService + AdminService
//	-> embedded.Transport -> qrdbsdk.Client -> Backend
//
// FastStateMachine is used instead of SimpleStateMachine because it
// supports PrefixQuery lookups required by the Scan operation.
//
// The returned Backend owns the SDK client lifecycle; Close() tears down the
// client and then drains the state machine.
//
// Draining is not optional and cannot be delegated to the client: FastBackend
// applies each Put on a detached goroutine, and the only join point is
// FastStateMachine.Close (wg.Wait). The SDK client's Close reaches the embedded
// transport, whose Close just flips a closed flag — it never reaches the state
// machine. Without the explicit drain below, a write issued shortly before
// shutdown lands after Close returns, or not at all, and the only trace is an
// error logged from a goroutine nobody is waiting on. For a key store that is
// silent data loss.
func newEmbedded(store qrdbsdk.Storage, engine string) (*Backend, error) {
	fsm := qrdbsdk.NewFastStateMachine(1, 1, store)
	host := qrdbsdk.NewLocalBackend(fsm)
	kvSvc := qrdbsdk.NewKVService(host, 1)
	adminSvc := qrdbsdk.NewAdminService(host)

	t, err := embedded.New(kvSvc, adminSvc)
	if err != nil {
		return nil, &FactoryError{Engine: engine, Err: err}
	}

	client, err := qrdbsdk.NewClient(t)
	if err != nil {
		return nil, &FactoryError{Engine: engine, Err: err}
	}

	if err := client.Connect(context.Background()); err != nil {
		return nil, &FactoryError{Engine: engine, Err: err}
	}

	// guardedWrites is computed the same way NewBackend computes it for a
	// caller-supplied client, rather than hardcoded, so this stays correct if
	// the embedded transport's capabilities ever change without another edit
	// here. It is true today: kv implements transport.GuardedKVClient (see the
	// file comment and #125), so PutIfAbsent, CompareAndSwap and
	// CompareAndDelete all execute through it.
	kv := client.KV()
	_, guardedWrites := kv.(transport.GuardedKVClient)
	return newOwnedBackend(kv, &embeddedCloser{client: client, fsm: fsm, store: store}, guardedWrites), nil
}

// embeddedCloser tears down the embedded stack in dependency order: the client
// first, so no further writes are accepted; then the state machine, which waits
// for every in-flight apply to reach the storage engine; then the engine, which
// releases its files and locks.
//
// Nothing below the client was being closed at all. FastStateMachine.Close is
// only a wg.Wait, and no layer forwarded a close to the engine, so a PebbleDB
// instance kept its handle and directory lock for the life of the process --
// reopening the same path failed with "lock held by current process".
type embeddedCloser struct {
	client io.Closer
	fsm    interface {
		Close(context.Context) error
	}
	store  io.Closer
	closed atomic.Bool
}

// Close tears the stack down and returns the first error encountered.
//
// Every stage runs even if an earlier one fails: writes already accepted must
// still reach disk, and the engine must release its lock regardless of how the
// layers above it fared. Close is idempotent — callers commonly close from a
// defer as well as an explicit shutdown path.
func (c *embeddedCloser) Close() error {
	if c.closed.Swap(true) {
		return nil
	}

	var firstErr error
	record := func(err error) {
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}

	if c.client != nil {
		record(c.client.Close())
	}
	if c.fsm != nil {
		record(c.fsm.Close(context.Background()))
	}
	if c.store != nil {
		record(c.store.Close())
	}
	return firstErr
}

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

	"github.com/jeremyhahn/go-qrdb/sdk/go/transport/embedded"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
)

// COMPARE-AND-SWAP IS NOT AVAILABLE FROM ANY CONSTRUCTOR BELOW.
//
// Backend advertises PutIfAbsent and CompareAndSwap, but no embedded
// constructor here supports them. Measured 2026-08-21 against go-qrdb
// v0.9.0-alpha, through these exact constructors
// (factory_cas_characterization_test.go):
//
//	memory  ->  embedded: TransactionServicer must not be nil
//	file    ->  embedded: TransactionServicer must not be nil
//	pebble  ->  embedded: TransactionServicer must not be nil
//
// The behaviour is UNIFORM, and that uniformity is the point: the request
// never reaches a storage engine, so there is no per-backend capability
// difference to route around. Plain Put/Get is unaffected on all three, which
// is what makes this a trap -- a caller sees a working store and only
// discovers the gap on the path that needs the operation.
//
// The cause is in newEmbedded below: it builds its transport with
// embedded.New(kvSvc, adminSvc) and no transaction service. This is tracked as
// issue #125 — distinct from #61, which was the pkg/server `storage.backend:
// qrdb` path and is fixed in go-qrdb v0.11.0-alpha (the sdk/go/node daemon node
// now serves standalone CAS). These low-level constructors are a separate path;
// the sanctioned fix is embedded.NewServer (memory/pebble gain CAS; the file KV
// engine cannot — measured). See #125.
//
// What this note deliberately does NOT say is what happens after #61 is fixed.
// An earlier revision published a file-vs-memory capability matrix derived
// from qrdb's pkg/server/lifecycle.NewLocalEngine, which selects a KVEngine or
// an MVCCEngine from the backend type. These constructors do not use that path
// -- newEmbedded passes the storage straight to NewFastStateMachine -- so the
// matrix described something else and would have had callers avoiding NewFile
// for a reason that does not apply to it. Reading the current source, qrdb's
// FastStateMachine.handleTransaction also requires an MVCC store supplied via
// WithMVCCStore, and newEmbedded passes no options, so a transaction service
// alone may not be sufficient either. Whatever the answer turns out to be, it
// gets measured through these constructors before it is written down here.
//
// A caller cannot currently ask a Backend which operations it supports; that
// needs a capability on the interface and is an owner decision (#29).

// NewMemory creates an embedded in-memory backend. The entire QRDB stack
// (storage, state machine, services, transport, and SDK client) is
// initialized in-process. Close() tears down all resources.
//
// Does not support compare-and-swap; see the note above these constructors.
func NewMemory() (*Backend, error) {
	store := qrdbsdk.NewMemoryStorage()
	return newEmbedded(store, "memory")
}

// NewFile creates an embedded file-based backend at the given path. Each
// key-value pair is stored as a separate file under the directory. The
// entire QRDB stack is initialized in-process. Close() tears down all
// resources.
//
// Does not support compare-and-swap; see the note above these constructors.
// It is no worse off than NewMemory or NewPebble in this respect -- all three
// fail identically.
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
// Does not support compare-and-swap; see the note above these constructors.
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

	// guardedWrites is false: this transport carries no transaction service
	// (see the file comment and #125), so PutIfAbsent, CompareAndSwap and
	// CompareAndDelete are declared by Backend and cannot execute here.
	return newOwnedBackend(client.KV(), &embeddedCloser{client: client, fsm: fsm, store: store}, false), nil
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

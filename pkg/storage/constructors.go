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

package storage

import "github.com/jeremyhahn/go-xkms/pkg/storage/qrdb"

func init() {
	// Align qrdb's not-found sentinel with storage.ErrNotFound so that
	// errors.Is works across packages without circular imports.
	qrdb.SetNotFoundError(ErrNotFound)
}

// The QRDB backend reports whether its guarded writes can execute, and the
// embedded constructors below build backends that answer true (#125). The
// assertion lives here rather than in that package because the dependency
// runs one way: this package imports qrdb, never the reverse.
var _ GuardedWriteReporter = (*qrdb.Backend)(nil)

// THE EMBEDDED CONSTRUCTORS BELOW DIVERGE FROM THE Backend CONTRACT IN ONE
// WAY, and it is silent, which is what makes it the dangerous one.
//
// This divergence travels with the embedded QRDB client, NOT with the storage
// medium, and that is the distinction to hold on to. "Memory versus disk" is
// the obvious reading and the wrong one:
//
//	                        NewMemory   NewFile   NewPebble   qrdb.NewMemory
//	                        (engine)    (QRDB)    (QRDB)      (QRDB)
//	Exists, absent key      false OK    true      true        true
//	Get, absent key         NotFound    nil,nil   nil,nil     nil,nil
//	Delete, absent key      NotFound    nil       nil         nil
//	PutIfAbsent             works       works     works       works
//
// So NewMemory -- this package's engineBackend -- conforms on every row, while
// all three QRDB-backed constructors still diverge on absent-key semantics
// (row 2 below). PutIfAbsent used to be a fourth divergent row (#125): the
// embedded QRDB transport is built without a transaction service, and
// PutIfAbsent and CompareAndSwap dispatched to one exclusively, so both failed
// with "embedded: TransactionServicer must not be nil" on NewFile, NewPebble
// and qrdb.NewMemory alike. They now prefer the transport's own
// transport.GuardedKVClient capability first -- the same dispatch
// CompareAndDelete already used -- which needs no transaction service, so all
// four constructors in the table serve PutIfAbsent identically. Pinned by
// pkg/storage/qrdb/factory_cas_characterization_test.go.
//
// ABSENT KEYS STILL ANSWER WRONGLY, WITHOUT ERRORING, on every QRDB-backed
// constructor. Exists reports true for a key that was never written, and Get
// and Delete report success where the interface documents ErrNotFound. Plain
// Put and a Get of a key that IS present are unaffected, which is what makes
// this a trap rather than an outage: the store looks healthy and the wrong
// answers propagate.
//
// The practical consequences, because they are not symmetric: a "refuse if
// already present" guard built on Exists is INVERTED here -- it refuses every
// request rather than none -- and code written as
// `if _, err := b.Get(...); errors.Is(err, ErrNotFound)` takes the wrong
// branch. A presence check that works on every engine has to read the value
// and treat "no error AND non-empty" as present. Tracked as #252 and pinned by
// the absent-key contract in pkg/storage/storagetest, which fails when the
// engines are fixed so this note cannot outlive them.
//
// This warning is repeated here rather than left on pkg/storage/qrdb because
// THIS is the layer callers use: pkg/server/backend_factory.go selects a
// backend through these constructors, and a caller reading the Backend
// interface has no reason to look further down. Documenting only the internal
// layer leaves the advertised contract misleading at the point of use.

// NewFile creates a file-based storage backend at the given path.
// Delegates to the go-qrdb embedded file engine. Each key-value pair is
// stored as a separate file under the directory. The entire QRDB stack
// is initialized in-process. Close() tears down all resources.
//
// Supports PutIfAbsent, CompareAndSwap and CompareAndDelete; see the absent-key
// note above for the divergence that remains.
func NewFile(path string) (Backend, error) {
	backend, err := qrdb.NewFile(path)
	if err != nil {
		return nil, err
	}
	return backend, nil
}

// NewPebble creates a PebbleDB storage backend at the given path.
// Delegates to the go-qrdb embedded PebbleDB engine. Uses a test-optimized
// PebbleDB configuration suitable for lightweight embedded usage. The entire
// QRDB stack is initialized in-process. Close() tears down all resources.
//
// Supports PutIfAbsent, CompareAndSwap and CompareAndDelete; see the
// package-level note above NewFile for the absent-key divergence that remains.
func NewPebble(path string) (Backend, error) {
	backend, err := qrdb.NewPebble(path)
	if err != nil {
		return nil, err
	}
	return backend, nil
}

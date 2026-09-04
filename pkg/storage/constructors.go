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

// THE EMBEDDED CONSTRUCTORS BELOW DIVERGE FROM THE Backend CONTRACT IN TWO
// WAYS. One fails loudly; the other is silent and is the dangerous one.
//
// Both divergences travel with the embedded QRDB client, NOT with the storage
// medium, and that is the distinction to hold on to. "Memory versus disk" is
// the obvious reading and the wrong one:
//
//	                        NewMemory   NewFile   NewPebble   qrdb.NewMemory
//	                        (engine)    (QRDB)    (QRDB)      (QRDB)
//	Exists, absent key      false OK    true      true        true
//	Get, absent key         NotFound    nil,nil   nil,nil     nil,nil
//	Delete, absent key      NotFound    nil       nil         nil
//	PutIfAbsent             works       error     error       error
//
// So NewMemory -- this package's engineBackend -- conforms, while an
// in-memory QRDB backend diverges exactly like the two on disk.
//
// 1. COMPARE-AND-SWAP IS NOT AVAILABLE. The Backend contract says PutIfAbsent
// atomically stores the value. NewFile and NewPebble do not satisfy that: the
// embedded QRDB transport is built without a transaction service, so
// PutIfAbsent and CompareAndSwap fail with "embedded: TransactionServicer must
// not be nil". A caller must handle that error and must not read it as "the
// key was present". Tracked as #61, blocked on go-qrdb#62, and pinned by
// pkg/storage/qrdb/factory_cas_characterization_test.go.
//
// 2. ABSENT KEYS ANSWER WRONGLY, WITHOUT ERRORING. Exists reports true for a
// key that was never written, and Get and Delete report success where the
// interface documents ErrNotFound. Plain Put and a Get of a key that IS
// present are unaffected, which is what makes this a trap rather than an
// outage: the store looks healthy and the wrong answers propagate.
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
// Does not support compare-and-swap; see the note above.
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
func NewPebble(path string) (Backend, error) {
	backend, err := qrdb.NewPebble(path)
	if err != nil {
		return nil, err
	}
	return backend, nil
}

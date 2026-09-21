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

// Package storage provides an abstraction layer for key-value storage backends.
// It supports multiple backend engines through go-qrdb: memory, file, PebbleDB,
// Raft, and remote QRDB clusters.
package storage

import "context"

// Backend defines the interface for storage backends.
// All implementations must be thread-safe.
//
// This interface is designed to be a subset of go-qrdb's KVClient, enabling
// any QRDB transport (embedded, REST, gRPC, QUIC, Unix, MCP) to natively
// satisfy Backend with zero adapter code.
//
// GUARDED WRITES ARE OPTIONAL CAPABILITIES, not methods here: CompareAndSwapper
// for the guarded edit and CompareAndDeleter for the guarded release. A caller
// that needs one type-asserts for it. Keeping them off this interface is what
// lets a backend that cannot provide the guarantee say so by not having the
// method, rather than by shipping one that always errors — the absence is
// visible at the assertion instead of on the first call in production.
//
// One expansion of the guarded-delete capability is tracked: execution on
// qrdb's embedded constructors (go-qrdb #175). The hardware certificate
// adapter does not implement it by design; see pkg/storage/compareanddelete.go.
type Backend interface {
	// Get retrieves the value for the given key.
	// Returns ErrNotFound if the key does not exist.
	Get(ctx context.Context, key string) ([]byte, error)

	// Put stores the value for the given key.
	// If the key already exists, it will be overwritten.
	//
	// AN IMPLEMENTATION MUST NOT RETAIN value. It must copy or otherwise
	// fully consume the slice before returning, and must not hold a reference
	// to it for asynchronous persistence.
	//
	// This is a requirement rather than a convention because callers wipe
	// secret material after a successful Put: this backend stores KEYS, and a
	// plaintext private key left on the ordinary Go heap is unwipeable and
	// outlives every guarantee the protected-memory types provide
	// (pkg/backend/software.ImportKey is the caller that depends on it). An
	// implementation that retained the slice would have its stored value
	// zeroed underneath it -- so the rule protects the implementation as much
	// as the caller.
	//
	// Every in-tree implementation satisfies this. Re-derived from the code
	// on 2026-08-27 against go-qrdb v0.13.0-alpha / go-objstore v0.3.0-alpha,
	// by enumerating the engines rather than the ones already known -- the
	// first pass named four and the set is larger:
	//
	//   - memory: copies into its own buffer (memory/storage.go valCopy).
	//   - file: writes to a temp file and renames.
	//   - pebble: Set copies into the batch/memtable before returning.
	//   - qrdb (raft): encodes the value into a command buffer (kv.EncodePut)
	//     BEFORE proposing, so the state machine's detached apply goroutine
	//     reads that buffer rather than this slice.
	//   - objstore: does NOT copy -- it wraps the slice in a bytes.Reader
	//     (objstore/objstore.go) and hands it to the go-objstore backend. Safe
	//     only because every backend there (local, memory, s3, gcs, azure,
	//     minio, glacier) drains the reader synchronously inside Put. This is
	//     the implementation to re-check first when a backend is added, since
	//     it is the one that aliases rather than copies.
	//   - namespace / partition / prefix: pass the slice straight through to
	//     one of the above, so they inherit its answer.
	Put(ctx context.Context, key string, value []byte) error

	// PutIfAbsent atomically stores value at key only if key does not already
	// exist. It returns stored=true when the value was written, stored=false
	// when key already held a value (store left unchanged). Replicated/clustered
	// implementations MUST make this atomic across nodes (e.g. a consensus
	// compare-and-swap); single-process implementations satisfy it via internal
	// synchronization.
	//
	// AN IMPLEMENTATION MAY REPORT THIS OPERATION AS UNAVAILABLE, via
	// GuardedWriteReporter (guardedwrites.go). The embedded QRDB backends
	// returned by NewFile, NewPebble and qrdb.NewMemory used to do so
	// uniformly (#125): the two guarded methods that needed it dispatched to a
	// transaction their transport wires no service for, instead of the
	// transport's own guarded-write capability. All three now report it
	// available. A caller that needs cross-node uniqueness must still handle
	// an error rather than assume the operation exists -- and must not read a
	// failure here as "the key was present", which is what stored=false means
	// and an error does not.
	PutIfAbsent(ctx context.Context, key string, value []byte) (stored bool, err error)

	// Delete removes the key and its value from storage.
	// Returns ErrNotFound if the key does not exist.
	Delete(ctx context.Context, key string) error

	// List returns all keys with the given prefix.
	// If prefix is empty, all keys are returned.
	List(ctx context.Context, prefix string) ([]string, error)

	// Scan iterates over all key-value pairs matching the given prefix,
	// calling fn for each pair. If prefix is empty, all pairs are visited.
	// Return a non-nil error from fn to stop iteration early.
	Scan(ctx context.Context, prefix string, fn func(key string, value []byte) error) error

	// Exists checks if a key exists in storage.
	Exists(ctx context.Context, key string) (bool, error)

	// Close releases any resources held by the backend.
	Close() error
}

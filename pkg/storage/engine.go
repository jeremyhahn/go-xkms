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

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbstorage "github.com/jeremyhahn/go-qrdb/sdk/go/storage"
)

// EngineError wraps a failure returned by the underlying go-qrdb storage
// engine, capturing the operation and key for diagnosis. It unwraps to the
// engine's own error so callers can inspect it with errors.As/errors.Is.
type EngineError struct {
	Op  string // operation: get, put, delete, list, scan, exists, close
	Key string // key involved, when applicable
	Err error  // underlying engine error
}

// Error implements the error interface.
func (e *EngineError) Error() string {
	if e.Key != "" {
		return fmt.Sprintf("storage: engine %s %q: %v", e.Op, e.Key, e.Err)
	}
	return fmt.Sprintf("storage: engine %s: %v", e.Op, e.Err)
}

// Unwrap returns the underlying engine error.
func (e *EngineError) Unwrap() error { return e.Err }

// mapErr translates a go-qrdb engine error into the xkms storage contract. A
// closed-engine error becomes the ErrClosed sentinel (so errors.Is(err,
// ErrClosed) holds across the adapter); every other failure is wrapped in an
// EngineError carrying the operation and key.
func mapErr(op, key string, err error) error {
	var closed *qrdbsdk.StorageClosedError
	if errors.As(err, &closed) {
		return ErrClosed
	}
	return &EngineError{Op: op, Key: key, Err: err}
}

// engineBackend adapts a go-qrdb raw storage engine (qrdbstorage.Storage) to the
// xkms Backend interface. It is the single bridge through which xkms local
// persistence reaches a go-qrdb engine, so the concrete engine — file,
// PebbleDB, or memory — is selectable at construction time without changing
// any call site. The file engine writes a flat <root>/<key> layout, one file
// per key, identical to xkms's historical on-disk format, so adopting it
// requires no data migration.
type engineBackend struct {
	eng qrdbstorage.Storage

	// writeMu serializes EVERY write this backend performs — the unconditional
	// Put and Delete as well as the guarded PutIfAbsent, CompareAndSwap and
	// CompareAndDelete. The underlying engine is a single-writer process-local
	// store, so holding this mutex across a read-then-write makes the guarded
	// verbs genuinely atomic for this process.
	//
	// It must cover the unconditional writers too, and that is the whole point
	// rather than an over-cautious extra. A guard that only excluded the other
	// guarded verbs would be defeated by a plain Put: CompareAndDelete could
	// read value A, a concurrent Put could store B, and the delete would then
	// remove B — a value the releaser never observed, which is exactly the race
	// the guarded verbs exist to close.
	writeMu sync.Mutex
}

// Compile-time assertion that engineBackend satisfies Backend.
var _ Backend = (*engineBackend)(nil)
var _ CompareAndSwapper = (*engineBackend)(nil)
var _ CompareAndDeleter = (*engineBackend)(nil)
var _ FencedCreator = (*engineBackend)(nil)

// NewEngineBackend wraps a go-qrdb storage engine as an xkms Backend.
func NewEngineBackend(eng qrdbstorage.Storage) Backend {
	return &engineBackend{eng: eng}
}

// Get retrieves the value for key. The go-qrdb engine reports a missing key as
// (nil, nil); Get translates that into ErrNotFound to honor the Backend
// contract.
func (b *engineBackend) Get(_ context.Context, key string) ([]byte, error) {
	value, err := b.eng.Get([]byte(key))
	if err != nil {
		return nil, mapErr("get", key, err)
	}
	if value == nil {
		return nil, ErrNotFound
	}
	return value, nil
}

// Put stores value under key, overwriting any existing value.
//
// It takes writeMu even though a single Set needs no critical section of its
// own: the guarded verbs read and then write, and a Put that slipped between
// those two steps would defeat their guard. See writeMu.
func (b *engineBackend) Put(_ context.Context, key string, value []byte) error {
	b.writeMu.Lock()
	defer b.writeMu.Unlock()

	if err := b.eng.Set([]byte(key), value); err != nil {
		return mapErr("put", key, err)
	}
	return nil
}

// PutIfAbsent atomically stores value under key only if key is absent.
//
// Atomicity guarantee: the underlying go-qrdb engine is a single-writer,
// process-local store. Holding writeMu across the Exists check and the
// Set makes this check-then-write linearizable for this process — there is no
// other writer to interleave with — so the guarantee is genuine, not a
// best-effort fallback. (A clustered/replicated Backend must instead implement
// this via a consensus compare-and-swap.)
func (b *engineBackend) PutIfAbsent(_ context.Context, key string, value []byte) (bool, error) {
	b.writeMu.Lock()
	defer b.writeMu.Unlock()

	exists, err := b.eng.Exists([]byte(key))
	if err != nil {
		return false, mapErr("put-if-absent", key, err)
	}
	if exists {
		return false, nil
	}
	if err := b.eng.Set([]byte(key), value); err != nil {
		return false, mapErr("put-if-absent", key, err)
	}
	return true, nil
}

// PutIfAllAbsent stores value at key only when key and every fence are
// absent, deciding every absence and the write under writeMu -- the lock
// PutIfAbsent, CompareAndSwap and CompareAndDelete share -- so for this
// single-writer, process-local engine the decision is genuinely atomic.
func (b *engineBackend) PutIfAllAbsent(_ context.Context, key string, value []byte, fences ...string) (bool, error) {
	b.writeMu.Lock()
	defer b.writeMu.Unlock()

	for _, k := range append([]string{key}, fences...) {
		exists, err := b.eng.Exists([]byte(k))
		if err != nil {
			return false, mapErr("put-if-all-absent", k, err)
		}
		if exists {
			return false, nil
		}
	}
	if err := b.eng.Set([]byte(key), value); err != nil {
		return false, mapErr("put-if-all-absent", key, err)
	}
	return true, nil
}

// CompareAndSwap atomically stores newValue at key only if the key exists and
// its current value equals expected exactly, returning the current value when
// it does not swap.
//
// An absent key REFUSES regardless of expected (#186): a swap edits, it does
// not create, so expected == nil is compared like any other value (matching
// only a stored empty value) rather than being read as "require absent". A
// caller that wants to create only when the key is absent calls PutIfAbsent.
//
// It shares writeMu with PutIfAbsent so the get-compare-set is
// linearizable for this single-writer, process-local engine — the same genuine
// (not best-effort) guarantee PutIfAbsent gives. A clustered Backend implements
// CompareAndSwap via a consensus compare-and-swap instead (see
// pkg/storage/qrdb).
func (b *engineBackend) CompareAndSwap(_ context.Context, key string, expected, newValue []byte) (bool, []byte, error) {
	b.writeMu.Lock()
	defer b.writeMu.Unlock()

	exists, err := b.eng.Exists([]byte(key))
	if err != nil {
		return false, nil, mapErr("compare-and-swap", key, err)
	}

	var current []byte
	if exists {
		current, err = b.eng.Get([]byte(key))
		if err != nil {
			return false, nil, mapErr("compare-and-swap", key, err)
		}
	}

	// Require the key to exist AND its value to equal expected exactly. Absence
	// is checked unconditionally, before the byte comparison, so a nil expected
	// can never match an absent key even though bytes.Equal(nil, nil) would
	// otherwise say it does.
	if !exists || !bytes.Equal(current, expected) {
		return false, current, nil
	}

	if err := b.eng.Set([]byte(key), newValue); err != nil {
		return false, nil, mapErr("compare-and-swap", key, err)
	}
	return true, nil, nil
}

// CompareAndDelete atomically removes key only when its stored value still
// equals expected, reporting deleted=false (with a nil error) when the key was
// absent or held a different value.
//
// It shares writeMu with PutIfAbsent and CompareAndSwap so the
// get-compare-delete is linearizable for this single-writer, process-local
// engine — the same genuine (not best-effort) guarantee those two give. Sharing
// the one mutex is what makes the guarantee hold against them and not merely
// against other CompareAndDelete callers: a release must not interleave with
// the acquire it is racing.
//
// Unlike Delete, an absent key is NOT ErrNotFound here. The guarded delete
// reports refusal through deleted=false, and a caller that lost the guard
// cannot tell — and does not need to tell — "already released" from "never
// present".
func (b *engineBackend) CompareAndDelete(_ context.Context, key string, expected []byte) (bool, error) {
	b.writeMu.Lock()
	defer b.writeMu.Unlock()

	// Exists before Get, as CompareAndSwap does: the engine reports both an
	// absent key and a stored empty value as (nil, nil) from Get, and those are
	// different answers here — an absent key refuses, a stored empty value
	// matches a nil/empty expected.
	exists, err := b.eng.Exists([]byte(key))
	if err != nil {
		// A failed guard READ must refuse rather than decide: treating a read
		// fault as "the value differs" would silently skip a delete the caller
		// is entitled to, so the outcome is reported as unknown instead.
		return false, mapErr("compare-and-delete", key, err)
	}
	if !exists {
		return false, nil
	}
	current, err := b.eng.Get([]byte(key))
	if err != nil {
		return false, mapErr("compare-and-delete", key, err)
	}
	if !bytes.Equal(current, expected) {
		return false, nil
	}
	if err := b.eng.Delete([]byte(key)); err != nil {
		return false, mapErr("compare-and-delete", key, err)
	}
	return true, nil
}

// Delete removes key. The go-qrdb engine deletes idempotently (no error on a
// missing key), so Delete checks existence first to preserve the Backend
// contract of returning ErrNotFound for an absent key.
//
// It takes writeMu for two reasons: its own Exists-then-Delete is a
// read-then-write that would otherwise report ErrNotFound for a key a
// concurrent Put had just created, and an unguarded delete slipping into a
// guarded verb's read-then-write would defeat that verb's guard. See writeMu.
func (b *engineBackend) Delete(_ context.Context, key string) error {
	b.writeMu.Lock()
	defer b.writeMu.Unlock()

	exists, err := b.eng.Exists([]byte(key))
	if err != nil {
		return mapErr("delete", key, err)
	}
	if !exists {
		return ErrNotFound
	}
	if err := b.eng.Delete([]byte(key)); err != nil {
		return mapErr("delete", key, err)
	}
	return nil
}

// List returns all keys carrying the given prefix in sorted order. An empty
// prefix returns every key.
func (b *engineBackend) List(_ context.Context, prefix string) ([]string, error) {
	raw, err := b.eng.List([]byte(prefix))
	if err != nil {
		return nil, mapErr("list", prefix, err)
	}
	keys := make([]string, len(raw))
	for i, k := range raw {
		keys[i] = string(k)
	}
	sort.Strings(keys)
	return keys, nil
}

// Scan visits every key-value pair whose key carries prefix, in sorted key
// order, invoking fn for each. A non-nil error from fn stops iteration and is
// returned to the caller.
func (b *engineBackend) Scan(ctx context.Context, prefix string, fn func(key string, value []byte) error) error {
	keys, err := b.List(ctx, prefix)
	if err != nil {
		return err
	}
	for _, key := range keys {
		value, err := b.eng.Get([]byte(key))
		if err != nil {
			return mapErr("scan", key, err)
		}
		if value == nil {
			// Key was deleted between List and Get; skip it.
			continue
		}
		if err := fn(key, value); err != nil {
			return err
		}
	}
	return nil
}

// Exists reports whether key is present in storage.
func (b *engineBackend) Exists(_ context.Context, key string) (bool, error) {
	exists, err := b.eng.Exists([]byte(key))
	if err != nil {
		return false, mapErr("exists", key, err)
	}
	return exists, nil
}

// Close releases the resources held by the underlying engine.
func (b *engineBackend) Close() error {
	if err := b.eng.Close(); err != nil {
		return mapErr("close", "", err)
	}
	return nil
}

// EngineKind identifies which go-qrdb storage engine backs a Backend.
type EngineKind string

const (
	// EngineFile selects the go-qrdb file engine: one owner-only file per key,
	// named by the SHA-256 of the key in hashed shard directories under <path>.
	// It is the default. The engine refuses a non-empty <path> it did not
	// initialise.
	EngineFile EngineKind = "file"

	// EnginePebble selects the go-qrdb PebbleDB engine: an embedded LSM-tree
	// store contained in a single database directory at <path>.
	EnginePebble EngineKind = "pebble"

	// EngineMemory selects the go-qrdb in-memory engine: non-durable, intended
	// for tests and ephemeral use.
	EngineMemory EngineKind = "memory"

	// EngineObjstore selects the go-qrdb object-storage engine, backed by a
	// go-objstore provider (Config.Provider + Config.Options). "local" and
	// "memory" providers are always available; cloud providers (s3, gcs, azure,
	// …) require go-objstore's matching build tag. This lets the same DAOs
	// persist to cloud object storage exactly as they do to file/pebble.
	EngineObjstore EngineKind = "objstore"
)

// EngineConfig selects and configures a storage engine for OpenEngine.
type EngineConfig struct {
	// Kind selects the engine. An empty Kind defaults to EngineFile.
	Kind EngineKind

	// Path is the filesystem location for the file and pebble engines. It is
	// required by those engines and ignored by the memory engine.
	Path string

	// Provider names the object-storage provider when Kind is EngineObjstore
	// ("local", "memory", "s3", "gcs", …). Defaults to "local" when empty.
	Provider string

	// Options carries provider-specific settings for EngineObjstore, passed
	// verbatim to go-objstore (e.g. "path" for local, bucket/region/credentials
	// for cloud providers).
	Options map[string]string
}

// OpenEngine constructs a Backend backed by the go-qrdb storage engine selected
// by cfg. It is the single configuration-driven entry point for local xkms
// persistence: callers flip cfg.Kind — "file", "pebble", or "memory" — to
// change the underlying engine without any other code change. The file and
// pebble engines persist under cfg.Path; the memory engine is ephemeral. All
// engines are reached only through go-qrdb's SDK, never its internal packages.
func OpenEngine(cfg EngineConfig) (Backend, error) {
	switch cfg.Kind {
	case EngineFile, "":
		if cfg.Path == "" {
			return nil, ErrEnginePathRequired
		}
		eng, err := qrdbstorage.NewFileStorage(cfg.Path)
		if err != nil {
			return nil, &EngineError{Op: "open-file", Key: cfg.Path, Err: err}
		}
		return NewEngineBackend(eng), nil

	case EnginePebble:
		if cfg.Path == "" {
			return nil, ErrEnginePathRequired
		}
		eng, err := qrdbstorage.NewPebbleStorage(qrdbstorage.DefaultPebbleConfig(cfg.Path))
		if err != nil {
			return nil, &EngineError{Op: "open-pebble", Key: cfg.Path, Err: err}
		}
		return NewEngineBackend(eng), nil

	case EngineMemory:
		return NewEngineBackend(qrdbstorage.NewMemoryStorage()), nil

	case EngineObjstore:
		provider := cfg.Provider
		if provider == "" {
			provider = "local"
		}
		eng, err := qrdbstorage.NewObjStoreStorage(provider, cfg.Options)
		if err != nil {
			return nil, &EngineError{Op: "open-objstore", Key: provider, Err: err}
		}
		return NewEngineBackend(eng), nil

	default:
		return nil, &errs.Detail{Err: ErrUnknownEngine, Detail: fmt.Sprintf("%q", cfg.Kind)}
	}
}

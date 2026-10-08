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

package xkms

import (
	"github.com/jeremyhahn/go-xkms/pkg/dao"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/storage/kvadapter"
	"github.com/jeremyhahn/go-xkms/pkg/storage/pinadapter"
)

// Storage engine-selector surface re-exported so SDK consumers construct and
// select persistence engines without importing go-xkms/pkg/storage directly.
// The Backend interface is aliased as StorageBackend, the in-memory constructor
// as NewStorageMemory, and the not-found sentinel as ErrStorageNotFound, all in
// storage.go; the symbols below add the pluggable engine selector and the
// prefixed backend.

// StorageEngineConfig configures the pluggable storage engine selected by
// StorageOpenEngine.
type StorageEngineConfig = storage.EngineConfig

// StorageEngineKind identifies a persistence engine implementation.
type StorageEngineKind = storage.EngineKind

// StorageEngineFile selects the file-backed persistence engine.
const StorageEngineFile = storage.EngineFile

// NewStoragePrefixBackend wraps an existing backend so every key is namespaced
// by the given prefix.
var NewStoragePrefixBackend = storage.NewPrefixBackend

// StorageOpenEngine opens the persistence engine described by cfg.
var StorageOpenEngine = storage.OpenEngine

// NewKVStoreAdapter adapts a storage.Backend to the go-qrdb KVStore interface.
var NewKVStoreAdapter = kvadapter.New

// NewStoreDAOFactory returns a DAO factory that serves one KVStore for the
// default database and every named one: the factory a host without a go-qrdb
// node injects into features such as the OIDC token store.
var NewStoreDAOFactory = dao.NewStoreFactory

// ErrIndexingNotSupported is reported by every secondary-index operation on a
// KVStoreAdapter. The adapter cannot maintain an index: doing so requires
// decoding each entity payload to read the indexed fields, and the encoding is
// chosen by the DAO (JSON, CBOR, MsgPack) and never communicated to the store.
//
// It is an error rather than an empty result so a caller can never mistake
// "this store cannot answer index queries" for "the index matched nothing".
// Callers that can degrade gracefully detect it with errors.Is and fall back to
// a scan:
//
//	entities, err := dao.QueryByIndex(ctx, "RPID", rpID)
//	if errors.Is(err, xkms.ErrIndexingNotSupported) {
//	        return scanFallback(rpID)
//	}
//
// It is re-exported here because consumers outside this module reach xkms only
// through the SDK and must be able to recognize the sentinel.
//
// The same refusal ALSO matches go-qrdb's index-capability sentinel
// (kvstore.ErrIndexUnsupported, re-exported by the go-qrdb SDK as
// ErrKVIndexUnsupported). That is what allows a go-qrdb DAO to be constructed
// over a KVStoreAdapter at all: since go-qrdb v0.8.0-alpha, pkg/dao registers
// indexes at construction and reads the reply as a capability negotiation --
// a match means "no index subsystem, plan full scans", anything else aborts
// construction. So a consumer may test for either sentinel, and neither may be
// dropped from the match. See kvadapter.IndexingNotSupportedError.Is.
var ErrIndexingNotSupported = kvadapter.ErrIndexingNotSupported

// NewPINStoreAdapter adapts a storage.Backend to the PIN-store interface.
var NewPINStoreAdapter = pinadapter.New

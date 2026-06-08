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

// NewPINStoreAdapter adapts a storage.Backend to the PIN-store interface.
var NewPINStoreAdapter = pinadapter.New

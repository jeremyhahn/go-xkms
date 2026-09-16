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

import "github.com/jeremyhahn/go-xkms/pkg/sealblobstore"

// Sealed-blob store surface re-exported so SDK consumers persist sealed data
// blobs without importing go-xkms/pkg/sealblobstore directly. The Store type
// is aliased as SealedBlobStore, the Entity as SealedBlobEntity, and the
// constructor as NewSealedBlobStore. Backing storage is supplied as a
// github.com/jeremyhahn/go-qrdb/sdk/go KVStore (see NewKVStoreAdapter);
// go-xkms does not re-export the qrdb database surface.

// SealedBlobStore persists sealed data blobs through a go-qrdb GenericDAO
// keyed by a deterministic ID derived from each blob label.
type SealedBlobStore = sealblobstore.Store

// SealedBlobEntity is the DAO entity representation of a sealed data blob.
type SealedBlobEntity = sealblobstore.Entity

// SealedBlobCreationError is returned when the DAO layer fails to initialize.
type SealedBlobCreationError = sealblobstore.ErrCreation

// NewSealedBlobStore creates a SealedBlobStore backed by the given KVStore.
var NewSealedBlobStore = sealblobstore.NewStore

// Sealed-blob store error sentinels.
var (
	// ErrSealedBlobNilKVStore is returned when a nil kvstore is provided.
	ErrSealedBlobNilKVStore = sealblobstore.ErrNilKVStore

	// ErrSealedBlobStoreClosed is returned when operations are attempted on a
	// closed store.
	ErrSealedBlobStoreClosed = sealblobstore.ErrStoreClosed

	// ErrSealedBlobNotFound is returned when a sealed blob is not found.
	ErrSealedBlobNotFound = sealblobstore.ErrNotFound

	// ErrSealedBlobInvalidLabel is returned when the label is empty.
	ErrSealedBlobInvalidLabel = sealblobstore.ErrInvalidLabel

	// ErrSealedBlobNilEntity is returned when a nil entity is provided.
	ErrSealedBlobNilEntity = sealblobstore.ErrNilEntity
)

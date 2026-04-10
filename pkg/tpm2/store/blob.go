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

package store

import (
	"context"
	"log/slog"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/storage/kvadapter"
)

const blobEntityType = "blobs"

// BlobEntry is the DAO entity for binary blob storage. Each blob is
// identified by a human-readable Name, which is hashed via
// FieldHashGenerator to produce a deterministic uint64 ID.
type BlobEntry struct {
	ID   uint64 `json:"id"`
	Name string `json:"name"`
	Data []byte `json:"data"`
}

// EntityID returns the unique identifier for this blob entry.
func (b *BlobEntry) EntityID() uint64 { return b.ID }

// SetEntityID sets the blob entry's unique identifier.
func (b *BlobEntry) SetEntityID(id uint64) { b.ID = id }

// FSBlobStore implements BlobStorer using go-qrdb's DAO layer for typed
// entity persistence. Blob names are hashed via FieldHashGenerator to
// produce deterministic IDs, enabling name-based lookup without secondary
// indexes.
//
// For convenience, use NewStorageFactory to create a complete storage setup.
type FSBlobStore struct {
	logger *slog.Logger
	dao    qrdbsdk.GenericDAO[*BlobEntry]
}

// NewFSBlobStore creates a new blob store backed by the given storage.Backend.
// The storage.Backend is adapted to kvstore.KVStore via kvadapter, then
// wrapped with a DAO using FieldHashGenerator("Name") for deterministic
// blob ID generation.
//
// For convenience, use NewStorageFactory to create a complete storage setup.
func NewFSBlobStore(logger *slog.Logger, backend storage.Backend) (BlobStorer, error) {
	kvStore, err := kvadapter.New(backend)
	if err != nil {
		return nil, &BlobStoreCreateError{Cause: err}
	}

	blobDAO, err := qrdbsdk.NewDAO[*BlobEntry](
		kvStore,
		blobEntityType,
		func() *BlobEntry { return &BlobEntry{} },
		qrdbsdk.WithIDGenerator(qrdbsdk.NewFieldHashGenerator("Name")),
	)
	if err != nil {
		return nil, &BlobStoreCreateError{Cause: err}
	}

	return &FSBlobStore{
		logger: logger,
		dao:    blobDAO,
	}, nil
}

// Read retrieves a blob by name. Returns an error if the blob does not exist.
func (b *FSBlobStore) Read(name string) ([]byte, error) {
	id := hashBlobName(name)
	entry, err := b.dao.Get(context.Background(), id)
	if err != nil {
		return nil, &BlobReadError{Name: name, Cause: err}
	}
	return entry.Data, nil
}

// Write stores a blob by name. If a blob with the same name already exists,
// it is overwritten.
func (b *FSBlobStore) Write(name string, data []byte) error {
	entry := &BlobEntry{
		Name: name,
		Data: data,
	}
	if err := b.dao.Save(context.Background(), entry); err != nil {
		return &BlobWriteError{Name: name, Cause: err}
	}
	return nil
}

// Delete removes a blob by name. Deleting a non-existent blob is a no-op.
func (b *FSBlobStore) Delete(name string) error {
	id := hashBlobName(name)
	entry := &BlobEntry{ID: id, Name: name}
	if err := b.dao.Delete(context.Background(), entry); err != nil {
		return &BlobDeleteError{Name: name, Cause: err}
	}
	return nil
}

// hashBlobName produces a deterministic uint64 ID from a blob name using
// the same FNV-1a algorithm as FieldHashGenerator("Name"). This allows
// direct lookup by name without scanning.
func hashBlobName(name string) uint64 {
	entry := &BlobEntry{Name: name}
	gen := qrdbsdk.NewFieldHashGenerator("Name")
	return gen.NextID(entry)
}

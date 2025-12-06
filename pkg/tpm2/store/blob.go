// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package store

import (
	"fmt"

	"github.com/jeremyhahn/go-keychain/pkg/storage"
)

// FSBlobStore implements BlobStorer using storage.Backend.
// For convenience, use NewStorageFactory to create a complete storage setup.
type FSBlobStore struct {
	logger  Logger
	storage storage.Backend
}

// NewFSBlobStore creates a new blob store using the storage.Backend interface.
// For convenience, use NewStorageFactory to create a complete storage setup.
func NewFSBlobStore(logger Logger, backend storage.Backend) BlobStorer {
	return &FSBlobStore{
		logger:  logger,
		storage: backend,
	}
}

// Read reads a blob from storage
func (b *FSBlobStore) Read(name string) ([]byte, error) {
	data, err := b.storage.Get(name)
	if err != nil {
		return nil, fmt.Errorf("failed to read blob %s: %w", name, err)
	}
	return data, nil
}

// Write writes a blob to storage
func (b *FSBlobStore) Write(name string, data []byte) error {
	if err := b.storage.Put(name, data, storage.DefaultOptions()); err != nil {
		return fmt.Errorf("failed to write blob %s: %w", name, err)
	}
	return nil
}

// Delete deletes a blob from storage
func (b *FSBlobStore) Delete(name string) error {
	if err := b.storage.Delete(name); err != nil {
		if err != storage.ErrNotFound {
			return fmt.Errorf("failed to delete blob %s: %w", name, err)
		}
	}
	return nil
}

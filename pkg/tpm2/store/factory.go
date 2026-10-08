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
	"log/slog"
	"os"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/storage/file"
)

// StorageFactory provides a convenient way to create storage backends
// for TPM operations. It manages the lifecycle of the underlying storage
// and provides both blob storage and key backend capabilities.
type StorageFactory struct {
	logger    *slog.Logger
	backend   storage.Backend
	blobStore BlobStorer
	keyStore  KeyBackend
	tempDir   string
}

// NewStorageFactory creates a new storage factory backed by a private,
// file-based engine rooted at baseDir. If baseDir is empty, a temporary
// directory is created and removed on Close. This constructor is for direct
// file/test use (see doc comment on StorageFactory); a caller composing
// through the shared datastore (pkg/compose.FactoryBackend over its DAO
// factory, or any other storage.Backend -- e.g. pkg/server's createStorage view) uses NewFactory
// instead, so TPM key blobs are never a second, private storage engine.
func NewStorageFactory(logger *slog.Logger, baseDir string) (*StorageFactory, error) {
	var tempDir string

	if baseDir == "" {
		// Create a temporary directory for testing
		dir, err := os.MkdirTemp("", "tpm-store-*")
		if err != nil {
			return nil, err
		}
		tempDir = dir
		baseDir = tempDir
	}

	// Use file-based storage
	backend, err := file.New(baseDir)
	if err != nil {
		if tempDir != "" {
			if rmErr := os.RemoveAll(tempDir); rmErr != nil {
				logger.Error("failed to remove temp directory",
					slog.String("path", tempDir),
					slog.String("error", rmErr.Error()))
			}
		}
		return nil, err
	}

	factory, err := NewFactory(logger, backend)
	if err != nil {
		if closeErr := backend.Close(); closeErr != nil {
			logger.Error("failed to close backend",
				slog.String("error", closeErr.Error()))
		}
		if tempDir != "" {
			if rmErr := os.RemoveAll(tempDir); rmErr != nil {
				logger.Error("failed to remove temp directory",
					slog.String("path", tempDir),
					slog.String("error", rmErr.Error()))
			}
		}
		return nil, err
	}
	factory.tempDir = tempDir
	return factory, nil
}

// NewMemoryStorageFactory creates a storage factory using in-memory storage.
// This is useful for testing where persistence is not required.
func NewMemoryStorageFactory(logger *slog.Logger) (*StorageFactory, error) {
	return NewFactory(logger, storage.NewMemory())
}

// NewFactory creates a storage factory over an already-open storage.Backend
// -- e.g. a key-prefixed view of the shared datastore
// (pkg/compose.FactoryBackend, or pkg/server's createStorage) -- rather than opening a private file or
// memory engine. This is the constructor datastore-backed callers use;
// NewStorageFactory/NewMemoryStorageFactory remain for direct file/in-memory
// use (tests, standalone tooling) and are implemented in terms of this one.
func NewFactory(logger *slog.Logger, backend storage.Backend) (*StorageFactory, error) {
	blobStore, err := NewFSBlobStore(logger, backend)
	if err != nil {
		return nil, err
	}

	return &StorageFactory{
		logger:    logger,
		backend:   backend,
		blobStore: blobStore,
		keyStore:  NewFileBackend(logger, backend),
	}, nil
}

// BlobStore returns the blob storage interface
func (f *StorageFactory) BlobStore() BlobStorer {
	return f.blobStore
}

// KeyBackend returns the key backend interface
func (f *StorageFactory) KeyBackend() KeyBackend {
	return f.keyStore
}

// Backend returns the underlying storage backend
func (f *StorageFactory) Backend() storage.Backend {
	return f.backend
}

// Close releases resources held by the factory
func (f *StorageFactory) Close() error {
	var err error
	if f.backend != nil {
		err = f.backend.Close()
	}
	if f.tempDir != "" {
		if rmErr := os.RemoveAll(f.tempDir); rmErr != nil {
			f.logger.Error("failed to remove temp directory",
				slog.String("path", f.tempDir),
				slog.String("error", rmErr.Error()))
		}
	}
	return err
}

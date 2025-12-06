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
	"os"

	"github.com/jeremyhahn/go-keychain/pkg/storage"
	"github.com/jeremyhahn/go-keychain/pkg/storage/file"
)

// StorageFactory provides a convenient way to create storage backends
// for TPM operations. It manages the lifecycle of the underlying storage
// and provides both blob storage and key backend capabilities.
type StorageFactory struct {
	logger    Logger
	backend   storage.Backend
	blobStore BlobStorer
	keyStore  KeyBackend
	tempDir   string
}

// NewStorageFactory creates a new storage factory. If baseDir is empty,
// a temporary directory is created. The factory uses the local storage
// package implementations (file or memory based).
func NewStorageFactory(logger Logger, baseDir string) (*StorageFactory, error) {
	var backend storage.Backend
	var err error
	var tempDir string

	if baseDir == "" {
		// Create a temporary directory for testing
		tempDir, err = os.MkdirTemp("", "tpm-store-*")
		if err != nil {
			return nil, err
		}
		baseDir = tempDir
	}

	// Use file-based storage
	backend, err = file.New(baseDir)
	if err != nil {
		if tempDir != "" {
			_ = os.RemoveAll(tempDir)
		}
		return nil, err
	}

	return &StorageFactory{
		logger:    logger,
		backend:   backend,
		blobStore: NewFSBlobStore(logger, backend),
		keyStore:  NewFileBackend(logger, backend),
		tempDir:   tempDir,
	}, nil
}

// NewMemoryStorageFactory creates a storage factory using in-memory storage.
// This is useful for testing where persistence is not required.
func NewMemoryStorageFactory(logger Logger) (*StorageFactory, error) {
	backend := storage.NewMemory()

	return &StorageFactory{
		logger:    logger,
		backend:   backend,
		blobStore: NewFSBlobStore(logger, backend),
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
		_ = os.RemoveAll(f.tempDir)
	}
	return err
}

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
	"io"
	"log/slog"
	"os"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/dao"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/storage/file"
	"github.com/jeremyhahn/go-xkms/pkg/storage/kvadapter"
)

// StorageFactory opens a BlobStore for a host with no go-qrdb datastore to
// inject one from: a directory of its own, or memory. A host that has a
// datastore builds its BlobStore with NewBlobStore over the datastore's DAO
// factory instead.
type StorageFactory struct {
	logger  *slog.Logger
	closer  io.Closer
	blobs   *BlobStore
	tempDir string
}

// NewStorageFactory opens the BlobStore kept in dir. If dir is empty, a
// temporary directory is created and removed on Close.
func NewStorageFactory(logger *slog.Logger, dir string) (*StorageFactory, error) {
	if logger == nil {
		logger = slog.Default()
	}
	var tempDir string
	if dir == "" {
		temp, err := os.MkdirTemp("", "tpm-store-*")
		if err != nil {
			return nil, &BlobStoreCreateError{Cause: err}
		}
		tempDir = temp
		dir = temp
	}
	factory, err := openDirFactory(logger, dir)
	if err != nil {
		removeTempDir(logger, tempDir)
		return nil, err
	}
	factory.tempDir = tempDir
	return factory, nil
}

// openDirFactory opens the BlobStore kept in dir.
func openDirFactory(logger *slog.Logger, dir string) (*StorageFactory, error) {
	backend, err := file.New(dir)
	if err != nil {
		return nil, &BlobStoreCreateError{Cause: err}
	}
	blobs, err := NewBackendBlobStore(logger, backend)
	if err != nil {
		if closeErr := backend.Close(); closeErr != nil {
			logger.Error("failed to close blob store directory", slog.String("error", closeErr.Error()))
		}
		return nil, err
	}
	return &StorageFactory{logger: logger, closer: backend, blobs: blobs}, nil
}

// NewBackendBlobStore returns the system tenant's BlobStore over backend, for
// a host whose datastore is a storage.Backend rather than a DAO factory (an
// xkms.AutoConfig.Datastore). The blobs are TPMBlob entities in the backend;
// it must support guarded writes.
func NewBackendBlobStore(logger *slog.Logger, backend storage.Backend) (*BlobStore, error) {
	kv, err := kvadapter.New(backend)
	if err != nil {
		return nil, &BlobStoreCreateError{Cause: err}
	}
	return NewBlobStore(logger, dao.NewStoreFactory(kv))
}

// NewMemoryStorageFactory returns a factory whose BlobStore lives in memory,
// for callers that need no persistence.
func NewMemoryStorageFactory(logger *slog.Logger) (*StorageFactory, error) {
	blobs, err := NewBlobStore(logger, dao.NewStoreFactory(qrdbsdk.NewMemoryKVStore()))
	if err != nil {
		return nil, err
	}
	return &StorageFactory{logger: blobs.logger, blobs: blobs}, nil
}

// KeyBackend returns the system tenant's BlobStore.
func (f *StorageFactory) KeyBackend() *BlobStore {
	return f.blobs
}

// Close releases the store and removes its temporary directory, if any.
func (f *StorageFactory) Close() error {
	var err error
	if f.closer != nil {
		err = f.closer.Close()
	}
	removeTempDir(f.logger, f.tempDir)
	return err
}

// removeTempDir removes dir when it is set, logging a failure.
func removeTempDir(logger *slog.Logger, dir string) {
	if dir == "" {
		return
	}
	if err := os.RemoveAll(dir); err != nil {
		logger.Error("failed to remove temp directory",
			slog.String("path", dir),
			slog.String("error", err.Error()))
	}
}

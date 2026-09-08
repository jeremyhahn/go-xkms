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
	"errors"
	"fmt"
	"log/slog"
	"os"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// FileBackend implements KeyBackend using storage.Backend.
// For convenience, use NewStorageFactory to create a complete storage setup.
type FileBackend struct {
	logger  *slog.Logger
	storage storage.Backend
}

// NewFileBackend creates a new file-based key backend using the storage.Backend interface.
// For convenience, use NewStorageFactory to create a complete storage setup.
func NewFileBackend(logger *slog.Logger, backend storage.Backend) KeyBackend {
	return &FileBackend{
		logger:  logger,
		storage: backend,
	}
}

// storageKey composes the storage key for a key's artifact: the Common Name
// plus the artifact's extension. It refuses an empty CN, because "" + ext is
// a valid-looking key that every nameless key would share.
func storageKey(attrs *types.KeyAttributes, ext string) (string, error) {
	if attrs == nil || attrs.CN == "" {
		return "", ErrEmptyKeyCN
	}
	return attrs.CN + ext, nil
}

// Get retrieves key data from storage
func (fb *FileBackend) Get(attrs *types.KeyAttributes, ext types.FSExtension) ([]byte, error) {
	key, err := storageKey(attrs, string(ext))
	if err != nil {
		return nil, err
	}
	data, err := fb.storage.Get(context.Background(), key)
	if err != nil {
		return nil, &errs.Wrapped{Msg: fmt.Sprintf("failed to read key %s", key), Err: err}
	}
	return data, nil
}

// Save writes key data to storage
func (fb *FileBackend) Save(attrs *types.KeyAttributes, data []byte, ext types.FSExtension, overwrite bool) error {
	key, err := storageKey(attrs, string(ext))
	if err != nil {
		return err
	}

	// Check if key exists when overwrite is false
	if !overwrite {
		exists, err := fb.storage.Exists(context.Background(), key)
		if err != nil {
			return &errs.Wrapped{Msg: fmt.Sprintf("failed to check key existence %s", key), Err: err}
		}
		if exists {
			return &errs.Message{Msg: fmt.Sprintf("key already exists: %s", key)}
		}
	}

	// Write to storage
	if err := fb.storage.Put(context.Background(), key, data); err != nil {
		return &errs.Wrapped{Msg: fmt.Sprintf("failed to write key %s", key), Err: err}
	}

	return nil
}

// Delete removes key files from storage
func (fb *FileBackend) Delete(attrs *types.KeyAttributes) error {
	// Delete all possible extensions for this key
	extensions := []string{
		FSEXT_PRIVATE_BLOB,
		FSEXT_PUBLIC_BLOB,
		FSEXT_TPM_CONTEXT,
		FSEXT_PLATFORM_POLICY,
	}

	var lastErr error
	for _, ext := range extensions {
		key, err := storageKey(attrs, ext)
		if err != nil {
			return err
		}
		if err := fb.storage.Delete(context.Background(), key); err != nil {
			// Ignore "not found" errors - the file may not exist
			// Check for both storage.ErrNotFound and OS-level not found errors
			if !errors.Is(err, storage.ErrNotFound) && !os.IsNotExist(err) {
				lastErr = err
				if fb.logger != nil {
					fb.logger.Warn("failed to delete key file",
						slog.String("key", key),
						slog.String("error", err.Error()))
				}
			}
		}
	}

	return lastErr
}

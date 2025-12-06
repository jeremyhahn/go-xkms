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
	"errors"
	"fmt"
	"os"

	"github.com/jeremyhahn/go-keychain/pkg/storage"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// FileBackend implements KeyBackend using storage.Backend.
// For convenience, use NewStorageFactory to create a complete storage setup.
type FileBackend struct {
	logger  Logger
	storage storage.Backend
}

// NewFileBackend creates a new file-based key backend using the storage.Backend interface.
// For convenience, use NewStorageFactory to create a complete storage setup.
func NewFileBackend(logger Logger, backend storage.Backend) KeyBackend {
	return &FileBackend{
		logger:  logger,
		storage: backend,
	}
}

// Get retrieves key data from storage
func (fb *FileBackend) Get(attrs *types.KeyAttributes, ext types.FSExtension) ([]byte, error) {
	key := attrs.CN + string(ext)
	data, err := fb.storage.Get(key)
	if err != nil {
		return nil, fmt.Errorf("failed to read key %s: %w", key, err)
	}
	return data, nil
}

// Save writes key data to storage
func (fb *FileBackend) Save(attrs *types.KeyAttributes, data []byte, ext types.FSExtension, overwrite bool) error {
	key := attrs.CN + string(ext)

	// Check if key exists when overwrite is false
	if !overwrite {
		exists, err := fb.storage.Exists(key)
		if err != nil {
			return fmt.Errorf("failed to check key existence %s: %w", key, err)
		}
		if exists {
			return fmt.Errorf("key already exists: %s", key)
		}
	}

	// Write to storage
	if err := fb.storage.Put(key, data, storage.DefaultOptions()); err != nil {
		return fmt.Errorf("failed to write key %s: %w", key, err)
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
	}

	var lastErr error
	for _, ext := range extensions {
		key := attrs.CN + ext
		if err := fb.storage.Delete(key); err != nil {
			// Ignore "not found" errors - the file may not exist
			// Check for both storage.ErrNotFound and OS-level not found errors
			if !errors.Is(err, storage.ErrNotFound) && !os.IsNotExist(err) {
				lastErr = err
				if fb.logger != nil {
					fb.logger.Warnf("failed to delete %s: %v", key, err)
				}
			}
		}
	}

	return lastErr
}

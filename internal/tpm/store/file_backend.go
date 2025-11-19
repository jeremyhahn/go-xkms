// Package store provides file backend implementations
package store

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/jeremyhahn/go-keychain/internal/tpm/logging"
	"github.com/jeremyhahn/go-keychain/pkg/types"
	"github.com/spf13/afero"
)

// FileBackend implements KeyBackend for file-based storage
type FileBackend struct {
	logger *logging.Logger
	fs     afero.Fs
	dir    string
}

// NewFileBackend creates a new file-based key backend
func NewFileBackend(logger *logging.Logger, fs afero.Fs, dir string) KeyBackend {
	return &FileBackend{
		logger: logger,
		fs:     fs,
		dir:    dir,
	}
}

// Get retrieves key data from the filesystem
func (fb *FileBackend) Get(attrs *types.KeyAttributes, ext string) ([]byte, error) {
	filename := filepath.Join(fb.dir, attrs.CN+ext)
	data, err := afero.ReadFile(fb.fs, filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file %s: %w", filename, err)
	}
	return data, nil
}

// Save writes key data to the filesystem
func (fb *FileBackend) Save(attrs *types.KeyAttributes, data []byte, ext string, overwrite bool) error {
	filename := filepath.Join(fb.dir, attrs.CN+ext)

	// Check if file exists when overwrite is false
	if !overwrite {
		exists, err := afero.Exists(fb.fs, filename)
		if err != nil {
			return fmt.Errorf("failed to check file existence %s: %w", filename, err)
		}
		if exists {
			return fmt.Errorf("file already exists: %s", filename)
		}
	}

	// Ensure directory exists
	dir := filepath.Dir(filename)
	if err := fb.fs.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}

	// Write file
	if err := afero.WriteFile(fb.fs, filename, data, 0600); err != nil {
		return fmt.Errorf("failed to write key file %s: %w", filename, err)
	}

	return nil
}

// Delete removes key files from the filesystem
func (fb *FileBackend) Delete(attrs *types.KeyAttributes) error {
	// Delete all possible extensions for this key
	extensions := []string{
		FSEXT_PRIVATE_BLOB,
		FSEXT_PUBLIC_BLOB,
		FSEXT_TPM_CONTEXT,
	}

	var lastErr error
	for _, ext := range extensions {
		filename := filepath.Join(fb.dir, attrs.CN+ext)
		if err := fb.fs.Remove(filename); err != nil && !os.IsNotExist(err) {
			lastErr = err
			fb.logger.Warnf("failed to delete %s: %v", filename, err)
		}
	}

	return lastErr
}

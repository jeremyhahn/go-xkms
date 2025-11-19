// Package store provides blob storage implementations
package store

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/jeremyhahn/go-keychain/internal/tpm/logging"
	"github.com/spf13/afero"
)

// FSBlobStore implements BlobStorer using the filesystem
type FSBlobStore struct {
	logger *logging.Logger
	fs     afero.Fs
	dir    string
}

// NewFSBlobStore creates a new filesystem-based blob store
func NewFSBlobStore(logger *logging.Logger, fs afero.Fs, dir string, encryption interface{}) (BlobStorer, error) {
	// Create directory if it doesn't exist
	if err := fs.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create blob store directory: %w", err)
	}

	return &FSBlobStore{
		logger: logger,
		fs:     fs,
		dir:    dir,
	}, nil
}

// Read reads a blob from the filesystem
func (b *FSBlobStore) Read(name string) ([]byte, error) {
	filename := filepath.Join(b.dir, name)
	data, err := afero.ReadFile(b.fs, filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read blob %s: %w", name, err)
	}
	return data, nil
}

// Write writes a blob to the filesystem
func (b *FSBlobStore) Write(name string, data []byte) error {
	filename := filepath.Join(b.dir, name)

	// Ensure directory exists
	dir := filepath.Dir(filename)
	if err := b.fs.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}

	if err := afero.WriteFile(b.fs, filename, data, 0600); err != nil {
		return fmt.Errorf("failed to write blob %s: %w", name, err)
	}

	return nil
}

// Delete deletes a blob from the filesystem
func (b *FSBlobStore) Delete(name string) error {
	filename := filepath.Join(b.dir, name)
	if err := b.fs.Remove(filename); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to delete blob %s: %w", name, err)
	}
	return nil
}

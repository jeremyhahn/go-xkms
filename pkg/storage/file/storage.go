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

// Package file provides a file-based implementation of the storage.Backend interface.
// It uses the os package directly for file operations with RWMutex for thread-safe operations.
package file

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/jeremyhahn/go-keychain/pkg/storage"
)

const (
	// Default directory permissions (owner rwx only)
	defaultDirPerms = 0700

	// File permissions based on key prefix
	keysFilePerms  = 0600 // keys/* = owner rw only
	certsFilePerms = 0644 // certs/* = owner rw, others r
	defaultPerms   = 0600 // default = owner rw only
)

// FileStorage is a file-based implementation of storage.Backend.
// It stores key-value pairs as files in a directory hierarchy and is thread-safe.
type FileStorage struct {
	mu      sync.RWMutex
	rootDir string
}

// New creates a new FileStorage instance with the specified root directory.
// The root directory is created with 0700 permissions if it doesn't exist.
func New(rootDir string) (storage.Backend, error) {
	if rootDir == "" {
		return nil, fmt.Errorf("file storage: root directory cannot be empty")
	}

	// Create root directory if it doesn't exist
	if err := os.MkdirAll(rootDir, defaultDirPerms); err != nil {
		return nil, fmt.Errorf("file storage: failed to create root directory: %w", err)
	}

	return &FileStorage{
		rootDir: rootDir,
	}, nil
}

// Get retrieves the value for the given key.
// Returns storage.ErrNotFound if the key does not exist.
func (f *FileStorage) Get(key string) ([]byte, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	filePath := f.keyToPath(key)

	cleanPath := filepath.Clean(filePath)
	if !filepath.IsAbs(cleanPath) {
		return nil, fmt.Errorf("file path must be absolute: %s", filePath)
	}
	data, err := os.ReadFile(cleanPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, storage.ErrNotFound
		}
		return nil, fmt.Errorf("file storage: failed to read key %q: %w", key, err)
	}

	return data, nil
}

// Put stores the value for the given key with optional metadata.
// If the key already exists, it will be overwritten.
// File permissions are determined by the key prefix:
//   - keys/* = 0600 (owner rw only)
//   - certs/* = 0644 (owner rw, others r)
//   - default = 0600 (owner rw only)
func (f *FileStorage) Put(key string, value []byte, opts *storage.Options) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	filePath := f.keyToPath(key)

	// Create parent directories if they don't exist
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, defaultDirPerms); err != nil {
		return fmt.Errorf("file storage: failed to create directory for key %q: %w", key, err)
	}

	// Determine file permissions based on key prefix or options
	perms := f.getFilePermissions(key, opts)

	// Write the file
	if err := os.WriteFile(filePath, value, perms); err != nil {
		return fmt.Errorf("file storage: failed to write key %q: %w", key, err)
	}

	return nil
}

// Delete removes the key and its value from storage.
// Returns storage.ErrNotFound if the key does not exist.
func (f *FileStorage) Delete(key string) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	filePath := f.keyToPath(key)

	// Check if file exists first
	if _, err := os.Stat(filePath); err != nil {
		if os.IsNotExist(err) {
			return storage.ErrNotFound
		}
		return fmt.Errorf("file storage: failed to stat key %q: %w", key, err)
	}

	// Remove the file
	if err := os.Remove(filePath); err != nil {
		return fmt.Errorf("file storage: failed to delete key %q: %w", key, err)
	}

	return nil
}

// List returns all keys with the given prefix.
// If prefix is empty, all keys are returned.
// Keys are returned in sorted order.
func (f *FileStorage) List(prefix string) ([]string, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	keys := make([]string, 0)

	// Walk the directory tree
	err := filepath.WalkDir(f.rootDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		// Skip directories
		if d.IsDir() {
			return nil
		}

		// Convert file path back to key
		key, err := f.pathToKey(path)
		if err != nil {
			return err
		}

		// Filter by prefix
		if prefix == "" || strings.HasPrefix(key, prefix) {
			keys = append(keys, key)
		}

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("file storage: failed to list keys: %w", err)
	}

	// Sort for consistent ordering
	sort.Strings(keys)
	return keys, nil
}

// Exists checks if a key exists in storage.
func (f *FileStorage) Exists(key string) (bool, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	filePath := f.keyToPath(key)

	_, err := os.Stat(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("file storage: failed to check key %q: %w", key, err)
	}

	return true, nil
}

// Close releases any resources held by the backend.
// For file storage, this is a no-op but provided for interface compliance.
func (f *FileStorage) Close() error {
	return nil
}

// keyToPath converts a storage key to a file path.
// Validates key safety before constructing path.
func (f *FileStorage) keyToPath(key string) string {
	// Validate key safety (allows internal paths like "keys/alice" but blocks traversal)
	if err := validateStorageKey(key); err != nil {
		// Return a safe invalid path that will fail gracefully
		return filepath.Join(f.rootDir, "invalid")
	}
	return filepath.Join(f.rootDir, key)
}

// validateStorageKey validates storage keys (more permissive than facade validation).
// Storage is internal - allows path separators for organization but blocks traversal.
func validateStorageKey(key string) error {
	if key == "" {
		return fmt.Errorf("key cannot be empty")
	}

	// Check for null bytes
	if strings.Contains(key, "\x00") {
		return fmt.Errorf("key contains null byte")
	}

	// Check for absolute paths
	if filepath.IsAbs(key) {
		return fmt.Errorf("key cannot be an absolute path")
	}

	// Check for path traversal - the key is that we don't allow starting with .. or containing /..
	cleaned := filepath.Clean(key)
	if strings.HasPrefix(cleaned, "..") {
		return fmt.Errorf("key contains path traversal attempt")
	}
	// Check for /../ pattern (directory traversal in middle of path)
	if strings.Contains(cleaned, string(filepath.Separator)+".."+string(filepath.Separator)) ||
		strings.HasSuffix(cleaned, string(filepath.Separator)+"..") {
		return fmt.Errorf("key contains path traversal attempt")
	}

	return nil
}

// pathToKey converts a file path to a storage key.
func (f *FileStorage) pathToKey(path string) (string, error) {
	rel, err := filepath.Rel(f.rootDir, path)
	if err != nil {
		return "", fmt.Errorf("file storage: failed to convert path to key: %w", err)
	}
	return rel, nil
}

// getFilePermissions determines the file permissions based on the key prefix.
func (f *FileStorage) getFilePermissions(key string, opts *storage.Options) fs.FileMode {
	// If options specify permissions, use them
	if opts != nil && opts.Permissions != 0 {
		return opts.Permissions
	}

	// Otherwise, use default permissions based on key prefix
	if strings.HasPrefix(key, "keys/") {
		return keysFilePerms
	}
	if strings.HasPrefix(key, "certs/") {
		return certsFilePerms
	}
	return defaultPerms
}

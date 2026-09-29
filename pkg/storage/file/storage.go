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

// Package file provides a file-based implementation of the storage.Backend
// interface. Key/value I/O is delegated to the canonical go-qrdb file engine
// (one flat file per key at <root>/<key>); this package layers three
// xkms-specific behaviors the raw engine does not provide: storage-key
// validation that blocks path traversal, prefix-based file permissions so
// private key material stays owner-only (0600) while public certificates are
// world-readable (0644), and an advisory cross-process lock (lock.go) around
// every write so guarded writes (PutIfAbsent, CompareAndSwap,
// CompareAndDelete) stay atomic when several processes share one store
// directory -- the file-token case the PKCS#11 module's PIN attempt counter
// depends on (#1144, #1157).
package file

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

const (
	// Default directory permissions (owner rwx only)
	defaultDirPerms = 0700

	// File permissions based on key prefix
	keysFilePerms  = 0600 // keys/* = owner rw only
	certsFilePerms = 0644 // certs/* = owner rw, others r
	defaultPerms   = 0600 // default = owner rw only
)

// FileStorage is a file-based implementation of storage.Backend. It wraps the
// go-qrdb file engine for I/O and is safe for concurrent use: within one
// process the wrapped engine serializes access, and every write this type
// performs additionally holds an advisory lock on the store directory (see
// lock.go) that excludes the same operations running against the same
// directory from another process (#1157) -- which is what makes a guarded
// write here safe for several processes sharing one file-backed token.
type FileStorage struct {
	backend  storage.Backend // engine adapter over the go-qrdb file engine
	rootDir  string          // absolute root, used to apply per-file permissions
	lockPath string          // cross-process advisory lock file under rootDir
}

// Compile-time assertion that FileStorage satisfies storage.Backend.
var _ storage.Backend = (*FileStorage)(nil)

// New creates a new FileStorage instance with the specified root directory.
// The root directory is created with 0700 permissions if it doesn't exist.
// Relative paths are converted to absolute paths using the current working directory.
func New(rootDir string) (storage.Backend, error) {
	if rootDir == "" {
		return nil, &errs.Message{Msg: "file storage: root directory cannot be empty"}
	}

	// Convert relative paths to absolute paths
	absRootDir := rootDir
	if !filepath.IsAbs(rootDir) {
		var err error
		absRootDir, err = filepath.Abs(rootDir)
		if err != nil {
			return nil, &errs.Wrapped{Msg: "file storage: failed to get absolute path", Err: err}
		}
	}

	// Create root directory if it doesn't exist
	if err := os.MkdirAll(absRootDir, defaultDirPerms); err != nil {
		return nil, &errs.Wrapped{Msg: "file storage: failed to create root directory", Err: err}
	}

	backend, err := storage.OpenEngine(storage.EngineConfig{Kind: storage.EngineFile, Path: absRootDir})
	if err != nil {
		return nil, &errs.Wrapped{Msg: "file storage: failed to open file engine", Err: err}
	}

	return &FileStorage{
		backend:  backend,
		rootDir:  absRootDir,
		lockPath: filepath.Join(absRootDir, lockFileName),
	}, nil
}

// Get retrieves the value for the given key.
// Returns storage.ErrNotFound if the key does not exist.
func (f *FileStorage) Get(ctx context.Context, key string) ([]byte, error) {
	if err := validateStorageKey(key); err != nil {
		return nil, &errs.Wrapped{Msg: fmt.Sprintf("file storage: invalid key %q", key), Err: err}
	}
	return f.backend.Get(ctx, key)
}

// Put stores the value for the given key, overwriting any existing value.
// File permissions are determined by the key prefix:
//   - keys/* = 0600 (owner rw only)
//   - certs/* = 0644 (owner rw, others r)
//   - default = 0600 (owner rw only)
func (f *FileStorage) Put(ctx context.Context, key string, value []byte) error {
	if err := validateStorageKey(key); err != nil {
		return &errs.Wrapped{Msg: fmt.Sprintf("file storage: invalid key %q", key), Err: err}
	}
	return withCrossProcessLock(ctx, f.lockPath, func() error {
		if err := f.backend.Put(ctx, key, value); err != nil {
			return err
		}
		// The engine writes 0600; widen only the prefixes that require it.
		if perm := filePermissionsForKey(key); perm != defaultPerms {
			if err := os.Chmod(f.keyPath(key), perm); err != nil {
				return &errs.Wrapped{Msg: fmt.Sprintf("file storage: failed to set permissions for key %q", key), Err: err}
			}
		}
		return nil
	})
}

// Delete removes the key and its value from storage.
// Returns storage.ErrNotFound if the key does not exist.
func (f *FileStorage) Delete(ctx context.Context, key string) error {
	if err := validateStorageKey(key); err != nil {
		return &errs.Wrapped{Msg: fmt.Sprintf("file storage: invalid key %q", key), Err: err}
	}
	return withCrossProcessLock(ctx, f.lockPath, func() error {
		return f.backend.Delete(ctx, key)
	})
}

// List returns all keys with the given prefix in sorted order.
// If prefix is empty, all keys are returned.
func (f *FileStorage) List(ctx context.Context, prefix string) ([]string, error) {
	return f.backend.List(ctx, prefix)
}

// Scan iterates over all key-value pairs matching the given prefix,
// calling fn for each pair. If prefix is empty, all pairs are visited.
// Return a non-nil error from fn to stop iteration early.
func (f *FileStorage) Scan(ctx context.Context, prefix string, fn func(key string, value []byte) error) error {
	return f.backend.Scan(ctx, prefix, fn)
}

// Exists checks if a key exists in storage.
func (f *FileStorage) Exists(ctx context.Context, key string) (bool, error) {
	if err := validateStorageKey(key); err != nil {
		return false, &errs.Wrapped{Msg: fmt.Sprintf("file storage: invalid key %q", key), Err: err}
	}
	return f.backend.Exists(ctx, key)
}

// Close releases any resources held by the backend.
func (f *FileStorage) Close() error {
	return f.backend.Close()
}

// validateStorageKey validates storage keys (more permissive than service validation).
// Storage is internal - allows path separators for organization but blocks traversal.
func validateStorageKey(key string) error {
	if key == "" {
		return &errs.Message{Msg: "key cannot be empty"}
	}

	// Check for null bytes
	if strings.Contains(key, "\x00") {
		return &errs.Message{Msg: "key contains null byte"}
	}

	// Check for absolute paths
	if filepath.IsAbs(key) {
		return &errs.Message{Msg: "key cannot be an absolute path"}
	}

	// Check for path traversal - the key is that we don't allow starting with .. or containing /..
	cleaned := filepath.Clean(key)
	if strings.HasPrefix(cleaned, "..") {
		return &errs.Message{Msg: "key contains path traversal attempt"}
	}
	// Check for /../ pattern (directory traversal in middle of path)
	if strings.Contains(cleaned, string(filepath.Separator)+".."+string(filepath.Separator)) ||
		strings.HasSuffix(cleaned, string(filepath.Separator)+"..") {
		return &errs.Message{Msg: "key contains path traversal attempt"}
	}

	return nil
}

// filePermissionsForKey determines the file permissions based on the key prefix.
func filePermissionsForKey(key string) fs.FileMode {
	if strings.HasPrefix(key, "keys/") {
		return keysFilePerms
	}
	if strings.HasPrefix(key, "certs/") {
		return certsFilePerms
	}
	return defaultPerms
}

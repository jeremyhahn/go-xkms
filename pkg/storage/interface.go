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

// Package storage provides an abstraction layer for key-value storage backends.
// It supports both in-memory and file-based storage implementations with a
// common interface.
package storage

import (
	"io/fs"
)

// Backend defines the interface for storage backends.
// All implementations must be thread-safe.
type Backend interface {
	// Get retrieves the value for the given key.
	// Returns ErrNotFound if the key does not exist.
	Get(key string) ([]byte, error)

	// Put stores the value for the given key with optional metadata.
	// If the key already exists, it will be overwritten.
	Put(key string, value []byte, opts *Options) error

	// Delete removes the key and its value from storage.
	// Returns ErrNotFound if the key does not exist.
	Delete(key string) error

	// List returns all keys with the given prefix.
	// If prefix is empty, all keys are returned.
	List(prefix string) ([]string, error)

	// Exists checks if a key exists in storage.
	Exists(key string) (bool, error)

	// Close releases any resources held by the backend.
	Close() error
}

// Options contains optional parameters for storage operations.
type Options struct {
	// Path is the base path for file-based storage backends
	Path string

	// Permissions sets the file permissions for file-based storage
	Permissions fs.FileMode

	// Metadata contains additional key-value pairs for storage operations
	Metadata map[string]string
}

// DefaultOptions returns Options with sensible defaults.
func DefaultOptions() *Options {
	return &Options{
		Path:        "",
		Permissions: 0600, // Read/write for owner only
		Metadata:    make(map[string]string),
	}
}

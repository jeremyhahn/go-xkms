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

// Package storage provides an abstraction layer for key-value storage backends.
// It supports multiple backend engines through go-qrdb: memory, file, PebbleDB,
// Raft, and remote QRDB clusters.
package storage

import "context"

// Backend defines the interface for storage backends.
// All implementations must be thread-safe.
//
// This interface is designed to be a subset of go-qrdb's KVClient, enabling
// any QRDB transport (embedded, REST, gRPC, QUIC, Unix, MCP) to natively
// satisfy Backend with zero adapter code.
type Backend interface {
	// Get retrieves the value for the given key.
	// Returns ErrNotFound if the key does not exist.
	Get(ctx context.Context, key string) ([]byte, error)

	// Put stores the value for the given key.
	// If the key already exists, it will be overwritten.
	Put(ctx context.Context, key string, value []byte) error

	// Delete removes the key and its value from storage.
	// Returns ErrNotFound if the key does not exist.
	Delete(ctx context.Context, key string) error

	// List returns all keys with the given prefix.
	// If prefix is empty, all keys are returned.
	List(ctx context.Context, prefix string) ([]string, error)

	// Scan iterates over all key-value pairs matching the given prefix,
	// calling fn for each pair. If prefix is empty, all pairs are visited.
	// Return a non-nil error from fn to stop iteration early.
	Scan(ctx context.Context, prefix string, fn func(key string, value []byte) error) error

	// Exists checks if a key exists in storage.
	Exists(ctx context.Context, key string) (bool, error)

	// Close releases any resources held by the backend.
	Close() error
}

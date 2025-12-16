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

// Package versioning provides key version management for go-keychain backends.
// It enables version tracking across all backend types, including hardware backends
// (TPM2, PKCS#11) that don't natively support key versioning.
//
// For backends without native versioning, each version becomes a separate key
// with a deterministic naming convention (e.g., "mykey-v1", "mykey-v2").
// The VersionStore tracks which versions exist and which is current.
package versioning

import (
	"context"
	"errors"
	"time"
)

// Common errors returned by VersionStore implementations.
var (
	// ErrKeyNotFound is returned when the requested key doesn't exist.
	ErrKeyNotFound = errors.New("key not found")

	// ErrVersionNotFound is returned when the requested version doesn't exist.
	ErrVersionNotFound = errors.New("version not found")

	// ErrVersionExists is returned when trying to create a version that already exists.
	ErrVersionExists = errors.New("version already exists")

	// ErrStoreClosed is returned when operations are attempted on a closed store.
	ErrStoreClosed = errors.New("version store is closed")
)

// KeyState represents the lifecycle state of a key version.
type KeyState string

const (
	// KeyStateEnabled indicates the key version is active and usable.
	KeyStateEnabled KeyState = "enabled"

	// KeyStateDisabled indicates the key version is temporarily disabled.
	KeyStateDisabled KeyState = "disabled"

	// KeyStatePendingDeletion indicates the key is scheduled for deletion.
	KeyStatePendingDeletion KeyState = "pending_deletion"

	// KeyStateDestroyed indicates the key material has been destroyed.
	KeyStateDestroyed KeyState = "destroyed"
)

// VersionInfo contains metadata about a specific key version.
type VersionInfo struct {
	// Version is the version number (1-indexed, 0 is reserved for "latest").
	Version uint64 `json:"version"`

	// BackendKeyID is the actual key identifier used by the backend.
	// For hardware backends, this might be "mykey-v1" while the logical ID is "mykey".
	BackendKeyID string `json:"backend_key_id"`

	// Algorithm is the cryptographic algorithm (e.g., "Ed25519", "RSA-4096").
	Algorithm string `json:"algorithm"`

	// State is the current lifecycle state of this version.
	State KeyState `json:"state"`

	// Created is when this version was created.
	Created time.Time `json:"created"`

	// Updated is when this version's metadata was last modified.
	Updated time.Time `json:"updated"`

	// Metadata contains optional key-value pairs for additional information.
	Metadata map[string]string `json:"metadata,omitempty"`
}

// KeyVersions contains all version information for a key.
type KeyVersions struct {
	// KeyID is the logical key identifier.
	KeyID string `json:"key_id"`

	// CurrentVersion is the version number that should be used for new operations.
	CurrentVersion uint64 `json:"current_version"`

	// Versions maps version numbers to their metadata.
	Versions map[uint64]*VersionInfo `json:"versions"`

	// Created is when the key was first created.
	Created time.Time `json:"created"`

	// Updated is when any version was last modified.
	Updated time.Time `json:"updated"`
}

// VersionStore defines the interface for storing and retrieving key version metadata.
// Implementations must be thread-safe.
//
// The VersionStore is separate from key material storage - it only tracks metadata
// about which versions exist, their states, and which version is current.
// Actual key material is managed by the backend (PKCS8, TPM2, PKCS#11, etc.).
type VersionStore interface {
	// GetCurrentVersion returns the current version number for a key.
	// Returns 0 and ErrKeyNotFound if the key doesn't exist.
	GetCurrentVersion(ctx context.Context, keyID string) (uint64, error)

	// GetVersionInfo returns metadata for a specific version of a key.
	// Use version=0 to get the current version's info.
	// Returns ErrKeyNotFound if the key doesn't exist.
	// Returns ErrVersionNotFound if the specific version doesn't exist.
	GetVersionInfo(ctx context.Context, keyID string, version uint64) (*VersionInfo, error)

	// GetKeyVersions returns all version information for a key.
	// Returns ErrKeyNotFound if the key doesn't exist.
	GetKeyVersions(ctx context.Context, keyID string) (*KeyVersions, error)

	// ListVersions returns all versions of a key, ordered by version number.
	// Returns ErrKeyNotFound if the key doesn't exist.
	ListVersions(ctx context.Context, keyID string) ([]*VersionInfo, error)

	// CreateVersion registers a new version for a key.
	// If this is the first version, the key is also created.
	// Returns ErrVersionExists if the version already exists.
	CreateVersion(ctx context.Context, keyID string, info *VersionInfo) error

	// SetCurrentVersion updates which version is the current/active version.
	// Returns ErrKeyNotFound if the key doesn't exist.
	// Returns ErrVersionNotFound if the version doesn't exist.
	SetCurrentVersion(ctx context.Context, keyID string, version uint64) error

	// UpdateVersionState changes the state of a specific version.
	// Returns ErrKeyNotFound if the key doesn't exist.
	// Returns ErrVersionNotFound if the version doesn't exist.
	UpdateVersionState(ctx context.Context, keyID string, version uint64, state KeyState) error

	// DeleteVersion removes a version's metadata.
	// This should only be called after the backend key material is destroyed.
	// Returns ErrKeyNotFound if the key doesn't exist.
	// Returns ErrVersionNotFound if the version doesn't exist.
	DeleteVersion(ctx context.Context, keyID string, version uint64) error

	// DeleteKey removes all version metadata for a key.
	// This should only be called after all backend key material is destroyed.
	// Returns ErrKeyNotFound if the key doesn't exist.
	DeleteKey(ctx context.Context, keyID string) error

	// ListKeys returns all key IDs in the store.
	ListKeys(ctx context.Context) ([]string, error)

	// Close releases any resources held by the store.
	Close() error
}

// BackendKeyID generates the backend key identifier for a specific version.
// This is the naming convention used for backends that don't support native versioning.
// Format: "{keyID}-v{version}"
func BackendKeyID(keyID string, version uint64) string {
	return keyID + "-v" + uintToString(version)
}

// uintToString converts a uint64 to string without importing strconv.
func uintToString(n uint64) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

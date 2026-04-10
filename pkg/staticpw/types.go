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

// Package staticpw provides static password management with pluggable
// storage backends, multi-tenant support, and symmetric encryption via
// the types.SymmetricEncrypter interface.
package staticpw

import (
	"fmt"
	"strings"
	"time"

	"github.com/cespare/xxhash/v2"
)

// StaticPassword represents a stored static password entry.
type StaticPassword struct {
	// ID is a deterministic identifier derived from the entry name and folder path.
	ID string `json:"id"`

	// Name is the human-readable label for this password entry.
	Name string `json:"name"`

	// Title is an optional display label. Falls back to Name if empty.
	Title string `json:"title,omitempty"`

	// Username is the optional username or login associated with this entry.
	Username string `json:"username,omitempty"`

	// Password is the stored password value.
	Password string `json:"password"`

	// URL is the optional website or service URL for this entry.
	URL string `json:"url,omitempty"`

	// MatchPatterns contains optional glob patterns for URL matching.
	// Each pattern supports a leading "*." wildcard (e.g. "*.signin.aws.amazon.com").
	// When non-empty, these patterns are checked IN ADDITION TO the standard
	// URL-based domain matching.
	MatchPatterns []string `json:"match_patterns,omitempty"`

	// Notes contains optional user-provided notes.
	Notes string `json:"notes,omitempty"`

	// FolderPath is the hierarchical folder location (e.g. "Work/Email").
	FolderPath string `json:"folder_path,omitempty"`

	// ExpiresAt is the optional expiration time. Zero value means no expiry.
	ExpiresAt time.Time `json:"expires_at,omitempty"`

	// CreatedAt records when the entry was first created.
	CreatedAt time.Time `json:"created_at"`

	// UpdatedAt records the last modification time.
	UpdatedAt time.Time `json:"updated_at"`

	// ReadOnly indicates the entry was auto-generated (e.g. by TPM policy
	// creation) and should not be edited or deleted by the user.
	ReadOnly bool `json:"read_only,omitempty"`

	// OwnerID identifies the user who created this password entry.
	// Set automatically when adding via a ScopedStore.
	OwnerID string `json:"owner_id,omitempty"`

	// Shared indicates this is a tenant-wide shared password visible to
	// all users in the tenant. When false (default), the password is
	// personal and scoped to the owning user.
	Shared bool `json:"shared,omitempty"`
}

// Validate checks that the static password entry contains all required fields.
// It returns ErrInvalidName if Name is empty and ErrEmptyPassword if Password
// is empty.
func (sp *StaticPassword) Validate() error {
	if strings.TrimSpace(sp.Name) == "" {
		return ErrInvalidName
	}
	if sp.Password == "" {
		return ErrEmptyPassword
	}
	return nil
}

// DisplayTitle returns the Title if set, otherwise falls back to Name.
func (sp *StaticPassword) DisplayTitle() string {
	if sp.Title != "" {
		return sp.Title
	}
	return sp.Name
}

// GenerateID creates a deterministic 16-character hex identifier from the
// entry name and optional folder path by hashing the lowercased
// "folderPath/name" (or just "name") with xxhash64.
func GenerateID(name string, folderPath string) string {
	var path string
	if folderPath != "" {
		path = strings.ToLower(folderPath + "/" + name)
	} else {
		path = strings.ToLower(name)
	}
	return fmt.Sprintf("%016x", xxhash.Sum64String(path))
}

// generateID is an unexported convenience wrapper that delegates to GenerateID.
func generateID(name string, folderPath string) string {
	return GenerateID(name, folderPath)
}

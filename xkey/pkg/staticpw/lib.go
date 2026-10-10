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

// Package staticpw provides static password management for xkey.
//
// Core types (StaticPassword, Store, DAOStore, ExpiryChecker) and their
// helpers are re-exported from the go-xkms library package. This package
// adds xkey-specific encrypted store, encryption configuration, and
// AES-256-GCM crypto helpers.
package staticpw

import (
	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

// Type aliases -- identical types at the Go level, not wrappers.
type (
	// StaticPassword represents a stored static password entry.
	StaticPassword = xkms.StaticPassword

	// Store defines the interface for static password persistence.
	Store = xkms.StaticPasswordStore

	// DAOStore implements Store as go-qrdb DAO records.
	DAOStore = xkms.StaticPasswordDAOStore

	// ExpiryChecker periodically checks for expired password entries.
	ExpiryChecker = xkms.StaticPasswordExpiryChecker

	// TeamStore defines the interface for team persistence and membership.
	TeamStore = xkms.StaticPasswordTeamStore

	// TeamEntity is the DAO entity for team password sharing.
	TeamEntity = xkms.StaticPasswordTeamEntity

	// DAOTeamStore implements TeamStore using a go-qrdb GenericDAO.
	DAOTeamStore = xkms.StaticPasswordDAOTeamStore
)

// Re-export constructors.
var (
	// NewStore creates a DAOStore over the provided go-qrdb DAO factory.
	NewStore = xkms.NewStaticPasswordStore

	// NewTenantStore creates a DAOStore with tenant isolation.
	NewTenantStore = xkms.NewStaticPasswordTenantStore

	// NewExpiryChecker creates a new ExpiryChecker that periodically scans
	// the store for expired entries.
	NewExpiryChecker = xkms.NewStaticPasswordExpiryChecker

	// GeneratePassword produces a cryptographically random password.
	GeneratePassword = xkms.GenerateStaticPassword

	// GenerateID creates a deterministic identifier from the entry name
	// and optional folder path.
	GenerateID = xkms.GenerateStaticPasswordID

	// NewDAOTeamStore creates a DAOTeamStore over a go-qrdb DAO factory.
	NewDAOTeamStore = xkms.NewStaticPasswordDAOTeamStore
)

// NewBackendStore creates a DAOStore over a storage backend, the barrier or
// plain file backend xkey keeps its data in. The caller keeps ownership of
// backend.
func NewBackendStore(backend xkms.StorageBackend) (*DAOStore, error) {
	daos, err := xkms.NewBackendDAOFactory(backend)
	if err != nil {
		return nil, err
	}
	return NewStore(daos)
}

// Re-export error sentinels.
var (
	ErrStoreClosed      = xkms.ErrStaticPasswordStoreClosed
	ErrPasswordNotFound = xkms.ErrStaticPasswordNotFound
	ErrPasswordExists   = xkms.ErrStaticPasswordExists
	ErrInvalidPassword  = xkms.ErrStaticPasswordInvalid
	ErrInvalidName      = xkms.ErrStaticPasswordInvalidName
	ErrEmptyPassword    = xkms.ErrStaticPasswordEmpty
	ErrGenerateFailed   = xkms.ErrStaticPasswordGenerateFailed
	ErrInvalidLength    = xkms.ErrStaticPasswordInvalidLength
	ErrInvalidCharset   = xkms.ErrStaticPasswordInvalidCharset
	ErrMarshalFailed    = xkms.ErrStaticPasswordMarshalFailed
	ErrUnmarshalFailed  = xkms.ErrStaticPasswordUnmarshalFailed
	ErrFolderEmpty      = xkms.ErrStaticPasswordFolderEmpty
	ErrMoveToSameFolder = xkms.ErrStaticPasswordMoveToSameFolder
	ErrPasswordReadOnly = xkms.ErrStaticPasswordReadOnly
)

// Re-export character set constants.
const (
	CharsetAlphanumeric = xkms.StaticPasswordCharsetAlphanumeric
	CharsetAll          = xkms.StaticPasswordCharsetAll
)

// Re-export password length boundaries.
const (
	DefaultLength = xkms.StaticPasswordDefaultLength
	MinLength     = xkms.StaticPasswordMinLength
	MaxLength     = xkms.StaticPasswordMaxLength
)

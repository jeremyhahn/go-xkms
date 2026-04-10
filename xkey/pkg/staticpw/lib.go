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
// Core types (StaticPassword, Store, BackendStore, ExpiryChecker) and their
// helpers are re-exported from the go-xkms library package. This package
// adds xkey-specific encrypted store, encryption configuration, and
// AES-256-GCM crypto helpers.
package staticpw

import (
	libpw "github.com/jeremyhahn/go-xkms/pkg/staticpw"
)

// Type aliases -- identical types at the Go level, not wrappers.
type (
	// StaticPassword represents a stored static password entry.
	StaticPassword = libpw.StaticPassword

	// Store defines the interface for static password persistence.
	Store = libpw.Store

	// BackendStore implements Store backed by a storage.Backend.
	BackendStore = libpw.BackendStore

	// ExpiryChecker periodically checks for expired password entries.
	ExpiryChecker = libpw.ExpiryChecker

	// TeamStore defines the interface for team persistence and membership.
	TeamStore = libpw.TeamStore

	// TeamEntity is the DAO entity for team password sharing.
	TeamEntity = libpw.TeamEntity

	// DAOTeamStore implements TeamStore using a go-qrdb GenericDAO.
	DAOTeamStore = libpw.DAOTeamStore
)

// Re-export constructors.
var (
	// NewStore creates a new BackendStore wrapping the provided storage backend.
	NewStore = libpw.NewStore

	// NewTenantStore creates a new BackendStore with tenant isolation.
	NewTenantStore = libpw.NewTenantStore

	// NewExpiryChecker creates a new ExpiryChecker that periodically scans
	// the store for expired entries.
	NewExpiryChecker = libpw.NewExpiryChecker

	// GeneratePassword produces a cryptographically random password.
	GeneratePassword = libpw.GeneratePassword

	// MigrateEntry populates Title from Name if Title is empty.
	MigrateEntry = libpw.MigrateEntry

	// MigrateStore iterates all entries and migrates each one.
	MigrateStore = libpw.MigrateStore

	// GenerateID creates a deterministic identifier from the entry name
	// and optional folder path.
	GenerateID = libpw.GenerateID

	// NewDAOTeamStore creates a new DAOTeamStore using a kvstore.KVStore.
	NewDAOTeamStore = libpw.NewDAOTeamStore
)

// Re-export error sentinels.
var (
	ErrStoreClosed      = libpw.ErrStoreClosed
	ErrPasswordNotFound = libpw.ErrPasswordNotFound
	ErrPasswordExists   = libpw.ErrPasswordExists
	ErrInvalidPassword  = libpw.ErrInvalidPassword
	ErrInvalidName      = libpw.ErrInvalidName
	ErrEmptyPassword    = libpw.ErrEmptyPassword
	ErrGenerateFailed   = libpw.ErrGenerateFailed
	ErrInvalidLength    = libpw.ErrInvalidLength
	ErrInvalidCharset   = libpw.ErrInvalidCharset
	ErrMarshalFailed    = libpw.ErrMarshalFailed
	ErrUnmarshalFailed  = libpw.ErrUnmarshalFailed
	ErrFolderEmpty      = libpw.ErrFolderEmpty
	ErrMoveToSameFolder = libpw.ErrMoveToSameFolder
	ErrPasswordReadOnly = libpw.ErrPasswordReadOnly
)

// Re-export character set constants.
const (
	CharsetAlphanumeric = libpw.CharsetAlphanumeric
	CharsetAll          = libpw.CharsetAll
)

// Re-export password length boundaries.
const (
	DefaultLength = libpw.DefaultLength
	MinLength     = libpw.MinLength
	MaxLength     = libpw.MaxLength
)

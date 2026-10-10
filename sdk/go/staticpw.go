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

package xkms

import "github.com/jeremyhahn/go-xkms/pkg/staticpw"

// Static-password (password-manager) surface re-exported so the xkey GUI/CLI
// reach the canonical pkg/staticpw store through the SDK. The generic Store and
// DAOStore identifiers are prefixed StaticPassword* to stay unambiguous in the
// flat SDK namespace. Every store persists through a go-qrdb DAO factory (see
// NewStoreDAOFactory) serving the staticpw database.

// --- Core types ---

// StaticPassword is a stored password-manager entry.
type StaticPassword = staticpw.StaticPassword

// StaticPasswordStore is the password store interface.
type StaticPasswordStore = staticpw.Store

// StaticPasswordDAOStore is the password store kept as go-qrdb DAO records.
type StaticPasswordDAOStore = staticpw.DAOStore

// StaticPasswordExpiryChecker periodically checks for expired passwords.
type StaticPasswordExpiryChecker = staticpw.ExpiryChecker

// StaticPasswordTeamEntity is a shared-team password entity.
type StaticPasswordTeamEntity = staticpw.TeamEntity

// StaticPasswordTeamStore is the team password store interface.
type StaticPasswordTeamStore = staticpw.TeamStore

// StaticPasswordDAOTeamStore is the DAO-backed team password store.
type StaticPasswordDAOTeamStore = staticpw.DAOTeamStore

// --- Constructors ---

// NewStaticPasswordStore constructs the platform password store over a DAO factory.
var NewStaticPasswordStore = staticpw.NewStore

// NewStaticPasswordTenantStore constructs a tenant-scoped password store.
var NewStaticPasswordTenantStore = staticpw.NewTenantStore

// NewStaticPasswordDAOTeamStore constructs a DAO-backed team password store.
var NewStaticPasswordDAOTeamStore = staticpw.NewDAOTeamStore

// NewStaticPasswordExpiryChecker constructs an expiry checker.
var NewStaticPasswordExpiryChecker = staticpw.NewExpiryChecker

// --- Helpers ---

// GenerateStaticPassword generates a random password of the given length and charset.
var GenerateStaticPassword = staticpw.GeneratePassword

// GenerateStaticPasswordID derives a deterministic entry ID.
var GenerateStaticPasswordID = staticpw.GenerateID

// --- Generation constants ---

const (
	// StaticPasswordCharsetAll is the full character set for generation.
	StaticPasswordCharsetAll = staticpw.CharsetAll
	// StaticPasswordCharsetAlphanumeric restricts generation to letters and digits.
	StaticPasswordCharsetAlphanumeric = staticpw.CharsetAlphanumeric
	// StaticPasswordDefaultLength is the default generated-password length.
	StaticPasswordDefaultLength = staticpw.DefaultLength
	// StaticPasswordMinLength is the minimum generated-password length.
	StaticPasswordMinLength = staticpw.MinLength
	// StaticPasswordMaxLength is the maximum generated-password length.
	StaticPasswordMaxLength = staticpw.MaxLength
)

// --- Sentinel errors ---

var (
	// ErrStaticPasswordEmpty is returned for an empty password value.
	ErrStaticPasswordEmpty = staticpw.ErrEmptyPassword
	// ErrStaticPasswordFolderEmpty is returned for an empty folder.
	ErrStaticPasswordFolderEmpty = staticpw.ErrFolderEmpty
	// ErrStaticPasswordAliasNameEmpty is returned for an empty alias name.
	ErrStaticPasswordAliasNameEmpty = staticpw.ErrAliasNameEmpty
	// ErrStaticPasswordGenerateFailed is returned when generation fails.
	ErrStaticPasswordGenerateFailed = staticpw.ErrGenerateFailed
	// ErrStaticPasswordInvalidCharset is returned for an invalid charset.
	ErrStaticPasswordInvalidCharset = staticpw.ErrInvalidCharset
	// ErrStaticPasswordInvalidLength is returned for an invalid length.
	ErrStaticPasswordInvalidLength = staticpw.ErrInvalidLength
	// ErrStaticPasswordInvalidName is returned for an invalid entry name.
	ErrStaticPasswordInvalidName = staticpw.ErrInvalidName
	// ErrStaticPasswordInvalid is returned for an otherwise-invalid password.
	ErrStaticPasswordInvalid = staticpw.ErrInvalidPassword
	// ErrStaticPasswordMarshalFailed is returned when marshalling fails.
	ErrStaticPasswordMarshalFailed = staticpw.ErrMarshalFailed
	// ErrStaticPasswordMoveToSameFolder is returned when moving into the same folder.
	ErrStaticPasswordMoveToSameFolder = staticpw.ErrMoveToSameFolder
	// ErrStaticPasswordExists is returned when an entry already exists.
	ErrStaticPasswordExists = staticpw.ErrPasswordExists
	// ErrStaticPasswordNotFound is returned when an entry is missing.
	ErrStaticPasswordNotFound = staticpw.ErrPasswordNotFound
	// ErrStaticPasswordReadOnly is returned when modifying a read-only entry.
	ErrStaticPasswordReadOnly = staticpw.ErrPasswordReadOnly
	// ErrStaticPasswordStoreClosed is returned when operating on a closed store.
	ErrStaticPasswordStoreClosed = staticpw.ErrStoreClosed
	// ErrStaticPasswordTeamNotFound is returned when a team is missing.
	ErrStaticPasswordTeamNotFound = staticpw.ErrTeamNotFound
	// ErrStaticPasswordUnmarshalFailed is returned when unmarshalling fails.
	ErrStaticPasswordUnmarshalFailed = staticpw.ErrUnmarshalFailed
)

var (
	// ErrStaticPasswordInvalidTenantID is returned for an invalid tenant ID.
	ErrStaticPasswordInvalidTenantID = staticpw.ErrInvalidTenantID
	// ErrStaticPasswordInvalidUserID is returned for an empty or invalid user ID.
	ErrStaticPasswordInvalidUserID = staticpw.ErrInvalidUserID
	// ErrStaticPasswordTeamExists is returned when a team already exists.
	ErrStaticPasswordTeamExists = staticpw.ErrTeamExists
)

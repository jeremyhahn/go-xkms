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
// BackendStore identifiers are prefixed StaticPassword* to stay unambiguous in
// the flat SDK namespace.

// --- Core types ---

// StaticPassword is a stored password-manager entry.
type StaticPassword = staticpw.StaticPassword

// StaticPasswordStore is the password store interface.
type StaticPasswordStore = staticpw.Store

// StaticPasswordBackendStore is the barrier-backed password store.
type StaticPasswordBackendStore = staticpw.BackendStore

// StaticPasswordExpiryChecker periodically checks for expired passwords.
type StaticPasswordExpiryChecker = staticpw.ExpiryChecker

// StaticPasswordTeamEntity is a shared-team password entity.
type StaticPasswordTeamEntity = staticpw.TeamEntity

// StaticPasswordTeamStore is the team password store interface.
type StaticPasswordTeamStore = staticpw.TeamStore

// StaticPasswordDAOTeamStore is the DAO-backed team password store.
type StaticPasswordDAOTeamStore = staticpw.DAOTeamStore

// --- Constructors ---

// NewStaticPasswordStore constructs a barrier-backed password store.
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

// --- Multi-tenant + team-scoped surface ---

// StaticPasswordTeamScopedStore enforces team membership on password operations.
type StaticPasswordTeamScopedStore = staticpw.TeamScopedStore

// StaticPasswordTenantDAOFactory builds isolated per-tenant DAO password and
// team stores from the system KV store and a barrier registry accessor.
type StaticPasswordTenantDAOFactory = staticpw.TenantDAOFactory

// StaticPasswordBarrierRegistryAccessor resolves a per-tenant barrier-backed KV
// store for the tenant DAO factory.
type StaticPasswordBarrierRegistryAccessor = staticpw.BarrierRegistryAccessor

// ErrStaticPasswordInvalidTenant is the typed error for an invalid tenant.
type ErrStaticPasswordInvalidTenant = staticpw.ErrInvalidTenant

// ErrStaticPasswordNilBarrierRegistryAccessor is the typed error for a nil registry.
type ErrStaticPasswordNilBarrierRegistryAccessor = staticpw.ErrNilBarrierRegistryAccessor

// ErrStaticPasswordNilSystemKVStore is the typed error for a nil system KV store.
type ErrStaticPasswordNilSystemKVStore = staticpw.ErrNilSystemKVStore

// NewStaticPasswordTeamScopedStore constructs a team-membership-scoped store.
var NewStaticPasswordTeamScopedStore = staticpw.NewTeamScopedStore

// NewStaticPasswordTenantDAOFactory constructs a per-tenant DAO store factory.
var NewStaticPasswordTenantDAOFactory = staticpw.NewTenantDAOFactory

var (
	// ErrStaticPasswordInvalidTenantID is returned for an invalid tenant ID.
	ErrStaticPasswordInvalidTenantID = staticpw.ErrInvalidTenantID
	// ErrStaticPasswordInvalidUserID is returned for an empty or invalid user ID.
	ErrStaticPasswordInvalidUserID = staticpw.ErrInvalidUserID
	// ErrStaticPasswordNilPasswordStore is returned for a nil password store.
	ErrStaticPasswordNilPasswordStore = staticpw.ErrNilPasswordStore
	// ErrStaticPasswordNilTeamStore is returned for a nil team store.
	ErrStaticPasswordNilTeamStore = staticpw.ErrNilTeamStore
	// ErrStaticPasswordNotTeamMember is returned when the user is not a member.
	ErrStaticPasswordNotTeamMember = staticpw.ErrNotTeamMember
	// ErrStaticPasswordNotTeamOwner is returned when the user is not the owner.
	ErrStaticPasswordNotTeamOwner = staticpw.ErrNotTeamOwner
	// ErrStaticPasswordTeamExists is returned when a team already exists.
	ErrStaticPasswordTeamExists = staticpw.ErrTeamExists
)

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

package staticpw

import "errors"

var (
	// ErrStoreClosed is returned when the store has been closed.
	ErrStoreClosed = errors.New("staticpw: store is closed")

	// ErrStoreLocked is returned when operations are attempted on a locked session store.
	ErrStoreLocked = errors.New("staticpw: store is locked")

	// ErrPasswordNotFound is returned when a password entry cannot be found.
	ErrPasswordNotFound = errors.New("staticpw: password not found")

	// ErrPasswordExists is returned when a duplicate password entry is detected
	// by ID or name.
	ErrPasswordExists = errors.New("staticpw: password already exists")

	// ErrInvalidPassword is returned when password validation fails.
	ErrInvalidPassword = errors.New("staticpw: password validation failed")

	// ErrInvalidName is returned when the name field is empty.
	ErrInvalidName = errors.New("staticpw: name is required")

	// ErrEmptyPassword is returned when the password field is empty.
	ErrEmptyPassword = errors.New("staticpw: password is empty")

	// ErrGenerateFailed is returned when password generation fails.
	ErrGenerateFailed = errors.New("staticpw: password generation failed")

	// ErrInvalidLength is returned when the requested password length is
	// outside the allowed range (8-128).
	ErrInvalidLength = errors.New("staticpw: invalid password length (min 8, max 128)")

	// ErrInvalidCharset is returned when an unrecognized charset name is
	// specified.
	ErrInvalidCharset = errors.New("staticpw: invalid charset specified")

	// ErrMarshalFailed is returned when JSON marshaling fails.
	ErrMarshalFailed = errors.New("staticpw: JSON marshal failed")

	// ErrUnmarshalFailed is returned when JSON unmarshaling fails.
	ErrUnmarshalFailed = errors.New("staticpw: JSON unmarshal failed")

	// ErrCryptoEncryptFailed is returned when encryption fails.
	ErrCryptoEncryptFailed = errors.New("staticpw: encryption failed")

	// ErrCryptoDecryptFailed is returned when decryption fails.
	ErrCryptoDecryptFailed = errors.New("staticpw: decryption failed")

	// ErrFolderEmpty is returned when the folder path is empty where one is required.
	ErrFolderEmpty = errors.New("staticpw: folder path is empty")

	// ErrMoveToSameFolder is returned when moving an entry to its current folder.
	ErrMoveToSameFolder = errors.New("staticpw: already in target folder")

	// ErrPasswordReadOnly is returned when attempting to modify or delete a
	// read-only password entry.
	ErrPasswordReadOnly = errors.New("staticpw: password is read-only")

	// ErrInvalidTenantID is returned when a tenant ID is empty or contains
	// invalid characters.
	ErrInvalidTenantID = errors.New("staticpw: invalid tenant ID")

	// ErrNilEncrypter is returned when a nil SymmetricEncrypter is provided.
	ErrNilEncrypter = errors.New("staticpw: encrypter is nil")

	// ErrNilStore is returned when a nil Store is provided.
	ErrNilStore = errors.New("staticpw: store is nil")

	// ErrNilInnerStore is returned when a nil inner Store is provided to a wrapper.
	ErrNilInnerStore = errors.New("staticpw: inner store is nil")

	// ErrNilPINManager is returned when a nil PINManager is provided.
	ErrNilPINManager = errors.New("staticpw: PIN manager is nil")

	// ErrPINRequired is returned when a PIN is required but not provided.
	ErrPINRequired = errors.New("staticpw: PIN is required")

	// ErrStoreNotLocked is returned when Unlock is called on an already-unlocked store.
	ErrStoreNotLocked = errors.New("staticpw: store is not locked")

	// ErrStoreAlreadyLocked is returned when Lock is called on an already-locked store.
	ErrStoreAlreadyLocked = errors.New("staticpw: store is already locked")

	// ErrEncryptFailed is returned when password encryption fails.
	ErrEncryptFailed = errors.New("staticpw: encrypt failed")

	// ErrDecryptFailed is returned when password decryption fails.
	ErrDecryptFailed = errors.New("staticpw: decrypt failed")

	// ErrNilBarrierRegistry is returned when a nil BarrierRegistry is provided
	// to the TenantPasswordStoreManager constructor.
	ErrNilBarrierRegistry = errors.New("staticpw: barrier registry is nil")

	// ErrNotConfigured is returned when a required component (manager or store)
	// has not been configured.
	ErrNotConfigured = errors.New("staticpw: not configured")

	// ErrInvalidUserID is returned when a user ID is empty, too long,
	// or contains invalid characters.
	ErrInvalidUserID = errors.New("staticpw: invalid user ID")

	// ErrNotOwner is returned when a non-owner attempts to modify or
	// delete a shared password entry.
	ErrNotOwner = errors.New("staticpw: not the owner of this password")

	// ErrInvalidScope is returned when an unrecognized scope value is provided.
	ErrInvalidScope = errors.New("staticpw: invalid scope")

	// ErrInvalidFolderPath is returned when a folder path contains invalid characters
	// or has empty segments.
	ErrInvalidFolderPath = errors.New("staticpw: invalid folder path")

	// ErrFolderPathTooDeep is returned when a folder path exceeds the maximum allowed depth.
	ErrFolderPathTooDeep = errors.New("staticpw: folder path exceeds maximum depth")

	// ErrTeamNotFound is returned when a team cannot be found.
	ErrTeamNotFound = errors.New("staticpw: team not found")

	// ErrTeamExists is returned when a team with the same name already exists.
	ErrTeamExists = errors.New("staticpw: team already exists")

	// ErrTeamNameEmpty is returned when the team name is empty.
	ErrTeamNameEmpty = errors.New("staticpw: team name is required")

	// ErrNotTeamMember is returned when a user attempts an operation on a team
	// they do not belong to.
	ErrNotTeamMember = errors.New("staticpw: not a team member")

	// ErrNotTeamOwner is returned when a non-owner attempts a write operation
	// on a team's passwords.
	ErrNotTeamOwner = errors.New("staticpw: not the team owner")

	// ErrNilTeamStore is returned when a nil TeamStore is provided.
	ErrNilTeamStore = errors.New("staticpw: team store is nil")

	// ErrNilPasswordStore is returned when a nil password Store is provided
	// to TeamScopedStore.
	ErrNilPasswordStore = errors.New("staticpw: password store is nil")
)

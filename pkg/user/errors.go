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

package user

import "errors"

var (
	// ErrUserNotFound is returned when a user is not found.
	ErrUserNotFound = errors.New("user not found")

	// ErrUserAlreadyExists is returned when trying to create a user that already exists.
	ErrUserAlreadyExists = errors.New("user already exists")

	// ErrUserDisabled is returned when a user account is disabled.
	ErrUserDisabled = errors.New("user account is disabled")

	// ErrInvalidCredential is returned when a credential is invalid.
	ErrInvalidCredential = errors.New("invalid credential")

	// ErrCredentialNotFound is returned when a credential is not found.
	ErrCredentialNotFound = errors.New("credential not found")

	// ErrNoUsersExist is returned when no users exist yet.
	ErrNoUsersExist = errors.New("no users exist")

	// ErrLastAdmin is returned when trying to delete the last admin user.
	ErrLastAdmin = errors.New("cannot delete the last admin")

	// ErrInsufficientPermissions is returned when user lacks required permissions.
	ErrInsufficientPermissions = errors.New("insufficient permissions")

	// ErrSessionNotFound is returned when a session is not found or expired.
	ErrSessionNotFound = errors.New("session not found")

	// ErrStorageClosed is returned when the storage backend has been closed.
	ErrStorageClosed = errors.New("storage closed")

	// ErrInvalidUsername is returned when a username is invalid.
	ErrInvalidUsername = errors.New("invalid username")

	// ErrInvalidRole is returned when a role is invalid.
	ErrInvalidRole = errors.New("invalid role")
)

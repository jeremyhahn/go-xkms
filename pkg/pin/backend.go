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

package pin

// PINBackend defines the interface for backend-native PIN operations.
// Each backend implements PIN verification using its native mechanism:
//   - TPM2: PlatformSRK password auth (hardware-enforced, DA protection)
//   - Software: Argon2id/PBKDF2 password hashing with file persistence
//
// Lockout is enforced by the backend's native mechanism where available
// (TPM dictionary attack protection for TPM2, none for software).
type PINBackend interface {
	// Strategy returns the backend strategy identifier.
	Strategy() StrategyID

	// SetSOPIN sets the Security Officer PIN. For first-time setup,
	// currentSOPIN must be empty. For backends that don't distinguish
	// SO PIN from setup, this initializes the backend.
	SetSOPIN(currentSOPIN, newSOPIN string) error

	// SetUserPIN sets the user PIN using SO PIN authorization.
	SetUserPIN(soPIN, newUserPIN string) error

	// ChangeSOPIN changes the SO PIN from current to new.
	ChangeSOPIN(currentSOPIN, newSOPIN string) error

	// ChangeUserPIN changes the user PIN from current to new.
	ChangeUserPIN(currentUserPIN, newUserPIN string) error

	// VerifySOPIN verifies the SO PIN using the backend's native mechanism.
	VerifySOPIN(pin string) error

	// VerifyUserPIN verifies the user PIN using the backend's native mechanism.
	VerifyUserPIN(pin string) error

	// IsInitialized returns true if the backend has been initialized
	// (SO PIN set or equivalent first-time setup completed).
	IsInitialized() bool

	// SOPINSet returns true if the SO PIN has been configured.
	SOPINSet() bool

	// UserPINSet returns true if the user PIN has been configured.
	UserPINSet() bool

	// GetLockoutStatus returns the backend's native lockout state.
	// Returns nil if the backend has no lockout mechanism (e.g., software).
	GetLockoutStatus() *LockoutStatus

	// ResetLockout resets the lockout state using SO PIN authorization.
	// Returns nil if the backend has no lockout mechanism.
	ResetLockout(soPIN string) error
}

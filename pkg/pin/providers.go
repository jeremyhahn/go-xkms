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

import "strings"

// PlatformAuthProvider abstracts the TPM platform key store's auth operations
// for PIN verification. The pin.TPM2Backend delegates all user PIN verification
// to this provider, which verifies against the PlatformSRK's password auth
// value rather than hierarchy auth.
type PlatformAuthProvider interface {
	// VerifyAuth verifies the user PIN against the PlatformSRK's password auth.
	VerifyAuth(pin string) error

	// ChangeAuth changes the PlatformSRK's password auth (user PIN change).
	ChangeAuth(currentPIN, newPIN string) error

	// GetLockoutInfo returns TPM DA lockout counters:
	// failedAttempts, maxFail, interval, recovery seconds.
	GetLockoutInfo() (failedAttempts, maxFail, interval, recovery int, err error)

	// DictionaryAttackLockoutReset resets the DA lockout counter.
	DictionaryAttackLockoutReset(lockoutAuth []byte) error

	// IsProvisioned returns true if the TPM is provisioned with a PlatformSRK.
	IsProvisioned() bool
}

// isAuthError returns true if the error indicates a TPM authorization failure.
// Matches raw TPM response codes (TPM_RC_BAD_AUTH, TPM_RC_AUTH_FAIL) via
// their string representations, and the wrapped sentinel error from
// TPM2.VerifyAuth ("auth verification failed"). Since the pin package uses
// the PlatformAuthProvider interface (not go-tpm types directly), this uses
// string matching on the error message as a portable detection mechanism.
func isAuthError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "bad_auth") ||
		strings.Contains(msg, "auth_fail") ||
		strings.Contains(msg, "auth verification failed")
}

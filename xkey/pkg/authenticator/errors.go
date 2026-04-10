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

package authenticator

import (
	"errors"
	"fmt"
)

// CTAP2 error codes as defined in the FIDO2 specification.
// These errors map to standard CTAP2 status codes.

// ErrInvalidCommand indicates an invalid or unsupported CTAP command was received.
var ErrInvalidCommand = errors.New("authenticator: invalid command")

// ErrInvalidParameter indicates one or more parameters in the request are invalid.
var ErrInvalidParameter = errors.New("authenticator: invalid parameter")

// ErrCredentialNotFound indicates the requested credential does not exist.
var ErrCredentialNotFound = errors.New("authenticator: credential not found")

// ErrOperationDenied indicates the operation was denied by policy or user action.
var ErrOperationDenied = errors.New("authenticator: operation denied")

// ErrPINRequired indicates a PIN is required but was not provided.
var ErrPINRequired = errors.New("authenticator: PIN required")

// ErrPINInvalid indicates the provided PIN is incorrect.
var ErrPINInvalid = errors.New("authenticator: PIN invalid")

// ErrPINBlocked indicates the PIN has been blocked due to too many failed attempts.
var ErrPINBlocked = errors.New("authenticator: PIN blocked")

// ErrPINAuthInvalid indicates PIN authentication failed (pinUvAuthToken invalid).
var ErrPINAuthInvalid = errors.New("authenticator: PIN auth invalid")

// ErrPINPolicyViolation indicates the PIN does not meet policy requirements.
var ErrPINPolicyViolation = errors.New("authenticator: PIN policy violation")

// ErrNoCredentials indicates no credentials match the request criteria.
var ErrNoCredentials = errors.New("authenticator: no credentials")

// ErrUnsupportedExtension indicates the requested extension is not supported.
var ErrUnsupportedExtension = errors.New("authenticator: unsupported extension")

// ErrUserPresenceRequired indicates user presence verification is required but not satisfied.
var ErrUserPresenceRequired = errors.New("authenticator: user presence required")

// ErrUserVerificationRequired indicates user verification is required but not satisfied.
var ErrUserVerificationRequired = errors.New("authenticator: user verification required")

// ErrUVBlocked indicates user verification has been blocked due to too many failed attempts.
var ErrUVBlocked = errors.New("authenticator: UV blocked")

// ErrStorageError indicates an error occurred while accessing credential storage.
var ErrStorageError = errors.New("authenticator: storage error")

// ErrCryptoError indicates a cryptographic operation failed.
var ErrCryptoError = errors.New("authenticator: crypto error")

// ErrInvalidRPID indicates the relying party ID is invalid or does not match.
var ErrInvalidRPID = errors.New("authenticator: invalid relying party ID")

// ErrCredentialExcluded indicates a credential in the exclude list was found,
// preventing credential creation to avoid duplicate registrations.
var ErrCredentialExcluded = errors.New("authenticator: credential excluded")

// Policy HMAC integrity errors.
// These errors relate to the HMAC-based tamper detection system for
// SO-controlled policy fields.

// ErrPolicyTampered is returned when policy HMAC verification fails,
// indicating the policy fields were modified outside SO operations.
var ErrPolicyTampered = errors.New("authenticator: policy integrity check failed - tamper detected")

// ErrPolicyHMACMissing is returned when no HMAC tag exists in state.
// This occurs on first run or when policy has not been signed by SO.
var ErrPolicyHMACMissing = errors.New("authenticator: policy HMAC tag not found")

// ErrPolicySignFailed is returned when HMAC computation fails during signing.
var ErrPolicySignFailed = errors.New("authenticator: failed to sign policy")

// ErrPolicyVerifyFailed is returned when HMAC verification computation fails.
var ErrPolicyVerifyFailed = errors.New("authenticator: failed to verify policy")

// ErrPolicyKeyTooShort is returned when the policy HMAC key is less than 32 bytes.
var ErrPolicyKeyTooShort = errors.New("authenticator: policy key must be at least 32 bytes")

// ErrDAOCreation is returned when the DAO layer fails to initialize.
type ErrDAOCreation struct {
	Cause error
}

// Error implements the error interface.
func (e ErrDAOCreation) Error() string {
	return fmt.Sprintf("authenticator: failed to create DAO: %v", e.Cause)
}

// Unwrap returns the underlying cause.
func (e ErrDAOCreation) Unwrap() error {
	return e.Cause
}

// ErrMigration is returned when migration from old storage format fails.
type ErrMigration struct {
	CredentialIDHex string
	Cause           error
}

// Error implements the error interface.
func (e ErrMigration) Error() string {
	return fmt.Sprintf("authenticator: migration failed for credential %q: %v", e.CredentialIDHex, e.Cause)
}

// Unwrap returns the underlying cause.
func (e ErrMigration) Unwrap() error {
	return e.Cause
}

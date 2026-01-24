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

package authenticator

import "errors"

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

// ErrStorageError indicates an error occurred while accessing credential storage.
var ErrStorageError = errors.New("authenticator: storage error")

// ErrCryptoError indicates a cryptographic operation failed.
var ErrCryptoError = errors.New("authenticator: crypto error")

// ErrInvalidRPID indicates the relying party ID is invalid or does not match.
var ErrInvalidRPID = errors.New("authenticator: invalid relying party ID")

// ErrCredentialExcluded indicates a credential in the exclude list was found,
// preventing credential creation to avoid duplicate registrations.
var ErrCredentialExcluded = errors.New("authenticator: credential excluded")

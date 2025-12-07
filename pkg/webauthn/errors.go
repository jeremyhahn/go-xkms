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

package webauthn

import (
	"errors"
	"fmt"
)

// Sentinel errors for WebAuthn operations.
var (
	// ErrUserNotFound is returned when a user cannot be found.
	ErrUserNotFound = errors.New("user not found")

	// ErrUserAlreadyExists is returned when attempting to create a user that already exists.
	ErrUserAlreadyExists = errors.New("user already exists")

	// ErrCredentialNotFound is returned when a credential cannot be found.
	ErrCredentialNotFound = errors.New("credential not found")

	// ErrCredentialAlreadyExists is returned when attempting to register a duplicate credential.
	ErrCredentialAlreadyExists = errors.New("credential already exists")

	// ErrSessionNotFound is returned when a session cannot be found or has expired.
	ErrSessionNotFound = errors.New("session not found")

	// ErrSessionExpired is returned when a session has expired.
	ErrSessionExpired = errors.New("session expired")

	// ErrInvalidSession is returned when session data is invalid.
	ErrInvalidSession = errors.New("invalid session data")

	// ErrInvalidCredential is returned when credential data is invalid.
	ErrInvalidCredential = errors.New("invalid credential")

	// ErrInvalidRequest is returned when the request is malformed.
	ErrInvalidRequest = errors.New("invalid request")

	// ErrInvalidResponse is returned when the authenticator response is invalid.
	ErrInvalidResponse = errors.New("invalid authenticator response")

	// ErrVerificationFailed is returned when credential verification fails.
	ErrVerificationFailed = errors.New("verification failed")

	// ErrNoCredentials is returned when a user has no registered credentials.
	ErrNoCredentials = errors.New("user has no registered credentials")

	// ErrClonedAuthenticator is returned when a cloned authenticator is detected.
	ErrClonedAuthenticator = errors.New("cloned authenticator detected")

	// ErrNotConfigured is returned when the service is not properly configured.
	ErrNotConfigured = errors.New("webauthn service not configured")
)

// WebAuthnError wraps an error with additional context.
type WebAuthnError struct {
	Op  string // Operation that failed
	Err error  // Underlying error
}

// Error returns the error message.
func (e *WebAuthnError) Error() string {
	if e.Op != "" {
		return fmt.Sprintf("%s: %v", e.Op, e.Err)
	}
	return e.Err.Error()
}

// Unwrap returns the underlying error.
func (e *WebAuthnError) Unwrap() error {
	return e.Err
}

// Is reports whether the target error matches.
func (e *WebAuthnError) Is(target error) bool {
	return errors.Is(e.Err, target)
}

// NewError creates a new WebAuthnError with the given operation and error.
func NewError(op string, err error) error {
	return &WebAuthnError{
		Op:  op,
		Err: err,
	}
}

// WrapError wraps an error with an operation name if it's not nil.
func WrapError(op string, err error) error {
	if err == nil {
		return nil
	}
	return NewError(op, err)
}

// IsUserNotFound returns true if the error indicates a user was not found.
func IsUserNotFound(err error) bool {
	return errors.Is(err, ErrUserNotFound)
}

// IsCredentialNotFound returns true if the error indicates a credential was not found.
func IsCredentialNotFound(err error) bool {
	return errors.Is(err, ErrCredentialNotFound)
}

// IsSessionNotFound returns true if the error indicates a session was not found.
func IsSessionNotFound(err error) bool {
	return errors.Is(err, ErrSessionNotFound)
}

// IsSessionExpired returns true if the error indicates a session has expired.
func IsSessionExpired(err error) bool {
	return errors.Is(err, ErrSessionExpired)
}

// IsVerificationFailed returns true if the error indicates verification failed.
func IsVerificationFailed(err error) bool {
	return errors.Is(err, ErrVerificationFailed)
}

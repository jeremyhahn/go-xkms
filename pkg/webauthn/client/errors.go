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

package client

import (
	"errors"
	"fmt"
)

// Sentinel errors for the WebAuthn client.
var (
	// ErrServerURLRequired is returned when the server URL is empty.
	ErrServerURLRequired = errors.New("webauthn/client: server URL is required")

	// ErrUsernameRequired is returned when the username is empty.
	ErrUsernameRequired = errors.New("webauthn/client: username is required")

	// ErrRegistrationFailed is returned when the registration ceremony fails.
	ErrRegistrationFailed = errors.New("webauthn/client: registration failed")

	// ErrAuthenticationFailed is returned when the authentication ceremony fails.
	ErrAuthenticationFailed = errors.New("webauthn/client: authentication failed")

	// ErrServerUnavailable is returned when the server cannot be reached.
	ErrServerUnavailable = errors.New("webauthn/client: server unavailable")

	// ErrInvalidServerResponse is returned when the server returns an unexpected response.
	ErrInvalidServerResponse = errors.New("webauthn/client: invalid server response")

	// ErrAuthenticatorNotFound is returned when the authenticator is not available.
	ErrAuthenticatorNotFound = errors.New("webauthn/client: authenticator not found or not responding")

	// ErrCTAPOperationFailed is returned when a CTAP operation fails.
	ErrCTAPOperationFailed = errors.New("webauthn/client: CTAP operation failed")

	// ErrNilConfig is returned when a nil config is passed.
	ErrNilConfig = errors.New("webauthn/client: nil config")

	// ErrInvalidChallenge is returned when the server provides an invalid challenge.
	ErrInvalidChallenge = errors.New("webauthn/client: invalid challenge from server")

	// ErrSessionExpired is returned when a server session has expired.
	ErrSessionExpired = errors.New("webauthn/client: session expired")

	// ErrNilHTTPClient is returned when a nil HTTP client is configured.
	ErrNilHTTPClient = errors.New("webauthn/client: nil HTTP client")

	// ErrNilRequest is returned when a nil request is passed.
	ErrNilRequest = errors.New("webauthn/client: nil request")

	// ErrNilAuthenticatorAdapter is returned when no authenticator adapter is configured.
	ErrNilAuthenticatorAdapter = errors.New("webauthn/client: nil authenticator adapter")
)

// ClientError wraps an error with the operation context.
type ClientError struct {
	Op  string // Operation that failed
	Err error  // Underlying error
}

// Error returns the error message.
func (e *ClientError) Error() string {
	if e.Op != "" {
		return fmt.Sprintf("webauthn/client: %s: %v", e.Op, e.Err)
	}
	return e.Err.Error()
}

// Unwrap returns the underlying error.
func (e *ClientError) Unwrap() error {
	return e.Err
}

// wrapError wraps an error with operation context. Returns nil if err is nil.
func wrapError(op string, err error) error {
	if err == nil {
		return nil
	}
	return &ClientError{Op: op, Err: err}
}

// ServerError represents an HTTP error from the RP server.
type ServerError struct {
	StatusCode int    // HTTP status code
	ErrorCode  string // Error code from the response body
	Message    string // Human-readable message from the response body
}

// Error returns the error message.
func (e *ServerError) Error() string {
	if e.ErrorCode != "" {
		return fmt.Sprintf("webauthn/client: server error %d (%s): %s", e.StatusCode, e.ErrorCode, e.Message)
	}
	return fmt.Sprintf("webauthn/client: server error %d: %s", e.StatusCode, e.Message)
}

// Is allows matching against sentinel errors for common status codes.
func (e *ServerError) Is(target error) bool {
	if e.StatusCode >= 500 {
		return errors.Is(target, ErrServerUnavailable)
	}
	return false
}

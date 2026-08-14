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

package token

// NilInputError is returned when a required constructor argument is nil or
// empty.
type NilInputError struct {
	Field string
}

// Error implements the error interface.
func (e *NilInputError) Error() string { return "auth/token: nil or empty input: " + e.Field }

// InvalidTokenError is returned when a presented token fails signature,
// shape, or claim validation.
type InvalidTokenError struct {
	Reason string
	Err    error
}

// Error implements the error interface.
func (e *InvalidTokenError) Error() string {
	msg := "auth/token: invalid token: " + e.Reason
	if e.Err != nil {
		msg += ": " + e.Err.Error()
	}
	return msg
}

// Unwrap returns the underlying error.
func (e *InvalidTokenError) Unwrap() error { return e.Err }

// RefreshReuseError is returned when a refresh token that was already rotated
// is presented again. The whole token family is revoked in response: replay
// of a rotated refresh token is the signature of token theft.
type RefreshReuseError struct {
	Family string
}

// Error implements the error interface.
func (e *RefreshReuseError) Error() string {
	return "auth/token: refresh token reuse detected; token family revoked"
}

// RefreshRevokedError is returned when the presented refresh token belongs to
// a family that was revoked (logout or reuse response) or is unknown to the
// store (expired and cleaned, or never issued by this issuer).
type RefreshRevokedError struct{}

// Error implements the error interface.
func (e *RefreshRevokedError) Error() string {
	return "auth/token: refresh token revoked or unknown"
}

// StoreError wraps a refresh-store failure.
type StoreError struct {
	Op  string
	Err error
}

// Error implements the error interface.
func (e *StoreError) Error() string {
	return "auth/token: refresh store " + e.Op + " failed: " + e.Err.Error()
}

// Unwrap returns the underlying error.
func (e *StoreError) Unwrap() error { return e.Err }

// SigningError wraps a token signing failure.
type SigningError struct {
	Err error
}

// Error implements the error interface.
func (e *SigningError) Error() string { return "auth/token: signing failed: " + e.Err.Error() }

// Unwrap returns the underlying error.
func (e *SigningError) Unwrap() error { return e.Err }

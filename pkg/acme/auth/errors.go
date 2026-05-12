// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-ca.
//
// go-trusted-ca is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package auth

import (
	"time"
)

// InvalidTokenError indicates the token is malformed or otherwise invalid.
type InvalidTokenError struct {
	Reason string
}

// Error returns the error message.
func (e *InvalidTokenError) Error() string {
	return "invalid token: " + e.Reason
}

// TokenExpiredError indicates the token has passed its expiration time.
type TokenExpiredError struct {
	ExpiredAt time.Time
}

// Error returns the error message.
func (e *TokenExpiredError) Error() string {
	return "token expired at " + e.ExpiredAt.UTC().Format(time.RFC3339)
}

// TokenRevokedError indicates the token has been revoked.
type TokenRevokedError struct {
	TokenID string
}

// Error returns the error message.
func (e *TokenRevokedError) Error() string {
	return "token revoked: " + e.TokenID
}

// AuthServiceError indicates an error communicating with the auth service.
type AuthServiceError struct {
	Message string
	Cause   error
}

// Error returns the error message.
func (e *AuthServiceError) Error() string {
	if e.Cause != nil {
		return "auth service error: " + e.Message + ": " + e.Cause.Error()
	}
	return "auth service error: " + e.Message
}

// Unwrap returns the underlying cause for errors.Is/As compatibility.
func (e *AuthServiceError) Unwrap() error {
	return e.Cause
}

// IsInvalidToken returns true if the error is an InvalidTokenError.
func IsInvalidToken(err error) bool {
	_, ok := err.(*InvalidTokenError)
	return ok
}

// IsTokenExpired returns true if the error is a TokenExpiredError.
func IsTokenExpired(err error) bool {
	_, ok := err.(*TokenExpiredError)
	return ok
}

// IsTokenRevoked returns true if the error is a TokenRevokedError.
func IsTokenRevoked(err error) bool {
	_, ok := err.(*TokenRevokedError)
	return ok
}

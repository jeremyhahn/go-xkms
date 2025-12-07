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

package http

// HeaderSessionID is the header name for the session ID.
const HeaderSessionID = "X-Session-Id"

// HeaderUserID is the header name for the user ID.
const HeaderUserID = "X-User-Id"

// BeginRegistrationRequest is the request body for starting registration.
type BeginRegistrationRequest struct {
	// Email is the user's email address (required).
	Email string `json:"email"`

	// DisplayName is the user's display name (optional, defaults to email).
	DisplayName string `json:"display_name,omitempty"`
}

// BeginLoginRequest is the request body for starting authentication.
type BeginLoginRequest struct {
	// UserID is the base64-encoded user ID (optional).
	// If not provided, discoverable credentials flow is used.
	UserID string `json:"user_id,omitempty"`

	// Email is the user's email address (optional, alternative to UserID).
	Email string `json:"email,omitempty"`
}

// RegistrationStatusRequest is used for checking registration status.
type RegistrationStatusRequest struct {
	// UserID is the base64-encoded user ID (optional).
	UserID string `json:"user_id,omitempty"`

	// Email is the user's email address (optional, alternative to UserID).
	Email string `json:"email,omitempty"`
}

// RegistrationStatusResponse is the response for registration status.
type RegistrationStatusResponse struct {
	// Registered indicates if the user has registered credentials.
	Registered bool `json:"registered"`
}

// AuthResponse is the response after successful registration or login.
type AuthResponse struct {
	// Token is the authentication token (JWT or base64 user ID).
	Token string `json:"token"`

	// UserID is the base64-encoded user ID.
	UserID string `json:"user_id"`
}

// ErrorResponse is the response format for errors.
type ErrorResponse struct {
	// Error is the error code.
	Error string `json:"error"`

	// Message is a human-readable error message.
	Message string `json:"message"`
}

// Error codes returned in ErrorResponse.
const (
	ErrorCodeInvalidRequest     = "invalid_request"
	ErrorCodeInvalidSession     = "invalid_session"
	ErrorCodeSessionExpired     = "session_expired"
	ErrorCodeUserNotFound       = "user_not_found"
	ErrorCodeNoCredentials      = "no_credentials"
	ErrorCodeVerificationFailed = "verification_failed"
	ErrorCodeInternalError      = "internal_error"
)

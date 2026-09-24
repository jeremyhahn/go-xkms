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

// Package aws provides AWS-specific OIDC functionality.
package aws

import "errors"

var (
	// ErrMissingRegion is returned when the AWS region is not specified.
	ErrMissingRegion = errors.New("aws: region is required")

	// ErrMissingClientID is returned when the client ID is not specified.
	ErrMissingClientID = errors.New("aws: client ID is required")

	// ErrMissingDPoPKey is returned when DPoP key is required but not provided.
	ErrMissingDPoPKey = errors.New("aws: DPoP key is required for token requests")

	// ErrTokenRequestFailed is returned when the token request fails.
	ErrTokenRequestFailed = errors.New("aws: token request failed")

	// ErrAuthorizationFailed is returned when authorization fails.
	ErrAuthorizationFailed = errors.New("aws: authorization failed")

	// ErrInvalidResponse is returned when the AWS response is invalid.
	ErrInvalidResponse = errors.New("aws: invalid response format")

	// ErrMissingCredentials is returned when credentials are missing from response.
	ErrMissingCredentials = errors.New("aws: credentials missing from response")

	// ErrDPoPNonceRequired is returned when a DPoP nonce is required.
	ErrDPoPNonceRequired = errors.New("aws: DPoP nonce required, retry with nonce")

	// ErrCredentialsExpired is returned when credentials have expired.
	ErrCredentialsExpired = errors.New("aws: credentials have expired")

	// ErrNonceRetryExhausted is returned when nonce retry attempts are exhausted.
	ErrNonceRetryExhausted = errors.New("aws: nonce retry attempts exhausted")

	// ErrLoginFailed is returned when the interactive login flow could not
	// be set up (key generation, client construction, callback listener).
	ErrLoginFailed = errors.New("aws: login failed")

	// ErrCallbackFailed is returned when the local OAuth2 callback reports
	// an error, such as the user denying consent.
	ErrCallbackFailed = errors.New("aws: callback failed")

	// ErrLoginTimeout is returned when the browser callback does not
	// arrive before the login's timeout elapses.
	ErrLoginTimeout = errors.New("aws: authorization timed out")

	// ErrStateMismatch is returned when the callback's state parameter
	// does not match the one sent in the authorization request.
	ErrStateMismatch = errors.New("aws: state mismatch -- possible CSRF attack")

	// ErrNoAuthorizationCode is returned when the callback carries no
	// "code" query parameter and no "error" parameter either.
	ErrNoAuthorizationCode = errors.New("aws: no authorization code received")

	// ErrTokenExchangeFailed is returned when exchanging the authorization
	// code for credentials fails.
	ErrTokenExchangeFailed = errors.New("aws: token exchange failed")

	// ErrRefreshFailed is returned when refreshing AWS credentials fails.
	ErrRefreshFailed = errors.New("aws: credential refresh failed")
)

// DetailError appends detail text directly after a wrapped error while
// preserving errors.Is / errors.As matching of the wrapped error through
// Unwrap. The detail text carries its own leading separator.
type DetailError struct {
	Err    error
	Detail string
}

// Error implements the error interface.
func (e *DetailError) Error() string {
	return e.Err.Error() + e.Detail
}

// Unwrap returns the wrapped cause.
func (e *DetailError) Unwrap() error {
	return e.Err
}

// SentinelCauseError attaches an underlying cause to a package sentinel
// error so errors.Is matches both the sentinel and the cause.
type SentinelCauseError struct {
	Sentinel error
	Cause    error
}

// Error implements the error interface.
func (e *SentinelCauseError) Error() string {
	return e.Sentinel.Error() + ": " + e.Cause.Error()
}

// Unwrap returns the sentinel and the cause for errors.Is / errors.As.
func (e *SentinelCauseError) Unwrap() []error {
	return []error{e.Sentinel, e.Cause}
}

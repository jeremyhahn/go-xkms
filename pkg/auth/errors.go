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

package auth

import "errors"

var (
	// ErrNoAuthenticators is returned when a composite authenticator is created with no authenticators.
	ErrNoAuthenticators = errors.New("at least one authenticator is required")

	// ErrAuthenticationFailed is returned when all authenticators in a chain fail.
	ErrAuthenticationFailed = errors.New("authentication failed")

	// ErrUserDisabled is returned when a matched user account is disabled.
	ErrUserDisabled = errors.New("user account is disabled")

	// ErrNoPeerCertificate is returned when no client certificate is provided in the TLS handshake.
	ErrNoPeerCertificate = errors.New("no client certificate provided")

	// ErrNoPeerInfo is returned when gRPC peer information is not available in the context.
	ErrNoPeerInfo = errors.New("no peer information in context")

	// ErrNoTLSInfo is returned when gRPC peer does not contain TLS authentication info.
	ErrNoTLSInfo = errors.New("no TLS information in peer")

	// ErrUnauthenticated is returned by the Authorizer when no identity is
	// present on the request context — authentication must run first.
	ErrUnauthenticated = errors.New("authentication required")

	// ErrCertNotBound is returned by the mTLS authenticator when a UserStore
	// is configured and the client certificate's SPKI thumbprint is bound to
	// no user. Once an identity plane is present, only a bound certificate
	// authenticates.
	ErrCertNotBound = errors.New("client certificate is not bound to a user")

	// ErrRefreshSubjectNotFound is returned by QRDBUserResolver when a
	// refresh token's subject resolves to no qrdb user under its declared
	// SubjectKindMetadataKey encoding (username or WebAuthn handle). It is
	// never returned by trying the OTHER encoding as a fallback: that would
	// let a deleted username that happens to also decode as a live user's
	// WebAuthn handle resolve to that other account.
	ErrRefreshSubjectNotFound = errors.New("refresh token subject resolves to no user")
)

// UserLookupError is returned by the mTLS authenticator when the configured
// UserStore fails to resolve a client certificate for any reason other than a
// definite not-found: the store is sealed, unreachable, or otherwise
// unavailable. Authentication fails closed, because an account the store
// would have refused (disabled or unbound) must not authenticate while the
// store cannot say so.
type UserLookupError struct {
	// Err is the store's error.
	Err error
}

// Error returns a human-readable description.
func (e *UserLookupError) Error() string {
	return "mtls user lookup failed: " + e.Err.Error()
}

// Unwrap returns the store's error.
func (e *UserLookupError) Unwrap() error {
	return e.Err
}

// PermissionListError is returned by Authorizer.ListPermissions when qrdb
// cannot resolve the identity's permissions.
type PermissionListError struct {
	// Err is the RBAC client's error.
	Err error
}

// Error returns a human-readable description.
func (e *PermissionListError) Error() string {
	return "auth: list permissions failed: " + e.Err.Error()
}

// Unwrap returns the RBAC client's error.
func (e *PermissionListError) Unwrap() error {
	return e.Err
}

// RefreshUserLookupError is returned by QRDBUserResolver when the qrdb user
// client fails to answer a refresh-time re-check for any reason other than
// a definite not-found: the store is sealed, unreachable, or otherwise
// unavailable. It is UserLookupError's counterpart for the refresh path
// rather than the same type, because the two report through different
// prose ("mtls user lookup failed" would misdescribe a refresh that never
// touched a certificate).
type RefreshUserLookupError struct {
	// Err is the qrdb user client's error.
	Err error
}

// Error returns a human-readable description.
func (e *RefreshUserLookupError) Error() string {
	return "auth: refresh user lookup failed: " + e.Err.Error()
}

// Unwrap returns the qrdb user client's error.
func (e *RefreshUserLookupError) Unwrap() error {
	return e.Err
}

// RefreshSubjectKindError is returned by QRDBUserResolver when a refresh
// token's identity carries no SubjectKindMetadataKey, or a value other than
// SubjectKindUsername/SubjectKindUserHandle. The kind must be declared by
// the login flow that minted the token, never inferred from the shape of
// the subject -- guessing let a deleted username that happened to also
// decode as a live user's WebAuthn handle resolve to that OTHER account
// (go-xkms#1297 review). Pre-release: a token minted before this field
// existed simply fails refresh; there is no compatibility fallback.
type RefreshSubjectKindError struct {
	// Kind is the offending (possibly empty) claim value.
	Kind string
}

// Error returns a human-readable description.
func (e *RefreshSubjectKindError) Error() string {
	if e.Kind == "" {
		return "auth: refresh token identity carries no subject kind"
	}
	return "auth: refresh token identity carries unknown subject kind: " + e.Kind
}

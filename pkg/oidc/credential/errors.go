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

package credential

import (
	"errors"
)

var (
	// ErrNilBarriers is returned by New without a barrier resolver.
	ErrNilBarriers = errors.New("oidc credential: nil barrier resolver")

	// ErrInvalidName is returned for a credential name outside
	// [A-Za-z0-9._-]{1,128} or starting with a dot.
	ErrInvalidName = errors.New("oidc credential: invalid name")

	// ErrScopeUnsupported is returned for a scope other than tenant (shared)
	// or user (personal).
	ErrScopeUnsupported = errors.New("oidc credential: scope must be tenant or user")

	// ErrNotFound is returned when the credential does not exist, or the
	// caller may not see it.
	ErrNotFound = errors.New("oidc credential: not found")

	// ErrExists is returned when creating a credential whose name is taken
	// in its scope.
	ErrExists = errors.New("oidc credential: already exists")

	// ErrInvalidConfig is returned for a configuration that names no usable
	// provider: no issuer, no client ID, an unknown template, or an
	// endpoint that is not https.
	ErrInvalidConfig = errors.New("oidc credential: invalid configuration")

	// ErrInvalidTokens is returned when imported tokens carry no access
	// token.
	ErrInvalidTokens = errors.New("oidc credential: invalid tokens")

	// ErrNoLogin is returned when a credential has no tokens yet: it awaits
	// a device login or an import.
	ErrNoLogin = errors.New("oidc credential: no login yet")

	// ErrReloginRequired is returned when the provider rejected the
	// credential's refresh token: only a new login or import restores it.
	ErrReloginRequired = errors.New("oidc credential: re-login required")

	// ErrTokenExpired is returned when a credential's access token has
	// expired and cannot be refreshed.
	ErrTokenExpired = errors.New("oidc credential: token expired")

	// ErrNotRefreshable is returned when a refresh is requested for a
	// credential whose provider issues no refresh tokens.
	ErrNotRefreshable = errors.New("oidc credential: provider tokens are not refreshable")

	// ErrNoDeviceLogin is returned when polling a credential that has no
	// device login in progress.
	ErrNoDeviceLogin = errors.New("oidc credential: no device login in progress")

	// ErrFlowUnsupported is returned when the credential's template does
	// not support the requested login flow.
	ErrFlowUnsupported = errors.New("oidc credential: login flow not supported by this provider")

	// ErrConcurrentUpdate is returned when a credential changed between
	// read and write and the write was refused by compare-and-swap.
	ErrConcurrentUpdate = errors.New("oidc credential: concurrent update")

	// ErrCorruptRecord is returned when a stored credential cannot be
	// decoded.
	ErrCorruptRecord = errors.New("oidc credential: corrupt record")

	// ErrClosed is returned after the service was closed.
	ErrClosed = errors.New("oidc credential: service closed")
)

// RefreshError reports a refresh that failed. Relogin is true when the
// provider rejected the refresh token, false for a failure a later refresh
// may overcome.
type RefreshError struct {
	// Name is the credential.
	Name string

	// Relogin is true when only a new login restores the credential.
	Relogin bool

	// Reason is the provider's error code, when it gave one.
	Reason string

	// Err is the underlying failure.
	Err error
}

// Error implements error.
func (e *RefreshError) Error() string {
	msg := "oidc credential: refresh of " + e.Name + " failed"
	if e.Reason != "" {
		msg += " (" + e.Reason + ")"
	}
	return msg + ": " + e.Err.Error()
}

// Unwrap returns the underlying failure, and ErrReloginRequired when the
// failure needs a new login.
func (e *RefreshError) Unwrap() []error {
	if e.Relogin {
		return []error{ErrReloginRequired, e.Err}
	}
	return []error{e.Err}
}

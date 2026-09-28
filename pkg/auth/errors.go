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

import (
	"errors"
	"strings"
)

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
)

// AuthMethodNotPermittedError is returned when a certificate resolves to an
// account in good standing whose permitted-authentication-method policy does
// not include the method that authenticated the request.
//
// It mirrors go-qrdb's auth/middleware AuthMethodNotPermittedError field for
// field so an operator reads the same refusal on the xkms planes as on qrdb's
// own: which method was refused against which permitted set.
type AuthMethodNotPermittedError struct {
	// Username is the account the certificate resolved to.
	Username string

	// TenantID is the account's tenant.
	TenantID string

	// Method is the authenticator that succeeded (e.g. "mtls").
	Method string

	// Permitted is the account's policy, in the order qrdb stores it.
	Permitted []string
}

// Error names the refused method and the permitted set.
func (e *AuthMethodNotPermittedError) Error() string {
	return "auth: authentication method " + e.Method +
		" is not permitted for " + e.Username + " in tenant " + e.TenantID +
		" (permitted: " + strings.Join(e.Permitted, ", ") + ")"
}

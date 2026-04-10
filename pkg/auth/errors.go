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
)

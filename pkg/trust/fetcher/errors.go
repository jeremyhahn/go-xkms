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

package fetcher

import "errors"

// Package errors are typed sentinels that callers can match with errors.Is.
var (
	// ErrInvalidURL indicates the provided URL is malformed or uses an
	// unsupported scheme.
	ErrInvalidURL = errors.New("trust/fetcher: invalid URL")

	// ErrInvalidPin indicates the SPKI pin string is malformed (must be a
	// 64-character lowercase hex SHA-256 digest).
	ErrInvalidPin = errors.New("trust/fetcher: invalid SPKI pin")

	// ErrPinRequired indicates no SPKI pin was supplied. Direct platform
	// fetches always require a pin obtained out-of-band; there is no
	// trust-on-first-use path.
	ErrPinRequired = errors.New("trust/fetcher: SPKI pin is required")

	// ErrPinMismatch indicates the server's leaf certificate SPKI did not
	// match the configured pin.
	ErrPinMismatch = errors.New("trust/fetcher: SPKI pin mismatch")

	// ErrHTTPStatus indicates the HTTP server returned a non-2xx response.
	ErrHTTPStatus = errors.New("trust/fetcher: unexpected HTTP status")

	// ErrEmptyBundle indicates the server response did not contain any
	// certificates.
	ErrEmptyBundle = errors.New("trust/fetcher: empty CA bundle")

	// ErrInvalidPEM indicates the response could not be decoded as PEM.
	ErrInvalidPEM = errors.New("trust/fetcher: invalid PEM data")

	// ErrInvalidJSON indicates a JSON fallback response could not be parsed.
	ErrInvalidJSON = errors.New("trust/fetcher: invalid JSON response")

	// ErrNoLeafCert indicates no peer certificate was presented during the
	// TLS handshake. This should never happen for a valid HTTPS server.
	ErrNoLeafCert = errors.New("trust/fetcher: no peer certificate presented")
)

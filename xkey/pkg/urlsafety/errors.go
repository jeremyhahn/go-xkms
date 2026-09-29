// Copyright (c) 2025-2026 Jeremy Hahn
// Copyright (c) 2025-2026 Automate The Things, LLC
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

package urlsafety

import "errors"

var (
	// ErrEmptyURL indicates an empty string was passed to ValidateLaunchURL.
	ErrEmptyURL = errors.New("urlsafety: URL cannot be empty")

	// ErrLeadingDash indicates the raw URL begins with '-', which a target
	// program invoked as `execCommand(url, ...)` or `execCommand(..., url)`
	// may parse as a command-line flag instead of a positional argument.
	ErrLeadingDash = errors.New("urlsafety: URL must not begin with '-'")

	// ErrControlCharacter indicates the raw URL contains an ASCII control
	// character (0x00-0x1F or 0x7F).
	ErrControlCharacter = errors.New("urlsafety: URL contains a control character")

	// ErrInvalidURL indicates the URL could not be parsed.
	ErrInvalidURL = errors.New("urlsafety: URL could not be parsed")

	// ErrDisallowedScheme indicates the URL scheme is not http or https.
	ErrDisallowedScheme = errors.New("urlsafety: URL scheme is not allowed; only http and https may be launched")

	// ErrMissingHost indicates the URL has no host component.
	ErrMissingHost = errors.New("urlsafety: URL has no host")

	// ErrInsecureEndpoint indicates a remote, discovery-supplied endpoint
	// used https validation and failed it: the endpoint was neither https
	// nor http on a loopback host.
	ErrInsecureEndpoint = errors.New("urlsafety: endpoint must use https (http is only allowed on loopback)")
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

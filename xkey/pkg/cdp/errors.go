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

package cdp

import "errors"

// Connection and transport errors.
var (
	ErrCDPConnectionFailed     = errors.New("cdp: connection failed")
	ErrCDPVersionFetchFailed   = errors.New("cdp: failed to fetch browser version")
	ErrCDPWebSocketURLNotFound = errors.New("cdp: WebSocket URL not found in version response")
	ErrCDPWriteFailed          = errors.New("cdp: WebSocket write failed")
	ErrCDPReadFailed           = errors.New("cdp: WebSocket read failed")

	// ErrCDPFIPSUnsupported is returned when FIPS 140-only mode is
	// enforced: the RFC 6455 WebSocket handshake requires SHA-1, which
	// that mode refuses.
	ErrCDPFIPSUnsupported = errors.New("cdp: the WebSocket handshake requires SHA-1, which FIPS 140-only mode refuses")
)

// Protocol-level errors.
var (
	ErrCDPRequestFailed       = errors.New("cdp: request failed")
	ErrCDPRequestTimeout      = errors.New("cdp: request timed out")
	ErrCDPResponseParseFailed = errors.New("cdp: failed to parse response")
	ErrCDPProtocolError       = errors.New("cdp: protocol returned error")
)

// WebAuthn domain errors.
var (
	ErrCDPAuthenticatorFailed  = errors.New("cdp: virtual authenticator creation failed")
	ErrCDPCredentialFailed     = errors.New("cdp: credential registration failed")
	ErrCDPEnableFailed         = errors.New("cdp: WebAuthn enable failed")
	ErrCDPDisableFailed        = errors.New("cdp: WebAuthn disable failed")
	ErrCDPRemoveFailed         = errors.New("cdp: virtual authenticator removal failed")
	ErrCDPGetCredentialsFailed = errors.New("cdp: get credentials failed")
)

// Bridge lifecycle errors.
var (
	ErrBridgeNotStarted     = errors.New("cdp/bridge: bridge has not been started")
	ErrBridgeAlreadyStarted = errors.New("cdp/bridge: bridge is already started")
	ErrBridgeNilClient      = errors.New("cdp/bridge: client is nil")
)

// ErrProtectedMemory reports that a StoredCredential's private key could
// not be placed in mlocked protected memory. The key is never kept on the
// ordinary heap as a fallback (go-xkms#587).
var ErrProtectedMemory = errors.New("cdp: protected memory allocation failed")

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

// WrappedError wraps an underlying cause with a contextual message while
// preserving errors.Is / errors.As matching through Unwrap. It replaces
// inline formatted-error constructions that wrap another error.
type WrappedError struct {
	Msg string
	Err error
}

// Error implements the error interface.
func (e *WrappedError) Error() string {
	return e.Msg + ": " + e.Err.Error()
}

// Unwrap returns the wrapped cause.
func (e *WrappedError) Unwrap() error {
	return e.Err
}

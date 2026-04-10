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
	ErrCDPAuthenticatorFailed = errors.New("cdp: virtual authenticator creation failed")
	ErrCDPCredentialFailed    = errors.New("cdp: credential registration failed")
	ErrCDPEnableFailed        = errors.New("cdp: WebAuthn enable failed")
	ErrCDPDisableFailed       = errors.New("cdp: WebAuthn disable failed")
	ErrCDPRemoveFailed        = errors.New("cdp: virtual authenticator removal failed")
)

// Bridge lifecycle errors.
var (
	ErrBridgeNotStarted     = errors.New("cdp/bridge: bridge has not been started")
	ErrBridgeAlreadyStarted = errors.New("cdp/bridge: bridge is already started")
	ErrBridgeNilClient      = errors.New("cdp/bridge: client is nil")
)

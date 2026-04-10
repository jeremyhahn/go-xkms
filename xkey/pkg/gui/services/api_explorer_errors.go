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

package services

import "errors"

// APIExplorerService errors.
var (
	// ErrExplorerNilConfig is returned when a nil configuration is provided.
	ErrExplorerNilConfig = errors.New("api_explorer: config is nil")

	// ErrExplorerClosed is returned when the service has been closed.
	ErrExplorerClosed = errors.New("api_explorer: service is closed")

	// ErrExplorerInvalidURL is returned when the request URL is empty or malformed.
	ErrExplorerInvalidURL = errors.New("api_explorer: invalid URL")

	// ErrExplorerInvalidMethod is returned when the HTTP method is unrecognized.
	ErrExplorerInvalidMethod = errors.New("api_explorer: invalid HTTP method")

	// ErrExplorerRequestFailed is returned when the HTTP request execution fails.
	ErrExplorerRequestFailed = errors.New("api_explorer: request failed")

	// ErrExplorerNilTokenStore is returned when a nil token store is provided.
	ErrExplorerNilTokenStore = errors.New("api_explorer: token store is nil")

	// ErrExplorerNilRegistry is returned when a nil server registry is provided.
	ErrExplorerNilRegistry = errors.New("api_explorer: server registry is nil")

	// ErrExplorerNilTrustStore is returned when a nil trust store is provided.
	ErrExplorerNilTrustStore = errors.New("api_explorer: trust store is nil")

	// ErrExplorerNilHistoryStore is returned when a nil history store is provided.
	ErrExplorerNilHistoryStore = errors.New("api_explorer: history store is nil")

	// ErrExplorerInvalidRequest is returned when a nil or invalid request is provided.
	ErrExplorerInvalidRequest = errors.New("api_explorer: invalid request")

	// ErrExplorerBodyTooLarge is returned when the response body exceeds the maximum size.
	ErrExplorerBodyTooLarge = errors.New("api_explorer: response body too large")

	// ErrExplorerHistoryNotFound is returned when a history entry cannot be found.
	ErrExplorerHistoryNotFound = errors.New("api_explorer: history entry not found")

	// ErrExplorerTokenListFailed is returned when listing available tokens fails.
	ErrExplorerTokenListFailed = errors.New("api_explorer: failed to list available tokens")
)

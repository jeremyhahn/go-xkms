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

// Package webui provides SPA file serving for the admin web interface.
package webui

// ErrAssetLoad indicates that the embedded frontend assets could not be loaded.
type ErrAssetLoad struct {
	Detail string
}

// Error returns the error message.
func (e *ErrAssetLoad) Error() string {
	return "webui: failed to load assets: " + e.Detail
}

// ErrIndexNotFound indicates that the SPA index.html file is missing.
type ErrIndexNotFound struct {
	Detail string
}

// Error returns the error message.
func (e *ErrIndexNotFound) Error() string {
	return "webui: index.html not found: " + e.Detail
}

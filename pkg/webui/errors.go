// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

// Package webui serves a compiled single-page application (the vite dist
// output) over HTTP: static assets with correct content types, no directory
// listings, and an index.html fallback for client-side routes. It is the
// canonical SPA file server for every router in the project; router-specific
// adapters (chi via MountChi here, gorilla/mux in pkg/acme/gui/webui)
// delegate to the same handler.
package webui

// ErrNilAssets indicates the SPA asset filesystem was nil.
type ErrNilAssets struct{}

// Error returns the error message.
func (e *ErrNilAssets) Error() string {
	return "webui: assets filesystem is nil"
}

// ErrNilRouter indicates the router to mount the SPA on was nil.
type ErrNilRouter struct{}

// Error returns the error message.
func (e *ErrNilRouter) Error() string {
	return "webui: router is nil"
}

// ErrInvalidPrefix indicates a mount prefix that is not an absolute URL path.
type ErrInvalidPrefix struct {
	Prefix string
}

// Error returns the error message.
func (e *ErrInvalidPrefix) Error() string {
	return "webui: invalid mount prefix: " + e.Prefix
}

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

package api

import (
	"net/http"

	"github.com/jeremyhahn/go-xkms/pkg/acme/gui/guard"
)

// Option configures the request guard installed in front of every API route.
// It is an alias of guard.Option; see package guard for the cross-origin
// policy shared with the ACME client GUI API.
type Option = guard.Option

// WithInProcessTransport declares that the router is mounted behind an
// in-process handler instead of a network listener. See package guard for
// the rationale. The admin router has no networked deployment today — it is
// reachable only through the Wails AssetServer Handler — but it is wired
// through the same policy object rather than a separate code path, so
// callers pass this option explicitly instead of the guard defaulting to it.
var WithInProcessTransport = guard.WithInProcessTransport

// denyOrigin writes a rejected request in this package's error envelope.
func denyOrigin(w http.ResponseWriter, r *http.Request, status int, err error) {
	writeErrorResponse(w, status, "FORBIDDEN_ORIGIN", err.Error())
}

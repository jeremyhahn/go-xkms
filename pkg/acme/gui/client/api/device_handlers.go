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
)

// deviceEnroll handles POST /api/v1/device/enroll.
func (h *handlers) deviceEnroll(w http.ResponseWriter, _ *http.Request) {
	writeError(w, http.StatusNotImplemented, "multi-account migration: handler not yet updated")
}

// deviceAttest handles POST /api/v1/device/attest.
func (h *handlers) deviceAttest(w http.ResponseWriter, _ *http.Request) {
	writeError(w, http.StatusNotImplemented, "multi-account migration: handler not yet updated")
}

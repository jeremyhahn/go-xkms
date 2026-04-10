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

package rest

import (
	"net/http"

	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// AlgorithmsHandler handles GET /api/v1/algorithms requests.
// It returns all supported algorithms based on compiled backends.
// This is a public discovery endpoint and does not require authentication.
func (h *HandlerContext) AlgorithmsHandler(w http.ResponseWriter, r *http.Request) {
	resp := xkms.DiscoverAlgorithms()
	writeJSON(w, resp, http.StatusOK)
}

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

package quic

import "net/http"

// handleAlgorithms handles GET /api/v1/algorithms. Like the REST route it
// mirrors, this is public discovery: the inventory is derived from the
// compiled-in backend registry, so it carries no authorization gate.
func (s *Server) handleAlgorithms(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.xkmsService == nil {
		s.sendError(w, http.StatusServiceUnavailable, "xkms service not configured")
		return
	}

	resp, err := s.xkmsService.Algorithms(r.Context())
	if err != nil {
		s.sendError(w, http.StatusInternalServerError, "failed to discover algorithms")
		return
	}

	s.sendJSON(w, http.StatusOK, resp)
}

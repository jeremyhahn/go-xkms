// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-ca.
//
// go-trusted-ca is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package api

import (
	"log/slog"
	"net/http"
)

// getStatus handles GET /api/v1/status.
func (h *handlers) getStatus(w http.ResponseWriter, r *http.Request) {
	status, err := h.client.Admin().Status().Status(r.Context())
	if err != nil {
		h.logger.Error("failed to get status", slog.String("error", err.Error()))
		writeErrorResponse(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to get CA status")
		return
	}

	writeJSON(w, http.StatusOK, status, nil)
}

// getStats handles GET /api/v1/stats.
func (h *handlers) getStats(w http.ResponseWriter, r *http.Request) {
	stats, err := h.client.Admin().Status().Stats(r.Context())
	if err != nil {
		h.logger.Error("failed to get stats", slog.String("error", err.Error()))
		writeErrorResponse(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to get CA stats")
		return
	}

	writeJSON(w, http.StatusOK, stats, nil)
}

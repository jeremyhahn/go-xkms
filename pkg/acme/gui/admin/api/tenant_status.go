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
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/gorilla/mux"

	sdkadmin "github.com/jeremyhahn/go-xkms/sdk/go/acme/client/admin"
	sdkerrors "github.com/jeremyhahn/go-xkms/sdk/go/acme/errors"
)

// updateTenantStatus handles PUT /api/v1/tenants/{id}/status.
func (h *handlers) updateTenantStatus(w http.ResponseWriter, r *http.Request) {
	tenantID := mux.Vars(r)["id"]

	var req sdkadmin.UpdateTenantStatusRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErrorResponse(w, http.StatusBadRequest, "INVALID_REQUEST", "invalid request body")
		return
	}

	if req.Status == "" {
		writeErrorResponse(w, http.StatusBadRequest, "VALIDATION_ERROR", "status is required")
		return
	}

	if err := h.client.Admin().TenantCA().UpdateTenantStatus(r.Context(), tenantID, req.Status); err != nil {
		var notFound *sdkadmin.TenantNotFoundError
		if isErrorType(err, &notFound) {
			writeErrorResponse(w, http.StatusNotFound, "NOT_FOUND", "tenant not found")
			return
		}
		if errors.Is(err, sdkadmin.ErrTenantStatusUnsupported) || sdkerrors.IsInvalidInput(err) {
			writeErrorResponse(w, http.StatusBadRequest, "TENANT_STATUS_UNSUPPORTED", "tenant status is not supported")
			return
		}
		h.logger.Error("failed to update tenant status",
			slog.String("tenant_id", tenantID),
			slog.String("status", req.Status),
			slog.String("error", err.Error()),
		)
		writeErrorResponse(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to update tenant status")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "tenant status updated successfully"}, nil)
}

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
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/gorilla/mux"

	sdkadmin "github.com/jeremyhahn/go-xkms/sdk/go/acme/client/admin"
)

// createTenantRootCA handles POST /api/v1/tenants/{id}/root-ca.
func (h *handlers) createTenantRootCA(w http.ResponseWriter, r *http.Request) {
	tenantID := mux.Vars(r)["id"]

	var req sdkadmin.CreateTenantRootCARequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErrorResponse(w, http.StatusBadRequest, "INVALID_REQUEST", "invalid request body")
		return
	}

	rootCA, err := h.client.Admin().TenantCA().CreateRootCA(r.Context(), tenantID, &req)
	if err != nil {
		var notFound *sdkadmin.TenantNotFoundError
		var exists *sdkadmin.TenantRootCAExistsError
		switch {
		case isErrorType(err, &notFound):
			writeErrorResponse(w, http.StatusNotFound, "NOT_FOUND", "tenant not found")
		case isErrorType(err, &exists):
			writeErrorResponse(w, http.StatusConflict, "ALREADY_EXISTS", "tenant root CA already exists")
		default:
			h.logger.Error("failed to create tenant root CA",
				slog.String("tenant_id", tenantID),
				slog.String("error", err.Error()),
			)
			writeErrorResponse(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to create tenant root CA")
		}
		return
	}

	writeJSON(w, http.StatusCreated, rootCA, nil)
}

// getTenantCAStatus handles GET /api/v1/tenants/{id}/ca-status.
func (h *handlers) getTenantCAStatus(w http.ResponseWriter, r *http.Request) {
	tenantID := mux.Vars(r)["id"]

	status, err := h.client.Admin().TenantCA().CAStatus(r.Context(), tenantID)
	if err != nil {
		var notFound *sdkadmin.TenantNotFoundError
		if isErrorType(err, &notFound) {
			writeErrorResponse(w, http.StatusNotFound, "NOT_FOUND", "tenant not found")
			return
		}
		h.logger.Error("failed to get tenant CA status",
			slog.String("tenant_id", tenantID),
			slog.String("error", err.Error()),
		)
		writeErrorResponse(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to get tenant CA status")
		return
	}

	writeJSON(w, http.StatusOK, status, nil)
}

// createIntermediateCA handles POST /api/v1/tenants/{id}/intermediate-cas.
func (h *handlers) createIntermediateCA(w http.ResponseWriter, r *http.Request) {
	tenantID := mux.Vars(r)["id"]

	var req sdkadmin.CreateTenantIntermediateCARequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErrorResponse(w, http.StatusBadRequest, "INVALID_REQUEST", "invalid request body")
		return
	}

	intCA, err := h.client.Admin().TenantCA().CreateIntermediateCA(r.Context(), tenantID, &req)
	if err != nil {
		var notFound *sdkadmin.TenantNotFoundError
		var exists *sdkadmin.IntermediateCAExistsError
		switch {
		case isErrorType(err, &notFound):
			writeErrorResponse(w, http.StatusNotFound, "NOT_FOUND", "tenant not found")
		case isErrorType(err, &exists):
			writeErrorResponse(w, http.StatusConflict, "ALREADY_EXISTS", "intermediate CA already exists")
		default:
			h.logger.Error("failed to create intermediate CA",
				slog.String("tenant_id", tenantID),
				slog.String("error", err.Error()),
			)
			writeErrorResponse(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to create intermediate CA")
		}
		return
	}

	writeJSON(w, http.StatusCreated, intCA, nil)
}

// listIntermediateCAs handles GET /api/v1/tenants/{id}/intermediate-cas.
func (h *handlers) listIntermediateCAs(w http.ResponseWriter, r *http.Request) {
	tenantID := mux.Vars(r)["id"]

	cas, err := h.client.Admin().TenantCA().ListIntermediateCAs(r.Context(), tenantID)
	if err != nil {
		var notFound *sdkadmin.TenantNotFoundError
		if isErrorType(err, &notFound) {
			writeErrorResponse(w, http.StatusNotFound, "NOT_FOUND", "tenant not found")
			return
		}
		h.logger.Error("failed to list intermediate CAs",
			slog.String("tenant_id", tenantID),
			slog.String("error", err.Error()),
		)
		writeErrorResponse(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to list intermediate CAs")
		return
	}

	writeJSON(w, http.StatusOK, cas, nil)
}

// getIntermediateCA handles GET /api/v1/tenants/{id}/intermediate-cas/{caId}.
func (h *handlers) getIntermediateCA(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	tenantID := vars["id"]
	caID := vars["caId"]

	intCA, err := h.client.Admin().TenantCA().GetIntermediateCA(r.Context(), tenantID, caID)
	if err != nil {
		var notFound *sdkadmin.IntermediateCANotFoundError
		if isErrorType(err, &notFound) {
			writeErrorResponse(w, http.StatusNotFound, "NOT_FOUND", "intermediate CA not found")
			return
		}
		h.logger.Error("failed to get intermediate CA",
			slog.String("tenant_id", tenantID),
			slog.String("ca_id", caID),
			slog.String("error", err.Error()),
		)
		writeErrorResponse(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to get intermediate CA")
		return
	}

	writeJSON(w, http.StatusOK, intCA, nil)
}

// updateIntermediateCAStatus handles PUT /api/v1/tenants/{id}/intermediate-cas/{caId}.
func (h *handlers) updateIntermediateCAStatus(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	tenantID := vars["id"]
	caID := vars["caId"]

	var req sdkadmin.UpdateIntermediateCAStatusRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErrorResponse(w, http.StatusBadRequest, "INVALID_REQUEST", "invalid request body")
		return
	}

	if req.Status == "" {
		writeErrorResponse(w, http.StatusBadRequest, "VALIDATION_ERROR", "status is required")
		return
	}

	if err := h.client.Admin().TenantCA().UpdateIntermediateCAStatus(r.Context(), tenantID, caID, req.Status); err != nil {
		var notFound *sdkadmin.IntermediateCANotFoundError
		if isErrorType(err, &notFound) {
			writeErrorResponse(w, http.StatusNotFound, "NOT_FOUND", "intermediate CA not found")
			return
		}
		h.logger.Error("failed to update intermediate CA status",
			slog.String("tenant_id", tenantID),
			slog.String("ca_id", caID),
			slog.String("error", err.Error()),
		)
		writeErrorResponse(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to update intermediate CA status")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "intermediate CA status updated successfully"}, nil)
}

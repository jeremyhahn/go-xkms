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
	"log/slog"
	"net/http"

	"github.com/gorilla/mux"

	adminsdk "github.com/jeremyhahn/go-xkms/sdk/go/acme/client/admin"
	sdkerrors "github.com/jeremyhahn/go-xkms/sdk/go/acme/errors"
)

// revokeRequest is the JSON request body for certificate revocation.
type revokeRequest struct {
	Reason string `json:"reason,omitempty"`
}

// listCertificates handles GET /admin/certificates.
func (h *handlers) listCertificates(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	req := &adminsdk.ListCertificatesRequest{
		Page:    parseInt(query.Get("page"), 1),
		PerPage: parseInt(query.Get("per_page"), 20),
		Status:  query.Get("status"),
		Subject: query.Get("subject"),
	}
	if query.Has("expires_days") {
		req.ExpiresDays = parseInt(query.Get("expires_days"), 0)
		if req.ExpiresDays <= 0 {
			writeErrorResponse(w, http.StatusBadRequest, "VALIDATION_ERROR", "expires_days must be a positive integer")
			return
		}
	}

	resp, err := h.client.Admin().Certificate().List(r.Context(), req)
	if err != nil {
		h.logger.Error("failed to list certificates", slog.String("error", err.Error()))
		writeErrorResponse(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to list certificates")
		return
	}

	writeJSON(w, http.StatusOK, resp.Certificates, resp.Pagination)
}

// getCertificate handles GET /admin/certificates/{serial}.
func (h *handlers) getCertificate(w http.ResponseWriter, r *http.Request) {
	serial := mux.Vars(r)["serial"]

	cert, err := h.client.Admin().Certificate().Get(r.Context(), serial)
	if err != nil {
		if sdkerrors.IsNotFound(err) {
			writeErrorResponse(w, http.StatusNotFound, "NOT_FOUND", "certificate not found")
			return
		}
		h.logger.Error("failed to get certificate",
			slog.String("serial", serial),
			slog.String("error", err.Error()),
		)
		writeErrorResponse(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to get certificate")
		return
	}

	writeJSON(w, http.StatusOK, cert, nil)
}

// revokeCertificate handles POST /admin/certificates/{serial}/revoke.
func (h *handlers) revokeCertificate(w http.ResponseWriter, r *http.Request) {
	serial := mux.Vars(r)["serial"]

	var req revokeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErrorResponse(w, http.StatusBadRequest, "INVALID_REQUEST", "invalid request body")
		return
	}

	if err := h.client.Admin().Certificate().Revoke(r.Context(), serial, req.Reason); err != nil {
		if sdkerrors.IsNotFound(err) {
			writeErrorResponse(w, http.StatusNotFound, "NOT_FOUND", "certificate not found")
			return
		}
		h.logger.Error("failed to revoke certificate",
			slog.String("serial", serial),
			slog.String("error", err.Error()),
		)
		writeErrorResponse(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to revoke certificate")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "certificate revoked successfully"}, nil)
}

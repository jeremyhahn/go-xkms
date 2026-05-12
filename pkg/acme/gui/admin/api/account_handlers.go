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
	"strconv"

	"github.com/gorilla/mux"

	adminsdk "github.com/jeremyhahn/go-xkms/sdk/go/acme/client/admin"
	sdkerrors "github.com/jeremyhahn/go-xkms/sdk/go/acme/errors"
)

// listAccounts handles GET /api/v1/accounts.
func (h *handlers) listAccounts(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	req := &adminsdk.ListAccountsRequest{
		Page:    parseInt(query.Get("page"), 1),
		PerPage: parseInt(query.Get("per_page"), 20),
		Status:  query.Get("status"),
	}

	resp, err := h.client.Admin().Account().List(r.Context(), req)
	if err != nil {
		h.logger.Error("failed to list accounts", slog.String("error", err.Error()))
		writeErrorResponse(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to list accounts")
		return
	}

	writeJSON(w, http.StatusOK, resp.Accounts, resp.Pagination)
}

// getAccount handles GET /api/v1/accounts/{id}.
func (h *handlers) getAccount(w http.ResponseWriter, r *http.Request) {
	accountID, err := strconv.ParseUint(mux.Vars(r)["id"], 10, 64)
	if err != nil {
		writeErrorResponse(w, http.StatusBadRequest, "INVALID_ID", "invalid account ID")
		return
	}

	account, err := h.client.Admin().Account().Get(r.Context(), accountID)
	if err != nil {
		if sdkerrors.IsNotFound(err) {
			writeErrorResponse(w, http.StatusNotFound, "NOT_FOUND", "account not found")
			return
		}
		h.logger.Error("failed to get account",
			slog.Uint64("id", accountID),
			slog.String("error", err.Error()),
		)
		writeErrorResponse(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to get account")
		return
	}

	writeJSON(w, http.StatusOK, account, nil)
}

// disableAccount handles DELETE /api/v1/accounts/{id}.
func (h *handlers) disableAccount(w http.ResponseWriter, r *http.Request) {
	accountID, err := strconv.ParseUint(mux.Vars(r)["id"], 10, 64)
	if err != nil {
		writeErrorResponse(w, http.StatusBadRequest, "INVALID_ID", "invalid account ID")
		return
	}

	if err := h.client.Admin().Account().Disable(r.Context(), accountID); err != nil {
		if sdkerrors.IsNotFound(err) {
			writeErrorResponse(w, http.StatusNotFound, "NOT_FOUND", "account not found")
			return
		}
		h.logger.Error("failed to disable account",
			slog.Uint64("id", accountID),
			slog.String("error", err.Error()),
		)
		writeErrorResponse(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to disable account")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "account disabled successfully"}, nil)
}

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
	"log/slog"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"

	sdkadmin "github.com/jeremyhahn/go-xkms/sdk/go/acme/client/admin"
)

// listOrders handles GET /admin/orders.
func (h *handlers) listOrders(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	req := &sdkadmin.ListOrdersRequest{
		Page:    parseInt(query.Get("page"), 1),
		PerPage: parseInt(query.Get("per_page"), 20),
		Status:  query.Get("status"),
	}

	if accountIDStr := query.Get("account_id"); accountIDStr != "" {
		accountID, err := strconv.ParseUint(accountIDStr, 10, 64)
		if err != nil {
			writeErrorResponse(w, http.StatusBadRequest, "INVALID_PARAM", "invalid account_id parameter")
			return
		}
		req.AccountID = accountID
	}

	resp, err := h.client.Admin().Order().List(r.Context(), req)
	if err != nil {
		h.logger.Error("failed to list orders", slog.String("error", err.Error()))
		writeErrorResponse(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to list orders")
		return
	}

	writeJSON(w, http.StatusOK, resp.Orders, resp.Pagination)
}

// getOrder handles GET /admin/orders/{id}.
func (h *handlers) getOrder(w http.ResponseWriter, r *http.Request) {
	orderID, err := strconv.ParseUint(mux.Vars(r)["id"], 10, 64)
	if err != nil {
		writeErrorResponse(w, http.StatusBadRequest, "INVALID_ID", "invalid order ID")
		return
	}

	order, err := h.client.Admin().Order().Get(r.Context(), orderID)
	if err != nil {
		var notFound *sdkadmin.OrderNotFoundError
		if isErrorType(err, &notFound) {
			writeErrorResponse(w, http.StatusNotFound, "NOT_FOUND", "order not found")
			return
		}
		h.logger.Error("failed to get order",
			slog.Uint64("id", orderID),
			slog.String("error", err.Error()),
		)
		writeErrorResponse(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to get order")
		return
	}

	writeJSON(w, http.StatusOK, order, nil)
}

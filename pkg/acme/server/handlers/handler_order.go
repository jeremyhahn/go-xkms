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

package handlers

import (
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
)

func (s *RestService) OrderHandler(w http.ResponseWriter, r *http.Request) {

	s.logger.Debug("OrderHandler", "method", r.Method, "url", r.URL)
	ctx := r.Context()

	account, _, err := s.parseKID(ctx, r)
	if err != nil {
		writeError(w, common.MalformedError("Failed to parse account key", nil))
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	strOrderID := mux.Vars(r)["id"]
	orderID, err := strconv.ParseUint(strOrderID, 10, 64)
	if err != nil {
		writeError(w, common.MalformedError("Invalid order ID", nil))
		return
	}

	orderDAO, err := s.storageFactory.OrderDAO(account.ID)
	if err != nil {
		writeError(w, common.ServerInternal("Failed to create order DAO"))
		return
	}

	order, err := orderDAO.Get(ctx, orderID)
	if err != nil {
		if qrdbsdk.IsDAONotFound(err) {
			writeError(w, common.MalformedError("Order not found", nil))
		} else {
			s.logger.Error("Storage error retrieving order", "error", err)
			writeError(w, common.ServerInternal("Storage error"))
		}
		return
	}

	if order.AccountID != account.ID {
		writeError(w, common.Unauthorized("Unauthorized"))
		return
	}

	s.orderResponse(w, order)
}

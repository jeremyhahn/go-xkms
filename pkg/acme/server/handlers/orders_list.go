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
	"fmt"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
)

const ordersListNonceSize = 16

func (s *RestService) OrdersListHandler(w http.ResponseWriter, r *http.Request) {

	s.logger.Debug("OrdersListHandler", "method", r.Method, "url", r.URL)
	ctx := r.Context()

	// Page parameter validation (not currently used)
	vars := mux.Vars(r)
	strPage := vars["page"]

	if len(strPage) > 0 {
		_, err := strconv.ParseInt(strPage, 10, 64)
		if err != nil {
			writeError(w, common.MalformedError("Invalid page ID", nil))
			return
		}
	}

	account, _, err := s.parseKID(ctx, r)
	if err != nil {
		writeError(w, common.MalformedError("Failed to parse account key", nil))
		return
	}

	orderDAO, err := s.storageFactory.OrderDAO(account.ID)
	if err != nil {
		writeError(w, common.ServerInternal("Failed to create order DAO"))
		return
	}

	if r.Method == http.MethodGet || r.Method == http.MethodPost {

		// List orders for the account using ForEachPage
		var orders []*entities.ACMEOrder
		err := orderDAO.ForEachPage(ctx, qrdbsdk.PageQuery{PageSize: 1000}, func(page qrdbsdk.PageResult[*entities.ACMEOrder]) error {
			orders = append(orders, page.Entities...)
			return nil
		})
		if err != nil {
			writeError(w, common.ServerInternal("Failed to retrieve orders"))
			return
		}

		orderURLs := []string{}
		for _, order := range orders {
			orderURLs = append(orderURLs, order.URL)
		}
		response := map[string][]string{
			"orders": orderURLs,
		}

		// Generate nonce for Replay-Nonce header per RFC 8555 Section 6.5
		nonce, err := common.GenerateNonce(ordersListNonceSize)
		if err != nil {
			writeError(w, common.ServerInternal("Unable to generate nonce"))
			return
		}
		s.nonceStore.Add(nonce)

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Replay-Nonce", nonce)
		w.Header().Set("Link", fmt.Sprintf("<%s/acme/directory>;rel=\"index\"", s.baseRESTURI))
		s.encodeJSON(w, response)

	} else {
		writeError(w, common.MalformedError("Method not allowed", nil))
	}
}

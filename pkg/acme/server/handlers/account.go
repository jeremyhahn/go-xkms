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

package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
)

// AccountRequest represents the structure of an account update/deactivation request.
type AccountRequest struct {
	Status  string   `json:"status,omitempty"`
	Contact []string `json:"contact,omitempty"`
}

// AccountHandler handles account retrieval and modification per RFC 8555 Section 7.3.2.
// It allows clients to:
// - Retrieve account details
// - Update contact information
// - Deactivate the account
func (s *RestService) AccountHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	s.logger.Debug("AccountHandler", "method", r.Method, "url", r.URL.String())

	account, payload, err := s.parseKID(ctx, r)
	if err != nil {
		s.logger.Error("Failed to parse KID", "error", err)
		writeError(w, common.MalformedError("Failed to parse account key", nil))
		return
	}

	accountDAO, err := s.storageFactory.AccountDAO()
	if err != nil {
		writeError(w, common.ServerInternal("Failed to create account DAO"))
		return
	}

	// Handle post-as-get (empty payload) - just return account details
	if len(payload) == 0 {
		s.respondWithAccount(w, account, http.StatusOK)
		return
	}

	var accountRequest AccountRequest
	if err := json.Unmarshal(payload, &accountRequest); err != nil {
		writeError(w, common.MalformedError("Invalid request payload", nil))
		return
	}

	// Handle account status update
	if accountRequest.Status != "" {
		if accountRequest.Status == common.StatusDeactivated {
			if account.Status == common.StatusDeactivated {
				writeError(w, common.MalformedError("Account is already deactivated", nil))
				return
			}
			account.Status = common.StatusDeactivated
			s.logger.Info("Account deactivated", "id", account.ID)
		} else {
			writeError(w, common.MalformedError("Invalid status value", nil))
			return
		}
	}

	// Handle contact update
	if accountRequest.Contact != nil {
		if err := ValidateContactURLs(accountRequest.Contact); err != nil {
			writeError(w, err)
			return
		}
		account.Contact = accountRequest.Contact
		s.logger.Info("Account contacts updated", "id", account.ID)
	}

	// Save updated account
	if err := accountDAO.Save(ctx, account); err != nil {
		s.logger.Error("Failed to update account", "error", err)
		writeError(w, common.ServerInternal("Failed to update account"))
		return
	}

	s.respondWithAccount(w, account, http.StatusOK)
}

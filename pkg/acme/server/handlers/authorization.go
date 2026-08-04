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
	"strings"

	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
)

const authzNonceSize = 16

func (s *RestService) AuthorizationHandler(w http.ResponseWriter, r *http.Request) {

	s.logger.Info("=== AuthorizationHandler CALLED ===",
		"method", r.Method,
		"url", r.URL.String(),
		"path", r.URL.Path)

	s.logger.Debug("AuthorizationHandler", "method", r.Method, "url", r.URL)
	ctx := r.Context()

	account, _, err := s.parseKID(ctx, r)
	if err != nil {
		s.logger.Error("Failed to parse account key", "error", err)
		writeError(w, common.MalformedError("Failed to parse account key", nil))
		return
	}

	s.logger.Info("Parsed account", "account_id", account.ID)

	pieces := strings.Split(r.URL.Path, "/")
	sAuthzID := pieces[len(pieces)-1]
	if sAuthzID == "" {
		s.logger.Error("Authorization ID not provided in URL")
		http.Error(w, "Authorization ID not provided", http.StatusBadRequest)
		return
	}

	s.logger.Info("Extracted authorization ID", "authz_id_string", sAuthzID)

	authzID, err := strconv.ParseUint(sAuthzID, 10, 64)
	if err != nil {
		s.logger.Error("Invalid authorization ID", "error", err)
		writeError(w, common.MalformedError("Invalid authorization ID", nil))
		return
	}

	s.logger.Info("Routing to handler", "method", r.Method, "authz_id", authzID, "account_id", account.ID)

	switch r.Method {
	case http.MethodGet:
		s.logger.Info("Calling GET handler")
		s.authorizationGetHandler(w, r, account.ID, authzID)
	case http.MethodPost:
		s.logger.Info("Calling POST handler")
		s.authorizationPostHandler(w, r, account.ID, authzID)
	default:
		s.logger.Error("Method not allowed", "method", r.Method)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleAuthorizationGet handles GET requests for an authorization.
func (s *RestService) authorizationGetHandler(
	w http.ResponseWriter, r *http.Request, accountID, authzID uint64) {

	ctx := r.Context()
	authorizationDAO, err := s.storageFactory.AuthorizationDAO(accountID)
	if err != nil {
		writeError(w, common.ServerInternal("Failed to create account DAO"))
		return
	}

	authorization, err := authorizationDAO.Get(ctx, authzID)
	if err != nil {
		writeError(w, common.MalformedError("Authorization not found", nil))
		return
	}

	// Generate nonce for Replay-Nonce header per RFC 8555 Section 6.5
	nonce, err := common.GenerateNonce(authzNonceSize)
	if err != nil {
		writeError(w, common.ServerInternal("Unable to generate nonce"))
		return
	}
	s.nonceStore.Add(nonce)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Replay-Nonce", nonce)
	w.Header().Set("Link", fmt.Sprintf("<%s/acme/directory>;rel=\"index\"", s.baseRESTURI))
	s.encodeJSON(w, authorization)
}

// handleAuthorizationPost handles POST requests to respond to a challenge.
func (s *RestService) authorizationPostHandler(
	w http.ResponseWriter, r *http.Request, accountID, authzID uint64) {

	s.logger.Info("Authorization POST handler called",
		"account_id", accountID,
		"authz_id", authzID)

	ctx := r.Context()
	authorizationDAO, err := s.storageFactory.AuthorizationDAO(accountID)
	if err != nil {
		writeError(w, common.ServerInternal("Failed to create account DAO"))
		return
	}

	authz, err := authorizationDAO.Get(ctx, authzID)
	if err != nil {
		s.logger.Error("Failed to get authorization", "error", err)
		writeError(w, common.MalformedError("Authorization not found", nil))
		return
	}

	s.logger.Info("Retrieved authorization",
		"num_challenges", len(authz.Challenges),
		"identifier_type", authz.Identifier.Type,
		"status", authz.Status)

	// Log each challenge
	for i, ch := range authz.Challenges {
		s.logger.Info("Challenge in authorization",
			"index", i,
			"type", ch.Type,
			"status", ch.Status,
			"token", ch.Token)
	}

	if authz.AccountID != accountID {
		writeError(w, common.Unauthorized("Unauthorized"))
		return
	}

	clientAuthz := struct {
		Identifier entities.ACMEIdentifier  `json:"identifier"`
		Status     string                   `json:"status"`
		Expires    string                   `json:"expires,omitempty"`
		Challenges []entities.ACMEChallenge `json:"challenges"`
		Wildcard   *bool                    `json:"wildcard,omitempty"`
	}{
		Identifier: authz.Identifier,
		Status:     authz.Status,
		Expires:    authz.Expires,
		Challenges: authz.Challenges,
	}

	if authz.Wildcard {
		clientAuthz.Wildcard = &authz.Wildcard
	}

	s.logger.Info("Sending authorization response",
		"num_challenges", len(clientAuthz.Challenges))

	// Generate nonce for Replay-Nonce header per RFC 8555 Section 6.5
	nonce, err := common.GenerateNonce(authzNonceSize)
	if err != nil {
		writeError(w, common.ServerInternal("Unable to generate nonce"))
		return
	}
	s.nonceStore.Add(nonce)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Replay-Nonce", nonce)
	w.Header().Set("Link", fmt.Sprintf("<%s/acme/directory>;rel=\"index\"", s.baseRESTURI))
	s.encodeJSON(w, clientAuthz)
}

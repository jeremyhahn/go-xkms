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
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/acme/audit"
	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	caerrors "github.com/jeremyhahn/go-xkms/pkg/acme/errors"
	"github.com/jeremyhahn/go-xkms/pkg/acme/server/metrics"
)

type NewOrderRequest struct {
	Identifiers []entities.ACMEIdentifier `yaml:"identifiers" json:"identifiers"`
	NotBefore   string                    `yaml:"not-before" json:"notBefore,omitempty"`
	NotAfter    string                    `yaml:"not-after" json:"notAfter,omitempty"`
}

func (s *RestService) NewOrderHandler(w http.ResponseWriter, r *http.Request) {

	s.logger.Debug("NewOrderHandler", "method", r.Method, "url", r.URL)
	ctx := r.Context()

	account, payload, err := s.parseKID(ctx, r)
	if err != nil {
		s.logger.Error("NewOrderHandler: parseKID failed", "error", err.Error())
		writeError(w, common.MalformedError("Failed to parse account key", nil))
		return
	}

	var req NewOrderRequest

	// Parse the payload
	if err := json.Unmarshal(payload, &req); err != nil {
		errResp := common.MalformedError("Invalid JSON payload", nil)
		writeError(w, errResp)
		return
	}

	authorizationDAO, err := s.storageFactory.AuthorizationDAO(account.ID)
	if err != nil {
		writeError(w, common.ServerInternal("Failed to create authorization DAO"))
		return
	}

	orderDAO, err := s.storageFactory.OrderDAO(account.ID)
	if err != nil {
		writeError(w, common.ServerInternal("Failed to create order DAO"))
		return
	}

	orderID, err := GenerateID()
	if err != nil {
		writeError(w, common.ServerInternal("Failed to generate order ID"))
		return
	}

	orderURL := fmt.Sprintf("%s/acme/order/%d", s.baseRESTURI, orderID)
	finalizeURL := fmt.Sprintf("%s/acme/order/%d/finalize", s.baseRESTURI, orderID)

	// Validate identifiers
	authzURLs := []string{}
	for _, id := range req.Identifiers {

		// Validate the identifier type
		switch id.Type {
		case common.AuthzTypeDNS, common.AuthzTypeIP, common.AuthzTypePermanentIdentifier:
			// Valid identifier type
		default:
			writeError(w, common.UnsupportedIdentifier("Unsupported authorization identifier"))
			return
		}

		if !s.challengePolicy.IsIdentifierTypeEnabled(id.Type) {
			writeError(w, common.UnsupportedIdentifier(
				fmt.Sprintf("Identifier type %q is disabled by policy", id.Type)))
			return
		}

		// RFC 1035 (DNS) / RFC 8738 (IP) / minimal (permanent-identifier)
		// syntax validation. A malformed identifier is a client error,
		// regardless of what the server's issuance policy allows.
		if err := validateIdentifierFormat(id); err != nil {
			writeError(w, common.MalformedError(err.Error(), nil))
			return
		}

		// Domain/FQDN/wildcard/CIDR blocklist, public-suffix, and
		// reserved-IP policy enforcement. The identifier is well-formed but
		// the server refuses to issue for it (RFC 8555 rejectedIdentifier).
		if err := s.checkIdentifierPolicy(id); err != nil {
			writeError(w, common.RejectedIdentifier(err.Error()))
			return
		}

		domain := id.Value
		isWildcard := false
		if id.Type == common.AuthzTypeDNS && strings.HasPrefix(domain, "*.") {
			isWildcard = true
			domain = strings.TrimPrefix(domain, "*.")
		}

		// Skip the issued check - the CA will handle duplicate certificate checks
		// if needed during signing

		// Create authorization
		authzID, err := GenerateID()
		if err != nil {
			writeError(w, common.ServerInternal("Failed to generate authorization ID"))
			return
		}
		authzURL := fmt.Sprintf("%s/acme/authz/%d", s.baseRESTURI, authzID)

		// Create challenge (pass isWildcard to restrict HTTP-01 for wildcard domains per RFC 8555)
		challenges, err := s.createChallenges(account.ID, authzID, id, isWildcard)
		if err != nil {
			writeError(w, common.ServerInternal("Failed to create authorization challenge"))
			return
		}

		// Save authorization
		authorization := &entities.ACMEAuthorization{
			ID:        authzID,
			OrderID:   orderID,
			AccountID: account.ID,
			Status:    common.StatusPending,
			Expires:   time.Now().Add(7 * 24 * time.Hour).Format(time.RFC3339),
			Identifier: entities.ACMEIdentifier{
				Type:  id.Type,
				Value: domain,
			},
			Challenges: challenges,
			Wildcard:   isWildcard,
			URL:        authzURL,
		}
		if err := authorizationDAO.Save(ctx, authorization); err != nil {
			s.logger.Error("Failed to save authorization", "error", err, "authzID", authzID, "accountID", account.ID)
			writeError(w, common.ServerInternal(fmt.Sprintf("Failed to save authorization: %v", err)))
			return
		}
		for range challenges {
			metrics.IncPendingChallenges()
		}

		authzURLs = append(authzURLs, authzURL)
	}

	order := &entities.ACMEOrder{
		ID:             orderID,
		AccountID:      account.ID,
		Status:         common.StatusPending,
		Expires:        time.Now().Add(24 * time.Hour).Format(time.RFC3339),
		Identifiers:    req.Identifiers,
		NotBefore:      req.NotBefore,
		NotAfter:       req.NotAfter,
		Authorizations: authzURLs,
		Finalize:       finalizeURL,
		URL:            orderURL,
	}

	if err := orderDAO.Save(ctx, order); err != nil {
		writeError(w, common.ServerInternal("Failed to save order"))
		return
	}
	metrics.IncActiveOrders()
	if account.TenantID != "" {
		metrics.IncTenantActiveOrders(account.TenantID)
	}

	orderIdentifiers := make([]string, 0, len(order.Identifiers))
	for _, identifier := range order.Identifiers {
		orderIdentifiers = append(orderIdentifiers, identifier.Value)
	}
	if auditErr := s.recordAudit(audit.EventOrderCreated, audit.LogOrderCreated(auditContext(r), s.auditLog,
		auditAccountID(account.ID), strconv.FormatUint(order.ID, 10), orderIdentifiers)); auditErr != nil {
		writeError(w, common.ServerInternal("Failed to record audit event"))
		return
	}

	// Respond with the order object
	w.Header().Set("Location", orderURL)
	w.WriteHeader(http.StatusCreated)
	s.orderResponse(w, order)
}

// Create challenges for the given account and authorization
// isWildcard indicates if the identifier is a wildcard domain (e.g., *.example.com)
// Per RFC 8555, wildcard domains MUST only use DNS-01 challenge (HTTP-01 not allowed)
func (s *RestService) createChallenges(accountID, authzID uint64, id entities.ACMEIdentifier, isWildcard bool) ([]entities.ACMEChallenge, error) {

	switch id.Type {
	case common.AuthzTypeDNS, common.AuthzTypeIP, common.AuthzTypePermanentIdentifier:
		// Supported identifier type
	default:
		s.logger.Error("Unsupported identifier type", "type", id.Type)
		return []entities.ACMEChallenge{}, caerrors.UnsupportedIdentifierError("unsupported identifier type: %s", id.Type)
	}

	// The challenge policy's wildcard restriction (RFC 8555 Section 7.1.4:
	// wildcards MUST only use dns-01) is keyed off a "*."-prefixed value.
	value := id.Value
	if isWildcard && !strings.HasPrefix(value, "*.") {
		value = "*." + value
	}

	// Candidates the policy allows for this identifier, intersected with the
	// challenge verifiers actually registered for this server (a challenge
	// type the policy allows but no verifier is registered for cannot be
	// offered).
	candidates := s.challengePolicy.AllowedChallenges(id.Type, value)
	var challengeTypes []string
	for _, challengeType := range candidates {
		if _, registered := s.challengeMap[challengeType]; registered {
			challengeTypes = append(challengeTypes, challengeType)
		}
	}

	s.logger.Info("Challenge types selected",
		"identifier_type", id.Type,
		"identifier_value", id.Value,
		"is_wildcard", isWildcard,
		"count", len(challengeTypes),
		"types", challengeTypes)

	if len(challengeTypes) == 0 {
		s.logger.Error("No challenges configured for identifier type", "type", id.Type)
		return []entities.ACMEChallenge{}, caerrors.InternalServerError("no challenges configured for identifier type: %s", id.Type)
	}

	// Create a final list of challenge objects to return to the client
	challenges := make([]entities.ACMEChallenge, len(challengeTypes))
	for i, challengeType := range challengeTypes {

		token, err := GenerateToken()
		if err != nil {
			return []entities.ACMEChallenge{}, err
		}

		challengeID, err := GenerateID()
		if err != nil {
			return []entities.ACMEChallenge{}, err
		}

		challengeURL := fmt.Sprintf("%s/acme/challenge/%d", s.baseRESTURI, challengeID)

		challenges[i] = entities.ACMEChallenge{
			ID:              challengeID,
			Type:            challengeType,
			URL:             challengeURL,
			Status:          common.StatusPending,
			Token:           string(token),
			AccountID:       accountID,
			AuthorizationID: authzID,
		}
	}

	return challenges, nil
}

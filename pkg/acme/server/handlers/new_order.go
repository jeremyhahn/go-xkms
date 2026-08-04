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
	"strings"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	caerrors "github.com/jeremyhahn/go-xkms/pkg/acme/errors"
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

		domain := id.Value
		isWildcard := false
		if id.Type == common.AuthzTypeDNS {
			if strings.HasPrefix(domain, "*.") {
				isWildcard = true
				domain = strings.TrimPrefix(domain, "*.")
			}
			// Validate domain name
			if !isValidDomainName(domain) {
				writeError(w, common.MalformedError("Invalid domain name", nil))
				return
			}
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

	// Respond with the order object
	w.Header().Set("Location", orderURL)
	w.WriteHeader(http.StatusCreated)
	s.orderResponse(w, order)
}

// Create challenges for the given account and authorization
// isWildcard indicates if the identifier is a wildcard domain (e.g., *.example.com)
// Per RFC 8555, wildcard domains MUST only use DNS-01 challenge (HTTP-01 not allowed)
func (s *RestService) createChallenges(accountID, authzID uint64, id entities.ACMEIdentifier, isWildcard bool) ([]entities.ACMEChallenge, error) {

	s.logger.Info("Creating challenges",
		"identifier_type", id.Type,
		"identifier_value", id.Value,
		"is_wildcard", isWildcard,
		"num_challenge_types", len(s.challengeMap))

	// Log all available challenge types
	for ct := range s.challengeMap {
		s.logger.Info("Available challenge type", "type", ct)
	}

	// Filter challenge types based on identifier type
	var challengeTypes []string
	for challengeType := range s.challengeMap {
		s.logger.Info("Checking challenge type",
			"type", challengeType,
			"identifier_type", id.Type,
			"is_wildcard", isWildcard)

		switch id.Type {
		case common.AuthzTypeDNS:
			// For DNS identifiers, use HTTP and DNS challenges
			// Per RFC 8555 Section 7.1.4: Wildcard domains MUST only use DNS-01 challenge
			if isWildcard {
				// Wildcard: only DNS-01 challenge allowed
				if strings.HasPrefix(challengeType, "dns-") {
					s.logger.Info("Matched DNS challenge for wildcard", "type", challengeType)
					challengeTypes = append(challengeTypes, challengeType)
				}
			} else {
				// Non-wildcard: HTTP-01 and DNS-01 allowed
				if strings.HasPrefix(challengeType, "http-") || strings.HasPrefix(challengeType, "dns-") {
					s.logger.Info("Matched DNS challenge", "type", challengeType)
					challengeTypes = append(challengeTypes, challengeType)
				}
			}
		case common.AuthzTypeIP, common.AuthzTypePermanentIdentifier:
			// For IP and permanent-identifier, use enrollment challenges
			s.logger.Info("Checking enrollment challenge prefixes",
				"type", challengeType,
				"has_enroll", strings.HasPrefix(challengeType, "enroll-"),
				"has_endorse", strings.HasPrefix(challengeType, "endorse-"),
				"has_device_attest", strings.HasPrefix(challengeType, "device-attest-"))
			if strings.HasPrefix(challengeType, "enroll-") || strings.HasPrefix(challengeType, "endorse-") || strings.HasPrefix(challengeType, "device-attest-") {
				s.logger.Info("Matched enrollment challenge", "type", challengeType)
				challengeTypes = append(challengeTypes, challengeType)
			}
		default:
			s.logger.Error("Unsupported identifier type", "type", id.Type)
			return []entities.ACMEChallenge{}, caerrors.UnsupportedIdentifierError("unsupported identifier type: %s", id.Type)
		}
	}

	s.logger.Info("Challenge types selected", "count", len(challengeTypes), "types", challengeTypes)

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

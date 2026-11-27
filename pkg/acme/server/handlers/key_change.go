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
	"errors"
	"fmt"
	"net/http"

	"github.com/go-jose/go-jose/v4"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/acme/audit"
	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	"github.com/jeremyhahn/go-xkms/pkg/acme/server"
	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
)

// KeyChangeRequest represents the key change request body.
type KeyChangeRequest struct {
	AccountURL string                 `json:"account"` // The account URL
	OldKey     map[string]interface{} `json:"oldKey"`  // The old key in JWK format
}

type NewKeyPayload struct {
	JWK string `json:"jwk"`
}

// KeyChangeResponse represents the successful key change response.
type KeyChangeResponse struct {
	Message string `json:"message"`
}

// ErrorResponse represents an error response for the API.
type ErrorResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// KeyChangeHandler handles key-change requests according to RFC 8555 Section
// 7.3.5 Account Key Rollover.
func (s *RestService) KeyChangeHandler(w http.ResponseWriter, r *http.Request) {

	// Parse the account and outer JWS payload from the request
	ctx := r.Context()
	account, outerPayload, err := s.parseKID(ctx, r)
	if err != nil {
		// RFC 8555 Section 7.3.6: Return 401 Unauthorized for deactivated accounts
		if errors.Is(err, ErrAccountDeactivated) {
			writeError(w, common.Unauthorized("Account is deactivated"))
			return
		}
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	accountDAO, err := s.storageFactory.AccountDAO()
	if err != nil {
		writeError(w, common.ServerInternal("Failed to create account DAO"))
		return
	}

	// (1) Validate the POST request belongs to a currently active account
	persistedAccount, err := accountDAO.Get(ctx, account.ID)
	if err != nil {
		if qrdbsdk.IsDAONotFound(err) {
			writeError(w, common.AccountDoesNotExist("Account not found"))
		} else {
			s.logger.Error("Storage error retrieving account", "error", err)
			writeError(w, common.ServerInternal("Failed to retrieve account"))
		}
		return
	}
	if persistedAccount.Status != common.StatusValid {
		writeError(w, common.Unauthorized("Invalid account"))
		return
	}

	// Decode the old public key for later comparison
	oldPublicKey, err := xkmssdk.DecodePublicKeyPEM([]byte(account.Key))
	if err != nil {
		writeError(w, common.MalformedError("Invalid account key", nil))
		return
	}

	// (2) Check that the payload of the JWS is a well-formed JWS object
	// The inner JWS is signed with the NEW key, so we must allow all algorithms
	innerJWS, err := parseSignedAny(string(outerPayload), server.AllowedJOSEAlgorithms)
	if err != nil {
		writeError(w, common.MalformedError("Invalid inner JWS", nil))
		return
	}

	if len(innerJWS.Signatures) == 0 {
		writeError(w, common.MalformedError("no signatures found within inner JWS", nil))
		return
	}

	protectedHeader := innerJWS.Signatures[0].Header

	// (3) Check that the JWS protected header of the inner JWS has a "jwk" field
	if protectedHeader.JSONWebKey == nil {
		writeError(w, common.MalformedError("JWK not found in JWS header", nil))
		return
	}

	// (4) Check that the inner JWS verifies using the key in its "jwk" field
	publicKey := protectedHeader.JSONWebKey.Key
	if publicKey == nil {
		writeError(w, common.MalformedError("public key not found in JWK", nil))
		return
	}
	innerPayload, err := innerJWS.Verify(publicKey)
	if err != nil {
		writeError(w, common.Unauthorized("Failed to verify inner JWS signature"))
		return
	}

	// (5) Check that the payload of the inner JWS is a well-formed keyChange object
	var keyChangeReq KeyChangeRequest
	if err := json.Unmarshal(innerPayload, &keyChangeReq); err != nil {
		writeError(w, common.MalformedError("Invalid inner payload", nil))
		return
	}

	// (6) Check that the "url" parameters of the inner and outer JWSs are the same
	// The outer JWS URL should match the HTTP request URL
	expectedURL := fmt.Sprintf("%s%s", s.baseRESTURI, r.URL.Path)
	innerURL, ok := protectedHeader.ExtraHeaders["url"].(string)
	if !ok || innerURL != expectedURL {
		writeError(w, common.MalformedError("inner and outer JWS URL parameters don't match", nil))
		return
	}

	// (7) Check that the "account" field of the keyChange object matches the old key's account
	if keyChangeReq.AccountURL != persistedAccount.URL {
		writeError(w, common.MalformedError("Account URL does not match the KID in outer JWS", nil))
		return
	}

	// (8) Check that the "oldKey" field matches the account's current key
	// Convert the old public key to JWK format for comparison
	oldKeyJWK := &jose.JSONWebKey{Key: oldPublicKey}
	oldKeyJSON, err := oldKeyJWK.MarshalJSON()
	if err != nil {
		writeError(w, common.ServerInternal("Failed to marshal old key"))
		return
	}
	var oldKeyMap map[string]interface{}
	if err := json.Unmarshal(oldKeyJSON, &oldKeyMap); err != nil {
		writeError(w, common.ServerInternal("Failed to unmarshal old key"))
		return
	}

	// Simple comparison of key parameters
	if !compareKeyMaps(oldKeyMap, keyChangeReq.OldKey) {
		writeError(w, common.MalformedError("Old key does not match account's current key", nil))
		return
	}

	// (9) Check that no account exists whose account key is the same as the
	//    key in the "jwk" header parameter of the inner JWS.
	// Serialize the new key first so we can check if any other account has it
	newSerializedKey, err := xkmssdk.EncodePublicKeyPEM(protectedHeader.JSONWebKey.Key)
	if err != nil {
		writeError(w, common.ServerInternal("Failed to serialize new key"))
		return
	}

	// Check if the new key is the same as the current key
	if string(newSerializedKey) == persistedAccount.Key {
		writeError(w, common.MalformedError("New key is the same as the current key", nil))
		return
	}

	// List all accounts and check if any (other than this one) has the new key
	var allAccounts []*entities.ACMEAccount
	err = accountDAO.ForEachPage(ctx, qrdbsdk.PageQuery{PageSize: 1000}, func(page qrdbsdk.PageResult[*entities.ACMEAccount]) error {
		allAccounts = append(allAccounts, page.Entities...)
		return nil
	})
	if err != nil {
		s.logger.Error("Storage error listing accounts", "error", err)
		writeError(w, common.ServerInternal("Storage error"))
		return
	}

	for _, acc := range allAccounts {
		if acc.ID != persistedAccount.ID && acc.Key == string(newSerializedKey) {
			// RFC 8555 Section 7.3.5: "If there is an existing account with the new key
			// provided, then the server SHOULD use status code 409 (Conflict) and provide
			// the URL of that account in the Location header field."
			existingAccountURL := s.accountURL(acc)
			w.Header().Set("Location", existingAccountURL)
			w.Header().Set("Content-Type", "application/problem+json")
			w.WriteHeader(http.StatusConflict)
			s.encodeJSON(w, map[string]interface{}{
				"type":   "urn:ietf:params:acme:error:malformed",
				"detail": "New account key already exists on another account",
				"status": http.StatusConflict,
			})
			return
		}
	}

	// Update the persisted account (not the partial account from parseKID)
	// to preserve all fields like Status, Contact, etc.
	persistedAccount.Key = string(newSerializedKey)

	if err := accountDAO.Save(ctx, persistedAccount); err != nil {
		writeError(w, common.ServerInternal("Failed to update account"))
		return
	}

	if auditErr := s.recordAudit(audit.EventAccountKeyChanged, audit.LogKeyChange(auditContext(r), s.auditLog,
		auditAccountID(persistedAccount.ID),
		auditKeyFingerprint(oldPublicKey),
		auditKeyFingerprint(publicKey))); auditErr != nil {
		writeError(w, common.ServerInternal("Failed to record audit event"))
		return
	}

	// Respond with success
	response := KeyChangeResponse{Message: "Key-change completed successfully"}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	s.encodeJSON(w, response)
}

// compareKeyMaps compares two JWK key maps for equality.
// It checks the key type and relevant parameters based on the key type.
func compareKeyMaps(key1, key2 map[string]interface{}) bool {
	// Check key type
	kty1, ok1 := key1["kty"].(string)
	kty2, ok2 := key2["kty"].(string)
	if !ok1 || !ok2 || kty1 != kty2 {
		return false
	}

	// Compare based on key type
	switch kty1 {
	case "RSA":
		// For RSA, compare modulus (n) and exponent (e)
		return key1["n"] == key2["n"] && key1["e"] == key2["e"]
	case "EC":
		// For EC, compare curve, x, and y
		return key1["crv"] == key2["crv"] && key1["x"] == key2["x"] && key1["y"] == key2["y"]
	case "OKP":
		// For EdDSA, compare curve and x
		return key1["crv"] == key2["crv"] && key1["x"] == key2["x"]
	default:
		return false
	}
}

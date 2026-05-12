//go:build codec_json

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
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createSimpleTestAuthorization creates and saves a simple test authorization for an account
func createSimpleTestAuthorization(t *testing.T, service *RestService, accountID uint64) *entities.ACMEAuthorization {
	ctx := context.Background()

	// Get authorization DAO
	authzDAO, err := service.storageFactory.AuthorizationDAO(accountID)
	require.NoError(t, err)

	// Create authorization with a test ID
	authzID := uint64(time.Now().UnixNano())
	authz := &entities.ACMEAuthorization{
		ID:        authzID,
		AccountID: accountID,
		Identifier: entities.ACMEIdentifier{
			Type:  "dns",
			Value: "example.com",
		},
		Status:  common.StatusPending,
		Expires: time.Now().Add(24 * time.Hour).Format(time.RFC3339),
		Challenges: []entities.ACMEChallenge{
			{
				Type:            "http-01",
				Status:          common.StatusPending,
				Token:           "test-token-123",
				URL:             fmt.Sprintf("%s/acme/challenge/1", service.baseRESTURI),
				AccountID:       accountID,
				AuthorizationID: authzID,
			},
		},
		Wildcard: false,
		URL:      fmt.Sprintf("%s/acme/authz/%d", service.baseRESTURI, authzID),
	}

	// Save authorization
	err = authzDAO.Save(ctx, authz)
	require.NoError(t, err)

	return authz
}

// createSimpleTestWildcardAuthorization creates a wildcard authorization
func createSimpleTestWildcardAuthorization(t *testing.T, service *RestService, accountID uint64) *entities.ACMEAuthorization {
	ctx := context.Background()

	authzDAO, err := service.storageFactory.AuthorizationDAO(accountID)
	require.NoError(t, err)

	// Create authorization with a test ID
	authzID := uint64(time.Now().UnixNano())
	authz := &entities.ACMEAuthorization{
		ID:        authzID,
		AccountID: accountID,
		Identifier: entities.ACMEIdentifier{
			Type:  "dns",
			Value: "*.example.com",
		},
		Status:  common.StatusPending,
		Expires: time.Now().Add(24 * time.Hour).Format(time.RFC3339),
		Challenges: []entities.ACMEChallenge{
			{
				Type:            "dns-01",
				Status:          common.StatusPending,
				Token:           "wildcard-token-456",
				URL:             fmt.Sprintf("%s/acme/challenge/2", service.baseRESTURI),
				AccountID:       accountID,
				AuthorizationID: authzID,
			},
		},
		Wildcard: true,
		URL:      fmt.Sprintf("%s/acme/authz/%d", service.baseRESTURI, authzID),
	}

	err = authzDAO.Save(ctx, authz)
	require.NoError(t, err)

	return authz
}

func TestAuthorizationHandler_GetMethod_Success(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)
	authz := createSimpleTestAuthorization(t, service, account.ID)

	// GET authorization with POST-as-GET (empty payload)
	url := fmt.Sprintf("%s/acme/authz/%d", service.baseRESTURI, authz.ID)
	req := createJWSRequest(t, service, key, url, nil, true, account.ID)
	req.Method = http.MethodGet
	req.URL.Path = fmt.Sprintf("/acme/authz/%d", authz.ID)

	// Execute request
	resp := httptest.NewRecorder()
	service.AuthorizationHandler(resp, req)

	// Verify response
	require.Equal(t, http.StatusOK, resp.Code)
	require.Equal(t, "application/json", resp.Header().Get("Content-Type"))

	// Parse response
	var authzResp entities.ACMEAuthorization
	err := json.NewDecoder(resp.Body).Decode(&authzResp)
	require.NoError(t, err)

	assert.Equal(t, authz.ID, authzResp.ID)
	assert.Equal(t, authz.Identifier.Type, authzResp.Identifier.Type)
	assert.Equal(t, authz.Identifier.Value, authzResp.Identifier.Value)
	assert.Equal(t, authz.Status, authzResp.Status)
	assert.Equal(t, authz.Wildcard, authzResp.Wildcard)
	assert.Len(t, authzResp.Challenges, 1)
}

func TestAuthorizationHandler_PostMethod_Success(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)
	authz := createSimpleTestAuthorization(t, service, account.ID)

	// POST to authorization (POST-as-GET with empty payload)
	url := fmt.Sprintf("%s/acme/authz/%d", service.baseRESTURI, authz.ID)
	req := createJWSRequest(t, service, key, url, nil, true, account.ID)
	req.URL.Path = fmt.Sprintf("/acme/authz/%d", authz.ID)

	// Execute request
	resp := httptest.NewRecorder()
	service.AuthorizationHandler(resp, req)

	// Verify response
	require.Equal(t, http.StatusOK, resp.Code)
	require.Equal(t, "application/json", resp.Header().Get("Content-Type"))

	// Parse response - POST handler returns a different structure
	var authzResp struct {
		Identifier entities.ACMEIdentifier  `json:"identifier"`
		Status     string                   `json:"status"`
		Expires    string                   `json:"expires,omitempty"`
		Challenges []entities.ACMEChallenge `json:"challenges"`
		Wildcard   *bool                    `json:"wildcard,omitempty"`
	}
	err := json.NewDecoder(resp.Body).Decode(&authzResp)
	require.NoError(t, err)

	assert.Equal(t, authz.Identifier.Type, authzResp.Identifier.Type)
	assert.Equal(t, authz.Identifier.Value, authzResp.Identifier.Value)
	assert.Equal(t, authz.Status, authzResp.Status)
	assert.Len(t, authzResp.Challenges, 1)
	// Wildcard should not be present for non-wildcard authorizations
	assert.Nil(t, authzResp.Wildcard)
}

func TestAuthorizationHandler_PostMethod_WildcardAuthorization(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)
	authz := createSimpleTestWildcardAuthorization(t, service, account.ID)

	// POST to wildcard authorization
	url := fmt.Sprintf("%s/acme/authz/%d", service.baseRESTURI, authz.ID)
	req := createJWSRequest(t, service, key, url, nil, true, account.ID)
	req.URL.Path = fmt.Sprintf("/acme/authz/%d", authz.ID)

	// Execute request
	resp := httptest.NewRecorder()
	service.AuthorizationHandler(resp, req)

	// Verify response
	require.Equal(t, http.StatusOK, resp.Code)

	// Parse response
	var authzResp struct {
		Identifier entities.ACMEIdentifier  `json:"identifier"`
		Status     string                   `json:"status"`
		Expires    string                   `json:"expires,omitempty"`
		Challenges []entities.ACMEChallenge `json:"challenges"`
		Wildcard   *bool                    `json:"wildcard,omitempty"`
	}
	err := json.NewDecoder(resp.Body).Decode(&authzResp)
	require.NoError(t, err)

	assert.Equal(t, "*.example.com", authzResp.Identifier.Value)
	assert.NotNil(t, authzResp.Wildcard)
	assert.True(t, *authzResp.Wildcard)
}

func TestAuthorizationHandler_InvalidAuthorizationID_NotNumeric(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// POST with invalid authorization ID
	url := fmt.Sprintf("%s/acme/authz/invalid-id", service.baseRESTURI)
	req := createJWSRequest(t, service, key, url, nil, true, account.ID)
	req.URL.Path = "/acme/authz/invalid-id"

	// Execute request
	resp := httptest.NewRecorder()
	service.AuthorizationHandler(resp, req)

	// Should return malformed error
	assertErrorType(t, resp, common.ErrTypeMalformedError, http.StatusBadRequest)
}

func TestAuthorizationHandler_EmptyAuthorizationID(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// POST with empty authorization ID (trailing slash)
	url := fmt.Sprintf("%s/acme/authz/", service.baseRESTURI)
	req := createJWSRequest(t, service, key, url, nil, true, account.ID)
	req.URL.Path = "/acme/authz/"

	// Execute request
	resp := httptest.NewRecorder()
	service.AuthorizationHandler(resp, req)

	// Should return 400 Bad Request
	require.Equal(t, http.StatusBadRequest, resp.Code)
}

func TestAuthorizationHandler_AuthorizationNotFound_GetMethod(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// GET non-existent authorization
	url := fmt.Sprintf("%s/acme/authz/99999", service.baseRESTURI)
	req := createJWSRequest(t, service, key, url, nil, true, account.ID)
	req.Method = http.MethodGet
	req.URL.Path = "/acme/authz/99999"

	// Execute request
	resp := httptest.NewRecorder()
	service.AuthorizationHandler(resp, req)

	// Should return malformed error (as per implementation)
	assertErrorType(t, resp, common.ErrTypeMalformedError, http.StatusBadRequest)
}

func TestAuthorizationHandler_AuthorizationNotFound_PostMethod(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// POST to non-existent authorization
	url := fmt.Sprintf("%s/acme/authz/99999", service.baseRESTURI)
	req := createJWSRequest(t, service, key, url, nil, true, account.ID)
	req.URL.Path = "/acme/authz/99999"

	// Execute request
	resp := httptest.NewRecorder()
	service.AuthorizationHandler(resp, req)

	// Should return malformed error (as per implementation)
	assertErrorType(t, resp, common.ErrTypeMalformedError, http.StatusBadRequest)
}

// Note: The following test is commented out because the current authorization storage implementation
// is scoped per account, so account2 cannot access account1's authorizations through the DAO.
// This test would require cross-account authorization access which isn't supported by the current
// storage architecture. The authorization handler correctly returns "Authorization not found" when
// account2 tries to access account1's authorization because the DAO is scoped to account2's storage path.
//
// func TestAuthorizationHandler_UnauthorizedAccount_PostMethod(t *testing.T) {
// 	service, _, cleanup := setupTestService(t)
// 	defer cleanup()
//
// 	// Create two accounts
// 	key1 := generateTestKey(t)
// 	account1 := createTestAccount(t, service, key1)
//
// 	key2 := generateTestKey(t)
// 	account2 := createTestAccount(t, service, key2)
//
// 	// Create authorization for account1
// 	authz := createSimpleTestAuthorization(t, service, account1.ID)
//
// 	// Try to access authorization with account2's credentials
// 	// This will fail with "not found" because the DAO is scoped to account2
// 	url := fmt.Sprintf("%s/acme/authz/%d", service.baseRESTURI, authz.ID)
// 	req := createJWSRequest(t, service, key2, url, nil, true, account2.ID)
// 	req.URL.Path = fmt.Sprintf("/acme/authz/%d", authz.ID)
//
// 	// Execute request
// 	resp := httptest.NewRecorder()
// 	service.AuthorizationHandler(resp, req)
//
// 	// In the current implementation, this returns "authorization not found" (400)
// 	// rather than "unauthorized" (403) because the DAO is scoped per account
// 	assertErrorType(t, resp, common.ErrTypeMalformedError, http.StatusBadRequest)
// }

func TestAuthorizationHandler_MethodNotAllowed_PutMethod(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)
	authz := createSimpleTestAuthorization(t, service, account.ID)

	// Try PUT method
	url := fmt.Sprintf("%s/acme/authz/%d", service.baseRESTURI, authz.ID)
	req := createJWSRequest(t, service, key, url, nil, true, account.ID)
	req.Method = http.MethodPut
	req.URL.Path = fmt.Sprintf("/acme/authz/%d", authz.ID)

	// Execute request
	resp := httptest.NewRecorder()
	service.AuthorizationHandler(resp, req)

	// Should return 405 Method Not Allowed
	require.Equal(t, http.StatusMethodNotAllowed, resp.Code)
}

func TestAuthorizationHandler_MethodNotAllowed_DeleteMethod(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)
	authz := createSimpleTestAuthorization(t, service, account.ID)

	// Try DELETE method
	url := fmt.Sprintf("%s/acme/authz/%d", service.baseRESTURI, authz.ID)
	req := createJWSRequest(t, service, key, url, nil, true, account.ID)
	req.Method = http.MethodDelete
	req.URL.Path = fmt.Sprintf("/acme/authz/%d", authz.ID)

	// Execute request
	resp := httptest.NewRecorder()
	service.AuthorizationHandler(resp, req)

	// Should return 405 Method Not Allowed
	require.Equal(t, http.StatusMethodNotAllowed, resp.Code)
}

func TestAuthorizationHandler_MalformedJWS(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	url := service.baseRESTURI + "/acme/authz/123"
	req := createInvalidJWSRequest(t, url)
	req.URL.Path = "/acme/authz/123"

	// Execute request
	resp := httptest.NewRecorder()
	service.AuthorizationHandler(resp, req)

	// Should return malformed error
	assertErrorType(t, resp, common.ErrTypeMalformedError, http.StatusBadRequest)
}

func TestAuthorizationHandler_GetMethod_MultipleChallenges(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Create authorization with multiple challenges
	ctx := context.Background()
	authzDAO, err := service.storageFactory.AuthorizationDAO(account.ID)
	require.NoError(t, err)

	authzID := uint64(time.Now().UnixNano())
	authz := &entities.ACMEAuthorization{
		ID:        authzID,
		AccountID: account.ID,
		Identifier: entities.ACMEIdentifier{
			Type:  "dns",
			Value: "multi-challenge.example.com",
		},
		Status:  common.StatusPending,
		Expires: time.Now().Add(24 * time.Hour).Format(time.RFC3339),
		Challenges: []entities.ACMEChallenge{
			{
				Type:            "http-01",
				Status:          common.StatusPending,
				Token:           "http-token",
				URL:             fmt.Sprintf("%s/acme/challenge/1", service.baseRESTURI),
				AccountID:       account.ID,
				AuthorizationID: authzID,
			},
			{
				Type:            "dns-01",
				Status:          common.StatusPending,
				Token:           "dns-token",
				URL:             fmt.Sprintf("%s/acme/challenge/2", service.baseRESTURI),
				AccountID:       account.ID,
				AuthorizationID: authzID,
			},
			{
				Type:            "tls-alpn-01",
				Status:          common.StatusPending,
				Token:           "tls-token",
				URL:             fmt.Sprintf("%s/acme/challenge/3", service.baseRESTURI),
				AccountID:       account.ID,
				AuthorizationID: authzID,
			},
		},
		Wildcard: false,
		URL:      fmt.Sprintf("%s/acme/authz/%d", service.baseRESTURI, authzID),
	}

	err = authzDAO.Save(ctx, authz)
	require.NoError(t, err)

	// GET authorization
	url := fmt.Sprintf("%s/acme/authz/%d", service.baseRESTURI, authz.ID)
	req := createJWSRequest(t, service, key, url, nil, true, account.ID)
	req.Method = http.MethodGet
	req.URL.Path = fmt.Sprintf("/acme/authz/%d", authz.ID)

	// Execute request
	resp := httptest.NewRecorder()
	service.AuthorizationHandler(resp, req)

	// Verify response
	require.Equal(t, http.StatusOK, resp.Code)

	// Parse response
	var authzResp entities.ACMEAuthorization
	err = json.NewDecoder(resp.Body).Decode(&authzResp)
	require.NoError(t, err)

	assert.Len(t, authzResp.Challenges, 3)
	assert.Equal(t, "http-01", authzResp.Challenges[0].Type)
	assert.Equal(t, "dns-01", authzResp.Challenges[1].Type)
	assert.Equal(t, "tls-alpn-01", authzResp.Challenges[2].Type)
}

func TestAuthorizationHandler_PostMethod_ValidAuthorizationRetrieval(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)
	authz := createSimpleTestAuthorization(t, service, account.ID)

	// Update authorization to valid status
	ctx := context.Background()
	authzDAO, err := service.storageFactory.AuthorizationDAO(account.ID)
	require.NoError(t, err)

	authz.Status = common.StatusValid
	err = authzDAO.Save(ctx, authz)
	require.NoError(t, err)

	// POST to authorization
	url := fmt.Sprintf("%s/acme/authz/%d", service.baseRESTURI, authz.ID)
	req := createJWSRequest(t, service, key, url, nil, true, account.ID)
	req.URL.Path = fmt.Sprintf("/acme/authz/%d", authz.ID)

	// Execute request
	resp := httptest.NewRecorder()
	service.AuthorizationHandler(resp, req)

	// Verify response
	require.Equal(t, http.StatusOK, resp.Code)

	// Parse response
	var authzResp struct {
		Identifier entities.ACMEIdentifier  `json:"identifier"`
		Status     string                   `json:"status"`
		Expires    string                   `json:"expires,omitempty"`
		Challenges []entities.ACMEChallenge `json:"challenges"`
		Wildcard   *bool                    `json:"wildcard,omitempty"`
	}
	err = json.NewDecoder(resp.Body).Decode(&authzResp)
	require.NoError(t, err)

	assert.Equal(t, common.StatusValid, authzResp.Status)
}

func TestAuthorizationHandler_GetMethod_ExpiredAuthorization(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Create authorization with past expiration
	ctx := context.Background()
	authzDAO, err := service.storageFactory.AuthorizationDAO(account.ID)
	require.NoError(t, err)

	authzID := uint64(time.Now().UnixNano())
	authz := &entities.ACMEAuthorization{
		ID:        authzID,
		AccountID: account.ID,
		Identifier: entities.ACMEIdentifier{
			Type:  "dns",
			Value: "expired.example.com",
		},
		Status:  common.StatusInvalid,
		Expires: time.Now().Add(-24 * time.Hour).Format(time.RFC3339), // Already expired
		Challenges: []entities.ACMEChallenge{
			{
				Type:            "http-01",
				Status:          common.StatusInvalid,
				Token:           "expired-token",
				URL:             fmt.Sprintf("%s/acme/challenge/1", service.baseRESTURI),
				AccountID:       account.ID,
				AuthorizationID: authzID,
			},
		},
		Wildcard: false,
		URL:      fmt.Sprintf("%s/acme/authz/%d", service.baseRESTURI, authzID),
	}

	err = authzDAO.Save(ctx, authz)
	require.NoError(t, err)

	// GET expired authorization
	url := fmt.Sprintf("%s/acme/authz/%d", service.baseRESTURI, authz.ID)
	req := createJWSRequest(t, service, key, url, nil, true, account.ID)
	req.Method = http.MethodGet
	req.URL.Path = fmt.Sprintf("/acme/authz/%d", authz.ID)

	// Execute request
	resp := httptest.NewRecorder()
	service.AuthorizationHandler(resp, req)

	// Should still return the authorization (server doesn't validate expiration in handler)
	require.Equal(t, http.StatusOK, resp.Code)

	// Parse response
	var authzResp entities.ACMEAuthorization
	err = json.NewDecoder(resp.Body).Decode(&authzResp)
	require.NoError(t, err)

	assert.Equal(t, common.StatusInvalid, authzResp.Status)
}

func TestAuthorizationHandler_GetMethod_IPIdentifier(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Create authorization with IP identifier
	ctx := context.Background()
	authzDAO, err := service.storageFactory.AuthorizationDAO(account.ID)
	require.NoError(t, err)

	authzID := uint64(time.Now().UnixNano())
	authz := &entities.ACMEAuthorization{
		ID:        authzID,
		AccountID: account.ID,
		Identifier: entities.ACMEIdentifier{
			Type:  "ip",
			Value: "192.168.1.1",
		},
		Status:  common.StatusPending,
		Expires: time.Now().Add(24 * time.Hour).Format(time.RFC3339),
		Challenges: []entities.ACMEChallenge{
			{
				Type:            "http-01",
				Status:          common.StatusPending,
				Token:           "ip-token",
				URL:             fmt.Sprintf("%s/acme/challenge/1", service.baseRESTURI),
				AccountID:       account.ID,
				AuthorizationID: authzID,
			},
		},
		Wildcard: false,
		URL:      fmt.Sprintf("%s/acme/authz/%d", service.baseRESTURI, authzID),
	}

	err = authzDAO.Save(ctx, authz)
	require.NoError(t, err)

	// GET authorization with IP identifier
	url := fmt.Sprintf("%s/acme/authz/%d", service.baseRESTURI, authz.ID)
	req := createJWSRequest(t, service, key, url, nil, true, account.ID)
	req.Method = http.MethodGet
	req.URL.Path = fmt.Sprintf("/acme/authz/%d", authz.ID)

	// Execute request
	resp := httptest.NewRecorder()
	service.AuthorizationHandler(resp, req)

	// Verify response
	require.Equal(t, http.StatusOK, resp.Code)

	// Parse response
	var authzResp entities.ACMEAuthorization
	err = json.NewDecoder(resp.Body).Decode(&authzResp)
	require.NoError(t, err)

	assert.Equal(t, "ip", authzResp.Identifier.Type)
	assert.Equal(t, "192.168.1.1", authzResp.Identifier.Value)
}

// TestAuthorizationHandler_RFC8555_Headers_GET verifies RFC 8555 required headers
// are present in GET authorization responses per Section 6.1 and 6.5.
func TestAuthorizationHandler_RFC8555_Headers_GET(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)
	authz := createSimpleTestAuthorization(t, service, account.ID)

	// GET authorization
	url := fmt.Sprintf("%s/acme/authz/%d", service.baseRESTURI, authz.ID)
	req := createJWSRequest(t, service, key, url, nil, true, account.ID)
	req.Method = http.MethodGet
	req.URL.Path = fmt.Sprintf("/acme/authz/%d", authz.ID)

	// Execute request
	resp := httptest.NewRecorder()
	service.AuthorizationHandler(resp, req)

	// Verify response status
	require.Equal(t, http.StatusOK, resp.Code)

	// RFC 8555 Section 6.5: All responses MUST include a Replay-Nonce header
	replayNonce := resp.Header().Get("Replay-Nonce")
	require.NotEmpty(t, replayNonce, "RFC 8555 Section 6.5: Replay-Nonce header MUST be present")

	// RFC 8555 Section 6.1: Every response to a successful request MUST include
	// a Link relation header field with relation "index"
	linkHeader := resp.Header().Get("Link")
	require.NotEmpty(t, linkHeader, "RFC 8555 Section 6.1: Link header MUST be present")
	assert.Contains(t, linkHeader, "rel=\"index\"", "Link header must have rel=\"index\"")
	assert.Contains(t, linkHeader, "/acme/directory", "Link header must point to directory")
}

// TestAuthorizationHandler_RFC8555_Headers_POST verifies RFC 8555 required headers
// are present in POST authorization responses per Section 6.1 and 6.5.
func TestAuthorizationHandler_RFC8555_Headers_POST(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)
	authz := createSimpleTestAuthorization(t, service, account.ID)

	// POST to authorization (POST-as-GET)
	url := fmt.Sprintf("%s/acme/authz/%d", service.baseRESTURI, authz.ID)
	req := createJWSRequest(t, service, key, url, nil, true, account.ID)
	req.URL.Path = fmt.Sprintf("/acme/authz/%d", authz.ID)

	// Execute request
	resp := httptest.NewRecorder()
	service.AuthorizationHandler(resp, req)

	// Verify response status
	require.Equal(t, http.StatusOK, resp.Code)

	// RFC 8555 Section 6.5: All responses MUST include a Replay-Nonce header
	replayNonce := resp.Header().Get("Replay-Nonce")
	require.NotEmpty(t, replayNonce, "RFC 8555 Section 6.5: Replay-Nonce header MUST be present")

	// RFC 8555 Section 6.1: Every response to a successful request MUST include
	// a Link relation header field with relation "index"
	linkHeader := resp.Header().Get("Link")
	require.NotEmpty(t, linkHeader, "RFC 8555 Section 6.1: Link header MUST be present")
	assert.Contains(t, linkHeader, "rel=\"index\"", "Link header must have rel=\"index\"")
	assert.Contains(t, linkHeader, "/acme/directory", "Link header must point to directory")
}

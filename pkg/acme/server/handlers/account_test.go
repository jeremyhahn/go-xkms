//go:build codec_json

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
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAccountHandler_GetAccount(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// GET account with POST-as-GET (empty payload)
	url := service.baseRESTURI + "/acme/account/" + string(rune(account.ID))
	req := createJWSRequest(t, service, key, url, nil, true, account.ID)

	// Execute request
	resp := httptest.NewRecorder()
	service.AccountHandler(resp, req)

	// Verify response
	require.Equal(t, http.StatusOK, resp.Code)
	require.Equal(t, "application/json", resp.Header().Get("Content-Type"))

	// Parse response
	var accountResp struct {
		Status  string   `json:"status"`
		Contact []string `json:"contact"`
		Orders  string   `json:"orders"`
	}
	err := json.NewDecoder(resp.Body).Decode(&accountResp)
	require.NoError(t, err)

	assert.Equal(t, account.Status, accountResp.Status)
	assert.Equal(t, account.Contact, accountResp.Contact)
}

func TestAccountHandler_UpdateContact(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Update contact
	payload := AccountRequest{
		Contact: []string{"mailto:updated@example.com"},
	}

	url := service.baseRESTURI + "/acme/account/" + string(rune(account.ID))
	req := createJWSRequest(t, service, key, url, payload, true, account.ID)

	// Execute request
	resp := httptest.NewRecorder()
	service.AccountHandler(resp, req)

	// Verify response
	require.Equal(t, http.StatusOK, resp.Code)

	// Parse response
	var accountResp struct {
		Status  string   `json:"status"`
		Contact []string `json:"contact"`
		Orders  string   `json:"orders"`
	}
	err := json.NewDecoder(resp.Body).Decode(&accountResp)
	require.NoError(t, err)

	assert.Equal(t, payload.Contact, accountResp.Contact)
}

func TestAccountHandler_DeactivateAccount(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Deactivate account
	payload := AccountRequest{
		Status: common.StatusDeactivated,
	}

	url := service.baseRESTURI + "/acme/account/" + string(rune(account.ID))
	req := createJWSRequest(t, service, key, url, payload, true, account.ID)

	// Execute request
	resp := httptest.NewRecorder()
	service.AccountHandler(resp, req)

	// Verify response
	require.Equal(t, http.StatusOK, resp.Code)

	// Parse response
	var accountResp struct {
		Status  string   `json:"status"`
		Contact []string `json:"contact"`
		Orders  string   `json:"orders"`
	}
	err := json.NewDecoder(resp.Body).Decode(&accountResp)
	require.NoError(t, err)

	assert.Equal(t, common.StatusDeactivated, accountResp.Status)
}

func TestAccountHandler_DeactivateAlreadyDeactivated(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// First deactivation
	payload := AccountRequest{
		Status: common.StatusDeactivated,
	}

	url := service.baseRESTURI + "/acme/account/" + string(rune(account.ID))
	req := createJWSRequest(t, service, key, url, payload, true, account.ID)

	resp := httptest.NewRecorder()
	service.AccountHandler(resp, req)
	require.Equal(t, http.StatusOK, resp.Code)

	// Try to deactivate again
	req2 := createJWSRequest(t, service, key, url, payload, true, account.ID)
	resp2 := httptest.NewRecorder()
	service.AccountHandler(resp2, req2)

	// Should return malformed error
	assertErrorType(t, resp2, common.ErrTypeMalformedError, http.StatusBadRequest)
}

func TestAccountHandler_InvalidContactUpdate(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Try to update with invalid contact
	payload := AccountRequest{
		Contact: []string{"tel:+1-555-1234"}, // Unsupported scheme
	}

	url := service.baseRESTURI + "/acme/account/" + string(rune(account.ID))
	req := createJWSRequest(t, service, key, url, payload, true, account.ID)

	// Execute request
	resp := httptest.NewRecorder()
	service.AccountHandler(resp, req)

	// Should return unsupportedContact error
	assertErrorType(t, resp, common.ErrTypeUnsupportedContact, http.StatusBadRequest)
}

func TestAccountHandler_InvalidStatus(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Try to set invalid status
	payload := AccountRequest{
		Status: "invalid-status",
	}

	url := service.baseRESTURI + "/acme/account/" + string(rune(account.ID))
	req := createJWSRequest(t, service, key, url, payload, true, account.ID)

	// Execute request
	resp := httptest.NewRecorder()
	service.AccountHandler(resp, req)

	// Should return malformed error
	assertErrorType(t, resp, common.ErrTypeMalformedError, http.StatusBadRequest)
}

func TestAccountHandler_MalformedJWS(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	url := service.baseRESTURI + "/acme/account/123"
	req := createInvalidJWSRequest(t, url)

	// Execute request
	resp := httptest.NewRecorder()
	service.AccountHandler(resp, req)

	// Should return malformed error
	assertErrorType(t, resp, common.ErrTypeMalformedError, http.StatusBadRequest)
}

func TestAccountHandler_ReplayNonceHeader(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// GET account
	url := service.baseRESTURI + "/acme/account/" + string(rune(account.ID))
	req := createJWSRequest(t, service, key, url, nil, true, account.ID)

	// Execute request
	resp := httptest.NewRecorder()
	service.AccountHandler(resp, req)

	// Verify Replay-Nonce header is present
	require.NotEmpty(t, resp.Header().Get("Replay-Nonce"))
}

// Tests from account_additional_test.go

func TestAccountHandler_UpdateContactAndStatus(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Update both contact and status
	payload := AccountRequest{
		Status:  common.StatusDeactivated,
		Contact: []string{"mailto:new@example.com"},
	}

	url := service.baseRESTURI + "/acme/account/" + string(rune(account.ID))
	req := createJWSRequest(t, service, key, url, payload, true, account.ID)

	// Execute request
	resp := httptest.NewRecorder()
	service.AccountHandler(resp, req)

	// Verify response
	require.Equal(t, http.StatusOK, resp.Code)

	// Parse response
	var accountResp struct {
		Status  string   `json:"status"`
		Contact []string `json:"contact"`
	}
	err := json.NewDecoder(resp.Body).Decode(&accountResp)
	require.NoError(t, err)

	// Both should be updated
	assert.Equal(t, common.StatusDeactivated, accountResp.Status)
	assert.Equal(t, []string{"mailto:new@example.com"}, accountResp.Contact)
}

func TestAccountHandler_RFC8555_Compliance(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// GET account
	url := service.baseRESTURI + "/acme/account/" + string(rune(account.ID))
	req := createJWSRequest(t, service, key, url, nil, true, account.ID)

	// Execute request
	resp := httptest.NewRecorder()
	service.AccountHandler(resp, req)

	// Verify response
	require.Equal(t, http.StatusOK, resp.Code)

	// RFC 8555 Section 6.1: Response MUST include Content-Type application/json
	assert.Equal(t, "application/json", resp.Header().Get("Content-Type"))

	// RFC 8555 Section 6.5: Response MUST include Replay-Nonce header
	replayNonce := resp.Header().Get("Replay-Nonce")
	require.NotEmpty(t, replayNonce, "RFC 8555 Section 6.5: Replay-Nonce header MUST be present")

	// RFC 8555 Section 6.1: Response MUST include Link header with rel="index"
	linkHeader := resp.Header().Get("Link")
	require.NotEmpty(t, linkHeader, "RFC 8555 Section 6.1: Link header MUST be present")
	assert.Contains(t, linkHeader, "rel=\"index\"", "Link header must have rel=\"index\"")

	// RFC 8555 Section 7.3: Account response MUST include status
	var accountResp struct {
		Status string `json:"status"`
		Orders string `json:"orders"`
	}
	err := json.NewDecoder(resp.Body).Decode(&accountResp)
	require.NoError(t, err)
	require.NotEmpty(t, accountResp.Status, "RFC 8555 Section 7.3: status field is required")
	require.NotEmpty(t, accountResp.Orders, "RFC 8555 Section 7.3: orders field is required")
}

func TestAccountHandler_MultipleContactURLs(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Update with multiple contacts
	payload := AccountRequest{
		Contact: []string{
			"mailto:admin@example.com",
			"mailto:security@example.com",
			"mailto:ops@example.com",
		},
	}

	url := service.baseRESTURI + "/acme/account/" + string(rune(account.ID))
	req := createJWSRequest(t, service, key, url, payload, true, account.ID)

	// Execute request
	resp := httptest.NewRecorder()
	service.AccountHandler(resp, req)

	// Verify response
	require.Equal(t, http.StatusOK, resp.Code)

	// Parse response
	var accountResp struct {
		Contact []string `json:"contact"`
	}
	err := json.NewDecoder(resp.Body).Decode(&accountResp)
	require.NoError(t, err)

	assert.Equal(t, 3, len(accountResp.Contact))
	assert.Equal(t, payload.Contact, accountResp.Contact)
}

func TestAccountHandler_UpdateStatusOnly(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Update only status (no contact field)
	payload := AccountRequest{
		Status: common.StatusDeactivated,
	}

	url := service.baseRESTURI + "/acme/account/" + string(rune(account.ID))
	req := createJWSRequest(t, service, key, url, payload, true, account.ID)

	// Execute request
	resp := httptest.NewRecorder()
	service.AccountHandler(resp, req)

	// Verify response
	require.Equal(t, http.StatusOK, resp.Code)

	// Parse response
	var accountResp struct {
		Status  string   `json:"status"`
		Contact []string `json:"contact"`
	}
	err := json.NewDecoder(resp.Body).Decode(&accountResp)
	require.NoError(t, err)

	assert.Equal(t, common.StatusDeactivated, accountResp.Status)
	// Contact should remain unchanged (original value)
	assert.Equal(t, account.Contact, accountResp.Contact)
}

func TestAccountHandler_UpdateContactOnly(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Update only contact (no status field)
	newContact := []string{"mailto:newcontact@example.com"}
	payload := AccountRequest{
		Contact: newContact,
	}

	url := service.baseRESTURI + "/acme/account/" + string(rune(account.ID))
	req := createJWSRequest(t, service, key, url, payload, true, account.ID)

	// Execute request
	resp := httptest.NewRecorder()
	service.AccountHandler(resp, req)

	// Verify response
	require.Equal(t, http.StatusOK, resp.Code)

	// Parse response
	var accountResp struct {
		Status  string   `json:"status"`
		Contact []string `json:"contact"`
	}
	err := json.NewDecoder(resp.Body).Decode(&accountResp)
	require.NoError(t, err)

	assert.Equal(t, newContact, accountResp.Contact)
	// Status should remain unchanged (valid)
	assert.Equal(t, common.StatusValid, accountResp.Status)
}

func TestAccountHandler_InvalidMailtoFormat(t *testing.T) {
	testCases := []struct {
		name    string
		contact string
	}{
		{
			name:    "mailto with hfields",
			contact: "mailto:test@example.com?subject=test",
		},
		{
			name:    "mailto with multiple addresses",
			contact: "mailto:test1@example.com,test2@example.com",
		},
		{
			name:    "mailto with invalid email",
			contact: "mailto:invalid-email",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			service, _, cleanup := setupTestService(t)
			defer cleanup()

			key := generateTestKey(t)
			account := createTestAccount(t, service, key)

			payload := AccountRequest{
				Contact: []string{tc.contact},
			}

			url := service.baseRESTURI + "/acme/account/" + string(rune(account.ID))
			req := createJWSRequest(t, service, key, url, payload, true, account.ID)

			// Execute request
			resp := httptest.NewRecorder()
			service.AccountHandler(resp, req)

			// Should return error
			require.Equal(t, http.StatusBadRequest, resp.Code)
		})
	}
}

// Tests from account_error_paths_test.go

func TestAccountHandler_ParseKID_Error(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	// Create invalid JWS request (malformed body)
	url := service.baseRESTURI + "/acme/account/123"
	req := httptest.NewRequest(http.MethodPost, url, bytes.NewBufferString("invalid-jws-content"))
	req.Header.Set("Content-Type", "application/jose+json")

	// Execute request
	resp := httptest.NewRecorder()
	service.AccountHandler(resp, req)

	// Should return malformed error from parseKID failure
	assertErrorType(t, resp, common.ErrTypeMalformedError, http.StatusBadRequest)
}

func TestAccountHandler_AccountDAO_SuccessPath(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// POST-as-GET request
	url := service.baseRESTURI + "/acme/account/" + string(rune(account.ID))
	req := createJWSRequest(t, service, key, url, nil, true, account.ID)

	// Execute request
	resp := httptest.NewRecorder()
	service.AccountHandler(resp, req)

	// Should succeed - this exercises the AccountDAO creation path
	require.Equal(t, http.StatusOK, resp.Code)
}

func TestAccountHandler_UnmarshalPayload_Error(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Create request with payload that's not valid JSON for AccountRequest
	// Using a raw string instead of a struct will create invalid JSON
	url := service.baseRESTURI + "/acme/account/" + string(rune(account.ID))
	req := createJWSRequest(t, service, key, url, "invalid-json-structure", true, account.ID)

	// Execute request
	resp := httptest.NewRecorder()
	service.AccountHandler(resp, req)

	// Should return malformed error
	assertErrorType(t, resp, common.ErrTypeMalformedError, http.StatusBadRequest)
}

func TestAccountHandler_InvalidContact_UnsupportedScheme(t *testing.T) {
	testCases := []struct {
		name    string
		contact string
	}{
		{name: "tel scheme", contact: "tel:+1-555-1234"},
		{name: "http scheme", contact: "http://example.com"},
		{name: "https scheme", contact: "https://example.com"},
		{name: "ftp scheme", contact: "ftp://example.com"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			service, _, cleanup := setupTestService(t)
			defer cleanup()

			key := generateTestKey(t)
			account := createTestAccount(t, service, key)

			payload := AccountRequest{
				Contact: []string{tc.contact},
			}

			url := service.baseRESTURI + "/acme/account/" + string(rune(account.ID))
			req := createJWSRequest(t, service, key, url, payload, true, account.ID)

			// Execute request
			resp := httptest.NewRecorder()
			service.AccountHandler(resp, req)

			// Should return unsupportedContact error
			assertErrorType(t, resp, common.ErrTypeUnsupportedContact, http.StatusBadRequest)
		})
	}
}

func TestAccountHandler_InvalidContact_Validation(t *testing.T) {
	testCases := []struct {
		name    string
		contact string
	}{
		{name: "invalid email", contact: "mailto:not-an-email"},
		{name: "email with hfields", contact: "mailto:test@example.com?subject=test"},
		{name: "multiple addresses", contact: "mailto:test1@example.com,test2@example.com"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			service, _, cleanup := setupTestService(t)
			defer cleanup()

			key := generateTestKey(t)
			account := createTestAccount(t, service, key)

			payload := AccountRequest{
				Contact: []string{tc.contact},
			}

			url := service.baseRESTURI + "/acme/account/" + string(rune(account.ID))
			req := createJWSRequest(t, service, key, url, payload, true, account.ID)

			// Execute request
			resp := httptest.NewRecorder()
			service.AccountHandler(resp, req)

			// Should return invalidContact error
			assertErrorType(t, resp, common.ErrTypeInvalidContact, http.StatusBadRequest)
		})
	}
}

func TestAccountHandler_AlreadyDeactivated(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// First deactivation
	payload := AccountRequest{
		Status: common.StatusDeactivated,
	}

	url := service.baseRESTURI + "/acme/account/" + string(rune(account.ID))
	req := createJWSRequest(t, service, key, url, payload, true, account.ID)

	resp := httptest.NewRecorder()
	service.AccountHandler(resp, req)
	require.Equal(t, http.StatusOK, resp.Code)

	// Try to deactivate again
	req2 := createJWSRequest(t, service, key, url, payload, true, account.ID)
	resp2 := httptest.NewRecorder()
	service.AccountHandler(resp2, req2)

	// Should return error - account is already deactivated
	assertErrorType(t, resp2, common.ErrTypeMalformedError, http.StatusBadRequest)
}

func TestAccountHandler_InvalidStatus_NotDeactivated(t *testing.T) {
	testCases := []struct {
		name   string
		status string
	}{
		{name: "valid status", status: common.StatusValid},
		{name: "pending status", status: common.StatusPending},
		{name: "invalid status", status: "invalid"},
		{name: "revoked status", status: common.StatusRevoked},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			service, _, cleanup := setupTestService(t)
			defer cleanup()

			key := generateTestKey(t)
			account := createTestAccount(t, service, key)

			payload := AccountRequest{
				Status: tc.status,
			}

			url := service.baseRESTURI + "/acme/account/" + string(rune(account.ID))
			req := createJWSRequest(t, service, key, url, payload, true, account.ID)

			// Execute request
			resp := httptest.NewRecorder()
			service.AccountHandler(resp, req)

			// Only StatusDeactivated is valid, all others should fail
			assertErrorType(t, resp, common.ErrTypeMalformedError, http.StatusBadRequest)
		})
	}
}

func TestAccountHandler_SaveAccount_Success(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Update contact
	payload := AccountRequest{
		Contact: []string{"mailto:updated@example.com"},
	}

	url := service.baseRESTURI + "/acme/account/" + string(rune(account.ID))
	req := createJWSRequest(t, service, key, url, payload, true, account.ID)

	// Execute request
	resp := httptest.NewRecorder()
	service.AccountHandler(resp, req)

	// Should succeed
	require.Equal(t, http.StatusOK, resp.Code)

	// Verify the account was actually saved
	ctx := context.Background()
	accountDAO, err := service.storageFactory.AccountDAO()
	require.NoError(t, err)

	savedAccount, err := accountDAO.Get(ctx, account.ID)
	require.NoError(t, err)
	assert.Equal(t, payload.Contact, savedAccount.Contact)
}

func TestAccountHandler_EmptyPayload_PostAsGet(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// POST-as-GET: nil payload
	url := service.baseRESTURI + "/acme/account/" + string(rune(account.ID))
	req := createJWSRequest(t, service, key, url, nil, true, account.ID)

	// Execute request
	resp := httptest.NewRecorder()
	service.AccountHandler(resp, req)

	// Should succeed and return account details
	require.Equal(t, http.StatusOK, resp.Code)

	// Verify response contains account data
	var accountResp struct {
		Status  string   `json:"status"`
		Contact []string `json:"contact"`
	}
	err := json.NewDecoder(resp.Body).Decode(&accountResp)
	require.NoError(t, err)
	assert.Equal(t, account.Status, accountResp.Status)
}

func TestAccountHandler_OnlyStatusChange(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)
	originalContact := account.Contact

	// Deactivate account without changing contact
	payload := AccountRequest{
		Status: common.StatusDeactivated,
		// Contact is nil, should not change
	}

	url := service.baseRESTURI + "/acme/account/" + string(rune(account.ID))
	req := createJWSRequest(t, service, key, url, payload, true, account.ID)

	// Execute request
	resp := httptest.NewRecorder()
	service.AccountHandler(resp, req)

	// Should succeed
	require.Equal(t, http.StatusOK, resp.Code)

	// Verify only status changed
	ctx := context.Background()
	accountDAO, err := service.storageFactory.AccountDAO()
	require.NoError(t, err)

	updatedAccount, err := accountDAO.Get(ctx, account.ID)
	require.NoError(t, err)
	assert.Equal(t, common.StatusDeactivated, updatedAccount.Status)
	assert.Equal(t, originalContact, updatedAccount.Contact)
}

func TestAccountHandler_OnlyContactChange(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Update contact without changing status
	payload := AccountRequest{
		Contact: []string{"mailto:newcontact@example.com"},
		// Status is empty string, should not change
	}

	url := service.baseRESTURI + "/acme/account/" + string(rune(account.ID))
	req := createJWSRequest(t, service, key, url, payload, true, account.ID)

	// Execute request
	resp := httptest.NewRecorder()
	service.AccountHandler(resp, req)

	// Should succeed
	require.Equal(t, http.StatusOK, resp.Code)

	// Verify only contact changed
	ctx := context.Background()
	accountDAO, err := service.storageFactory.AccountDAO()
	require.NoError(t, err)

	updatedAccount, err := accountDAO.Get(ctx, account.ID)
	require.NoError(t, err)
	assert.Equal(t, payload.Contact, updatedAccount.Contact)
	assert.Equal(t, common.StatusValid, updatedAccount.Status) // Should remain valid
}

func TestAccountHandler_BothStatusAndContact(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Update both status and contact
	payload := AccountRequest{
		Status:  common.StatusDeactivated,
		Contact: []string{"mailto:final@example.com"},
	}

	url := service.baseRESTURI + "/acme/account/" + string(rune(account.ID))
	req := createJWSRequest(t, service, key, url, payload, true, account.ID)

	// Execute request
	resp := httptest.NewRecorder()
	service.AccountHandler(resp, req)

	// Should succeed
	require.Equal(t, http.StatusOK, resp.Code)

	// Verify both changed
	ctx := context.Background()
	accountDAO, err := service.storageFactory.AccountDAO()
	require.NoError(t, err)

	updatedAccount, err := accountDAO.Get(ctx, account.ID)
	require.NoError(t, err)
	assert.Equal(t, common.StatusDeactivated, updatedAccount.Status)
	assert.Equal(t, payload.Contact, updatedAccount.Contact)
}

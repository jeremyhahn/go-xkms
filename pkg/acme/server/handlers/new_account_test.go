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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewAccountHandler_Success(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)

	// Create new account request
	payload := NewAccountRequest{
		Contact:              []string{"mailto:test@example.com"},
		TermsOfServiceAgreed: true,
	}

	url := service.baseRESTURI + "/acme/new-account"
	req := createJWSRequest(t, service, key, url, payload, false, 0)

	// Execute request
	resp := httptest.NewRecorder()
	service.NewAccountHandler(resp, req)

	// Verify response
	require.Equal(t, http.StatusCreated, resp.Code)
	require.Equal(t, "application/json", resp.Header().Get("Content-Type"))
	require.NotEmpty(t, resp.Header().Get("Replay-Nonce"))
	require.NotEmpty(t, resp.Header().Get("Location"))

	// Parse response body
	var account struct {
		Status  string   `json:"status"`
		Contact []string `json:"contact"`
		Orders  string   `json:"orders"`
	}
	err := json.NewDecoder(resp.Body).Decode(&account)
	require.NoError(t, err)

	assert.Equal(t, common.StatusValid, account.Status)
	assert.Equal(t, payload.Contact, account.Contact)
	assert.NotEmpty(t, account.Orders)
}

func TestNewAccountHandler_OnlyReturnExisting_AccountExists(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)

	// Create an existing account first
	existingAccount := createTestAccount(t, service, key)

	// Request with onlyReturnExisting=true
	payload := NewAccountRequest{
		OnlyReturnExisting: true,
	}

	url := service.baseRESTURI + "/acme/new-account"
	req := createJWSRequest(t, service, key, url, payload, false, 0)

	// Execute request
	resp := httptest.NewRecorder()
	service.NewAccountHandler(resp, req)

	// Verify response - should return existing account with 200 OK
	require.Equal(t, http.StatusOK, resp.Code)

	// Parse response body
	var account struct {
		Status  string   `json:"status"`
		Contact []string `json:"contact"`
		Orders  string   `json:"orders"`
	}
	err := json.NewDecoder(resp.Body).Decode(&account)
	require.NoError(t, err)

	assert.Equal(t, existingAccount.Status, account.Status)
	assert.Equal(t, existingAccount.Contact, account.Contact)
}

func TestNewAccountHandler_OnlyReturnExisting_AccountDoesNotExist(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)

	// Request with onlyReturnExisting=true but account doesn't exist
	payload := NewAccountRequest{
		OnlyReturnExisting: true,
	}

	url := service.baseRESTURI + "/acme/new-account"
	req := createJWSRequest(t, service, key, url, payload, false, 0)

	// Execute request
	resp := httptest.NewRecorder()
	service.NewAccountHandler(resp, req)

	// Should return accountDoesNotExist error
	assertErrorType(t, resp, common.ErrTypeAccountDoesNotExist, http.StatusNotFound)
}

// TestNewAccountHandler_AccountAlreadyExists exercises idempotent
// re-registration: per RFC 8555 §7.3, when the server already has an
// account registered with the supplied public key it MUST respond 200
// (OK) and return the existing account URL — regardless of whether the
// client set onlyReturnExisting. This is what stock ACME clients (e.g.
// golang.org/x/crypto/acme) rely on to recover the KID on retry.
func TestNewAccountHandler_AccountAlreadyExists(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)

	// Create an existing account first.
	existing := createTestAccount(t, service, key)

	// Re-register without onlyReturnExisting.
	payload := NewAccountRequest{
		Contact:              []string{"mailto:test@example.com"},
		TermsOfServiceAgreed: true,
	}

	url := service.baseRESTURI + "/acme/new-account"
	req := createJWSRequest(t, service, key, url, payload, false, 0)

	resp := httptest.NewRecorder()
	service.NewAccountHandler(resp, req)

	require.Equal(t, http.StatusOK, resp.Code, "RFC 8555 §7.3 requires 200 for idempotent re-registration")
	assert.Equal(t, existing.URL, resp.Header().Get("Location"), "Location header must point to the existing account")
}

func TestNewAccountHandler_InvalidContact_UnsupportedScheme(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)

	// Create request with unsupported contact scheme
	payload := NewAccountRequest{
		Contact:              []string{"tel:+1-555-1234"},
		TermsOfServiceAgreed: true,
	}

	url := service.baseRESTURI + "/acme/new-account"
	req := createJWSRequest(t, service, key, url, payload, false, 0)

	// Execute request
	resp := httptest.NewRecorder()
	service.NewAccountHandler(resp, req)

	// Should return unsupportedContact error
	assertErrorType(t, resp, common.ErrTypeUnsupportedContact, http.StatusBadRequest)
}

func TestNewAccountHandler_InvalidContact_InvalidEmail(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)

	// Create request with invalid email
	payload := NewAccountRequest{
		Contact:              []string{"mailto:invalid-email"},
		TermsOfServiceAgreed: true,
	}

	url := service.baseRESTURI + "/acme/new-account"
	req := createJWSRequest(t, service, key, url, payload, false, 0)

	// Execute request
	resp := httptest.NewRecorder()
	service.NewAccountHandler(resp, req)

	// Should return invalidContact error
	assertErrorType(t, resp, common.ErrTypeInvalidContact, http.StatusBadRequest)
}

func TestNewAccountHandler_InvalidContact_Hfields(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)

	// Create request with hfields in mailto URL
	payload := NewAccountRequest{
		Contact:              []string{"mailto:test@example.com?subject=test"},
		TermsOfServiceAgreed: true,
	}

	url := service.baseRESTURI + "/acme/new-account"
	req := createJWSRequest(t, service, key, url, payload, false, 0)

	// Execute request
	resp := httptest.NewRecorder()
	service.NewAccountHandler(resp, req)

	// Should return invalidContact error
	assertErrorType(t, resp, common.ErrTypeInvalidContact, http.StatusBadRequest)
}

func TestNewAccountHandler_InvalidContact_MultipleAddresses(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)

	// Create request with multiple addresses in mailto URL
	payload := NewAccountRequest{
		Contact:              []string{"mailto:test1@example.com,test2@example.com"},
		TermsOfServiceAgreed: true,
	}

	url := service.baseRESTURI + "/acme/new-account"
	req := createJWSRequest(t, service, key, url, payload, false, 0)

	// Execute request
	resp := httptest.NewRecorder()
	service.NewAccountHandler(resp, req)

	// Should return invalidContact error
	assertErrorType(t, resp, common.ErrTypeInvalidContact, http.StatusBadRequest)
}

func TestNewAccountHandler_MalformedJWS(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	url := service.baseRESTURI + "/acme/new-account"
	req := createInvalidJWSRequest(t, url)

	// Execute request
	resp := httptest.NewRecorder()
	service.NewAccountHandler(resp, req)

	// Should return malformed error
	assertErrorType(t, resp, common.ErrTypeMalformedError, http.StatusBadRequest)
}

func TestNewAccountHandler_InvalidJSON(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)

	// Create JWS with invalid JSON payload
	url := service.baseRESTURI + "/acme/new-account"

	// We need to create a JWS with malformed JSON
	// For now, we'll test this scenario by using a string instead of a proper struct
	payload := "invalid-json"
	req := createJWSRequest(t, service, key, url, payload, false, 0)

	// Execute request
	resp := httptest.NewRecorder()
	service.NewAccountHandler(resp, req)

	// Should return malformed error
	assertErrorType(t, resp, common.ErrTypeMalformedError, http.StatusBadRequest)
}

func TestNewAccountHandler_MultipleContacts(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)

	// Create new account request with multiple valid contacts
	payload := NewAccountRequest{
		Contact: []string{
			"mailto:test1@example.com",
			"mailto:test2@example.com",
		},
		TermsOfServiceAgreed: true,
	}

	url := service.baseRESTURI + "/acme/new-account"
	req := createJWSRequest(t, service, key, url, payload, false, 0)

	// Execute request
	resp := httptest.NewRecorder()
	service.NewAccountHandler(resp, req)

	// Verify response
	require.Equal(t, http.StatusCreated, resp.Code)

	// Parse response body
	var account struct {
		Status  string   `json:"status"`
		Contact []string `json:"contact"`
		Orders  string   `json:"orders"`
	}
	err := json.NewDecoder(resp.Body).Decode(&account)
	require.NoError(t, err)

	assert.Equal(t, common.StatusValid, account.Status)
	assert.Equal(t, payload.Contact, account.Contact)
}

func TestNewAccountHandler_EmptyContact(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)

	// Create new account request with empty contact list
	payload := NewAccountRequest{
		Contact:              []string{},
		TermsOfServiceAgreed: true,
	}

	url := service.baseRESTURI + "/acme/new-account"
	req := createJWSRequest(t, service, key, url, payload, false, 0)

	// Execute request
	resp := httptest.NewRecorder()
	service.NewAccountHandler(resp, req)

	// Should succeed - contact is optional
	require.Equal(t, http.StatusCreated, resp.Code)

	// Parse response body
	var account struct {
		Status  string   `json:"status"`
		Contact []string `json:"contact"`
		Orders  string   `json:"orders"`
	}
	err := json.NewDecoder(resp.Body).Decode(&account)
	require.NoError(t, err)

	assert.Equal(t, common.StatusValid, account.Status)
}

func TestNewAccountHandler_ReplayNonceHeader(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)

	// Create new account request
	payload := NewAccountRequest{
		Contact:              []string{"mailto:test@example.com"},
		TermsOfServiceAgreed: true,
	}

	url := service.baseRESTURI + "/acme/new-account"
	req := createJWSRequest(t, service, key, url, payload, false, 0)

	// Execute request
	resp := httptest.NewRecorder()
	service.NewAccountHandler(resp, req)

	// Verify Replay-Nonce header is present
	require.NotEmpty(t, resp.Header().Get("Replay-Nonce"))
}

func TestNewAccountHandler_LinkHeader(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)

	// Create new account request
	payload := NewAccountRequest{
		Contact:              []string{"mailto:test@example.com"},
		TermsOfServiceAgreed: true,
	}

	url := service.baseRESTURI + "/acme/new-account"
	req := createJWSRequest(t, service, key, url, payload, false, 0)

	// Execute request
	resp := httptest.NewRecorder()
	service.NewAccountHandler(resp, req)

	// Verify Link header is present and points to directory
	linkHeader := resp.Header().Get("Link")
	require.NotEmpty(t, linkHeader)
	require.Contains(t, linkHeader, "/acme/directory")
	require.Contains(t, linkHeader, "rel=\"index\"")
}

func TestNewAccountHandler_LocationHeader(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)

	// Create new account request
	payload := NewAccountRequest{
		Contact:              []string{"mailto:test@example.com"},
		TermsOfServiceAgreed: true,
	}

	url := service.baseRESTURI + "/acme/new-account"
	req := createJWSRequest(t, service, key, url, payload, false, 0)

	// Execute request
	resp := httptest.NewRecorder()
	service.NewAccountHandler(resp, req)

	// Verify Location header points to the account URL
	locationHeader := resp.Header().Get("Location")
	require.NotEmpty(t, locationHeader)
	require.Contains(t, locationHeader, "/acme/account/")

	// Verify the header contains the base URI
	assert.Contains(t, locationHeader, service.baseRESTURI)
}

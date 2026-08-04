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
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOrderHandler_GetOrder_Success(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)
	order := createTestOrderSimple(t, service, account.ID)

	// GET order with POST-as-GET (empty payload)
	url := fmt.Sprintf("%s/acme/orders/%d", service.baseRESTURI, order.ID)
	req := createJWSRequest(t, service, key, url, nil, true, account.ID)

	// Add mux vars to simulate route parameters
	req = mux.SetURLVars(req, map[string]string{"id": fmt.Sprintf("%d", order.ID)})

	// Execute request
	resp := httptest.NewRecorder()
	service.OrderHandler(resp, req)

	// Verify response
	require.Equal(t, http.StatusOK, resp.Code)
	require.Equal(t, "application/json", resp.Header().Get("Content-Type"))

	// Parse response
	var orderResp struct {
		Status         string                    `json:"status"`
		Identifiers    []entities.ACMEIdentifier `json:"identifiers"`
		Authorizations []string                  `json:"authorizations"`
		Finalize       string                    `json:"finalize"`
		Expires        string                    `json:"expires,omitempty"`
	}
	err := json.NewDecoder(resp.Body).Decode(&orderResp)
	require.NoError(t, err)

	assert.Equal(t, order.Status, orderResp.Status)
	assert.Equal(t, order.Identifiers, orderResp.Identifiers)
	assert.Equal(t, order.Authorizations, orderResp.Authorizations)
	assert.Equal(t, order.Finalize, orderResp.Finalize)
}

func TestOrderHandler_GetOrder_WithPayload(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)
	order := createTestOrderSimple(t, service, account.ID)

	// POST order status check with empty payload (POST-as-GET)
	url := fmt.Sprintf("%s/acme/orders/%d", service.baseRESTURI, order.ID)
	req := createJWSRequest(t, service, key, url, "", true, account.ID)

	// Add mux vars to simulate route parameters
	req = mux.SetURLVars(req, map[string]string{"id": fmt.Sprintf("%d", order.ID)})

	// Execute request
	resp := httptest.NewRecorder()
	service.OrderHandler(resp, req)

	// Verify response
	require.Equal(t, http.StatusOK, resp.Code)
	require.Equal(t, "application/json", resp.Header().Get("Content-Type"))

	// Parse response
	var orderResp struct {
		Status         string                    `json:"status"`
		Identifiers    []entities.ACMEIdentifier `json:"identifiers"`
		Authorizations []string                  `json:"authorizations"`
		Finalize       string                    `json:"finalize"`
	}
	err := json.NewDecoder(resp.Body).Decode(&orderResp)
	require.NoError(t, err)

	assert.Equal(t, order.Status, orderResp.Status)
}

func TestOrderHandler_InvalidOrderID_NotNumeric(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Try to get order with invalid (non-numeric) ID
	url := fmt.Sprintf("%s/acme/orders/invalid-id", service.baseRESTURI)
	req := createJWSRequest(t, service, key, url, nil, true, account.ID)

	// Add mux vars with invalid ID
	req = mux.SetURLVars(req, map[string]string{"id": "invalid-id"})

	// Execute request
	resp := httptest.NewRecorder()
	service.OrderHandler(resp, req)

	// Should return malformed error
	assertErrorType(t, resp, common.ErrTypeMalformedError, http.StatusBadRequest)
}

func TestOrderHandler_InvalidOrderID_Negative(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Try to get order with negative ID (will fail parsing as uint64)
	url := fmt.Sprintf("%s/acme/orders/-1", service.baseRESTURI)
	req := createJWSRequest(t, service, key, url, nil, true, account.ID)

	// Add mux vars with negative ID
	req = mux.SetURLVars(req, map[string]string{"id": "-1"})

	// Execute request
	resp := httptest.NewRecorder()
	service.OrderHandler(resp, req)

	// Should return malformed error
	assertErrorType(t, resp, common.ErrTypeMalformedError, http.StatusBadRequest)
}

func TestOrderHandler_OrderNotFound(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Try to get order that doesn't exist
	nonExistentOrderID := uint64(99999)
	url := fmt.Sprintf("%s/acme/orders/%d", service.baseRESTURI, nonExistentOrderID)
	req := createJWSRequest(t, service, key, url, nil, true, account.ID)

	// Add mux vars
	req = mux.SetURLVars(req, map[string]string{"id": fmt.Sprintf("%d", nonExistentOrderID)})

	// Execute request
	resp := httptest.NewRecorder()
	service.OrderHandler(resp, req)

	// Should return malformed error (order not found)
	assertErrorType(t, resp, common.ErrTypeMalformedError, http.StatusBadRequest)
}

func TestOrderHandler_MethodNotAllowed_Get(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Try to use GET method (only POST is allowed)
	url := fmt.Sprintf("%s/acme/orders/1", service.baseRESTURI)

	// We need to add valid account context for parseKID to work
	// Create a proper JWS request first to get past parseKID
	jwsReq := createJWSRequest(t, service, key, url, nil, true, account.ID)
	// But change the method to GET
	jwsReq.Method = http.MethodGet
	jwsReq = mux.SetURLVars(jwsReq, map[string]string{"id": "1"})

	// Execute request
	resp := httptest.NewRecorder()
	service.OrderHandler(resp, jwsReq)

	// Should return method not allowed
	require.Equal(t, http.StatusMethodNotAllowed, resp.Code)
}

func TestOrderHandler_MethodNotAllowed_Put(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Try to use PUT method (only POST is allowed)
	url := fmt.Sprintf("%s/acme/orders/1", service.baseRESTURI)
	jwsReq := createJWSRequest(t, service, key, url, nil, true, account.ID)
	jwsReq.Method = http.MethodPut
	jwsReq = mux.SetURLVars(jwsReq, map[string]string{"id": "1"})

	// Execute request
	resp := httptest.NewRecorder()
	service.OrderHandler(resp, jwsReq)

	// Should return method not allowed
	require.Equal(t, http.StatusMethodNotAllowed, resp.Code)
}

func TestOrderHandler_MethodNotAllowed_Delete(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Try to use DELETE method (only POST is allowed)
	url := fmt.Sprintf("%s/acme/orders/1", service.baseRESTURI)
	jwsReq := createJWSRequest(t, service, key, url, nil, true, account.ID)
	jwsReq.Method = http.MethodDelete
	jwsReq = mux.SetURLVars(jwsReq, map[string]string{"id": "1"})

	// Execute request
	resp := httptest.NewRecorder()
	service.OrderHandler(resp, jwsReq)

	// Should return method not allowed
	require.Equal(t, http.StatusMethodNotAllowed, resp.Code)
}

func TestOrderHandler_Unauthorized_WrongAccount(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	// Create two different accounts
	key1 := generateTestKey(t)
	account1 := createTestAccount(t, service, key1)

	key2 := generateTestKey(t)
	account2 := createTestAccount(t, service, key2)

	// Create order for account1
	order := createTestOrderSimple(t, service, account1.ID)

	// Try to access account1's order using account2's credentials
	url := fmt.Sprintf("%s/acme/orders/%d", service.baseRESTURI, order.ID)
	req := createJWSRequest(t, service, key2, url, nil, true, account2.ID)

	// Add mux vars
	req = mux.SetURLVars(req, map[string]string{"id": fmt.Sprintf("%d", order.ID)})

	// Execute request
	resp := httptest.NewRecorder()
	service.OrderHandler(resp, req)

	// Should return malformed error (order not found in account2's storage)
	// Orders are partitioned by account ID, so the order doesn't exist in account2's view
	assertErrorType(t, resp, common.ErrTypeMalformedError, http.StatusBadRequest)
}

func TestOrderHandler_MalformedJWS(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	url := fmt.Sprintf("%s/acme/orders/1", service.baseRESTURI)
	req := createInvalidJWSRequest(t, url)

	// Add mux vars
	req = mux.SetURLVars(req, map[string]string{"id": "1"})

	// Execute request
	resp := httptest.NewRecorder()
	service.OrderHandler(resp, req)

	// Should return malformed error
	assertErrorType(t, resp, common.ErrTypeMalformedError, http.StatusBadRequest)
}

func TestOrderHandler_ReplayNonceHeader(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)
	order := createTestOrderSimple(t, service, account.ID)

	// GET order
	url := fmt.Sprintf("%s/acme/orders/%d", service.baseRESTURI, order.ID)
	req := createJWSRequest(t, service, key, url, nil, true, account.ID)

	// Add mux vars
	req = mux.SetURLVars(req, map[string]string{"id": fmt.Sprintf("%d", order.ID)})

	// Execute request
	resp := httptest.NewRecorder()
	service.OrderHandler(resp, req)

	// Verify Replay-Nonce header is present
	require.NotEmpty(t, resp.Header().Get("Replay-Nonce"))
}

func TestOrderHandler_OrderWithCertificate(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	ctx := context.Background()
	orderDAO, err := service.storageFactory.OrderDAO(account.ID)
	require.NoError(t, err)

	// Generate order ID
	orderID, err := GenerateID()
	require.NoError(t, err)

	// Create order with certificate (ready/valid status)
	order := &entities.ACMEOrder{
		ID:     orderID,
		Status: common.StatusValid,
		Identifiers: []entities.ACMEIdentifier{
			{Type: "dns", Value: "example.com"},
		},
		Expires:        time.Now().Add(24 * time.Hour).Format(time.RFC3339),
		Authorizations: []string{fmt.Sprintf("%s/acme/authz/1", service.baseRESTURI)},
		Finalize:       fmt.Sprintf("%s/acme/orders/1/finalize", service.baseRESTURI),
		Certificate:    fmt.Sprintf("%s/acme/cert/1", service.baseRESTURI),
		AccountID:      account.ID,
	}

	err = orderDAO.Save(ctx, order)
	require.NoError(t, err)

	// GET order
	url := fmt.Sprintf("%s/acme/orders/%d", service.baseRESTURI, order.ID)
	req := createJWSRequest(t, service, key, url, nil, true, account.ID)

	// Add mux vars
	req = mux.SetURLVars(req, map[string]string{"id": fmt.Sprintf("%d", order.ID)})

	// Execute request
	resp := httptest.NewRecorder()
	service.OrderHandler(resp, req)

	// Verify response
	require.Equal(t, http.StatusOK, resp.Code)

	// Parse response
	var orderResp struct {
		Status      string                    `json:"status"`
		Identifiers []entities.ACMEIdentifier `json:"identifiers"`
		Certificate string                    `json:"certificate,omitempty"`
	}
	err = json.NewDecoder(resp.Body).Decode(&orderResp)
	require.NoError(t, err)

	assert.Equal(t, common.StatusValid, orderResp.Status)
	assert.Equal(t, order.Certificate, orderResp.Certificate)
}

func TestOrderHandler_OrderWithError(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	ctx := context.Background()
	orderDAO, err := service.storageFactory.OrderDAO(account.ID)
	require.NoError(t, err)

	// Generate order ID
	orderID, err := GenerateID()
	require.NoError(t, err)

	// Create order with error (invalid status)
	order := &entities.ACMEOrder{
		ID:     orderID,
		Status: common.StatusInvalid,
		Identifiers: []entities.ACMEIdentifier{
			{Type: "dns", Value: "example.com"},
		},
		Expires:        time.Now().Add(24 * time.Hour).Format(time.RFC3339),
		Authorizations: []string{fmt.Sprintf("%s/acme/authz/1", service.baseRESTURI)},
		Finalize:       fmt.Sprintf("%s/acme/orders/1/finalize", service.baseRESTURI),
		Error: &entities.Error{
			Type:   "urn:ietf:params:acme:error:rejectedIdentifier",
			Detail: "The identifier is not acceptable",
		},
		AccountID: account.ID,
	}

	err = orderDAO.Save(ctx, order)
	require.NoError(t, err)

	// GET order
	url := fmt.Sprintf("%s/acme/orders/%d", service.baseRESTURI, order.ID)
	req := createJWSRequest(t, service, key, url, nil, true, account.ID)

	// Add mux vars
	req = mux.SetURLVars(req, map[string]string{"id": fmt.Sprintf("%d", order.ID)})

	// Execute request
	resp := httptest.NewRecorder()
	service.OrderHandler(resp, req)

	// Verify response
	require.Equal(t, http.StatusOK, resp.Code)

	// Parse response
	var orderResp struct {
		Status string          `json:"status"`
		Error  *entities.Error `json:"error,omitempty"`
	}
	err = json.NewDecoder(resp.Body).Decode(&orderResp)
	require.NoError(t, err)

	assert.Equal(t, common.StatusInvalid, orderResp.Status)
	require.NotNil(t, orderResp.Error)
	assert.Equal(t, order.Error.Type, orderResp.Error.Type)
	assert.Equal(t, order.Error.Detail, orderResp.Error.Detail)
}

func TestOrderHandler_OrderWithNotBeforeNotAfter(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	ctx := context.Background()
	orderDAO, err := service.storageFactory.OrderDAO(account.ID)
	require.NoError(t, err)

	// Generate order ID
	orderID, err := GenerateID()
	require.NoError(t, err)

	// Create order with notBefore and notAfter
	notBefore := time.Now().Add(1 * time.Hour).Format(time.RFC3339)
	notAfter := time.Now().Add(90 * 24 * time.Hour).Format(time.RFC3339)

	order := &entities.ACMEOrder{
		ID:     orderID,
		Status: common.StatusPending,
		Identifiers: []entities.ACMEIdentifier{
			{Type: "dns", Value: "example.com"},
		},
		Expires:        time.Now().Add(24 * time.Hour).Format(time.RFC3339),
		NotBefore:      notBefore,
		NotAfter:       notAfter,
		Authorizations: []string{fmt.Sprintf("%s/acme/authz/1", service.baseRESTURI)},
		Finalize:       fmt.Sprintf("%s/acme/orders/1/finalize", service.baseRESTURI),
		AccountID:      account.ID,
	}

	err = orderDAO.Save(ctx, order)
	require.NoError(t, err)

	// GET order
	url := fmt.Sprintf("%s/acme/orders/%d", service.baseRESTURI, order.ID)
	req := createJWSRequest(t, service, key, url, nil, true, account.ID)

	// Add mux vars
	req = mux.SetURLVars(req, map[string]string{"id": fmt.Sprintf("%d", order.ID)})

	// Execute request
	resp := httptest.NewRecorder()
	service.OrderHandler(resp, req)

	// Verify response
	require.Equal(t, http.StatusOK, resp.Code)

	// Parse response
	var orderResp struct {
		Status    string `json:"status"`
		NotBefore string `json:"notBefore,omitempty"`
		NotAfter  string `json:"notAfter,omitempty"`
	}
	err = json.NewDecoder(resp.Body).Decode(&orderResp)
	require.NoError(t, err)

	assert.Equal(t, common.StatusPending, orderResp.Status)
	assert.Equal(t, notBefore, orderResp.NotBefore)
	assert.Equal(t, notAfter, orderResp.NotAfter)
}

func TestOrderHandler_MultipleIdentifiers(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	ctx := context.Background()
	orderDAO, err := service.storageFactory.OrderDAO(account.ID)
	require.NoError(t, err)

	// Generate order ID
	orderID, err := GenerateID()
	require.NoError(t, err)

	// Create order with multiple identifiers
	order := &entities.ACMEOrder{
		ID:     orderID,
		Status: common.StatusPending,
		Identifiers: []entities.ACMEIdentifier{
			{Type: "dns", Value: "example.com"},
			{Type: "dns", Value: "www.example.com"},
			{Type: "dns", Value: "api.example.com"},
		},
		Expires:        time.Now().Add(24 * time.Hour).Format(time.RFC3339),
		Authorizations: []string{fmt.Sprintf("%s/acme/authz/1", service.baseRESTURI)},
		Finalize:       fmt.Sprintf("%s/acme/orders/1/finalize", service.baseRESTURI),
		AccountID:      account.ID,
	}

	err = orderDAO.Save(ctx, order)
	require.NoError(t, err)

	// GET order
	url := fmt.Sprintf("%s/acme/orders/%d", service.baseRESTURI, order.ID)
	req := createJWSRequest(t, service, key, url, nil, true, account.ID)

	// Add mux vars
	req = mux.SetURLVars(req, map[string]string{"id": fmt.Sprintf("%d", order.ID)})

	// Execute request
	resp := httptest.NewRecorder()
	service.OrderHandler(resp, req)

	// Verify response
	require.Equal(t, http.StatusOK, resp.Code)

	// Parse response
	var orderResp struct {
		Status      string                    `json:"status"`
		Identifiers []entities.ACMEIdentifier `json:"identifiers"`
	}
	err = json.NewDecoder(resp.Body).Decode(&orderResp)
	require.NoError(t, err)

	assert.Equal(t, common.StatusPending, orderResp.Status)
	assert.Len(t, orderResp.Identifiers, 3)
	assert.Equal(t, order.Identifiers, orderResp.Identifiers)
}

// TestOrderHandler_RFC8555_Headers verifies RFC 8555 required headers
// are present in order responses per Section 6.1 and 6.5.
func TestOrderHandler_RFC8555_Headers(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)
	order := createTestOrderSimple(t, service, account.ID)

	// GET order
	url := fmt.Sprintf("%s/acme/orders/%d", service.baseRESTURI, order.ID)
	req := createJWSRequest(t, service, key, url, nil, true, account.ID)
	req = mux.SetURLVars(req, map[string]string{"id": fmt.Sprintf("%d", order.ID)})

	resp := httptest.NewRecorder()
	service.OrderHandler(resp, req)

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

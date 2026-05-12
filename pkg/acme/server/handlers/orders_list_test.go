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
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOrdersListHandler_GetOrdersList(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Create a test order for the account
	order := createTestOrderSimple(t, service, account.ID)

	// GET orders list with POST-as-GET (empty payload)
	url := service.baseRESTURI + "/acme/account/" + string(rune(account.ID)) + "/orders"
	req := createJWSRequest(t, service, key, url, nil, true, account.ID)

	// Execute request
	resp := httptest.NewRecorder()
	service.OrdersListHandler(resp, req)

	// Verify response
	require.Equal(t, http.StatusOK, resp.Code)
	require.Equal(t, "application/json", resp.Header().Get("Content-Type"))

	// Parse response
	var ordersResp struct {
		Orders []string `json:"orders"`
	}
	err := json.NewDecoder(resp.Body).Decode(&ordersResp)
	require.NoError(t, err)

	// Verify the order URL is in the list
	require.Len(t, ordersResp.Orders, 1)
	assert.Equal(t, order.URL, ordersResp.Orders[0])
}

func TestOrdersListHandler_EmptyOrdersList(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// GET orders list without creating any orders
	url := service.baseRESTURI + "/acme/account/" + string(rune(account.ID)) + "/orders"
	req := createJWSRequest(t, service, key, url, nil, true, account.ID)

	// Execute request
	resp := httptest.NewRecorder()
	service.OrdersListHandler(resp, req)

	// Verify response
	require.Equal(t, http.StatusOK, resp.Code)
	require.Equal(t, "application/json", resp.Header().Get("Content-Type"))

	// Parse response
	var ordersResp struct {
		Orders []string `json:"orders"`
	}
	err := json.NewDecoder(resp.Body).Decode(&ordersResp)
	require.NoError(t, err)

	// Verify empty list
	require.Len(t, ordersResp.Orders, 0)
}

func TestOrdersListHandler_MultipleOrders(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Create multiple test orders for the account
	order1 := createTestOrderSimple(t, service, account.ID)
	order2 := createTestOrderSimple(t, service, account.ID)
	order3 := createTestOrderSimple(t, service, account.ID)

	// GET orders list with POST-as-GET (empty payload)
	url := service.baseRESTURI + "/acme/account/" + string(rune(account.ID)) + "/orders"
	req := createJWSRequest(t, service, key, url, nil, true, account.ID)

	// Execute request
	resp := httptest.NewRecorder()
	service.OrdersListHandler(resp, req)

	// Verify response
	require.Equal(t, http.StatusOK, resp.Code)
	require.Equal(t, "application/json", resp.Header().Get("Content-Type"))

	// Parse response
	var ordersResp struct {
		Orders []string `json:"orders"`
	}
	err := json.NewDecoder(resp.Body).Decode(&ordersResp)
	require.NoError(t, err)

	// Verify all order URLs are in the list
	require.Len(t, ordersResp.Orders, 3)
	assert.Contains(t, ordersResp.Orders, order1.URL)
	assert.Contains(t, ordersResp.Orders, order2.URL)
	assert.Contains(t, ordersResp.Orders, order3.URL)
}

func TestOrdersListHandler_PostAsGet(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Create a test order
	createTestOrderSimple(t, service, account.ID)

	// POST-as-GET with empty string payload
	url := service.baseRESTURI + "/acme/account/" + string(rune(account.ID)) + "/orders"
	req := createJWSRequest(t, service, key, url, nil, true, account.ID)
	req.Method = http.MethodPost

	// Execute request
	resp := httptest.NewRecorder()
	service.OrdersListHandler(resp, req)

	// Verify response - POST-as-GET should work
	require.Equal(t, http.StatusOK, resp.Code)
	require.Equal(t, "application/json", resp.Header().Get("Content-Type"))

	// Parse response
	var ordersResp struct {
		Orders []string `json:"orders"`
	}
	err := json.NewDecoder(resp.Body).Decode(&ordersResp)
	require.NoError(t, err)

	// Verify we got the orders list
	require.Len(t, ordersResp.Orders, 1)
}

func TestOrdersListHandler_InvalidAccountID(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	// Create account but use wrong account ID in request
	account := createTestAccount(t, service, key)

	// Create different key for different account
	wrongKey := generateTestKey(t)

	// Try to GET orders list with wrong account's key
	url := service.baseRESTURI + "/acme/account/" + string(rune(account.ID)) + "/orders"
	req := createJWSRequest(t, service, wrongKey, url, nil, true, account.ID)

	// Execute request
	resp := httptest.NewRecorder()
	service.OrdersListHandler(resp, req)

	// Should return malformed error due to key mismatch
	assertErrorType(t, resp, "malformed", http.StatusBadRequest)
}

func TestOrdersListHandler_MalformedJWS(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	url := service.baseRESTURI + "/acme/account/123/orders"
	req := createInvalidJWSRequest(t, url)

	// Execute request
	resp := httptest.NewRecorder()
	service.OrdersListHandler(resp, req)

	// Should return malformed error
	assertErrorType(t, resp, "malformed", http.StatusBadRequest)
}

func TestOrdersListHandler_MethodNotAllowed(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Try to use PUT method (not allowed)
	url := service.baseRESTURI + "/acme/account/" + string(rune(account.ID)) + "/orders"
	req := createJWSRequest(t, service, key, url, nil, true, account.ID)
	req.Method = http.MethodPut

	// Execute request
	resp := httptest.NewRecorder()
	service.OrdersListHandler(resp, req)

	// Should return malformed error for method not allowed
	assertErrorType(t, resp, "malformed", http.StatusBadRequest)
}

func TestOrdersListHandler_InvalidPageParameter(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Create a test order
	createTestOrderSimple(t, service, account.ID)

	// GET orders list with invalid page parameter
	url := fmt.Sprintf("%s/acme/account/%d/orders/invalid", service.baseRESTURI, account.ID)
	req := createJWSRequest(t, service, key, url, nil, true, account.ID)

	// Set invalid page parameter using mux vars
	req = mux.SetURLVars(req, map[string]string{"page": "invalid"})

	// Execute request
	resp := httptest.NewRecorder()
	service.OrdersListHandler(resp, req)

	// Should return malformed error for invalid page parameter
	assertErrorType(t, resp, "malformed", http.StatusBadRequest)
}

func TestOrdersListHandler_ValidPageParameter(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Create a test order
	order := createTestOrderSimple(t, service, account.ID)

	// GET orders list with valid page parameter
	url := fmt.Sprintf("%s/acme/account/%d/orders/1", service.baseRESTURI, account.ID)
	req := createJWSRequest(t, service, key, url, nil, true, account.ID)

	// Set valid page parameter using mux vars
	req = mux.SetURLVars(req, map[string]string{"page": "1"})

	// Execute request
	resp := httptest.NewRecorder()
	service.OrdersListHandler(resp, req)

	// Should succeed with valid page parameter
	require.Equal(t, http.StatusOK, resp.Code)
	require.Equal(t, "application/json", resp.Header().Get("Content-Type"))

	// Parse response
	var ordersResp struct {
		Orders []string `json:"orders"`
	}
	err := json.NewDecoder(resp.Body).Decode(&ordersResp)
	require.NoError(t, err)

	// Verify the order URL is in the list
	require.Len(t, ordersResp.Orders, 1)
	assert.Equal(t, order.URL, ordersResp.Orders[0])
}

// TestOrdersListHandler_RFC8555_Headers verifies that RFC 8555 required headers
// are present in the response per Section 6.1 (Replay-Nonce) and Section 6.5 (Link).
func TestOrdersListHandler_RFC8555_Headers(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// GET orders list
	url := service.baseRESTURI + "/acme/account/" + string(rune(account.ID)) + "/orders"
	req := createJWSRequest(t, service, key, url, nil, true, account.ID)

	// Execute request
	resp := httptest.NewRecorder()
	service.OrdersListHandler(resp, req)

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

func TestOrdersListHandler_NoPageParameter(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Create a test order
	order := createTestOrderSimple(t, service, account.ID)

	// GET orders list without page parameter (empty string)
	url := fmt.Sprintf("%s/acme/account/%d/orders", service.baseRESTURI, account.ID)
	req := createJWSRequest(t, service, key, url, nil, true, account.ID)

	// Set empty page parameter using mux vars
	req = mux.SetURLVars(req, map[string]string{"page": ""})

	// Execute request
	resp := httptest.NewRecorder()
	service.OrdersListHandler(resp, req)

	// Should succeed with empty page parameter
	require.Equal(t, http.StatusOK, resp.Code)
	require.Equal(t, "application/json", resp.Header().Get("Content-Type"))

	// Parse response
	var ordersResp struct {
		Orders []string `json:"orders"`
	}
	err := json.NewDecoder(resp.Body).Decode(&ordersResp)
	require.NoError(t, err)

	// Verify the order URL is in the list
	require.Len(t, ordersResp.Orders, 1)
	assert.Equal(t, order.URL, ordersResp.Orders[0])
}

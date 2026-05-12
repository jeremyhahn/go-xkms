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

//go:build local

package rfc8555

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	"github.com/jeremyhahn/go-xkms/test/integration"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// RFC 8555 Section 7.1 - Resources

// TestRFC_7_1_1_Directory verifies RFC 8555 Section 7.1.1 - Directory
// Requirements:
// - MUST return all required URLs (newNonce, newAccount, newOrder, revokeCert, keyChange)
// - MUST use Content-Type: application/json
// - MAY include meta field with additional information
func TestRFC_7_1_1_Directory(t *testing.T) {
	server := integration.NewACMEServer(t)
	defer server.Stop()

	t.Log("RFC 8555 Section 7.1.1 - Testing Directory endpoint")

	// Make GET request to directory
	resp, err := http.Get(integration.TestServerURL + "/acme/directory")
	require.NoError(t, err, "Directory endpoint must be accessible")
	defer resp.Body.Close()

	// Verify status code
	assert.Equal(t, http.StatusOK, resp.StatusCode, "Directory MUST return 200 OK")

	// Verify Content-Type header
	contentType := resp.Header.Get("Content-Type")
	assert.Equal(t, "application/json", contentType, "Directory MUST return Content-Type: application/json")

	// Parse response body
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var directory common.Directory
	err = json.Unmarshal(body, &directory)
	require.NoError(t, err, "Directory response must be valid JSON")

	// Verify required fields per RFC 8555 Section 7.1.1
	assert.NotEmpty(t, directory.NewNonce, "Directory MUST include newNonce URL")
	assert.NotEmpty(t, directory.NewAccount, "Directory MUST include newAccount URL")
	assert.NotEmpty(t, directory.NewOrder, "Directory MUST include newOrder URL")
	assert.NotEmpty(t, directory.RevokeCert, "Directory MUST include revokeCert URL")
	assert.NotEmpty(t, directory.KeyChange, "Directory MUST include keyChange URL")

	// Verify URLs are valid and contain base URL
	assert.Contains(t, directory.NewNonce, integration.TestServerURL, "newNonce URL must be absolute")
	assert.Contains(t, directory.NewAccount, integration.TestServerURL, "newAccount URL must be absolute")
	assert.Contains(t, directory.NewOrder, integration.TestServerURL, "newOrder URL must be absolute")
	assert.Contains(t, directory.RevokeCert, integration.TestServerURL, "revokeCert URL must be absolute")
	assert.Contains(t, directory.KeyChange, integration.TestServerURL, "keyChange URL must be absolute")

	t.Logf("✓ Directory contains all required RFC 8555 fields")
	t.Logf("  newNonce: %s", directory.NewNonce)
	t.Logf("  newAccount: %s", directory.NewAccount)
	t.Logf("  newOrder: %s", directory.NewOrder)
	t.Logf("  revokeCert: %s", directory.RevokeCert)
	t.Logf("  keyChange: %s", directory.KeyChange)
}

// TestRFC_7_1_2_Account verifies RFC 8555 Section 7.1.2 - Account Objects
// Requirements:
// - MUST include status field (valid, deactivated, or revoked)
// - MAY include contact array
// - MUST include orders URL
// - MUST be returned with Location header containing account URL
func TestRFC_7_1_2_Account(t *testing.T) {
	server := integration.NewACMEServer(t)
	defer server.Stop()

	t.Log("RFC 8555 Section 7.1.2 - Testing Account Object structure")

	// Create account
	accountKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	nonce := integration.GetNonce(t, integration.TestServerURL)
	accountPayload := map[string]interface{}{
		"termsOfServiceAgreed": true,
		"contact":              []string{"mailto:rfc7.1.2@example.com"},
	}
	accountJWS := integration.CreateJWS(t, accountKey, nonce, integration.TestServerURL+"/acme/new-account", accountPayload, false, "")

	resp, err := http.Post(integration.TestServerURL+"/acme/new-account", "application/jose+json", bytes.NewReader([]byte(accountJWS)))
	require.NoError(t, err)
	defer resp.Body.Close()

	// Verify response
	assert.Equal(t, http.StatusCreated, resp.StatusCode, "Account creation MUST return 201 Created")

	// Verify Location header (RFC 8555 Section 7.1.2)
	location := resp.Header.Get("Location")
	assert.NotEmpty(t, location, "Account creation MUST include Location header")
	assert.Contains(t, location, integration.TestServerURL, "Location must be absolute URL")

	// Parse account object
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var account entities.ACMEAccount
	err = json.Unmarshal(body, &account)
	require.NoError(t, err, "Account response must be valid JSON")

	// Verify required fields per RFC 8555 Section 7.1.2
	assert.NotEmpty(t, account.Status, "Account MUST include status field")
	assert.Contains(t, []string{"valid", "deactivated", "revoked"}, account.Status, "Status must be valid, deactivated, or revoked")
	assert.NotEmpty(t, account.Orders, "Account MUST include orders URL")
	assert.Contains(t, account.Contact, "mailto:rfc7.1.2@example.com", "Account MUST preserve contact information")

	t.Logf("✓ Account object contains all required RFC 8555 fields")
	t.Logf("  status: %s", account.Status)
	t.Logf("  orders: %s", account.Orders)
	t.Logf("  contact: %v", account.Contact)
	t.Logf("  Location: %s", location)

	// Verify account is persisted to backend storage (DAO verification)
	t.Log("Verifying account persisted to backend storage")
	accountDAO, err := server.StorageFactory().AccountDAO()
	require.NoError(t, err, "AccountDAO must be accessible")

	ctx := context.Background()
	// Get all accounts and find the one we just created
	var accounts []*entities.ACMEAccount
	err = accountDAO.ForEachPage(ctx, qrdbsdk.PageQuery{Page: 1, PageSize: 1000}, func(page qrdbsdk.PageResult[*entities.ACMEAccount]) error {
		accounts = append(accounts, page.Entities...)
		return nil
	})
	require.NoError(t, err, "Should be able to list accounts")
	require.NotEmpty(t, accounts, "Account MUST be persisted to backend storage")

	// Find our account by contact
	var storedAccount *entities.ACMEAccount
	for _, acc := range accounts {
		for _, contact := range acc.Contact {
			if contact == "mailto:rfc7.1.2@example.com" {
				storedAccount = acc
				break
			}
		}
	}
	require.NotNil(t, storedAccount, "Account MUST be persisted to backend storage")
	assert.Equal(t, account.Status, storedAccount.Status, "Stored account status must match")
	assert.Equal(t, account.Contact, storedAccount.Contact, "Stored account contact must match")

	t.Logf("✓ Account verified in backend storage (ID: %d)", storedAccount.ID)
}

// TestRFC_7_1_3_Order verifies RFC 8555 Section 7.1.3 - Order Objects
// Requirements:
// - MUST include status field (pending, ready, processing, valid, or invalid)
// - MUST include identifiers array
// - MUST include authorizations array
// - MUST include finalize URL
// - MAY include notBefore and notAfter
func TestRFC_7_1_3_Order(t *testing.T) {
	server := integration.NewACMEServer(t)
	defer server.Stop()

	t.Log("RFC 8555 Section 7.1.3 - Testing Order Object structure")

	// Create account first
	accountKey, accountURL := integration.CreateTestAccount(t, integration.TestServerURL, "rfc7.1.3@example.com")

	// Create order
	nonce := integration.GetNonce(t, integration.TestServerURL)
	orderPayload := map[string]interface{}{
		"identifiers": []map[string]string{
			{"type": "dns", "value": "rfc-test-7-1-3.example.com"},
		},
	}
	orderJWS := integration.CreateJWS(t, accountKey, nonce, integration.TestServerURL+"/acme/new-order", orderPayload, true, accountURL)

	resp, err := http.Post(integration.TestServerURL+"/acme/new-order", "application/jose+json", bytes.NewReader([]byte(orderJWS)))
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusCreated, resp.StatusCode, "Order creation MUST return 201 Created")

	// Parse order object
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var order entities.ACMEOrder
	err = json.Unmarshal(body, &order)
	require.NoError(t, err, "Order response must be valid JSON")

	// Verify required fields per RFC 8555 Section 7.1.3
	assert.NotEmpty(t, order.Status, "Order MUST include status field")
	validStatuses := []string{"pending", "ready", "processing", "valid", "invalid"}
	assert.Contains(t, validStatuses, order.Status, "Order status must be one of: pending, ready, processing, valid, invalid")

	assert.NotEmpty(t, order.Identifiers, "Order MUST include identifiers array")
	assert.Len(t, order.Identifiers, 1, "Order must have correct number of identifiers")
	assert.Equal(t, "dns", order.Identifiers[0].Type, "Identifier type must match request")
	assert.Equal(t, "rfc-test-7-1-3.example.com", order.Identifiers[0].Value, "Identifier value must match request")

	assert.NotEmpty(t, order.Authorizations, "Order MUST include authorizations array")
	assert.NotEmpty(t, order.Finalize, "Order MUST include finalize URL")
	assert.Contains(t, order.Finalize, integration.TestServerURL, "Finalize URL must be absolute")

	t.Logf("✓ Order object contains all required RFC 8555 fields")
	t.Logf("  status: %s", order.Status)
	t.Logf("  identifiers: %d", len(order.Identifiers))
	t.Logf("  authorizations: %d", len(order.Authorizations))
	t.Logf("  finalize: %s", order.Finalize)

	// Verify order is persisted to backend storage (DAO verification)
	t.Log("Verifying order persisted to backend storage")

	// First get the account ID from the account we created
	accountDAO, err := server.StorageFactory().AccountDAO()
	require.NoError(t, err)
	ctx := context.Background()

	var accounts []*entities.ACMEAccount
	err = accountDAO.ForEachPage(ctx, qrdbsdk.PageQuery{Page: 1, PageSize: 1000}, func(page qrdbsdk.PageResult[*entities.ACMEAccount]) error {
		accounts = append(accounts, page.Entities...)
		return nil
	})
	require.NoError(t, err)
	require.NotEmpty(t, accounts, "Account must exist")

	// Find the most recent account (the one we just created)
	var testAccount *entities.ACMEAccount
	for _, acc := range accounts {
		for _, contact := range acc.Contact {
			if contact == "mailto:rfc7.1.3@example.com" {
				testAccount = acc
				break
			}
		}
	}
	require.NotNil(t, testAccount, "Test account must exist")

	orderDAO, err := server.StorageFactory().OrderDAO(testAccount.ID)
	require.NoError(t, err, "OrderDAO must be accessible")

	// List all orders for this account and find the one we created
	var orders []*entities.ACMEOrder
	err = orderDAO.ForEachPage(ctx, qrdbsdk.PageQuery{Page: 1, PageSize: 1000}, func(page qrdbsdk.PageResult[*entities.ACMEOrder]) error {
		orders = append(orders, page.Entities...)
		return nil
	})
	require.NoError(t, err, "Should be able to list orders")
	require.NotEmpty(t, orders, "Order MUST be persisted to backend storage")

	// Get the most recent order (should be ours)
	storedOrder := orders[len(orders)-1]
	assert.Equal(t, order.Status, storedOrder.Status, "Stored order status must match")
	assert.Equal(t, len(order.Identifiers), len(storedOrder.Identifiers), "Stored order identifiers must match")

	t.Logf("✓ Order verified in backend storage (ID: %d)", storedOrder.ID)
}

// TestRFC_7_1_4_Authorization verifies RFC 8555 Section 7.1.4 - Authorization Objects
// Requirements:
// - MUST include identifier object
// - MUST include status field (pending, valid, invalid, deactivated, expired, revoked)
// - MUST include challenges array
// - MAY include expires field
func TestRFC_7_1_4_Authorization(t *testing.T) {
	server := integration.NewACMEServer(t)
	defer server.Stop()

	t.Log("RFC 8555 Section 7.1.4 - Testing Authorization Object structure")

	// Create account and order
	accountKey, accountURL := integration.CreateTestAccount(t, integration.TestServerURL, "rfc7.1.4@example.com")
	orderURL, authzURLs := integration.CreateTestOrder(t, integration.TestServerURL, accountKey, accountURL, "rfc-test-7-1-4.example.com")
	require.NotEmpty(t, authzURLs, "Order must have authorizations")

	t.Logf("Order created: %s", orderURL)
	t.Logf("Authorization URL: %s", authzURLs[0])

	// Fetch authorization (POST-as-GET)
	nonce := integration.GetNonce(t, integration.TestServerURL)
	authzJWS := integration.CreateJWS(t, accountKey, nonce, authzURLs[0], "", true, accountURL)

	resp, err := http.Post(authzURLs[0], "application/jose+json", bytes.NewReader([]byte(authzJWS)))
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode, "Authorization fetch MUST return 200 OK")

	// Parse authorization object
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var authz entities.ACMEAuthorization
	err = json.Unmarshal(body, &authz)
	require.NoError(t, err, "Authorization response must be valid JSON")

	// Verify required fields per RFC 8555 Section 7.1.4
	assert.NotEmpty(t, authz.Identifier, "Authorization MUST include identifier object")
	assert.NotEmpty(t, authz.Identifier.Type, "Identifier MUST include type")
	assert.NotEmpty(t, authz.Identifier.Value, "Identifier MUST include value")

	assert.NotEmpty(t, authz.Status, "Authorization MUST include status field")
	validStatuses := []string{"pending", "valid", "invalid", "deactivated", "expired", "revoked"}
	assert.Contains(t, validStatuses, authz.Status, "Authorization status must be valid")

	assert.NotEmpty(t, authz.Challenges, "Authorization MUST include challenges array")
	assert.Greater(t, len(authz.Challenges), 0, "Authorization must have at least one challenge")

	t.Logf("✓ Authorization object contains all required RFC 8555 fields")
	t.Logf("  identifier: %s:%s", authz.Identifier.Type, authz.Identifier.Value)
	t.Logf("  status: %s", authz.Status)
	t.Logf("  challenges: %d", len(authz.Challenges))
	if authz.Expires != "" {
		t.Logf("  expires: %s", authz.Expires)
	}
}

// TestRFC_7_1_5_Challenge verifies RFC 8555 Section 7.1.5 - Challenge Objects
// Requirements:
// - MUST include type field
// - MUST include url field
// - MUST include status field (pending, processing, valid, invalid)
// - MUST include token field for applicable challenge types
func TestRFC_7_1_5_Challenge(t *testing.T) {
	server := integration.NewACMEServer(t)
	defer server.Stop()

	t.Log("RFC 8555 Section 7.1.5 - Testing Challenge Object structure")

	// Create account and order
	accountKey, accountURL := integration.CreateTestAccount(t, integration.TestServerURL, "rfc7.1.5@example.com")
	_, authzURLs := integration.CreateTestOrder(t, integration.TestServerURL, accountKey, accountURL, "rfc-test-7-1-5.example.com")
	require.NotEmpty(t, authzURLs, "Order must have authorizations")

	// Fetch authorization to get challenges
	nonce := integration.GetNonce(t, integration.TestServerURL)
	authzJWS := integration.CreateJWS(t, accountKey, nonce, authzURLs[0], "", true, accountURL)

	resp, err := http.Post(authzURLs[0], "application/jose+json", bytes.NewReader([]byte(authzJWS)))
	require.NoError(t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var authz entities.ACMEAuthorization
	err = json.Unmarshal(body, &authz)
	require.NoError(t, err)

	require.NotEmpty(t, authz.Challenges, "Authorization must have challenges")

	// Verify each challenge object
	for i, challenge := range authz.Challenges {
		t.Logf("Verifying challenge %d: %s", i, challenge.Type)

		// Verify required fields per RFC 8555 Section 7.1.5
		assert.NotEmpty(t, challenge.Type, "Challenge MUST include type field")
		assert.NotEmpty(t, challenge.URL, "Challenge MUST include url field")
		assert.Contains(t, challenge.URL, integration.TestServerURL, "Challenge URL must be absolute")

		assert.NotEmpty(t, challenge.Status, "Challenge MUST include status field")
		validStatuses := []string{"pending", "processing", "valid", "invalid"}
		assert.Contains(t, validStatuses, challenge.Status, "Challenge status must be valid")

		// Token is required for most challenge types
		if challenge.Type != "tls-alpn-01" {
			assert.NotEmpty(t, challenge.Token, "Challenge MUST include token field")
		}

		t.Logf("  ✓ Challenge %s has all required fields", challenge.Type)
		t.Logf("    type: %s", challenge.Type)
		t.Logf("    url: %s", challenge.URL)
		t.Logf("    status: %s", challenge.Status)
		t.Logf("    token: %s", challenge.Token)
	}

	t.Logf("✓ All challenge objects contain required RFC 8555 fields")
}

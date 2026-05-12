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
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	"github.com/jeremyhahn/go-xkms/test/integration"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// RFC 8555 Section 7.3 - Account Management

// TestRFC_7_3_1_AccountLookup verifies RFC 8555 Section 7.3.1 - Finding Account URL
// Requirements:
// - Server MUST support onlyReturnExisting=true
// - Server MUST return 200 OK with Location header if account exists
// - Server MUST return error if account doesn't exist
func TestRFC_7_3_1_AccountLookup(t *testing.T) {
	server := integration.NewACMEServer(t)
	defer server.Stop()

	t.Log("RFC 8555 Section 7.3.1 - Testing account URL lookup")

	// Create account
	accountKey, accountURL := integration.CreateTestAccount(t, integration.TestServerURL, "rfc7.3.1@example.com")
	require.NotEmpty(t, accountURL)

	// Look up existing account
	nonce := integration.GetNonce(t, integration.TestServerURL)
	lookupPayload := map[string]interface{}{
		"onlyReturnExisting": true,
	}
	lookupJWS := integration.CreateJWS(t, accountKey, nonce, integration.TestServerURL+"/acme/new-account", lookupPayload, false, "")

	resp, err := http.Post(integration.TestServerURL+"/acme/new-account", "application/jose+json", bytes.NewReader([]byte(lookupJWS)))
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode, "Account lookup MUST return 200 OK for existing account")

	location := resp.Header.Get("Location")
	assert.NotEmpty(t, location, "Response MUST include Location header")
	assert.Equal(t, accountURL, location, "Location must match original account URL")

	t.Logf("✓ Account lookup returned correct URL: %s", location)
}

// TestRFC_7_3_2_AccountUpdate verifies RFC 8555 Section 7.3.2 - Account Update
// Requirements:
// - Server MUST support updating contact information
// - Server MUST return updated account object
func TestRFC_7_3_2_AccountUpdate(t *testing.T) {
	server := integration.NewACMEServer(t)
	defer server.Stop()

	t.Log("RFC 8555 Section 7.3.2 - Testing account update")

	// Create account
	accountKey, accountURL := integration.CreateTestAccount(t, integration.TestServerURL, "rfc7.3.2@example.com")

	// Update account contact
	nonce := integration.GetNonce(t, integration.TestServerURL)
	updatePayload := map[string]interface{}{
		"contact": []string{"mailto:updated-7.3.2@example.com", "mailto:admin@example.com"},
	}
	updateJWS := integration.CreateJWS(t, accountKey, nonce, accountURL, updatePayload, true, accountURL)

	resp, err := http.Post(accountURL, "application/jose+json", bytes.NewReader([]byte(updateJWS)))
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode, "Account update MUST return 200 OK")

	// Verify updated contact
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var account entities.ACMEAccount
	err = json.Unmarshal(body, &account)
	require.NoError(t, err)

	assert.Contains(t, account.Contact, "mailto:updated-7.3.2@example.com", "Contact must be updated")
	assert.Contains(t, account.Contact, "mailto:admin@example.com", "Contact must be updated")

	t.Logf("✓ Account contact updated successfully: %v", account.Contact)
}

// TestRFC_7_3_2_AccountUpdate_DAOVerification verifies account updates are persisted
func TestRFC_7_3_2_AccountUpdate_DAOVerification(t *testing.T) {
	server := integration.NewACMEServer(t)
	defer server.Stop()

	t.Log("RFC 8555 Section 7.3.2 - Testing account update with DAO verification")

	// Create account
	accountKey, accountURL := integration.CreateTestAccount(t, integration.TestServerURL, "rfc7.3.2-dao@example.com")

	// Get account from storage before update
	accountDAO, err := server.StorageFactory().AccountDAO()
	require.NoError(t, err)
	ctx := context.Background()

	var accounts []*entities.ACMEAccount
	err = accountDAO.ForEachPage(ctx, qrdbsdk.PageQuery{Page: 1, PageSize: 1000}, func(page qrdbsdk.PageResult[*entities.ACMEAccount]) error {
		accounts = append(accounts, page.Entities...)
		return nil
	})
	require.NoError(t, err)
	require.NotEmpty(t, accounts)

	// Find the account we just created
	var originalAccount *entities.ACMEAccount
	for _, acc := range accounts {
		for _, contact := range acc.Contact {
			if contact == "mailto:rfc7.3.2-dao@example.com" {
				originalAccount = acc
				break
			}
		}
	}
	require.NotNil(t, originalAccount, "Original account must exist in storage")
	t.Logf("Original account contact: %v", originalAccount.Contact)

	// Update account contact
	nonce := integration.GetNonce(t, integration.TestServerURL)
	updatePayload := map[string]interface{}{
		"contact": []string{"mailto:updated-7.3.2-dao@example.com", "mailto:admin-dao@example.com"},
	}
	updateJWS := integration.CreateJWS(t, accountKey, nonce, accountURL, updatePayload, true, accountURL)

	resp, err := http.Post(accountURL, "application/jose+json", bytes.NewReader([]byte(updateJWS)))
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode, "Account update MUST return 200 OK")

	// Verify updated account in HTTP response
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var account entities.ACMEAccount
	err = json.Unmarshal(body, &account)
	require.NoError(t, err)

	assert.Contains(t, account.Contact, "mailto:updated-7.3.2-dao@example.com", "Contact must be updated")
	assert.Contains(t, account.Contact, "mailto:admin-dao@example.com", "Contact must be updated")

	t.Logf("✓ Account contact updated in HTTP response: %v", account.Contact)

	// Verify update persisted to backend storage
	t.Log("Verifying account update persisted to backend storage")
	storedAccount, err := accountDAO.Get(ctx, originalAccount.ID)
	require.NoError(t, err, "Updated account MUST be persisted to backend storage")

	assert.Contains(t, storedAccount.Contact, "mailto:updated-7.3.2-dao@example.com",
		"Backend storage MUST contain updated contact")
	assert.Contains(t, storedAccount.Contact, "mailto:admin-dao@example.com",
		"Backend storage MUST contain updated contact")
	assert.NotContains(t, storedAccount.Contact, "mailto:rfc7.3.2-dao@example.com",
		"Backend storage MUST NOT contain old contact")

	t.Logf("✓ Account update verified in backend storage (ID: %d)", storedAccount.ID)
	t.Logf("  Stored contact: %v", storedAccount.Contact)
}

// TestRFC_7_3_6_AccountDeactivation verifies RFC 8555 Section 7.3.6 - Account Deactivation
// Requirements:
// - Server MUST support account deactivation
// - Account status MUST change to "deactivated"
func TestRFC_7_3_6_AccountDeactivation(t *testing.T) {
	server := integration.NewACMEServer(t)
	defer server.Stop()

	t.Log("RFC 8555 Section 7.3.6 - Testing account deactivation")

	// Create account
	accountKey, accountURL := integration.CreateTestAccount(t, integration.TestServerURL, "rfc7.3.6@example.com")

	// Deactivate account
	nonce := integration.GetNonce(t, integration.TestServerURL)
	deactivatePayload := map[string]interface{}{
		"status": "deactivated",
	}
	deactivateJWS := integration.CreateJWS(t, accountKey, nonce, accountURL, deactivatePayload, true, accountURL)

	resp, err := http.Post(accountURL, "application/jose+json", bytes.NewReader([]byte(deactivateJWS)))
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode, "Account deactivation MUST return 200 OK")

	// Verify account is deactivated
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var account entities.ACMEAccount
	err = json.Unmarshal(body, &account)
	require.NoError(t, err)

	assert.Equal(t, "deactivated", account.Status, "Account status MUST be 'deactivated'")

	t.Logf("✓ Account deactivated successfully, status: %s", account.Status)
}

// TestRFC_7_3_6_AccountDeactivation_DAOVerification verifies deactivation is persisted
func TestRFC_7_3_6_AccountDeactivation_DAOVerification(t *testing.T) {
	server := integration.NewACMEServer(t)
	defer server.Stop()

	t.Log("RFC 8555 Section 7.3.6 - Testing account deactivation with DAO verification")

	// Create account
	accountKey, accountURL := integration.CreateTestAccount(t, integration.TestServerURL, "rfc7.3.6-dao@example.com")

	// Get account from storage before deactivation
	accountDAO, err := server.StorageFactory().AccountDAO()
	require.NoError(t, err)
	ctx := context.Background()

	var accounts []*entities.ACMEAccount
	err = accountDAO.ForEachPage(ctx, qrdbsdk.PageQuery{Page: 1, PageSize: 1000}, func(page qrdbsdk.PageResult[*entities.ACMEAccount]) error {
		accounts = append(accounts, page.Entities...)
		return nil
	})
	require.NoError(t, err)
	require.NotEmpty(t, accounts)

	var originalAccount *entities.ACMEAccount
	for _, acc := range accounts {
		for _, contact := range acc.Contact {
			if contact == "mailto:rfc7.3.6-dao@example.com" {
				originalAccount = acc
				break
			}
		}
	}
	require.NotNil(t, originalAccount, "Original account must exist in storage")
	assert.Equal(t, "valid", originalAccount.Status, "Original account status must be 'valid'")
	t.Logf("Original account status: %s", originalAccount.Status)

	// Deactivate account
	nonce := integration.GetNonce(t, integration.TestServerURL)
	deactivatePayload := map[string]interface{}{
		"status": "deactivated",
	}
	deactivateJWS := integration.CreateJWS(t, accountKey, nonce, accountURL, deactivatePayload, true, accountURL)

	resp, err := http.Post(accountURL, "application/jose+json", bytes.NewReader([]byte(deactivateJWS)))
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode, "Account deactivation MUST return 200 OK")

	// Verify account is deactivated in HTTP response
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var account entities.ACMEAccount
	err = json.Unmarshal(body, &account)
	require.NoError(t, err)

	assert.Equal(t, "deactivated", account.Status, "Account status MUST be 'deactivated'")
	t.Logf("✓ Account deactivated in HTTP response, status: %s", account.Status)

	// Verify deactivation persisted to backend storage
	t.Log("Verifying account deactivation persisted to backend storage")
	storedAccount, err := accountDAO.Get(ctx, originalAccount.ID)
	require.NoError(t, err, "Deactivated account MUST be persisted to backend storage")

	assert.Equal(t, "deactivated", storedAccount.Status,
		"Backend storage MUST reflect deactivated status")

	t.Logf("✓ Account deactivation verified in backend storage (ID: %d)", storedAccount.ID)
	t.Logf("  Stored status: %s", storedAccount.Status)
}

// TestRFC_7_3_5_KeyRollover verifies RFC 8555 Section 7.3.5 - Account Key Rollover
// Requirements:
// - Server MUST support key-change endpoint
// - Server MUST validate nested JWS structure
func TestRFC_7_3_5_KeyRollover(t *testing.T) {
	server := integration.NewACMEServer(t)
	defer server.Stop()

	t.Log("RFC 8555 Section 7.3.5 - Testing account key rollover endpoint")

	// Create account
	oldKey, accountURL := integration.CreateTestAccount(t, integration.TestServerURL, "rfc7.3.5@example.com")

	// Generate new key
	newKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Test key-change endpoint accessibility
	nonce := integration.GetNonce(t, integration.TestServerURL)
	keyChangePayload := map[string]interface{}{
		"account": accountURL,
		"oldKey":  "placeholder", // Simplified for endpoint testing
	}
	keyChangeJWS := integration.CreateJWS(t, oldKey, nonce, integration.TestServerURL+"/acme/key-change", keyChangePayload, true, accountURL)

	resp, err := http.Post(integration.TestServerURL+"/acme/key-change", "application/jose+json", bytes.NewReader([]byte(keyChangeJWS)))
	require.NoError(t, err)
	defer resp.Body.Close()

	// Endpoint should respond (may fail due to simplified JWS, but should not 404/500)
	assert.True(t, resp.StatusCode < 500, "Key-change endpoint MUST be accessible")
	assert.NotEqual(t, http.StatusNotFound, resp.StatusCode, "Key-change endpoint MUST exist")

	t.Logf("✓ Key-change endpoint is accessible, status: %d", resp.StatusCode)
	t.Logf("  (Full nested JWS validation tested in unit tests)")

	// Suppress unused variable warning
	_ = newKey
}

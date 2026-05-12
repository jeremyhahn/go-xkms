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
	"github.com/jeremyhahn/go-xkms/test/integration"

	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	"github.com/stretchr/testify/require"
)

// RFC 8555 Section 7.4.2 - Order Finalization Integration Tests
//
// These tests verify the complete order finalization workflow as specified in RFC 8555.

// TestOrderFinalization_Success tests the complete order finalization workflow.
// This includes creating an account, creating an order, validating authorizations,
// finalizing the order with a CSR, and downloading the certificate.
func TestOrderFinalization_Success(t *testing.T) {
	server := integration.NewTestServer(t)
	defer server.Cleanup()

	// Step 1: Create account
	t.Log("Step 1: Creating test account")
	accountKey, accountURL := integration.CreateTestAccount(t, server.BaseURL, "finalize-success@example.com")
	require.NotEmpty(t, accountURL, "Account URL should not be empty")

	// Extract account ID from the account URL
	accountID := integration.AccountIDFromPublicKey(t, accountKey.Public())

	// Step 2: Create order for a domain
	t.Log("Step 2: Creating order for domain")
	orderURL, authzURLs := integration.CreateTestOrder(t, server.BaseURL, accountKey, accountURL, "finalize-test.example.com")
	require.NotEmpty(t, orderURL, "Order URL should not be empty")
	require.NotEmpty(t, authzURLs, "Authorization URLs should not be empty")

	// Step 3: Fetch authorization to get the authorization ID
	t.Log("Step 3: Fetching authorization")
	authzURL := authzURLs[0]
	authzID := extractIDFromURL(t, authzURL, "/acme/authz/")

	// Step 4: Mark authorization as valid (simulating successful challenge validation)
	t.Log("Step 4: Marking authorization as valid")
	markAuthorizationValid(t, server, accountID, authzID)

	// Step 5: Update order status to ready (since all authorizations are valid)
	t.Log("Step 5: Marking order as ready")
	orderID := extractIDFromURL(t, orderURL, "/acme/order/")
	markOrderReady(t, server, accountID, orderID)

	// Step 6: Fetch order to get finalize URL
	t.Log("Step 6: Fetching order to get finalize URL")
	order := integration.FetchOrder(t, server.BaseURL, accountKey, accountURL, orderURL)
	require.Equal(t, common.StatusReady, order.Status, "Order should be in ready status")
	require.NotEmpty(t, order.Finalize, "Order should have finalize URL")

	// Step 7: Generate CSR for the domain
	t.Log("Step 7: Generating CSR")
	csrDER := generateTestCSRDER(t, "finalize-test.example.com", x509.ECDSA)
	csrBase64 := base64.RawURLEncoding.EncodeToString(csrDER)

	// Step 8: Finalize order with CSR
	t.Log("Step 8: Finalizing order with CSR")
	finalizePayload := map[string]string{"csr": csrBase64}
	nonce := integration.GetNonce(t, server.BaseURL)
	jwsBody := integration.CreateJWS(t, accountKey, nonce, order.Finalize, finalizePayload, true, accountURL)

	resp, err := http.Post(order.Finalize, "application/jose+json", bytes.NewReader([]byte(jwsBody)))
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode, "Finalization should succeed with 200 OK")

	// Verify response contains certificate URL
	var finalizedOrder entities.ACMEOrder
	err = json.NewDecoder(resp.Body).Decode(&finalizedOrder)
	require.NoError(t, err)

	require.Equal(t, common.StatusValid, finalizedOrder.Status, "Order should be in valid status after finalization")
	require.NotEmpty(t, finalizedOrder.Certificate, "Order should have certificate URL")
	t.Logf("Certificate available at: %s", finalizedOrder.Certificate)

	// Step 9: Download certificate (POST-as-GET)
	t.Log("Step 9: Downloading certificate")
	nonce = integration.GetNonce(t, server.BaseURL)
	jwsBody = integration.CreateJWS(t, accountKey, nonce, finalizedOrder.Certificate, nil, true, accountURL)

	certResp, err := http.Post(finalizedOrder.Certificate, "application/jose+json", bytes.NewReader([]byte(jwsBody)))
	require.NoError(t, err)
	defer certResp.Body.Close()

	require.Equal(t, http.StatusOK, certResp.StatusCode, "Certificate download should succeed")

	// Verify certificate content - RFC 8555 specifies certificates are returned as application/pem-certificate-chain
	certPEM, err := io.ReadAll(certResp.Body)
	require.NoError(t, err)
	require.NotEmpty(t, certPEM, "Certificate PEM should not be empty")
	require.Contains(t, string(certPEM), "-----BEGIN CERTIFICATE-----", "Should contain PEM certificate")

	t.Log("Order finalization workflow completed successfully")
}

// TestOrderFinalization_InvalidCSR tests various invalid CSR scenarios.
func TestOrderFinalization_InvalidCSR(t *testing.T) {
	server := integration.NewTestServer(t)
	defer server.Cleanup()

	// Setup: Create account and order, mark as ready
	accountKey, accountURL := integration.CreateTestAccount(t, server.BaseURL, "invalid-csr@example.com")
	accountID := integration.AccountIDFromPublicKey(t, accountKey.Public())

	testCases := []struct {
		name          string
		csr           string
		expectedError string
	}{
		{
			name:          "Invalid base64 encoding",
			csr:           "!!!invalid-base64!!!",
			expectedError: "malformed",
		},
		{
			name:          "Invalid CSR format",
			csr:           base64.RawURLEncoding.EncodeToString([]byte("not a valid CSR")),
			expectedError: "malformed",
		},
		{
			name:          "CSR domain mismatch",
			csr:           generateBase64CSR(t, "wrong-domain.example.com", x509.ECDSA),
			expectedError: "malformed",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create a new order for each test case
			orderURL, authzURLs := integration.CreateTestOrder(t, server.BaseURL, accountKey, accountURL, "invalid-csr-test.example.com")
			require.NotEmpty(t, orderURL)
			require.NotEmpty(t, authzURLs)

			// Mark authorization as valid
			authzID := extractIDFromURL(t, authzURLs[0], "/acme/authz/")
			markAuthorizationValid(t, server, accountID, authzID)

			// Mark order as ready
			orderID := extractIDFromURL(t, orderURL, "/acme/order/")
			markOrderReady(t, server, accountID, orderID)

			// Fetch order to get finalize URL
			order := integration.FetchOrder(t, server.BaseURL, accountKey, accountURL, orderURL)
			require.Equal(t, common.StatusReady, order.Status)

			// Attempt to finalize with invalid CSR
			finalizePayload := map[string]string{"csr": tc.csr}
			nonce := integration.GetNonce(t, server.BaseURL)
			jwsBody := integration.CreateJWS(t, accountKey, nonce, order.Finalize, finalizePayload, true, accountURL)

			resp, err := http.Post(order.Finalize, "application/jose+json", bytes.NewReader([]byte(jwsBody)))
			require.NoError(t, err)
			defer resp.Body.Close()

			// Should return an error response
			require.True(t, resp.StatusCode >= 400, "Should return error status code, got %d", resp.StatusCode)

			// Parse error response
			var acmeError entities.Error
			err = json.NewDecoder(resp.Body).Decode(&acmeError)
			require.NoError(t, err)
			require.Contains(t, strings.ToLower(acmeError.Type), tc.expectedError,
				"Error type should contain '%s', got '%s'", tc.expectedError, acmeError.Type)

			t.Logf("Correctly rejected %s with error: %s", tc.name, acmeError.Type)
		})
	}
}

// TestOrderFinalization_OrderNotReady tests finalizing an order before challenges are validated.
func TestOrderFinalization_OrderNotReady(t *testing.T) {
	server := integration.NewTestServer(t)
	defer server.Cleanup()

	// Create account and order
	accountKey, accountURL := integration.CreateTestAccount(t, server.BaseURL, "not-ready@example.com")

	orderURL, authzURLs := integration.CreateTestOrder(t, server.BaseURL, accountKey, accountURL, "not-ready.example.com")
	require.NotEmpty(t, orderURL)
	require.NotEmpty(t, authzURLs)

	// Fetch order (should be in pending status since authorizations are not complete)
	order := integration.FetchOrder(t, server.BaseURL, accountKey, accountURL, orderURL)
	require.Equal(t, common.StatusPending, order.Status, "Order should be pending initially")

	// Generate CSR
	csrDER := generateTestCSRDER(t, "not-ready.example.com", x509.ECDSA)
	csrBase64 := base64.RawURLEncoding.EncodeToString(csrDER)

	// Attempt to finalize order before it's ready
	finalizePayload := map[string]string{"csr": csrBase64}
	nonce := integration.GetNonce(t, server.BaseURL)
	jwsBody := integration.CreateJWS(t, accountKey, nonce, order.Finalize, finalizePayload, true, accountURL)

	resp, err := http.Post(order.Finalize, "application/jose+json", bytes.NewReader([]byte(jwsBody)))
	require.NoError(t, err)
	defer resp.Body.Close()

	// Should return orderNotReady error (403 Forbidden)
	require.Equal(t, http.StatusForbidden, resp.StatusCode, "Should return 403 Forbidden")

	var acmeError entities.Error
	err = json.NewDecoder(resp.Body).Decode(&acmeError)
	require.NoError(t, err)

	expectedType := "urn:ietf:params:acme:error:orderNotReady"
	require.Equal(t, expectedType, acmeError.Type, "Should return orderNotReady error")

	t.Log("Correctly rejected finalization of order that is not ready")
}

// TestOrderFinalization_WrongAccount tests account isolation - one account cannot finalize another's order.
func TestOrderFinalization_WrongAccount(t *testing.T) {
	server := integration.NewTestServer(t)
	defer server.Cleanup()

	// Create first account and order
	accountKey1, accountURL1 := integration.CreateTestAccount(t, server.BaseURL, "account1@example.com")
	accountID1 := integration.AccountIDFromPublicKey(t, accountKey1.Public())

	orderURL, authzURLs := integration.CreateTestOrder(t, server.BaseURL, accountKey1, accountURL1, "account1-domain.example.com")
	require.NotEmpty(t, orderURL)
	require.NotEmpty(t, authzURLs)

	// Mark first account's order as ready
	authzID := extractIDFromURL(t, authzURLs[0], "/acme/authz/")
	markAuthorizationValid(t, server, accountID1, authzID)

	orderID := extractIDFromURL(t, orderURL, "/acme/order/")
	markOrderReady(t, server, accountID1, orderID)

	// Fetch order to get finalize URL
	order := integration.FetchOrder(t, server.BaseURL, accountKey1, accountURL1, orderURL)
	require.Equal(t, common.StatusReady, order.Status)

	// Create second account
	accountKey2, accountURL2 := integration.CreateTestAccount(t, server.BaseURL, "account2@example.com")

	// Generate CSR (domain doesn't matter since we expect authorization failure first)
	csrDER := generateTestCSRDER(t, "account1-domain.example.com", x509.ECDSA)
	csrBase64 := base64.RawURLEncoding.EncodeToString(csrDER)

	// Attempt to finalize first account's order using second account's credentials
	finalizePayload := map[string]string{"csr": csrBase64}
	nonce := integration.GetNonce(t, server.BaseURL)
	jwsBody := integration.CreateJWS(t, accountKey2, nonce, order.Finalize, finalizePayload, true, accountURL2)

	resp, err := http.Post(order.Finalize, "application/jose+json", bytes.NewReader([]byte(jwsBody)))
	require.NoError(t, err)
	defer resp.Body.Close()

	// Should return unauthorized error
	require.True(t, resp.StatusCode >= 400, "Should return error status code, got %d", resp.StatusCode)

	var acmeError entities.Error
	err = json.NewDecoder(resp.Body).Decode(&acmeError)
	require.NoError(t, err)

	// The error should indicate unauthorized access
	require.True(t,
		strings.Contains(acmeError.Type, "unauthorized") || strings.Contains(acmeError.Type, "malformed"),
		"Should return unauthorized or malformed error, got: %s", acmeError.Type)

	t.Log("Correctly prevented cross-account order finalization")
}

// Helper functions

// extractIDFromURL extracts the numeric ID from a URL path component.
// Example: /acme/authz/12345 -> 12345
func extractIDFromURL(t *testing.T, url string, prefix string) uint64 {
	// Find the prefix in the URL
	idx := strings.Index(url, prefix)
	require.NotEqual(t, -1, idx, "URL should contain prefix %s", prefix)

	// Extract the part after the prefix
	remaining := url[idx+len(prefix):]

	// Handle any trailing path components (e.g., /acme/order/123/finalize -> 123)
	if slashIdx := strings.Index(remaining, "/"); slashIdx != -1 {
		remaining = remaining[:slashIdx]
	}

	// Parse as uint64
	id, err := strconv.ParseUint(remaining, 10, 64)
	require.NoError(t, err, "Failed to parse ID from URL: %s", url)

	return id
}

// markAuthorizationValid marks an authorization as valid by directly updating storage.
func markAuthorizationValid(t *testing.T, server *integration.TestServer, accountID, authzID uint64) {
	ctx := context.Background()

	authzDAO, err := server.StorageFactory().AuthorizationDAO(accountID)
	require.NoError(t, err, "Failed to create authorization DAO")

	authz, err := authzDAO.Get(ctx, authzID)
	require.NoError(t, err, "Failed to get authorization")

	// Mark authorization and all its challenges as valid
	authz.Status = common.StatusValid
	for i := range authz.Challenges {
		authz.Challenges[i].Status = common.StatusValid
		authz.Challenges[i].Validated = time.Now().UTC().Format(time.RFC3339)
	}

	err = authzDAO.Save(ctx, authz)
	require.NoError(t, err, "Failed to save authorization")
}

// markOrderReady marks an order as ready for finalization.
func markOrderReady(t *testing.T, server *integration.TestServer, accountID, orderID uint64) {
	ctx := context.Background()

	orderDAO, err := server.StorageFactory().OrderDAO(accountID)
	require.NoError(t, err, "Failed to create order DAO")

	order, err := orderDAO.Get(ctx, orderID)
	require.NoError(t, err, "Failed to get order")

	order.Status = common.StatusReady

	err = orderDAO.Save(ctx, order)
	require.NoError(t, err, "Failed to save order")
}

// generateTestCSRDER generates a Certificate Signing Request in DER format.
func generateTestCSRDER(t *testing.T, cn string, keyAlgo x509.PublicKeyAlgorithm) []byte {
	var privateKey crypto.Signer
	var err error
	var sigAlgo x509.SignatureAlgorithm

	switch keyAlgo {
	case x509.RSA:
		t.Fatal("RSA not supported in this test")
	case x509.ECDSA:
		privateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		sigAlgo = x509.ECDSAWithSHA256
	default:
		t.Fatalf("Unsupported key algorithm: %v", keyAlgo)
	}
	require.NoError(t, err)

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"Test Organization"},
			Country:      []string{"US"},
		},
		SignatureAlgorithm: sigAlgo,
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, privateKey)
	require.NoError(t, err)

	return csrDER
}

// generateBase64CSR generates a CSR and returns it as base64url-encoded string.
func generateBase64CSR(t *testing.T, cn string, keyAlgo x509.PublicKeyAlgorithm) string {
	csrDER := generateTestCSRDER(t, cn, keyAlgo)
	return base64.RawURLEncoding.EncodeToString(csrDER)
}

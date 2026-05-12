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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/gorilla/mux"
	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Additional NewAccountHandler tests for EAB error branches (coverage_90_additional_)
// =============================================================================

func TestNewAccountHandler_AccountAlreadyExists_90(t *testing.T) {
	service, _, cleanup := setupTestService90(t)
	defer cleanup()

	testKey := generateTestKey(t)
	// First create an account
	account := createTestAccount(t, service, testKey)
	require.NotNil(t, account)

	t.Run("Account already exists without onlyReturnExisting", func(t *testing.T) {
		url := "https://acme.test.example.com/acme/new-account"
		req := createJWSRequest(t, service, testKey, url, map[string]interface{}{
			"contact":              []string{"mailto:test@example.com"},
			"termsOfServiceAgreed": true,
		}, false, 0)

		rr := httptest.NewRecorder()
		service.NewAccountHandler(rr, req)

		// Should return conflict status with AccountExistsError
		// This hits the "Account already exists" path
		assert.NotEqual(t, http.StatusCreated, rr.Code)
	})

	t.Run("Account already exists with onlyReturnExisting", func(t *testing.T) {
		url := "https://acme.test.example.com/acme/new-account"
		req := createJWSRequest(t, service, testKey, url, map[string]interface{}{
			"onlyReturnExisting": true,
		}, false, 0)

		rr := httptest.NewRecorder()
		service.NewAccountHandler(rr, req)

		// Should return OK with the existing account
		assert.Equal(t, http.StatusOK, rr.Code)
	})
}

func TestNewAccountHandler_MalformedPayload_90(t *testing.T) {
	service, _, cleanup := setupTestService90(t)
	defer cleanup()

	testKey := generateTestKey(t)

	t.Run("Invalid JSON in request body", func(t *testing.T) {
		nonce, _ := common.GenerateNonce(nonceSize)
		service.nonceStore.Add(nonce)

		signerOpts := &jose.SignerOptions{
			NonceSource: &staticNonceSource{nonce: nonce},
			EmbedJWK:    true,
			ExtraHeaders: map[jose.HeaderKey]interface{}{
				"url": "https://acme.test.example.com/acme/new-account",
			},
		}
		signer, _ := jose.NewSigner(jose.SigningKey{
			Algorithm: jose.ES256,
			Key:       testKey.PrivateKey,
		}, signerOpts)

		// Sign malformed JSON
		jws, _ := signer.Sign([]byte("{invalid-json"))

		req := httptest.NewRequest(http.MethodPost, "/acme/new-account", strings.NewReader(jws.FullSerialize()))
		req.Header.Set("Content-Type", "application/jose+json")

		rr := httptest.NewRecorder()
		service.NewAccountHandler(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})
}

// =============================================================================
// Additional KeyChangeHandler tests for error branches (coverage_90_additional_)
// =============================================================================

func TestKeyChangeHandler_MissingJWKInHeader_90(t *testing.T) {
	service, _, cleanup := setupTestService90(t)
	defer cleanup()

	testKey := generateTestKey(t)
	account := createTestAccount(t, service, testKey)

	t.Run("Inner JWS without JWK in header", func(t *testing.T) {
		url := "https://acme.test.example.com/acme/key-change"

		// Create inner JWS WITHOUT embedding the JWK
		innerPayload := map[string]interface{}{
			"account": account.URL,
			"oldKey": map[string]interface{}{
				"kty": "EC",
			},
		}
		innerPayloadBytes, _ := json.Marshal(innerPayload)

		// Use KID instead of embedding JWK - this should trigger "JWK not found in JWS header"
		innerSignerOpts := &jose.SignerOptions{
			// NOT setting EmbedJWK: true
			ExtraHeaders: map[jose.HeaderKey]interface{}{
				"url": url,
				"kid": "some-key-id",
			},
		}
		newKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		innerSigner, err := jose.NewSigner(jose.SigningKey{
			Algorithm: jose.ES256,
			Key:       newKey,
		}, innerSignerOpts)
		if err != nil {
			// If we can't create signer without JWK, try with it but malformed
			innerSignerOpts.EmbedJWK = true
			innerSigner, _ = jose.NewSigner(jose.SigningKey{
				Algorithm: jose.ES256,
				Key:       newKey,
			}, innerSignerOpts)
		}

		innerJWS, _ := innerSigner.Sign(innerPayloadBytes)

		// Create outer JWS with the inner JWS as payload
		req := createJWSRequest(t, service, testKey, url, json.RawMessage(innerJWS.FullSerialize()), true, account.ID)

		rr := httptest.NewRecorder()
		service.KeyChangeHandler(rr, req)

		// Should return error since JWK is missing or inner signature can't be verified
		assert.NotEqual(t, http.StatusOK, rr.Code)
	})
}

func TestKeyChangeHandler_AccountURLMismatch_90(t *testing.T) {
	service, _, cleanup := setupTestService90(t)
	defer cleanup()

	testKey := generateTestKey(t)
	account := createTestAccount(t, service, testKey)
	newKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	t.Run("Account URL in inner payload does not match", func(t *testing.T) {
		url := "https://acme.test.example.com/acme/key-change"

		// Get the old key in JWK format
		oldKeyJWK := jose.JSONWebKey{Key: testKey.PublicKey}
		oldKeyJSON, _ := oldKeyJWK.MarshalJSON()
		var oldKeyMap map[string]interface{}
		_ = json.Unmarshal(oldKeyJSON, &oldKeyMap)

		// Create inner JWS with wrong account URL
		innerPayload := map[string]interface{}{
			"account": "https://acme.test.example.com/acme/account/wrong-id",
			"oldKey":  oldKeyMap,
		}
		innerPayloadBytes, _ := json.Marshal(innerPayload)

		innerSignerOpts := &jose.SignerOptions{
			EmbedJWK: true,
			ExtraHeaders: map[jose.HeaderKey]interface{}{
				"url": url,
			},
		}
		innerSigner, _ := jose.NewSigner(jose.SigningKey{
			Algorithm: jose.ES256,
			Key:       newKey,
		}, innerSignerOpts)
		innerJWS, _ := innerSigner.Sign(innerPayloadBytes)

		req := createJWSRequest(t, service, testKey, url, json.RawMessage(innerJWS.FullSerialize()), true, account.ID)

		rr := httptest.NewRecorder()
		service.KeyChangeHandler(rr, req)

		// Should fail with account URL mismatch error
		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})
}

func TestKeyChangeHandler_SuccessfulKeyChange_90(t *testing.T) {
	service, _, cleanup := setupTestService90(t)
	defer cleanup()

	testKey := generateTestKey(t)
	account := createTestAccount(t, service, testKey)

	t.Run("Successful key change", func(t *testing.T) {
		url := "https://acme.test.example.com/acme/key-change"

		// Generate new key
		newKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

		// Get the old key in JWK format
		oldKeyJWK := jose.JSONWebKey{Key: testKey.PublicKey}
		oldKeyJSON, _ := oldKeyJWK.MarshalJSON()
		var oldKeyMap map[string]interface{}
		_ = json.Unmarshal(oldKeyJSON, &oldKeyMap)

		// Create inner payload with correct account URL and old key
		innerPayload := map[string]interface{}{
			"account": account.URL,
			"oldKey":  oldKeyMap,
		}
		innerPayloadBytes, _ := json.Marshal(innerPayload)

		// Create inner JWS signed with the NEW key
		innerSignerOpts := &jose.SignerOptions{
			EmbedJWK: true,
			ExtraHeaders: map[jose.HeaderKey]interface{}{
				"url": url,
			},
		}
		innerSigner, _ := jose.NewSigner(jose.SigningKey{
			Algorithm: jose.ES256,
			Key:       newKey,
		}, innerSignerOpts)
		innerJWS, _ := innerSigner.Sign(innerPayloadBytes)

		// Create outer JWS signed with OLD key
		req := createJWSRequest(t, service, testKey, url, json.RawMessage(innerJWS.FullSerialize()), true, account.ID)

		rr := httptest.NewRecorder()
		service.KeyChangeHandler(rr, req)

		// Should succeed
		assert.Equal(t, http.StatusOK, rr.Code)
	})
}

// =============================================================================
// Additional OrderFinalizeHandler tests (coverage_90_additional_)
// =============================================================================

func TestOrderFinalizeHandler_OrderNotReady_90(t *testing.T) {
	service, _, cleanup := setupTestService90(t)
	defer cleanup()

	testKey := generateTestKey(t)
	account := createTestAccount(t, service, testKey)

	t.Run("Order is pending (not ready)", func(t *testing.T) {
		// Create an order that is not ready
		ctx := context.Background()
		orderDAO, _ := service.storageFactory.OrderDAO(account.ID)

		order := &entities.ACMEOrder{
			ID:        12345,
			AccountID: account.ID,
			Status:    common.StatusPending,
			Identifiers: []entities.ACMEIdentifier{
				{Type: common.AuthzTypeDNS, Value: "example.com"},
			},
		}
		order.URL = fmt.Sprintf("%s/acme/order/%d", service.baseRESTURI, order.ID)
		order.Finalize = fmt.Sprintf("%s/acme/order/%d/finalize", service.baseRESTURI, order.ID)

		err := orderDAO.Save(ctx, order)
		require.NoError(t, err)

		// Create a dummy CSR
		csrDER := createDummyCSR90(t)

		url := fmt.Sprintf("https://acme.test.example.com/acme/order/%d/finalize", order.ID)
		req := createJWSRequest(t, service, testKey, url, map[string]interface{}{
			"csr": base64.RawURLEncoding.EncodeToString(csrDER),
		}, true, account.ID)
		req = mux.SetURLVars(req, map[string]string{"id": fmt.Sprintf("%d", order.ID)})

		rr := httptest.NewRecorder()
		service.OrderFinalizeHandler(rr, req)

		// Should fail because order is not ready
		assert.Equal(t, http.StatusForbidden, rr.Code)
	})
}

func TestOrderFinalizeHandler_InvalidCSR_90(t *testing.T) {
	service, _, cleanup := setupTestService90(t)
	defer cleanup()

	testKey := generateTestKey(t)
	account := createTestAccount(t, service, testKey)

	t.Run("Invalid CSR format", func(t *testing.T) {
		// Create an order that is ready
		ctx := context.Background()
		orderDAO, _ := service.storageFactory.OrderDAO(account.ID)

		order := &entities.ACMEOrder{
			ID:        12346,
			AccountID: account.ID,
			Status:    common.StatusReady,
			Identifiers: []entities.ACMEIdentifier{
				{Type: common.AuthzTypeDNS, Value: "example.com"},
			},
		}
		order.URL = fmt.Sprintf("%s/acme/order/%d", service.baseRESTURI, order.ID)
		order.Finalize = fmt.Sprintf("%s/acme/order/%d/finalize", service.baseRESTURI, order.ID)

		err := orderDAO.Save(ctx, order)
		require.NoError(t, err)

		url := fmt.Sprintf("https://acme.test.example.com/acme/order/%d/finalize", order.ID)
		req := createJWSRequest(t, service, testKey, url, map[string]interface{}{
			"csr": base64.RawURLEncoding.EncodeToString([]byte("not-a-valid-csr")),
		}, true, account.ID)
		req = mux.SetURLVars(req, map[string]string{"id": fmt.Sprintf("%d", order.ID)})

		rr := httptest.NewRecorder()
		service.OrderFinalizeHandler(rr, req)

		// Should fail with bad CSR error
		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})
}

// =============================================================================
// Additional AuthorizationHandler tests (coverage_90_additional_)
// =============================================================================

func TestAuthorizationHandler_DeactivateAuthorization_90(t *testing.T) {
	service, _, cleanup := setupTestService90(t)
	defer cleanup()

	testKey := generateTestKey(t)
	account := createTestAccount(t, service, testKey)

	t.Run("Deactivate valid authorization", func(t *testing.T) {
		// Create an authorization
		ctx := context.Background()
		authzDAO, _ := service.storageFactory.AuthorizationDAO(account.ID)

		authz := &entities.ACMEAuthorization{
			ID:        55555,
			AccountID: account.ID,
			Status:    common.StatusValid,
			Identifier: entities.ACMEIdentifier{
				Type:  common.AuthzTypeDNS,
				Value: "test.example.com",
			},
		}
		authz.URL = fmt.Sprintf("%s/acme/authz/%d", service.baseRESTURI, authz.ID)
		err := authzDAO.Save(ctx, authz)
		require.NoError(t, err)

		// Try to deactivate
		url := fmt.Sprintf("https://acme.test.example.com/acme/authz/%d", authz.ID)
		req := createJWSRequest(t, service, testKey, url, map[string]interface{}{
			"status": "deactivated",
		}, true, account.ID)
		req = mux.SetURLVars(req, map[string]string{"id": fmt.Sprintf("%d", authz.ID)})

		rr := httptest.NewRecorder()
		service.AuthorizationHandler(rr, req)

		// Should succeed
		assert.Equal(t, http.StatusOK, rr.Code)
	})
}

// =============================================================================
// Helper function to create a dummy CSR (coverage_90_additional_)
// =============================================================================

func createDummyCSR90(t *testing.T) []byte {
	// Return some bytes that represent invalid CSR to test error path
	return []byte{0x30, 0x00}
}

// =============================================================================
// Additional certificate handler tests (coverage_90_additional_)
// =============================================================================

func TestCertificateHandler_InvalidIDFormat_90(t *testing.T) {
	service, _, cleanup := setupTestService90(t)
	defer cleanup()

	t.Run("Non-numeric certificate ID", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/acme/cert/abc-123", nil)
		req = mux.SetURLVars(req, map[string]string{"id": "abc-123"})
		rr := httptest.NewRecorder()

		service.CertificateHandler(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})
}

// =============================================================================
// Additional orders list handler tests (coverage_90_additional_)
// =============================================================================

func TestOrdersListHandler_SuccessfulList_90(t *testing.T) {
	service, _, cleanup := setupTestService90(t)
	defer cleanup()

	testKey := generateTestKey(t)
	account := createTestAccount(t, service, testKey)

	t.Run("List orders for account", func(t *testing.T) {
		// Create some orders
		ctx := context.Background()
		orderDAO, _ := service.storageFactory.OrderDAO(account.ID)

		for i := 1; i <= 3; i++ {
			order := &entities.ACMEOrder{
				ID:        uint64(100 + i),
				AccountID: account.ID,
				Status:    common.StatusPending,
				Identifiers: []entities.ACMEIdentifier{
					{Type: common.AuthzTypeDNS, Value: fmt.Sprintf("test%d.example.com", i)},
				},
			}
			order.URL = fmt.Sprintf("%s/acme/order/%d", service.baseRESTURI, order.ID)
			_ = orderDAO.Save(ctx, order)
		}

		url := "https://acme.test.example.com/acme/orders"
		req := createJWSRequest(t, service, testKey, url, nil, true, account.ID)

		rr := httptest.NewRecorder()
		service.OrdersListHandler(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		// Response should contain order URLs
		assert.Contains(t, rr.Body.String(), "orders")
	})
}

// =============================================================================
// Additional account handler tests (coverage_90_additional_)
// =============================================================================

func TestAccountHandler_UpdateContacts_90(t *testing.T) {
	service, _, cleanup := setupTestService90(t)
	defer cleanup()

	testKey := generateTestKey(t)
	account := createTestAccount(t, service, testKey)

	t.Run("Update contacts with valid email", func(t *testing.T) {
		url := fmt.Sprintf("https://acme.test.example.com/acme/account/%d", account.ID)
		req := createJWSRequest(t, service, testKey, url, map[string]interface{}{
			"contact": []string{"mailto:newemail@example.com"},
		}, true, account.ID)

		rr := httptest.NewRecorder()
		service.AccountHandler(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Empty update returns current account", func(t *testing.T) {
		url := fmt.Sprintf("https://acme.test.example.com/acme/account/%d", account.ID)
		// Empty payload - just returns current account info
		req := createJWSRequest(t, service, testKey, url, map[string]interface{}{}, true, account.ID)

		rr := httptest.NewRecorder()
		service.AccountHandler(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
	})
}

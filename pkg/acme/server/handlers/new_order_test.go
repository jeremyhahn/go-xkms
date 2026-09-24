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
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewOrderHandler_Success_DNSIdentifier(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	// Add DNS challenge to the challenge map
	service.challengeMap["http-01"] = func(resolver *net.Resolver, ca common.CertificateAuthority, authzValue, challengePort, challengeToken, expectedKeyAuth string) error {
		return nil
	}
	service.challengeMap["dns-01"] = func(resolver *net.Resolver, ca common.CertificateAuthority, authzValue, challengePort, challengeToken, expectedKeyAuth string) error {
		return nil
	}

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Create new order request with DNS identifier
	payload := NewOrderRequest{
		Identifiers: []entities.ACMEIdentifier{
			{
				Type:  common.AuthzTypeDNS,
				Value: "example.com",
			},
		},
		NotBefore: "",
		NotAfter:  "",
	}

	url := service.baseRESTURI + "/acme/new-order"
	req := createJWSRequest(t, service, key, url, payload, true, account.ID)

	// Execute request
	resp := httptest.NewRecorder()
	service.NewOrderHandler(resp, req)

	// Verify response
	require.Equal(t, http.StatusCreated, resp.Code)
	require.Equal(t, "application/json", resp.Header().Get("Content-Type"))
	require.NotEmpty(t, resp.Header().Get("Replay-Nonce"))

	// Parse response body
	var order entities.ACMEOrder
	err := json.NewDecoder(resp.Body).Decode(&order)
	require.NoError(t, err)

	assert.Equal(t, common.StatusPending, order.Status)
	assert.Len(t, order.Identifiers, 1)
	assert.Equal(t, common.AuthzTypeDNS, order.Identifiers[0].Type)
	assert.Equal(t, "example.com", order.Identifiers[0].Value)
	assert.Len(t, order.Authorizations, 1)
	assert.NotEmpty(t, order.Finalize)
	assert.NotEmpty(t, order.Expires)
}

func TestNewOrderHandler_Success_MultipleIdentifiers(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	// Add DNS challenges to the challenge map
	service.challengeMap["http-01"] = func(resolver *net.Resolver, ca common.CertificateAuthority, authzValue, challengePort, challengeToken, expectedKeyAuth string) error {
		return nil
	}
	service.challengeMap["dns-01"] = func(resolver *net.Resolver, ca common.CertificateAuthority, authzValue, challengePort, challengeToken, expectedKeyAuth string) error {
		return nil
	}

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Create new order request with multiple DNS identifiers
	payload := NewOrderRequest{
		Identifiers: []entities.ACMEIdentifier{
			{
				Type:  common.AuthzTypeDNS,
				Value: "example.com",
			},
			{
				Type:  common.AuthzTypeDNS,
				Value: "www.example.com",
			},
		},
	}

	url := service.baseRESTURI + "/acme/new-order"
	req := createJWSRequest(t, service, key, url, payload, true, account.ID)

	// Execute request
	resp := httptest.NewRecorder()
	service.NewOrderHandler(resp, req)

	// Verify response
	require.Equal(t, http.StatusCreated, resp.Code)

	// Parse response body
	var order entities.ACMEOrder
	err := json.NewDecoder(resp.Body).Decode(&order)
	require.NoError(t, err)

	assert.Equal(t, common.StatusPending, order.Status)
	assert.Len(t, order.Identifiers, 2)
	assert.Len(t, order.Authorizations, 2)
}

func TestNewOrderHandler_Success_WildcardDomain(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	// Add DNS challenges to the challenge map
	service.challengeMap["http-01"] = func(resolver *net.Resolver, ca common.CertificateAuthority, authzValue, challengePort, challengeToken, expectedKeyAuth string) error {
		return nil
	}
	service.challengeMap["dns-01"] = func(resolver *net.Resolver, ca common.CertificateAuthority, authzValue, challengePort, challengeToken, expectedKeyAuth string) error {
		return nil
	}

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Create new order request with wildcard DNS identifier
	payload := NewOrderRequest{
		Identifiers: []entities.ACMEIdentifier{
			{
				Type:  common.AuthzTypeDNS,
				Value: "*.example.com",
			},
		},
	}

	url := service.baseRESTURI + "/acme/new-order"
	req := createJWSRequest(t, service, key, url, payload, true, account.ID)

	// Execute request
	resp := httptest.NewRecorder()
	service.NewOrderHandler(resp, req)

	// Verify response
	require.Equal(t, http.StatusCreated, resp.Code)

	// Parse response body
	var order entities.ACMEOrder
	err := json.NewDecoder(resp.Body).Decode(&order)
	require.NoError(t, err)

	assert.Equal(t, common.StatusPending, order.Status)

	// Verify authorization has wildcard flag set
	ctx := context.Background()
	authzDAO, err := service.storageFactory.AuthorizationDAO(account.ID)
	require.NoError(t, err)

	// Extract authorization ID from URL
	authzURL := order.Authorizations[0]
	require.Contains(t, authzURL, "/acme/authz/")

	// Load all authorizations and find the one for this order
	authzPage, err := authzDAO.Page(ctx, qrdbsdk.PageQuery{PageSize: 1000})
	authzs := authzPage.Entities
	require.NoError(t, err)
	require.Len(t, authzs, 1)

	assert.True(t, authzs[0].Wildcard)
	assert.Equal(t, "example.com", authzs[0].Identifier.Value)
}

func TestNewOrderHandler_Success_IPIdentifier(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	// Add enrollment challenges to the challenge map
	service.challengeMap["enroll-01"] = func(resolver *net.Resolver, ca common.CertificateAuthority, authzValue, challengePort, challengeToken, expectedKeyAuth string) error {
		return nil
	}

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Create new order request with IP identifier
	payload := NewOrderRequest{
		Identifiers: []entities.ACMEIdentifier{
			{
				Type:  common.AuthzTypeIP,
				Value: "192.0.2.1",
			},
		},
	}

	url := service.baseRESTURI + "/acme/new-order"
	req := createJWSRequest(t, service, key, url, payload, true, account.ID)

	// Execute request
	resp := httptest.NewRecorder()
	service.NewOrderHandler(resp, req)

	// Verify response
	require.Equal(t, http.StatusCreated, resp.Code)

	// Parse response body
	var order entities.ACMEOrder
	err := json.NewDecoder(resp.Body).Decode(&order)
	require.NoError(t, err)

	assert.Equal(t, common.StatusPending, order.Status)
	assert.Len(t, order.Identifiers, 1)
	assert.Equal(t, common.AuthzTypeIP, order.Identifiers[0].Type)
	assert.Equal(t, "192.0.2.1", order.Identifiers[0].Value)
}

func TestNewOrderHandler_Success_PermanentIdentifier(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	// Add enrollment challenges to the challenge map
	service.challengeMap["endorse-01"] = func(resolver *net.Resolver, ca common.CertificateAuthority, authzValue, challengePort, challengeToken, expectedKeyAuth string) error {
		return nil
	}

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Create new order request with permanent-identifier
	payload := NewOrderRequest{
		Identifiers: []entities.ACMEIdentifier{
			{
				Type:  common.AuthzTypePermanentIdentifier,
				Value: "device-12345",
			},
		},
	}

	url := service.baseRESTURI + "/acme/new-order"
	req := createJWSRequest(t, service, key, url, payload, true, account.ID)

	// Execute request
	resp := httptest.NewRecorder()
	service.NewOrderHandler(resp, req)

	// Verify response
	require.Equal(t, http.StatusCreated, resp.Code)

	// Parse response body
	var order entities.ACMEOrder
	err := json.NewDecoder(resp.Body).Decode(&order)
	require.NoError(t, err)

	assert.Equal(t, common.StatusPending, order.Status)
	assert.Len(t, order.Identifiers, 1)
	assert.Equal(t, common.AuthzTypePermanentIdentifier, order.Identifiers[0].Type)
}

func TestNewOrderHandler_Success_WithNotBeforeNotAfter(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	// Add DNS challenges to the challenge map
	service.challengeMap["http-01"] = func(resolver *net.Resolver, ca common.CertificateAuthority, authzValue, challengePort, challengeToken, expectedKeyAuth string) error {
		return nil
	}

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Create new order request with notBefore and notAfter
	payload := NewOrderRequest{
		Identifiers: []entities.ACMEIdentifier{
			{
				Type:  common.AuthzTypeDNS,
				Value: "example.com",
			},
		},
		NotBefore: "2025-01-01T00:00:00Z",
		NotAfter:  "2026-01-01T00:00:00Z",
	}

	url := service.baseRESTURI + "/acme/new-order"
	req := createJWSRequest(t, service, key, url, payload, true, account.ID)

	// Execute request
	resp := httptest.NewRecorder()
	service.NewOrderHandler(resp, req)

	// Verify response
	require.Equal(t, http.StatusCreated, resp.Code)

	// Parse response body
	var order entities.ACMEOrder
	err := json.NewDecoder(resp.Body).Decode(&order)
	require.NoError(t, err)

	assert.Equal(t, common.StatusPending, order.Status)
	assert.Equal(t, "2025-01-01T00:00:00Z", order.NotBefore)
	assert.Equal(t, "2026-01-01T00:00:00Z", order.NotAfter)
}

func TestNewOrderHandler_InvalidIdentifierType(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Create new order request with invalid identifier type
	payload := NewOrderRequest{
		Identifiers: []entities.ACMEIdentifier{
			{
				Type:  "invalid-type",
				Value: "example.com",
			},
		},
	}

	url := service.baseRESTURI + "/acme/new-order"
	req := createJWSRequest(t, service, key, url, payload, true, account.ID)

	// Execute request
	resp := httptest.NewRecorder()
	service.NewOrderHandler(resp, req)

	// Should return unsupportedIdentifier error
	assertErrorType(t, resp, common.ErrTypeUnsupportedIdentifier, http.StatusBadRequest)
}

func TestNewOrderHandler_MissingIdentifiers(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Create new order request with empty identifiers
	payload := NewOrderRequest{
		Identifiers: []entities.ACMEIdentifier{},
	}

	url := service.baseRESTURI + "/acme/new-order"
	req := createJWSRequest(t, service, key, url, payload, true, account.ID)

	// Execute request
	resp := httptest.NewRecorder()
	service.NewOrderHandler(resp, req)

	// Should succeed but create an order with no authorizations
	require.Equal(t, http.StatusCreated, resp.Code)

	// Parse response body
	var order entities.ACMEOrder
	err := json.NewDecoder(resp.Body).Decode(&order)
	require.NoError(t, err)

	assert.Len(t, order.Identifiers, 0)
	assert.Len(t, order.Authorizations, 0)
}

func TestNewOrderHandler_MalformedJSON(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Create JWS with invalid JSON payload
	url := service.baseRESTURI + "/acme/new-order"
	payload := "invalid-json"
	req := createJWSRequest(t, service, key, url, payload, true, account.ID)

	// Execute request
	resp := httptest.NewRecorder()
	service.NewOrderHandler(resp, req)

	// Should return malformed error
	assertErrorType(t, resp, common.ErrTypeMalformedError, http.StatusBadRequest)
}

func TestNewOrderHandler_MalformedJWS(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	url := service.baseRESTURI + "/acme/new-order"
	req := createInvalidJWSRequest(t, url)

	// Execute request
	resp := httptest.NewRecorder()
	service.NewOrderHandler(resp, req)

	// Should return malformed error
	assertErrorType(t, resp, common.ErrTypeMalformedError, http.StatusBadRequest)
}

func TestNewOrderHandler_AuthorizationCreation(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	// Add DNS challenges to the challenge map
	service.challengeMap["http-01"] = func(resolver *net.Resolver, ca common.CertificateAuthority, authzValue, challengePort, challengeToken, expectedKeyAuth string) error {
		return nil
	}
	service.challengeMap["dns-01"] = func(resolver *net.Resolver, ca common.CertificateAuthority, authzValue, challengePort, challengeToken, expectedKeyAuth string) error {
		return nil
	}

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Create new order request
	payload := NewOrderRequest{
		Identifiers: []entities.ACMEIdentifier{
			{
				Type:  common.AuthzTypeDNS,
				Value: "example.com",
			},
		},
	}

	url := service.baseRESTURI + "/acme/new-order"
	req := createJWSRequest(t, service, key, url, payload, true, account.ID)

	// Execute request
	resp := httptest.NewRecorder()
	service.NewOrderHandler(resp, req)

	// Verify response
	require.Equal(t, http.StatusCreated, resp.Code)

	// Parse response body
	var order entities.ACMEOrder
	err := json.NewDecoder(resp.Body).Decode(&order)
	require.NoError(t, err)

	// Verify authorization was created
	ctx := context.Background()
	authzDAO, err := service.storageFactory.AuthorizationDAO(account.ID)
	require.NoError(t, err)

	authzPage, err := authzDAO.Page(ctx, qrdbsdk.PageQuery{PageSize: 1000})
	authzs := authzPage.Entities
	require.NoError(t, err)
	require.Len(t, authzs, 1)

	authz := authzs[0]
	assert.Equal(t, common.StatusPending, authz.Status)
	assert.Equal(t, common.AuthzTypeDNS, authz.Identifier.Type)
	assert.Equal(t, "example.com", authz.Identifier.Value)
	assert.NotEmpty(t, authz.Expires)
	assert.NotEmpty(t, authz.URL)
	assert.Len(t, authz.Challenges, 2) // http-01 and dns-01
}

func TestNewOrderHandler_ChallengeGeneration(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	// Add DNS challenges to the challenge map
	service.challengeMap["http-01"] = func(resolver *net.Resolver, ca common.CertificateAuthority, authzValue, challengePort, challengeToken, expectedKeyAuth string) error {
		return nil
	}
	service.challengeMap["dns-01"] = func(resolver *net.Resolver, ca common.CertificateAuthority, authzValue, challengePort, challengeToken, expectedKeyAuth string) error {
		return nil
	}

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Create new order request
	payload := NewOrderRequest{
		Identifiers: []entities.ACMEIdentifier{
			{
				Type:  common.AuthzTypeDNS,
				Value: "example.com",
			},
		},
	}

	url := service.baseRESTURI + "/acme/new-order"
	req := createJWSRequest(t, service, key, url, payload, true, account.ID)

	// Execute request
	resp := httptest.NewRecorder()
	service.NewOrderHandler(resp, req)

	// Verify response
	require.Equal(t, http.StatusCreated, resp.Code)

	// Verify challenges were created
	ctx := context.Background()
	authzDAO, err := service.storageFactory.AuthorizationDAO(account.ID)
	require.NoError(t, err)

	authzPage, err := authzDAO.Page(ctx, qrdbsdk.PageQuery{PageSize: 1000})
	authzs := authzPage.Entities
	require.NoError(t, err)
	require.Len(t, authzs, 1)

	authz := authzs[0]
	require.Len(t, authz.Challenges, 2)

	for _, challenge := range authz.Challenges {
		assert.Equal(t, common.StatusPending, challenge.Status)
		assert.NotEmpty(t, challenge.Token)
		assert.NotEmpty(t, challenge.URL)
		assert.Equal(t, account.ID, challenge.AccountID)
		assert.Equal(t, authz.ID, challenge.AuthorizationID)
		assert.Contains(t, []string{"http-01", "dns-01"}, challenge.Type)
	}
}

func TestNewOrderHandler_ReplayNonceHeader(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	// Add DNS challenges to the challenge map
	service.challengeMap["http-01"] = func(resolver *net.Resolver, ca common.CertificateAuthority, authzValue, challengePort, challengeToken, expectedKeyAuth string) error {
		return nil
	}

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Create new order request
	payload := NewOrderRequest{
		Identifiers: []entities.ACMEIdentifier{
			{
				Type:  common.AuthzTypeDNS,
				Value: "example.com",
			},
		},
	}

	url := service.baseRESTURI + "/acme/new-order"
	req := createJWSRequest(t, service, key, url, payload, true, account.ID)

	// Execute request
	resp := httptest.NewRecorder()
	service.NewOrderHandler(resp, req)

	// Verify Replay-Nonce header is present
	require.NotEmpty(t, resp.Header().Get("Replay-Nonce"))
}

func TestCreateChallenges_DNSIdentifier(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	// Add DNS challenges to the challenge map
	service.challengeMap["http-01"] = func(resolver *net.Resolver, ca common.CertificateAuthority, authzValue, challengePort, challengeToken, expectedKeyAuth string) error {
		return nil
	}
	service.challengeMap["dns-01"] = func(resolver *net.Resolver, ca common.CertificateAuthority, authzValue, challengePort, challengeToken, expectedKeyAuth string) error {
		return nil
	}

	accountID := uint64(12345)
	authzID := uint64(67890)

	identifier := entities.ACMEIdentifier{
		Type:  common.AuthzTypeDNS,
		Value: "example.com",
	}

	challenges, err := service.createChallenges(accountID, authzID, identifier, false)
	require.NoError(t, err)

	// Should create http-01 and dns-01 challenges
	assert.Len(t, challenges, 2)

	challengeTypes := []string{}
	for _, challenge := range challenges {
		challengeTypes = append(challengeTypes, challenge.Type)
		assert.Equal(t, common.StatusPending, challenge.Status)
		assert.NotEmpty(t, challenge.Token)
		assert.NotEmpty(t, challenge.URL)
		assert.Equal(t, accountID, challenge.AccountID)
		assert.Equal(t, authzID, challenge.AuthorizationID)
	}

	// Verify we have the expected challenge types (order may vary)
	assert.Contains(t, challengeTypes, "http-01")
	assert.Contains(t, challengeTypes, "dns-01")
}

func TestCreateChallenges_IPIdentifier(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	// Add enrollment challenges to the challenge map
	service.challengeMap["enroll-01"] = func(resolver *net.Resolver, ca common.CertificateAuthority, authzValue, challengePort, challengeToken, expectedKeyAuth string) error {
		return nil
	}
	service.challengeMap["device-attest-01"] = func(resolver *net.Resolver, ca common.CertificateAuthority, authzValue, challengePort, challengeToken, expectedKeyAuth string) error {
		return nil
	}

	accountID := uint64(12345)
	authzID := uint64(67890)

	identifier := entities.ACMEIdentifier{
		Type:  common.AuthzTypeIP,
		Value: "192.0.2.1",
	}

	challenges, err := service.createChallenges(accountID, authzID, identifier, false)
	require.NoError(t, err)

	// Should create enrollment challenges
	assert.Len(t, challenges, 2)

	for _, challenge := range challenges {
		assert.Equal(t, common.StatusPending, challenge.Status)
		assert.NotEmpty(t, challenge.Token)
		assert.NotEmpty(t, challenge.URL)
		assert.Equal(t, accountID, challenge.AccountID)
		assert.Equal(t, authzID, challenge.AuthorizationID)
		assert.True(t, challenge.Type == "enroll-01" || challenge.Type == "device-attest-01")
	}
}

func TestCreateChallenges_PermanentIdentifier(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	// Add enrollment challenges to the challenge map
	service.challengeMap["endorse-01"] = func(resolver *net.Resolver, ca common.CertificateAuthority, authzValue, challengePort, challengeToken, expectedKeyAuth string) error {
		return nil
	}

	accountID := uint64(12345)
	authzID := uint64(67890)

	identifier := entities.ACMEIdentifier{
		Type:  common.AuthzTypePermanentIdentifier,
		Value: "device-12345",
	}

	challenges, err := service.createChallenges(accountID, authzID, identifier, false)
	require.NoError(t, err)

	// Should create enrollment challenges
	assert.Len(t, challenges, 1)

	for _, challenge := range challenges {
		assert.Equal(t, common.StatusPending, challenge.Status)
		assert.NotEmpty(t, challenge.Token)
		assert.NotEmpty(t, challenge.URL)
		assert.Equal(t, accountID, challenge.AccountID)
		assert.Equal(t, authzID, challenge.AuthorizationID)
		assert.Equal(t, "endorse-01", challenge.Type)
	}
}

func TestCreateChallenges_UnsupportedIdentifier(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	accountID := uint64(12345)
	authzID := uint64(67890)

	identifier := entities.ACMEIdentifier{
		Type:  "unsupported-type",
		Value: "test-value",
	}

	challenges, err := service.createChallenges(accountID, authzID, identifier, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported identifier type")
	assert.Len(t, challenges, 0)
}

func TestCreateChallenges_NoChallengesConfigured(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	// Don't add any challenges to the challenge map

	accountID := uint64(12345)
	authzID := uint64(67890)

	identifier := entities.ACMEIdentifier{
		Type:  common.AuthzTypeDNS,
		Value: "example.com",
	}

	challenges, err := service.createChallenges(accountID, authzID, identifier, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no challenges configured")
	assert.Len(t, challenges, 0)
}

func TestNewOrderHandler_OrderPersistence(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	// Add DNS challenges to the challenge map
	service.challengeMap["http-01"] = func(resolver *net.Resolver, ca common.CertificateAuthority, authzValue, challengePort, challengeToken, expectedKeyAuth string) error {
		return nil
	}

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Create new order request
	payload := NewOrderRequest{
		Identifiers: []entities.ACMEIdentifier{
			{
				Type:  common.AuthzTypeDNS,
				Value: "example.com",
			},
		},
	}

	url := service.baseRESTURI + "/acme/new-order"
	req := createJWSRequest(t, service, key, url, payload, true, account.ID)

	// Execute request
	resp := httptest.NewRecorder()
	service.NewOrderHandler(resp, req)

	// Verify response
	require.Equal(t, http.StatusCreated, resp.Code)

	// Parse response body to verify order structure
	var orderResp struct {
		Status         string                    `json:"status"`
		Identifiers    []entities.ACMEIdentifier `json:"identifiers"`
		Authorizations []string                  `json:"authorizations"`
		Finalize       string                    `json:"finalize"`
	}
	err := json.NewDecoder(resp.Body).Decode(&orderResp)
	require.NoError(t, err)

	assert.Equal(t, common.StatusPending, orderResp.Status)
	assert.Len(t, orderResp.Identifiers, 1)

	// Verify order was persisted by listing all orders
	ctx := context.Background()
	orderDAO, err := service.storageFactory.OrderDAO(account.ID)
	require.NoError(t, err)

	orderPage, err := orderDAO.Page(ctx, qrdbsdk.PageQuery{PageSize: 1000})
	orders := orderPage.Entities
	require.NoError(t, err)
	require.Len(t, orders, 1)

	savedOrder := orders[0]
	assert.Equal(t, common.StatusPending, savedOrder.Status)
	assert.Equal(t, account.ID, savedOrder.AccountID)
	assert.Len(t, savedOrder.Identifiers, 1)
	assert.Len(t, savedOrder.Authorizations, 1)
}

func TestNewOrderHandler_NoChallengesForIdentifier(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	// Don't add any challenges to the challenge map - this will cause createChallenges to fail

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Create new order request with DNS identifier
	payload := NewOrderRequest{
		Identifiers: []entities.ACMEIdentifier{
			{
				Type:  common.AuthzTypeDNS,
				Value: "example.com",
			},
		},
	}

	url := service.baseRESTURI + "/acme/new-order"
	req := createJWSRequest(t, service, key, url, payload, true, account.ID)

	// Execute request
	resp := httptest.NewRecorder()
	service.NewOrderHandler(resp, req)

	// Should return serverInternal error when no challenges configured
	assertErrorType(t, resp, common.ErrTypeServerInternal, http.StatusInternalServerError)
}

func TestNewOrderHandler_ContentType(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	// Add DNS challenges to the challenge map
	service.challengeMap["http-01"] = func(resolver *net.Resolver, ca common.CertificateAuthority, authzValue, challengePort, challengeToken, expectedKeyAuth string) error {
		return nil
	}

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Create new order request
	payload := NewOrderRequest{
		Identifiers: []entities.ACMEIdentifier{
			{
				Type:  common.AuthzTypeDNS,
				Value: "example.com",
			},
		},
	}

	url := service.baseRESTURI + "/acme/new-order"
	req := createJWSRequest(t, service, key, url, payload, true, account.ID)

	// Execute request
	resp := httptest.NewRecorder()
	service.NewOrderHandler(resp, req)

	// Verify Content-Type header
	require.Equal(t, "application/json", resp.Header().Get("Content-Type"))
}

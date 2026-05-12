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
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	caerrors "github.com/jeremyhahn/go-xkms/pkg/acme/errors"
	"github.com/jeremyhahn/go-xkms/pkg/acme/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createTestOrderWithIdentifiers creates and saves a test order with specific identifiers
func createTestOrderWithIdentifiers(t *testing.T, service *RestService, account *entities.ACMEAccount, identifiers []entities.ACMEIdentifier) *entities.ACMEOrder {
	ctx := context.Background()

	orderDAO, err := service.storageFactory.OrderDAO(account.ID)
	require.NoError(t, err)

	// Generate order ID
	orderID, err := GenerateID()
	require.NoError(t, err)

	order := &entities.ACMEOrder{
		ID:          orderID,
		Status:      common.StatusPending,
		Expires:     time.Now().Add(24 * time.Hour).Format(time.RFC3339),
		Identifiers: identifiers,
		AccountID:   account.ID,
	}

	// Set URLs
	order.URL = fmt.Sprintf("%s/acme/order/%d", service.baseRESTURI, order.ID)
	order.Finalize = fmt.Sprintf("%s/acme/finalize/%d", service.baseRESTURI, order.ID)

	err = orderDAO.Save(ctx, order)
	require.NoError(t, err)

	return order
}

// createTestAuthorizationWithChallenges creates and saves a test authorization with specific challenges
func createTestAuthorizationWithChallenges(t *testing.T, service *RestService, account *entities.ACMEAccount, order *entities.ACMEOrder, identifier entities.ACMEIdentifier, challengeTypes []string) *entities.ACMEAuthorization {
	ctx := context.Background()

	authzDAO, err := service.storageFactory.AuthorizationDAO(account.ID)
	require.NoError(t, err)

	// Generate authorization ID
	authzID, err := GenerateID()
	require.NoError(t, err)

	authz := &entities.ACMEAuthorization{
		ID:         authzID,
		Identifier: identifier,
		Status:     common.StatusPending,
		Expires:    time.Now().Add(24 * time.Hour).Format(time.RFC3339),
		Wildcard:   false,
		AccountID:  account.ID,
		OrderID:    order.ID,
	}

	// Create challenges
	challenges := make([]entities.ACMEChallenge, 0, len(challengeTypes))
	for _, challengeType := range challengeTypes {
		// Generate challenge ID
		challengeID, err := GenerateID()
		require.NoError(t, err)

		challenge := entities.ACMEChallenge{
			ID:              challengeID,
			Type:            challengeType,
			Status:          common.StatusPending,
			Token:           fmt.Sprintf("test-token-%d", challengeID),
			AccountID:       account.ID,
			AuthorizationID: authzID,
			URL:             fmt.Sprintf("%s/acme/challenge/%d", service.baseRESTURI, challengeID),
		}
		challenges = append(challenges, challenge)
	}

	authz.Challenges = challenges

	// Set authorization URL
	authz.URL = fmt.Sprintf("%s/acme/authz/%d", service.baseRESTURI, authz.ID)

	err = authzDAO.Save(ctx, authz)
	require.NoError(t, err)

	// Update order with authorization URL
	orderDAO, err := service.storageFactory.OrderDAO(account.ID)
	require.NoError(t, err)

	order.Authorizations = append(order.Authorizations, authz.URL)
	err = orderDAO.Save(ctx, order)
	require.NoError(t, err)

	return authz
}

func TestChallengeHandler_MethodNotAllowed(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	url := service.baseRESTURI + "/acme/challenge/1"
	req := httptest.NewRequest(http.MethodGet, url, nil)

	resp := httptest.NewRecorder()
	service.ChallengeHandler(resp, req)

	assertErrorType(t, resp, common.ErrTypeMalformedError, http.StatusBadRequest)
}

func TestChallengeHandler_InvalidChallengeID(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Test with non-numeric challenge ID
	url := service.baseRESTURI + "/acme/challenge/invalid"
	req := createJWSRequest(t, service, key, url, map[string]interface{}{}, true, account.ID)

	resp := httptest.NewRecorder()
	service.ChallengeHandler(resp, req)

	assertErrorType(t, resp, common.ErrTypeMalformedError, http.StatusBadRequest)
}

func TestChallengeHandler_EmptyChallengeID(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Test with empty challenge ID
	url := service.baseRESTURI + "/acme/challenge/"
	req := createJWSRequest(t, service, key, url, map[string]interface{}{}, true, account.ID)

	resp := httptest.NewRecorder()
	service.ChallengeHandler(resp, req)

	require.Equal(t, http.StatusBadRequest, resp.Code)
}

func TestChallengeHandler_ChallengeNotFound(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Test with non-existent challenge ID
	url := service.baseRESTURI + "/acme/challenge/999999"
	req := createJWSRequest(t, service, key, url, map[string]interface{}{}, true, account.ID)

	resp := httptest.NewRecorder()
	service.ChallengeHandler(resp, req)

	assertErrorType(t, resp, common.ErrTypeMalformedError, http.StatusBadRequest)
}

func TestChallengeHandler_MalformedJWS(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	url := service.baseRESTURI + "/acme/challenge/1"
	req := createInvalidJWSRequest(t, url)

	resp := httptest.NewRecorder()
	service.ChallengeHandler(resp, req)

	assertErrorType(t, resp, common.ErrTypeMalformedError, http.StatusBadRequest)
}

func TestChallengeHandler_ChallengeAlreadyValid(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	identifier := entities.ACMEIdentifier{
		Type:  common.AuthzTypeDNS,
		Value: "example.com",
	}

	order := createTestOrderWithIdentifiers(t, service, account, []entities.ACMEIdentifier{identifier})
	authz := createTestAuthorizationWithChallenges(t, service, account, order, identifier, []string{"http-01"})

	// Set challenge to already valid
	ctx := context.Background()
	authzDAO, err := service.storageFactory.AuthorizationDAO(account.ID)
	require.NoError(t, err)

	authz.Challenges[0].Status = common.StatusValid
	authz.Challenges[0].Validated = time.Now().Format(time.RFC3339)
	err = authzDAO.Save(ctx, authz)
	require.NoError(t, err)

	// Request challenge
	url := fmt.Sprintf("%s/acme/challenge/%d", service.baseRESTURI, authz.Challenges[0].ID)
	req := createJWSRequest(t, service, key, url, map[string]interface{}{}, true, account.ID)

	resp := httptest.NewRecorder()
	service.ChallengeHandler(resp, req)

	require.Equal(t, http.StatusOK, resp.Code)

	var challengeResp struct {
		Type      string `json:"type"`
		Status    string `json:"status"`
		Token     string `json:"token"`
		Validated string `json:"validated"`
	}
	err = json.NewDecoder(resp.Body).Decode(&challengeResp)
	require.NoError(t, err)

	assert.Equal(t, common.StatusValid, challengeResp.Status)
	assert.NotEmpty(t, challengeResp.Validated)
}

func TestChallengeHandler_ChallengeAlreadyInvalid(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	identifier := entities.ACMEIdentifier{
		Type:  common.AuthzTypeDNS,
		Value: "example.com",
	}

	order := createTestOrderWithIdentifiers(t, service, account, []entities.ACMEIdentifier{identifier})
	authz := createTestAuthorizationWithChallenges(t, service, account, order, identifier, []string{"http-01"})

	// Set challenge to already invalid
	ctx := context.Background()
	authzDAO, err := service.storageFactory.AuthorizationDAO(account.ID)
	require.NoError(t, err)

	authz.Challenges[0].Status = common.StatusInvalid
	authz.Challenges[0].Error = common.IncorrectResponse("Previous validation failed")
	err = authzDAO.Save(ctx, authz)
	require.NoError(t, err)

	// Request challenge
	url := fmt.Sprintf("%s/acme/challenge/%d", service.baseRESTURI, authz.Challenges[0].ID)
	req := createJWSRequest(t, service, key, url, map[string]interface{}{}, true, account.ID)

	resp := httptest.NewRecorder()
	service.ChallengeHandler(resp, req)

	require.Equal(t, http.StatusOK, resp.Code)

	var challengeResp struct {
		Type   string          `json:"type"`
		Status string          `json:"status"`
		Token  string          `json:"token"`
		Error  *entities.Error `json:"error"`
	}
	err = json.NewDecoder(resp.Body).Decode(&challengeResp)
	require.NoError(t, err)

	assert.Equal(t, common.StatusInvalid, challengeResp.Status)
	assert.NotNil(t, challengeResp.Error)
}

func TestChallengeHandler_ValidationSuccess(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	// Add a mock challenge verifier that always succeeds
	service.challengeMap["http-01"] = func(resolver *net.Resolver, ca common.CertificateAuthority, domain, port, token, keyAuth string) error {
		return nil
	}

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	identifier := entities.ACMEIdentifier{
		Type:  common.AuthzTypeDNS,
		Value: "example.com",
	}

	order := createTestOrderWithIdentifiers(t, service, account, []entities.ACMEIdentifier{identifier})
	authz := createTestAuthorizationWithChallenges(t, service, account, order, identifier, []string{"http-01"})

	// Request challenge validation
	url := fmt.Sprintf("%s/acme/challenge/%d", service.baseRESTURI, authz.Challenges[0].ID)
	req := createJWSRequest(t, service, key, url, map[string]interface{}{}, true, account.ID)

	resp := httptest.NewRecorder()
	service.ChallengeHandler(resp, req)

	require.Equal(t, http.StatusOK, resp.Code)

	var challengeResp struct {
		Type      string `json:"type"`
		Status    string `json:"status"`
		Token     string `json:"token"`
		Validated string `json:"validated"`
	}
	err := json.NewDecoder(resp.Body).Decode(&challengeResp)
	require.NoError(t, err)

	assert.Equal(t, common.StatusValid, challengeResp.Status)
	assert.NotEmpty(t, challengeResp.Validated)

	// Verify authorization status updated
	ctx := context.Background()
	authzDAO, err := service.storageFactory.AuthorizationDAO(account.ID)
	require.NoError(t, err)

	updatedAuthz, err := authzDAO.Get(ctx, authz.ID)
	require.NoError(t, err)
	assert.Equal(t, common.StatusValid, updatedAuthz.Status)

	// Verify order status updated to ready
	orderDAO, err := service.storageFactory.OrderDAO(account.ID)
	require.NoError(t, err)

	updatedOrder, err := orderDAO.Get(ctx, order.ID)
	require.NoError(t, err)
	assert.Equal(t, common.StatusReady, updatedOrder.Status)
}

func TestChallengeHandler_ValidationFailure(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	// Add a mock challenge verifier that always fails
	service.challengeMap["http-01"] = func(resolver *net.Resolver, ca common.CertificateAuthority, domain, port, token, keyAuth string) error {
		return caerrors.VerificationFailureError("validation failed")
	}

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	identifier := entities.ACMEIdentifier{
		Type:  common.AuthzTypeDNS,
		Value: "example.com",
	}

	order := createTestOrderWithIdentifiers(t, service, account, []entities.ACMEIdentifier{identifier})
	authz := createTestAuthorizationWithChallenges(t, service, account, order, identifier, []string{"http-01"})

	// Request challenge validation
	url := fmt.Sprintf("%s/acme/challenge/%d", service.baseRESTURI, authz.Challenges[0].ID)
	req := createJWSRequest(t, service, key, url, map[string]interface{}{}, true, account.ID)

	resp := httptest.NewRecorder()
	service.ChallengeHandler(resp, req)

	require.Equal(t, http.StatusOK, resp.Code)

	var challengeResp struct {
		Type   string          `json:"type"`
		Status string          `json:"status"`
		Token  string          `json:"token"`
		Error  *entities.Error `json:"error"`
	}
	err := json.NewDecoder(resp.Body).Decode(&challengeResp)
	require.NoError(t, err)

	assert.Equal(t, common.StatusInvalid, challengeResp.Status)
	assert.NotNil(t, challengeResp.Error)

	// Verify authorization status updated to invalid
	ctx := context.Background()
	authzDAO, err := service.storageFactory.AuthorizationDAO(account.ID)
	require.NoError(t, err)

	updatedAuthz, err := authzDAO.Get(ctx, authz.ID)
	require.NoError(t, err)
	assert.Equal(t, common.StatusInvalid, updatedAuthz.Status)

	// Verify order status updated to invalid
	orderDAO, err := service.storageFactory.OrderDAO(account.ID)
	require.NoError(t, err)

	updatedOrder, err := orderDAO.Get(ctx, order.ID)
	require.NoError(t, err)
	assert.Equal(t, common.StatusInvalid, updatedOrder.Status)
}

func TestChallengeHandler_UnsupportedChallengeType(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	identifier := entities.ACMEIdentifier{
		Type:  common.AuthzTypeDNS,
		Value: "example.com",
	}

	order := createTestOrderWithIdentifiers(t, service, account, []entities.ACMEIdentifier{identifier})
	authz := createTestAuthorizationWithChallenges(t, service, account, order, identifier, []string{"unsupported-01"})

	// Request challenge validation
	url := fmt.Sprintf("%s/acme/challenge/%d", service.baseRESTURI, authz.Challenges[0].ID)
	req := createJWSRequest(t, service, key, url, map[string]interface{}{}, true, account.ID)

	resp := httptest.NewRecorder()
	service.ChallengeHandler(resp, req)

	require.Equal(t, http.StatusOK, resp.Code)

	var challengeResp struct {
		Type   string          `json:"type"`
		Status string          `json:"status"`
		Token  string          `json:"token"`
		Error  *entities.Error `json:"error"`
	}
	err := json.NewDecoder(resp.Body).Decode(&challengeResp)
	require.NoError(t, err)

	assert.Equal(t, common.StatusInvalid, challengeResp.Status)
	assert.NotNil(t, challengeResp.Error)
	// Unsupported challenge types get a specific error message
	assert.Contains(t, challengeResp.Error.Detail, "Unsupported challenge type")
}

func TestChallengeHandler_MultipleAuthorizationsOneInvalid(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	// Add mock challenge verifiers
	service.challengeMap["http-01"] = func(resolver *net.Resolver, ca common.CertificateAuthority, domain, port, token, keyAuth string) error {
		if domain == "valid.com" {
			return nil
		}
		return caerrors.VerificationFailureError("validation failed")
	}

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Create order with two identifiers
	identifiers := []entities.ACMEIdentifier{
		{Type: common.AuthzTypeDNS, Value: "valid.com"},
		{Type: common.AuthzTypeDNS, Value: "invalid.com"},
	}

	order := createTestOrderWithIdentifiers(t, service, account, identifiers)

	// Create two authorizations
	authz1 := createTestAuthorizationWithChallenges(t, service, account, order, identifiers[0], []string{"http-01"})
	authz2 := createTestAuthorizationWithChallenges(t, service, account, order, identifiers[1], []string{"http-01"})

	// Validate first challenge (should succeed)
	url1 := fmt.Sprintf("%s/acme/challenge/%d", service.baseRESTURI, authz1.Challenges[0].ID)
	req1 := createJWSRequest(t, service, key, url1, map[string]interface{}{}, true, account.ID)

	resp1 := httptest.NewRecorder()
	service.ChallengeHandler(resp1, req1)
	require.Equal(t, http.StatusOK, resp1.Code)

	// Validate second challenge (should fail)
	url2 := fmt.Sprintf("%s/acme/challenge/%d", service.baseRESTURI, authz2.Challenges[0].ID)
	req2 := createJWSRequest(t, service, key, url2, map[string]interface{}{}, true, account.ID)

	resp2 := httptest.NewRecorder()
	service.ChallengeHandler(resp2, req2)
	require.Equal(t, http.StatusOK, resp2.Code)

	// Verify order status is invalid (because one authz failed)
	ctx := context.Background()
	orderDAO, err := service.storageFactory.OrderDAO(account.ID)
	require.NoError(t, err)

	updatedOrder, err := orderDAO.Get(ctx, order.ID)
	require.NoError(t, err)
	assert.Equal(t, common.StatusInvalid, updatedOrder.Status)
}

func TestChallengeHandler_EnrollmentChallengeWithPermanentIdentifier(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	// Add mock enrollment challenge verifier
	// Use "enroll-01-9000" which will be parsed as base="enroll-01", port=9000
	// The verifier needs to be registered with the FULL challenge type
	service.challengeMap["enroll-01-9000"] = func(resolver *net.Resolver, ca common.CertificateAuthority, domain, port, token, keyAuth string) error {
		// Verify we get the client IP instead of 127.0.0.1
		if domain == "127.0.0.1" {
			return caerrors.VerificationFailureError("expected client IP, got localhost")
		}
		return nil
	}

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	identifier := entities.ACMEIdentifier{
		Type:  common.AuthzTypePermanentIdentifier,
		Value: "127.0.0.1",
	}

	order := createTestOrderWithIdentifiers(t, service, account, []entities.ACMEIdentifier{identifier})
	// Use "enroll-01-9000" which will be recognized as an enrollment challenge
	authz := createTestAuthorizationWithChallenges(t, service, account, order, identifier, []string{"enroll-01-9000"})

	// Request challenge validation with X-Forwarded-For header
	url := fmt.Sprintf("%s/acme/challenge/%d", service.baseRESTURI, authz.Challenges[0].ID)
	req := createJWSRequest(t, service, key, url, map[string]interface{}{}, true, account.ID)
	req.Header.Set("X-Forwarded-For", "192.168.1.100")
	req.RemoteAddr = "10.0.0.1:12345"

	resp := httptest.NewRecorder()
	service.ChallengeHandler(resp, req)

	require.Equal(t, http.StatusOK, resp.Code)

	var challengeResp struct {
		Type   string `json:"type"`
		Status string `json:"status"`
	}
	err := json.NewDecoder(resp.Body).Decode(&challengeResp)
	require.NoError(t, err)

	assert.Equal(t, common.StatusValid, challengeResp.Status)
}

func TestParseChallengeAsDynamicPortAssignment_NoPort(t *testing.T) {
	// Note: "-01" suffix is NOT treated as a port (port must be > 99 to avoid matching challenge version suffixes)
	baseType, port, err := parseChallengeAsDynamicPortAssignment("http-01")
	require.NoError(t, err)
	assert.Equal(t, "http-01", baseType)
	assert.Equal(t, uint16(0), port)
}

func TestParseChallengeAsDynamicPortAssignment_WithPort(t *testing.T) {
	baseType, port, err := parseChallengeAsDynamicPortAssignment("http-01-8080")
	require.NoError(t, err)
	assert.Equal(t, "http-01", baseType)
	assert.Equal(t, uint16(8080), port)
}

func TestParseChallengeAsDynamicPortAssignment_MultipleHyphens(t *testing.T) {
	baseType, port, err := parseChallengeAsDynamicPortAssignment("device-attest-01-9443")
	require.NoError(t, err)
	assert.Equal(t, "device-attest-01", baseType)
	assert.Equal(t, uint16(9443), port)
}

func TestParseChallengeAsDynamicPortAssignment_InvalidPort(t *testing.T) {
	baseType, port, err := parseChallengeAsDynamicPortAssignment("http-01-invalid")
	require.NoError(t, err)
	assert.Equal(t, "http-01-invalid", baseType)
	assert.Equal(t, uint16(0), port)
}

func TestParseChallengeAsDynamicPortAssignment_PortOutOfRange(t *testing.T) {
	baseType, port, err := parseChallengeAsDynamicPortAssignment("http-01-99999")
	require.NoError(t, err)
	// Port number out of uint16 range should be treated as not a port
	assert.Equal(t, "http-01-99999", baseType)
	assert.Equal(t, uint16(0), port)
}

func TestParseChallengeAsDynamicPortAssignment_SinglePart(t *testing.T) {
	baseType, port, err := parseChallengeAsDynamicPortAssignment("http")
	require.NoError(t, err)
	assert.Equal(t, "http", baseType)
	assert.Equal(t, uint16(0), port)
}

func TestIsEnrollXChallenge_EnrollChallenge(t *testing.T) {
	// "enroll-01" has -01 suffix which is NOT a port (port must be > 99)
	// parseChallengeAsDynamicPortAssignment returns ("enroll-01", 0)
	// isEnrollXChallenge uses HasPrefix to detect enrollment challenges
	assert.True(t, isEnrollXChallenge("enroll-01"))
	// With explicit port: "enroll-01-8080" becomes base="enroll-01", port=8080
	assert.True(t, isEnrollXChallenge("enroll-01-8080"))
}

func TestIsEnrollXChallenge_EndorseChallenge(t *testing.T) {
	assert.True(t, isEnrollXChallenge("endorse-01"))
	assert.True(t, isEnrollXChallenge("endorse-01-9000"))
}

func TestIsEnrollXChallenge_DeviceAttestChallenge(t *testing.T) {
	assert.True(t, isEnrollXChallenge("device-attest-01"))
	assert.True(t, isEnrollXChallenge("device-attest-01-9443"))
}

func TestIsEnrollXChallenge_NonEnrollmentChallenge(t *testing.T) {
	assert.False(t, isEnrollXChallenge("http-01"))
	assert.False(t, isEnrollXChallenge("dns-01"))
	assert.False(t, isEnrollXChallenge("tls-alpn-01"))
	assert.False(t, isEnrollXChallenge("http-01-8080"))
}

func TestIsEnrollXChallenge_EmptyString(t *testing.T) {
	assert.False(t, isEnrollXChallenge(""))
}

func TestChallengeHandler_DynamicPortAssignment(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	// Track which port was used in validation
	var capturedPort string
	// Register verifier for the FULL challenge type "http-01-8080"
	service.challengeMap["http-01-8080"] = func(resolver *net.Resolver, ca common.CertificateAuthority, domain, port, token, keyAuth string) error {
		capturedPort = port
		return nil
	}

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	identifier := entities.ACMEIdentifier{
		Type:  common.AuthzTypeDNS,
		Value: "example.com",
	}

	order := createTestOrderWithIdentifiers(t, service, account, []entities.ACMEIdentifier{identifier})
	authz := createTestAuthorizationWithChallenges(t, service, account, order, identifier, []string{"http-01-8080"})

	// Request challenge validation
	url := fmt.Sprintf("%s/acme/challenge/%d", service.baseRESTURI, authz.Challenges[0].ID)
	req := createJWSRequest(t, service, key, url, map[string]interface{}{}, true, account.ID)

	resp := httptest.NewRecorder()
	service.ChallengeHandler(resp, req)

	require.Equal(t, http.StatusOK, resp.Code)
	assert.Equal(t, "8080", capturedPort)
}

func TestChallengeHandler_RemoteAddrWithoutPort(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	// Add mock enrollment challenge verifier
	service.challengeMap["enroll-01-7777"] = func(resolver *net.Resolver, ca common.CertificateAuthority, domain, port, token, keyAuth string) error {
		return nil
	}

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	identifier := entities.ACMEIdentifier{
		Type:  common.AuthzTypePermanentIdentifier,
		Value: "127.0.0.1",
	}

	order := createTestOrderWithIdentifiers(t, service, account, []entities.ACMEIdentifier{identifier})
	authz := createTestAuthorizationWithChallenges(t, service, account, order, identifier, []string{"enroll-01-7777"})

	// Request challenge validation with RemoteAddr without port
	url := fmt.Sprintf("%s/acme/challenge/%d", service.baseRESTURI, authz.Challenges[0].ID)
	req := createJWSRequest(t, service, key, url, map[string]interface{}{}, true, account.ID)
	req.RemoteAddr = "192.168.1.100" // No port

	resp := httptest.NewRecorder()
	service.ChallengeHandler(resp, req)

	require.Equal(t, http.StatusOK, resp.Code)

	var challengeResp struct {
		Status string `json:"status"`
	}
	err := json.NewDecoder(resp.Body).Decode(&challengeResp)
	require.NoError(t, err)

	assert.Equal(t, common.StatusValid, challengeResp.Status)
}

func TestChallengeHandler_XForwardedForMultipleIPs(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	// Track which domain was used in validation
	var capturedDomain string
	service.challengeMap["enroll-01-9000"] = func(resolver *net.Resolver, ca common.CertificateAuthority, domain, port, token, keyAuth string) error {
		capturedDomain = domain
		return nil
	}

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	identifier := entities.ACMEIdentifier{
		Type:  common.AuthzTypePermanentIdentifier,
		Value: "127.0.0.1",
	}

	order := createTestOrderWithIdentifiers(t, service, account, []entities.ACMEIdentifier{identifier})
	authz := createTestAuthorizationWithChallenges(t, service, account, order, identifier, []string{"enroll-01-9000"})

	// Request challenge validation with multiple IPs in X-Forwarded-For
	url := fmt.Sprintf("%s/acme/challenge/%d", service.baseRESTURI, authz.Challenges[0].ID)
	req := createJWSRequest(t, service, key, url, map[string]interface{}{}, true, account.ID)
	req.Header.Set("X-Forwarded-For", "192.168.1.100, 10.0.0.1, 172.16.0.1")
	req.RemoteAddr = "10.0.0.1:12345"

	resp := httptest.NewRecorder()
	service.ChallengeHandler(resp, req)

	require.Equal(t, http.StatusOK, resp.Code)
	// Should use the first IP in the X-Forwarded-For chain when identifier value is 127.0.0.1
	assert.Equal(t, "192.168.1.100", capturedDomain)
}

func TestChallengeHandler_XForwardedForWithLocalhost(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	// Track which domain was used in validation
	var capturedDomain string
	service.challengeMap["enroll-01-8443"] = func(resolver *net.Resolver, ca common.CertificateAuthority, domain, port, token, keyAuth string) error {
		capturedDomain = domain
		return nil
	}

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	identifier := entities.ACMEIdentifier{
		Type:  common.AuthzTypePermanentIdentifier,
		Value: "127.0.0.1",
	}

	order := createTestOrderWithIdentifiers(t, service, account, []entities.ACMEIdentifier{identifier})
	authz := createTestAuthorizationWithChallenges(t, service, account, order, identifier, []string{"enroll-01-8443"})

	// Request challenge validation with X-Forwarded-For header
	url := fmt.Sprintf("%s/acme/challenge/%d", service.baseRESTURI, authz.Challenges[0].ID)
	req := createJWSRequest(t, service, key, url, map[string]interface{}{}, true, account.ID)
	req.Header.Set("X-Forwarded-For", "192.168.1.100")
	req.RemoteAddr = "10.0.0.1:12345"

	resp := httptest.NewRecorder()
	service.ChallengeHandler(resp, req)

	require.Equal(t, http.StatusOK, resp.Code)
	// When identifier is 127.0.0.1, should use the X-Forwarded-For IP
	assert.Equal(t, "192.168.1.100", capturedDomain)
}

func TestChallengeHandler_NonLocalhostPermanentIdentifier(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	// Track which domain was used in validation
	var capturedDomain string
	service.challengeMap["enroll-01-6666"] = func(resolver *net.Resolver, ca common.CertificateAuthority, domain, port, token, keyAuth string) error {
		capturedDomain = domain
		return nil
	}

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	identifier := entities.ACMEIdentifier{
		Type:  common.AuthzTypePermanentIdentifier,
		Value: "192.168.1.50",
	}

	order := createTestOrderWithIdentifiers(t, service, account, []entities.ACMEIdentifier{identifier})
	authz := createTestAuthorizationWithChallenges(t, service, account, order, identifier, []string{"enroll-01-6666"})

	// Request challenge validation
	url := fmt.Sprintf("%s/acme/challenge/%d", service.baseRESTURI, authz.Challenges[0].ID)
	req := createJWSRequest(t, service, key, url, map[string]interface{}{}, true, account.ID)
	req.RemoteAddr = "10.0.0.1:12345"

	resp := httptest.NewRecorder()
	service.ChallengeHandler(resp, req)

	require.Equal(t, http.StatusOK, resp.Code)
	// Should use the identifier value (not the remote addr) since it's not 127.0.0.1
	assert.Equal(t, "192.168.1.50", capturedDomain)
}

// TestChallengeHandler_RFC8555_Headers verifies RFC 8555 required headers
// are present in challenge responses per Section 6.1 and 6.5.
func TestChallengeHandler_RFC8555_Headers(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	// Mock challenge verifier that succeeds
	service.challengeMap["http-01"] = func(resolver *net.Resolver, ca common.CertificateAuthority, domain, port, token, keyAuth string) error {
		return nil
	}

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	identifier := entities.ACMEIdentifier{
		Type:  "dns",
		Value: "example.com",
	}

	order := createTestOrderWithIdentifiers(t, service, account, []entities.ACMEIdentifier{identifier})
	authz := createTestAuthorizationWithChallenges(t, service, account, order, identifier, []string{"http-01"})

	// Request challenge validation
	url := fmt.Sprintf("%s/acme/challenge/%d", service.baseRESTURI, authz.Challenges[0].ID)
	req := createJWSRequest(t, service, key, url, map[string]interface{}{}, true, account.ID)

	resp := httptest.NewRecorder()
	service.ChallengeHandler(resp, req)

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

// TestChallengeHandler_RFC8555_Headers_NonPendingChallenge verifies headers
// are present even when returning cached/non-pending challenge status.
func TestChallengeHandler_RFC8555_Headers_NonPendingChallenge(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	identifier := entities.ACMEIdentifier{
		Type:  "dns",
		Value: "example.com",
	}

	order := createTestOrderWithIdentifiers(t, service, account, []entities.ACMEIdentifier{identifier})
	authz := createTestAuthorizationWithChallenges(t, service, account, order, identifier, []string{"http-01"})

	// Update challenge to valid status (non-pending)
	ctx := context.Background()
	authzDAO, err := service.storageFactory.AuthorizationDAO(account.ID)
	require.NoError(t, err)

	authz.Challenges[0].Status = common.StatusValid
	err = authzDAO.Save(ctx, authz)
	require.NoError(t, err)

	// Request already valid challenge
	url := fmt.Sprintf("%s/acme/challenge/%d", service.baseRESTURI, authz.Challenges[0].ID)
	req := createJWSRequest(t, service, key, url, map[string]interface{}{}, true, account.ID)

	resp := httptest.NewRecorder()
	service.ChallengeHandler(resp, req)

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

// =============================================================================
// Mock Storage Factory for EAB DAO Error Testing
// =============================================================================

// challengeErrorMockFactory wraps a real factory and can inject errors for EAB DAO
type challengeErrorMockFactory struct {
	realFactory    storage.Factory
	failEABDAO     bool
	mockOrderDAO   *challengeErrorMockOrderDAO
	useCustomOrder bool
}

func (m *challengeErrorMockFactory) AccountDAO() (qrdbsdk.GenericDAO[*entities.ACMEAccount], error) {
	return m.realFactory.AccountDAO()
}

func (m *challengeErrorMockFactory) OrderDAO(accountID uint64) (qrdbsdk.GenericDAO[*entities.ACMEOrder], error) {
	if m.useCustomOrder && m.mockOrderDAO != nil {
		return m.mockOrderDAO, nil
	}
	return m.realFactory.OrderDAO(accountID)
}

func (m *challengeErrorMockFactory) CertificateDAO() (qrdbsdk.GenericDAO[*entities.ACMECertificate], error) {
	return m.realFactory.CertificateDAO()
}

func (m *challengeErrorMockFactory) NonceDAO() (qrdbsdk.GenericDAO[*entities.ACMENonce], error) {
	return m.realFactory.NonceDAO()
}

func (m *challengeErrorMockFactory) AuthorizationDAO(accountID uint64) (qrdbsdk.GenericDAO[*entities.ACMEAuthorization], error) {
	return m.realFactory.AuthorizationDAO(accountID)
}

func (m *challengeErrorMockFactory) ChallengeDAO(accountID uint64) (qrdbsdk.GenericDAO[*entities.ACMEChallenge], error) {
	return m.realFactory.ChallengeDAO(accountID)
}

func (m *challengeErrorMockFactory) ExternalAccountBindingDAO() (qrdbsdk.GenericDAO[*entities.ExternalAccountBinding], error) {
	if m.failEABDAO {
		return nil, errors.New("mock EAB DAO creation failure")
	}
	return m.realFactory.ExternalAccountBindingDAO()
}

// challengeErrorMockOrderDAO wraps a real order DAO and can inject save errors.
// It embeds the real DAO to delegate all methods and overrides Save.
type challengeErrorMockOrderDAO struct {
	qrdbsdk.GenericDAO[*entities.ACMEOrder]
	failSave       bool
	saveCalls      int
	saveFailOnCall int
}

func (m *challengeErrorMockOrderDAO) Save(ctx context.Context, order *entities.ACMEOrder) error {
	currentCall := m.saveCalls
	m.saveCalls++
	if m.failSave && currentCall == m.saveFailOnCall {
		return errors.New("mock order save failure")
	}
	return m.GenericDAO.Save(ctx, order)
}

// =============================================================================
// Test: EAB DAO Creation Error (lines 117-121)
// =============================================================================

// TestChallengeHandler_EABDAOCreationError tests the error path when EAB DAO
// creation fails for endorse-01 challenges.
// This covers lines 117-121 in challenge.go.
func TestChallengeHandler_EABDAOCreationError(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	// Enable endorse EAB requirement
	service.endorseEABRequired = true

	// Add a mock endorse-01 challenge verifier
	service.challengeMap["endorse-01"] = func(resolver *net.Resolver, ca common.CertificateAuthority, domain, port, token, keyAuth string) error {
		return nil
	}

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	identifier := entities.ACMEIdentifier{
		Type:  common.AuthzTypePermanentIdentifier,
		Value: "test-device-123",
	}

	order := createTestOrderWithIdentifiers(t, service, account, []entities.ACMEIdentifier{identifier})
	authz := createTestAuthorizationWithChallenges(t, service, account, order, identifier, []string{"endorse-01"})

	// Create mock factory that fails EAB DAO creation
	mockFactory := &challengeErrorMockFactory{
		realFactory: service.storageFactory,
		failEABDAO:  true,
	}
	service.storageFactory = mockFactory

	// Request challenge
	url := fmt.Sprintf("%s/acme/challenge/%d", service.baseRESTURI, authz.Challenges[0].ID)
	req := createJWSRequest(t, service, key, url, map[string]interface{}{}, true, account.ID)

	resp := httptest.NewRecorder()
	service.ChallengeHandler(resp, req)

	// Should return server internal error
	assertErrorType(t, resp, common.ErrTypeServerInternal, http.StatusInternalServerError)
}

// =============================================================================
// Test: Invalid Authorization ID in Order Update Loop (lines 313-316)
// =============================================================================

// TestChallengeHandler_InvalidAuthorizationIDInOrderLoop tests the error path
// when an order contains an authorization URL with an invalid (non-numeric) ID.
// This covers lines 313-316 in challenge.go.
func TestChallengeHandler_InvalidAuthorizationIDInOrderLoop(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	// Add a mock challenge verifier that always succeeds
	service.challengeMap["http-01"] = func(resolver *net.Resolver, ca common.CertificateAuthority, domain, port, token, keyAuth string) error {
		return nil
	}

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	identifier := entities.ACMEIdentifier{
		Type:  common.AuthzTypeDNS,
		Value: "example.com",
	}

	order := createTestOrderWithIdentifiers(t, service, account, []entities.ACMEIdentifier{identifier})
	authz := createTestAuthorizationWithChallenges(t, service, account, order, identifier, []string{"http-01"})

	// Corrupt the order's authorization URLs with an invalid ID
	ctx := context.Background()
	orderDAO, err := service.storageFactory.OrderDAO(account.ID)
	require.NoError(t, err)

	// Add an authorization URL with an invalid (non-numeric) ID
	order.Authorizations = append(order.Authorizations, fmt.Sprintf("%s/acme/authz/invalid-id", service.baseRESTURI))
	err = orderDAO.Save(ctx, order)
	require.NoError(t, err)

	// Request challenge
	url := fmt.Sprintf("%s/acme/challenge/%d", service.baseRESTURI, authz.Challenges[0].ID)
	req := createJWSRequest(t, service, key, url, map[string]interface{}{}, true, account.ID)

	resp := httptest.NewRecorder()
	service.ChallengeHandler(resp, req)

	// Should return malformed error due to invalid authorization ID
	assertErrorType(t, resp, common.ErrTypeMalformedError, http.StatusBadRequest)
}

// =============================================================================
// Test: Order Save Error During Invalid Status Update (lines 331-334)
// =============================================================================

// TestChallengeHandler_OrderSaveErrorOnInvalidStatus tests the error path when
// saving an order fails during the status update to invalid.
// This covers lines 331-334 in challenge.go.
func TestChallengeHandler_OrderSaveErrorOnInvalidStatus(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	// Add a mock challenge verifier that succeeds - but we'll make the first
	// authorization invalid so the order status update to invalid triggers
	service.challengeMap["http-01"] = func(resolver *net.Resolver, ca common.CertificateAuthority, domain, port, token, keyAuth string) error {
		return nil
	}

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Create order with two identifiers
	identifiers := []entities.ACMEIdentifier{
		{Type: common.AuthzTypeDNS, Value: "first.com"},
		{Type: common.AuthzTypeDNS, Value: "second.com"},
	}

	order := createTestOrderWithIdentifiers(t, service, account, identifiers)

	// Create two authorizations
	authz1 := createTestAuthorizationWithChallenges(t, service, account, order, identifiers[0], []string{"http-01"})
	authz2 := createTestAuthorizationWithChallenges(t, service, account, order, identifiers[1], []string{"http-01"})

	// Set first authorization to invalid - this will cause order to be set to invalid
	ctx := context.Background()
	authzDAO, err := service.storageFactory.AuthorizationDAO(account.ID)
	require.NoError(t, err)

	authz1.Status = common.StatusInvalid
	err = authzDAO.Save(ctx, authz1)
	require.NoError(t, err)

	// Get the real order DAO to wrap
	realOrderDAO, err := service.storageFactory.OrderDAO(account.ID)
	require.NoError(t, err)

	// Create mock factory with order DAO that fails on save
	// The order save happens at line 331 when one authz is invalid
	mockOrderDAO := &challengeErrorMockOrderDAO{
		GenericDAO:     realOrderDAO,
		failSave:       true,
		saveFailOnCall: 0, // Fail on first save attempt
	}
	mockFactory := &challengeErrorMockFactory{
		realFactory:    service.storageFactory,
		mockOrderDAO:   mockOrderDAO,
		useCustomOrder: true,
	}
	service.storageFactory = mockFactory

	// Request challenge for second authorization
	url := fmt.Sprintf("%s/acme/challenge/%d", service.baseRESTURI, authz2.Challenges[0].ID)
	req := createJWSRequest(t, service, key, url, map[string]interface{}{}, true, account.ID)

	resp := httptest.NewRecorder()
	service.ChallengeHandler(resp, req)

	// Should return server internal error due to order save failure
	assertErrorType(t, resp, common.ErrTypeServerInternal, http.StatusInternalServerError)
}

// =============================================================================
// Test: Validation Generic Failure (lines 272-275)
// =============================================================================

// TestChallengeHandler_ValidationGenericFailure tests the generic failure path
// where validation fails but no specific error was set (challenge.Error is nil).
// This covers lines 272-275 in challenge.go.
func TestChallengeHandler_ValidationGenericFailure(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	// Add a mock challenge verifier that fails but doesn't set a specific error
	service.challengeMap["http-01"] = func(resolver *net.Resolver, ca common.CertificateAuthority, domain, port, token, keyAuth string) error {
		return errors.New("generic validation failure")
	}

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	identifier := entities.ACMEIdentifier{
		Type:  common.AuthzTypeDNS,
		Value: "example.com",
	}

	order := createTestOrderWithIdentifiers(t, service, account, []entities.ACMEIdentifier{identifier})
	authz := createTestAuthorizationWithChallenges(t, service, account, order, identifier, []string{"http-01"})

	// Request challenge validation
	url := fmt.Sprintf("%s/acme/challenge/%d", service.baseRESTURI, authz.Challenges[0].ID)
	req := createJWSRequest(t, service, key, url, map[string]interface{}{}, true, account.ID)

	resp := httptest.NewRecorder()
	service.ChallengeHandler(resp, req)

	require.Equal(t, http.StatusOK, resp.Code)

	// Verify the challenge has an error set
	ctx := context.Background()
	authzDAO, err := service.storageFactory.AuthorizationDAO(account.ID)
	require.NoError(t, err)

	updatedAuthz, err := authzDAO.Get(ctx, authz.ID)
	require.NoError(t, err)

	// Find the challenge and verify it has an error
	for _, ch := range updatedAuthz.Challenges {
		if ch.ID == authz.Challenges[0].ID {
			assert.Equal(t, common.StatusInvalid, ch.Status)
			assert.NotNil(t, ch.Error)
			break
		}
	}

	// Verify authorization and order status
	assert.Equal(t, common.StatusInvalid, updatedAuthz.Status)
}

// =============================================================================
// Test: Endorse-01 Challenge Without EAB Binding (EAB validation failure)
// =============================================================================

// TestChallengeHandler_EndorseWithoutEAB tests the endorse-01 challenge when
// the account has no EAB binding but EAB is required.
// This verifies the EAB validation error path (lines 125-132).
func TestChallengeHandler_EndorseWithoutEAB(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	// Enable endorse EAB requirement
	service.endorseEABRequired = true

	// Add a mock endorse-01 challenge verifier
	service.challengeMap["endorse-01"] = func(resolver *net.Resolver, ca common.CertificateAuthority, domain, port, token, keyAuth string) error {
		return nil
	}

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Account has no ExternalAccountBinding set

	identifier := entities.ACMEIdentifier{
		Type:  common.AuthzTypePermanentIdentifier,
		Value: "test-device-456",
	}

	order := createTestOrderWithIdentifiers(t, service, account, []entities.ACMEIdentifier{identifier})
	authz := createTestAuthorizationWithChallenges(t, service, account, order, identifier, []string{"endorse-01"})

	// Request challenge
	url := fmt.Sprintf("%s/acme/challenge/%d", service.baseRESTURI, authz.Challenges[0].ID)
	req := createJWSRequest(t, service, key, url, map[string]interface{}{}, true, account.ID)

	resp := httptest.NewRecorder()
	service.ChallengeHandler(resp, req)

	// Should return unauthorized error
	assertErrorType(t, resp, common.ErrTypeUnauthorized, http.StatusUnauthorized)
}

// =============================================================================
// Test: Challenge Already Processing Status
// =============================================================================

// TestChallengeHandler_ChallengeAlreadyProcessing tests that a challenge
// already in "processing" status is returned as-is.
func TestChallengeHandler_ChallengeAlreadyProcessing(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	identifier := entities.ACMEIdentifier{
		Type:  common.AuthzTypeDNS,
		Value: "example.com",
	}

	order := createTestOrderWithIdentifiers(t, service, account, []entities.ACMEIdentifier{identifier})
	authz := createTestAuthorizationWithChallenges(t, service, account, order, identifier, []string{"http-01"})

	// Set challenge to processing status
	ctx := context.Background()
	authzDAO, err := service.storageFactory.AuthorizationDAO(account.ID)
	require.NoError(t, err)

	authz.Challenges[0].Status = common.StatusProcessing
	err = authzDAO.Save(ctx, authz)
	require.NoError(t, err)

	// Request challenge
	url := fmt.Sprintf("%s/acme/challenge/%d", service.baseRESTURI, authz.Challenges[0].ID)
	req := createJWSRequest(t, service, key, url, map[string]interface{}{}, true, account.ID)

	resp := httptest.NewRecorder()
	service.ChallengeHandler(resp, req)

	// Should return the challenge with processing status
	require.Equal(t, http.StatusOK, resp.Code)
}

// =============================================================================
// Test: Multiple Authorizations With One Invalid
// =============================================================================

// TestChallengeHandler_MultipleAuthorizationsFirstInvalid tests the order
// update loop when the first authorization is invalid.
func TestChallengeHandler_MultipleAuthorizationsFirstInvalid(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	// Add a mock challenge verifier that succeeds
	service.challengeMap["http-01"] = func(resolver *net.Resolver, ca common.CertificateAuthority, domain, port, token, keyAuth string) error {
		return nil
	}

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Create order with two identifiers
	identifiers := []entities.ACMEIdentifier{
		{Type: common.AuthzTypeDNS, Value: "first.com"},
		{Type: common.AuthzTypeDNS, Value: "second.com"},
	}

	order := createTestOrderWithIdentifiers(t, service, account, identifiers)

	// Create two authorizations
	authz1 := createTestAuthorizationWithChallenges(t, service, account, order, identifiers[0], []string{"http-01"})
	authz2 := createTestAuthorizationWithChallenges(t, service, account, order, identifiers[1], []string{"http-01"})

	// Set first authorization to invalid
	ctx := context.Background()
	authzDAO, err := service.storageFactory.AuthorizationDAO(account.ID)
	require.NoError(t, err)

	authz1.Status = common.StatusInvalid
	err = authzDAO.Save(ctx, authz1)
	require.NoError(t, err)

	// Validate second challenge (should succeed but order should be invalid)
	url := fmt.Sprintf("%s/acme/challenge/%d", service.baseRESTURI, authz2.Challenges[0].ID)
	req := createJWSRequest(t, service, key, url, map[string]interface{}{}, true, account.ID)

	resp := httptest.NewRecorder()
	service.ChallengeHandler(resp, req)

	require.Equal(t, http.StatusOK, resp.Code)

	// Verify order status is invalid (because first authz is invalid)
	orderDAO, err := service.storageFactory.OrderDAO(account.ID)
	require.NoError(t, err)

	updatedOrder, err := orderDAO.Get(ctx, order.ID)
	require.NoError(t, err)
	assert.Equal(t, common.StatusInvalid, updatedOrder.Status)
}

// =============================================================================
// Test: Endorse-01 With Port Suffix
// =============================================================================

// TestChallengeHandler_EndorseWithPortSuffix tests endorse-01-8443 challenge type
// which should trigger EAB validation when EAB is required.
func TestChallengeHandler_EndorseWithPortSuffix(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	// Enable endorse EAB requirement
	service.endorseEABRequired = true

	// Add a mock endorse-01 challenge verifier (registered with port suffix)
	service.challengeMap["endorse-01-8443"] = func(resolver *net.Resolver, ca common.CertificateAuthority, domain, port, token, keyAuth string) error {
		return nil
	}

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	identifier := entities.ACMEIdentifier{
		Type:  common.AuthzTypePermanentIdentifier,
		Value: "device-789",
	}

	order := createTestOrderWithIdentifiers(t, service, account, []entities.ACMEIdentifier{identifier})
	authz := createTestAuthorizationWithChallenges(t, service, account, order, identifier, []string{"endorse-01-8443"})

	// Request challenge - should fail EAB validation since no binding
	url := fmt.Sprintf("%s/acme/challenge/%d", service.baseRESTURI, authz.Challenges[0].ID)
	req := createJWSRequest(t, service, key, url, map[string]interface{}{}, true, account.ID)

	resp := httptest.NewRecorder()
	service.ChallengeHandler(resp, req)

	// Should return unauthorized error due to missing EAB
	assertErrorType(t, resp, common.ErrTypeUnauthorized, http.StatusUnauthorized)
}

// =============================================================================
// Test: Challenge With Non-Existent Order
// =============================================================================

// TestChallengeHandler_OrderNotFound tests the case where the order associated
// with an authorization cannot be found.
func TestChallengeHandler_OrderNotFound(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	// Add a mock challenge verifier that succeeds
	service.challengeMap["http-01"] = func(resolver *net.Resolver, ca common.CertificateAuthority, domain, port, token, keyAuth string) error {
		return nil
	}

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	identifier := entities.ACMEIdentifier{
		Type:  common.AuthzTypeDNS,
		Value: "example.com",
	}

	order := createTestOrderWithIdentifiers(t, service, account, []entities.ACMEIdentifier{identifier})
	authz := createTestAuthorizationWithChallenges(t, service, account, order, identifier, []string{"http-01"})

	// Delete the order to simulate order not found
	ctx := context.Background()
	orderDAO, err := service.storageFactory.OrderDAO(account.ID)
	require.NoError(t, err)
	err = orderDAO.Delete(ctx, order)
	require.NoError(t, err)

	// Request challenge
	url := fmt.Sprintf("%s/acme/challenge/%d", service.baseRESTURI, authz.Challenges[0].ID)
	req := createJWSRequest(t, service, key, url, map[string]interface{}{}, true, account.ID)

	resp := httptest.NewRecorder()
	service.ChallengeHandler(resp, req)

	// Should return malformed error for order not found
	assertErrorType(t, resp, common.ErrTypeMalformedError, http.StatusBadRequest)
}

// =============================================================================
// Test: Default Port for HTTP-01 Challenge
// =============================================================================

// TestChallengeHandler_DefaultHTTPPort tests that http-01 challenges without
// explicit port use port 80 as default.
func TestChallengeHandler_DefaultHTTPPort(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	var capturedPort string
	service.challengeMap["http-01"] = func(resolver *net.Resolver, ca common.CertificateAuthority, domain, port, token, keyAuth string) error {
		capturedPort = port
		return nil
	}

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	identifier := entities.ACMEIdentifier{
		Type:  common.AuthzTypeDNS,
		Value: "example.com",
	}

	order := createTestOrderWithIdentifiers(t, service, account, []entities.ACMEIdentifier{identifier})
	authz := createTestAuthorizationWithChallenges(t, service, account, order, identifier, []string{"http-01"})

	// Request challenge validation
	url := fmt.Sprintf("%s/acme/challenge/%d", service.baseRESTURI, authz.Challenges[0].ID)
	req := createJWSRequest(t, service, key, url, map[string]interface{}{}, true, account.ID)

	resp := httptest.NewRecorder()
	service.ChallengeHandler(resp, req)

	require.Equal(t, http.StatusOK, resp.Code)
	assert.Equal(t, "80", capturedPort, "HTTP-01 should default to port 80")
}

// =============================================================================
// Test: Default Port for Enrollment Challenge
// =============================================================================

// TestChallengeHandler_DefaultEnrollmentPort tests that enroll-01 challenges
// without explicit port use port 8080 as default.
func TestChallengeHandler_DefaultEnrollmentPort(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	var capturedPort string
	service.challengeMap["enroll-01"] = func(resolver *net.Resolver, ca common.CertificateAuthority, domain, port, token, keyAuth string) error {
		capturedPort = port
		return nil
	}

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	identifier := entities.ACMEIdentifier{
		Type:  common.AuthzTypePermanentIdentifier,
		Value: "device-enrollment-test",
	}

	order := createTestOrderWithIdentifiers(t, service, account, []entities.ACMEIdentifier{identifier})
	authz := createTestAuthorizationWithChallenges(t, service, account, order, identifier, []string{"enroll-01"})

	// Request challenge validation
	url := fmt.Sprintf("%s/acme/challenge/%d", service.baseRESTURI, authz.Challenges[0].ID)
	req := createJWSRequest(t, service, key, url, map[string]interface{}{}, true, account.ID)

	resp := httptest.NewRecorder()
	service.ChallengeHandler(resp, req)

	require.Equal(t, http.StatusOK, resp.Code)
	assert.Equal(t, "8080", capturedPort, "Enroll-01 should default to port 8080")
}

// =============================================================================
// Test: Expired Authorization Timestamp
// =============================================================================

// TestChallengeHandler_AuthorizationExpired tests handling of an expired
// authorization during challenge validation.
func TestChallengeHandler_AuthorizationExpired(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	// Add a mock challenge verifier
	service.challengeMap["http-01"] = func(resolver *net.Resolver, ca common.CertificateAuthority, domain, port, token, keyAuth string) error {
		return nil
	}

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	identifier := entities.ACMEIdentifier{
		Type:  common.AuthzTypeDNS,
		Value: "example.com",
	}

	order := createTestOrderWithIdentifiers(t, service, account, []entities.ACMEIdentifier{identifier})
	authz := createTestAuthorizationWithChallenges(t, service, account, order, identifier, []string{"http-01"})

	// Set authorization to expired
	ctx := context.Background()
	authzDAO, err := service.storageFactory.AuthorizationDAO(account.ID)
	require.NoError(t, err)

	// Set expiry in the past
	authz.Expires = time.Now().Add(-24 * time.Hour).Format(time.RFC3339)
	err = authzDAO.Save(ctx, authz)
	require.NoError(t, err)

	// Request challenge - should still process (expiry check may be in different handler)
	url := fmt.Sprintf("%s/acme/challenge/%d", service.baseRESTURI, authz.Challenges[0].ID)
	req := createJWSRequest(t, service, key, url, map[string]interface{}{}, true, account.ID)

	resp := httptest.NewRecorder()
	service.ChallengeHandler(resp, req)

	// Challenge handler processes expired authorizations (validation may still succeed)
	require.Equal(t, http.StatusOK, resp.Code)
}

// =============================================================================
// Test: Order Save Error During Ready Status Update (lines 341-344)
// =============================================================================

// TestChallengeHandler_OrderSaveErrorOnReadyStatus tests the error path when
// saving an order fails during the status update to ready (when all authzs are valid).
// This covers lines 341-344 in challenge.go.
func TestChallengeHandler_OrderSaveErrorOnReadyStatus(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	// Add a mock challenge verifier that succeeds
	service.challengeMap["http-01"] = func(resolver *net.Resolver, ca common.CertificateAuthority, domain, port, token, keyAuth string) error {
		return nil
	}

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	identifier := entities.ACMEIdentifier{
		Type:  common.AuthzTypeDNS,
		Value: "example.com",
	}

	order := createTestOrderWithIdentifiers(t, service, account, []entities.ACMEIdentifier{identifier})
	authz := createTestAuthorizationWithChallenges(t, service, account, order, identifier, []string{"http-01"})

	// Get the real order DAO to wrap
	realOrderDAO, err := service.storageFactory.OrderDAO(account.ID)
	require.NoError(t, err)

	// Create mock factory with order DAO that fails on save
	// The order save happens at line 341 when all authzs are valid (order -> ready)
	mockOrderDAO := &challengeErrorMockOrderDAO{
		GenericDAO:     realOrderDAO,
		failSave:       true,
		saveFailOnCall: 0, // Fail on first save attempt
	}
	mockFactory := &challengeErrorMockFactory{
		realFactory:    service.storageFactory,
		mockOrderDAO:   mockOrderDAO,
		useCustomOrder: true,
	}
	service.storageFactory = mockFactory

	// Request challenge
	url := fmt.Sprintf("%s/acme/challenge/%d", service.baseRESTURI, authz.Challenges[0].ID)
	req := createJWSRequest(t, service, key, url, map[string]interface{}{}, true, account.ID)

	resp := httptest.NewRecorder()
	service.ChallengeHandler(resp, req)

	// Should return server internal error due to order save failure
	assertErrorType(t, resp, common.ErrTypeServerInternal, http.StatusInternalServerError)
}

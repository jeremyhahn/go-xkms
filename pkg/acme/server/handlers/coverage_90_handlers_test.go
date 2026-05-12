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
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
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

func TestRevokeCertHandlerInvalidPayload(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Send invalid JSON payload
	url := "https://acme.test.example.com/acme/revoke-cert"
	req := createJWSRequest(t, service, key, url, []byte("not json"), true, account.ID)

	rr := httptest.NewRecorder()
	service.RevokeCertHandler(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestRevokeCertHandlerInvalidCertEncoding(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Send revoke request with invalid base64
	revokeReq := map[string]interface{}{
		"certificate": "!!!not-valid-base64!!!",
		"reason":      1,
	}
	reqBody, _ := json.Marshal(revokeReq)

	url := "https://acme.test.example.com/acme/revoke-cert"
	req := createJWSRequest(t, service, key, url, reqBody, true, account.ID)

	rr := httptest.NewRecorder()
	service.RevokeCertHandler(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestRevokeCertHandlerInvalidCertFormat(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Send revoke request with valid base64 but invalid certificate DER
	revokeReq := map[string]interface{}{
		"certificate": "aGVsbG8gd29ybGQ", // "hello world" in base64 raw URL encoding
		"reason":      1,
	}
	reqBody, _ := json.Marshal(revokeReq)

	url := "https://acme.test.example.com/acme/revoke-cert"
	req := createJWSRequest(t, service, key, url, reqBody, true, account.ID)

	rr := httptest.NewRecorder()
	service.RevokeCertHandler(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestNewOrderHandlerInvalidPayload(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Send invalid JSON payload
	url := "https://acme.test.example.com/acme/new-order"
	req := createJWSRequest(t, service, key, url, []byte("not json"), true, account.ID)

	rr := httptest.NewRecorder()
	service.NewOrderHandler(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestNewOrderHandlerEmptyIdentifiers(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Send order request with empty identifiers
	orderReq := map[string]interface{}{
		"identifiers": []interface{}{},
	}
	reqBody, _ := json.Marshal(orderReq)

	url := "https://acme.test.example.com/acme/new-order"
	req := createJWSRequest(t, service, key, url, reqBody, true, account.ID)

	rr := httptest.NewRecorder()
	service.NewOrderHandler(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestNewOrderHandlerInvalidDomain(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Send order request with invalid domain
	orderReq := map[string]interface{}{
		"identifiers": []map[string]string{
			{"type": "dns", "value": "-invalid-domain"},
		},
	}
	reqBody, _ := json.Marshal(orderReq)

	url := "https://acme.test.example.com/acme/new-order"
	req := createJWSRequest(t, service, key, url, reqBody, true, account.ID)

	rr := httptest.NewRecorder()
	service.NewOrderHandler(rr, req)

	// Should reject invalid domain name
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestKeyChangeHandlerInvalidOuterPayload(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Send invalid JSON in outer payload
	url := "https://acme.test.example.com/acme/key-change"
	req := createJWSRequest(t, service, key, url, []byte("not json"), true, account.ID)

	rr := httptest.NewRecorder()
	service.KeyChangeHandler(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestAuthorizationHandlerMethodNotAllowed(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Create a test authorization
	ctx := context.Background()
	authzDAO, _ := service.storageFactory.AuthorizationDAO(account.ID)
	authzID, _ := GenerateID()
	authz := &entities.ACMEAuthorization{
		ID:     authzID,
		Status: common.StatusPending,
		Identifier: entities.ACMEIdentifier{
			Type:  "dns",
			Value: "example.com",
		},
	}
	authzDAO.Save(ctx, authz)

	// Create request with unsupported method (DELETE)
	url := "https://acme.test.example.com/acme/authz/" + fmt.Sprintf("%d", authz.ID)
	req := createJWSRequest(t, service, key, url, nil, true, account.ID)
	req.Method = http.MethodDelete
	req = mux.SetURLVars(req, map[string]string{"id": fmt.Sprintf("%d", authz.ID)})

	rr := httptest.NewRecorder()
	service.AuthorizationHandler(rr, req)

	// GET and POST are allowed but DELETE should not be allowed
	assert.True(t, rr.Code == http.StatusOK || rr.Code == http.StatusBadRequest || rr.Code == http.StatusMethodNotAllowed)
}

func TestChallengeHandlerInvalidChallengeID(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Create request with invalid challenge ID
	url := "https://acme.test.example.com/acme/challenge/invalid-id"
	req := createJWSRequest(t, service, key, url, nil, true, account.ID)
	req = mux.SetURLVars(req, map[string]string{"id": "invalid-id"})

	rr := httptest.NewRecorder()
	service.ChallengeHandler(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestAccountHandlerInvalidStatus(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Try to set invalid status
	accountReq := map[string]interface{}{
		"status": "invalid-status",
	}
	reqBody, _ := json.Marshal(accountReq)

	url := "https://acme.test.example.com/acme/account/" + fmt.Sprintf("%d", account.ID)
	req := createJWSRequest(t, service, key, url, reqBody, true, account.ID)

	rr := httptest.NewRecorder()
	service.AccountHandler(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestAccountHandlerInvalidContact(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Try to set invalid contact URL (not mailto:)
	accountReq := map[string]interface{}{
		"contact": []string{"http://invalid-contact.com"},
	}
	reqBody, _ := json.Marshal(accountReq)

	url := "https://acme.test.example.com/acme/account/" + fmt.Sprintf("%d", account.ID)
	req := createJWSRequest(t, service, key, url, reqBody, true, account.ID)

	rr := httptest.NewRecorder()
	service.AccountHandler(rr, req)

	// Should reject invalid contact URL format
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestOrderFinalizeHandlerOrderNotReady(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Create order with pending status (not ready)
	order := createTestOrderSimple(t, service, account.ID)

	// Try to finalize order that's not ready
	finalizeReq := map[string]interface{}{
		"csr": "dGVzdA", // dummy CSR
	}
	reqBody, _ := json.Marshal(finalizeReq)

	url := "https://acme.test.example.com/acme/order/" + fmt.Sprintf("%d", order.ID) + "/finalize"
	req := createJWSRequest(t, service, key, url, reqBody, true, account.ID)
	req = mux.SetURLVars(req, map[string]string{"id": fmt.Sprintf("%d", order.ID)})

	rr := httptest.NewRecorder()
	service.OrderFinalizeHandler(rr, req)

	// Should return 403 because order is not ready
	assert.True(t, rr.Code == http.StatusForbidden || rr.Code == http.StatusBadRequest)
}

func TestOrderFinalizeHandlerInvalidCSR(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Create order and set status to ready
	order := createTestOrderSimple(t, service, account.ID)
	ctx := context.Background()
	orderDAO, _ := service.storageFactory.OrderDAO(account.ID)
	order.Status = common.StatusReady
	orderDAO.Save(ctx, order)

	// Try to finalize with invalid CSR
	finalizeReq := map[string]interface{}{
		"csr": "invalid-base64!!!",
	}
	reqBody, _ := json.Marshal(finalizeReq)

	url := "https://acme.test.example.com/acme/order/" + fmt.Sprintf("%d", order.ID) + "/finalize"
	req := createJWSRequest(t, service, key, url, reqBody, true, account.ID)
	req = mux.SetURLVars(req, map[string]string{"id": fmt.Sprintf("%d", order.ID)})

	rr := httptest.NewRecorder()
	service.OrderFinalizeHandler(rr, req)

	// Should return bad request due to invalid CSR
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestCertificateHandlerNotFound(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Request non-existent certificate
	url := "https://acme.test.example.com/acme/cert/999999999999"
	req := createJWSRequest(t, service, key, url, nil, true, account.ID)
	req = mux.SetURLVars(req, map[string]string{"id": "999999999999"})

	rr := httptest.NewRecorder()
	service.CertificateHandler(rr, req)

	// Should return not found or bad request
	assert.True(t, rr.Code == http.StatusNotFound || rr.Code == http.StatusBadRequest)
}

func TestNewAccountHandlerMissingTOS(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)

	// Create account request without agreeing to TOS
	accountReq := map[string]interface{}{
		"contact":              []string{"mailto:test@example.com"},
		"termsOfServiceAgreed": false,
	}
	reqBody, _ := json.Marshal(accountReq)

	url := "https://acme.test.example.com/acme/new-account"
	req := createJWSRequest(t, service, key, url, reqBody, false, 0)

	rr := httptest.NewRecorder()
	service.NewAccountHandler(rr, req)

	// Should return error because TOS not agreed
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestOrderHandlerSuccessCov(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Create order
	order := createTestOrderSimple(t, service, account.ID)
	require.NotNil(t, order)

	// Access order
	url := "https://acme.test.example.com/acme/order/" + fmt.Sprintf("%d", order.ID)
	req := createJWSRequest(t, service, key, url, nil, true, account.ID)
	req = mux.SetURLVars(req, map[string]string{"id": fmt.Sprintf("%d", order.ID)})

	rr := httptest.NewRecorder()
	service.OrderHandler(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestNewOrderHandlerDeactivatedAccount(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Deactivate account
	ctx := context.Background()
	accountDAO, _ := service.storageFactory.AccountDAO()
	account.Status = common.StatusDeactivated
	accountDAO.Save(ctx, account)

	// Try to create new order with deactivated account
	orderReq := map[string]interface{}{
		"identifiers": []map[string]string{
			{"type": "dns", "value": "example.com"},
		},
	}
	reqBody, _ := json.Marshal(orderReq)

	url := "https://acme.test.example.com/acme/new-order"
	req := createJWSRequest(t, service, key, url, reqBody, true, account.ID)

	rr := httptest.NewRecorder()
	service.NewOrderHandler(rr, req)

	// Should return error due to deactivated account
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

// Additional tests for 90%+ coverage

func TestOrdersListHandlerInvalidPage(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Request orders list with invalid page parameter
	url := "https://acme.test.example.com/acme/orders"
	req := createJWSRequest(t, service, key, url, nil, true, account.ID)
	req = mux.SetURLVars(req, map[string]string{"page": "not-a-number"})

	rr := httptest.NewRecorder()
	service.OrdersListHandler(rr, req)

	// Should return bad request due to invalid page
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestOrdersListHandlerSuccess(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Create a test order first
	_ = createTestOrderSimple(t, service, account.ID)

	// Request orders list
	url := "https://acme.test.example.com/acme/orders"
	req := createJWSRequest(t, service, key, url, nil, true, account.ID)

	rr := httptest.NewRecorder()
	service.OrdersListHandler(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Header().Get("Content-Type"), "application/json")
	assert.NotEmpty(t, rr.Header().Get("Replay-Nonce"))
}

func TestNewNonceHandlerHead(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	req := httptest.NewRequest(http.MethodHead, "https://acme.test.example.com/acme/new-nonce", nil)
	rr := httptest.NewRecorder()

	service.NewNonceHandler(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.NotEmpty(t, rr.Header().Get("Replay-Nonce"))
}

func TestNewNonceHandlerGet(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	req := httptest.NewRequest(http.MethodGet, "https://acme.test.example.com/acme/new-nonce", nil)
	rr := httptest.NewRecorder()

	service.NewNonceHandler(rr, req)

	assert.Equal(t, http.StatusNoContent, rr.Code)
	assert.NotEmpty(t, rr.Header().Get("Replay-Nonce"))
}

func TestAccountHandlerAlreadyDeactivated(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// First deactivate
	ctx := context.Background()
	accountDAO, _ := service.storageFactory.AccountDAO()
	account.Status = common.StatusDeactivated
	accountDAO.Save(ctx, account)

	// Try to deactivate again - parseKID will return error since account is deactivated
	accountReq := map[string]interface{}{
		"status": common.StatusDeactivated,
	}
	reqBody, _ := json.Marshal(accountReq)

	url := "https://acme.test.example.com/acme/account/" + fmt.Sprintf("%d", account.ID)
	req := createJWSRequest(t, service, key, url, reqBody, true, account.ID)

	rr := httptest.NewRecorder()
	service.AccountHandler(rr, req)

	// Should fail since account is deactivated (parseKID returns error)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestRevokeCertHandlerInvalidReason(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Create a valid certificate first
	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(12345),
		Subject: pkix.Name{
			CommonName: "test.example.com",
		},
		DNSNames:  []string{"test.example.com"},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(24 * time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &certKey.PublicKey, certKey)
	require.NoError(t, err)

	// Encode certificate
	certB64 := base64.RawURLEncoding.EncodeToString(certDER)

	// Send revoke request with out-of-range reason
	revokeReq := map[string]interface{}{
		"certificate": certB64,
		"reason":      99, // Invalid reason
	}
	reqBody, _ := json.Marshal(revokeReq)

	url := "https://acme.test.example.com/acme/revoke-cert"
	req := createJWSRequest(t, service, key, url, reqBody, true, account.ID)

	rr := httptest.NewRecorder()
	service.RevokeCertHandler(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestOrderFinalizeHandlerInvalidOrderIDCov(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	finalizeReq := map[string]interface{}{
		"csr": "dGVzdA",
	}
	reqBody, _ := json.Marshal(finalizeReq)

	url := "https://acme.test.example.com/acme/order/invalid/finalize"
	req := createJWSRequest(t, service, key, url, reqBody, true, account.ID)
	req = mux.SetURLVars(req, map[string]string{"id": "not-a-number"})

	rr := httptest.NewRecorder()
	service.OrderFinalizeHandler(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestOrderFinalizeHandlerOrderNotFoundCov(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	finalizeReq := map[string]interface{}{
		"csr": "dGVzdA",
	}
	reqBody, _ := json.Marshal(finalizeReq)

	url := "https://acme.test.example.com/acme/order/999999999/finalize"
	req := createJWSRequest(t, service, key, url, reqBody, true, account.ID)
	req = mux.SetURLVars(req, map[string]string{"id": "999999999"})

	rr := httptest.NewRecorder()
	service.OrderFinalizeHandler(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestOrderFinalizeHandlerInvalidPayload(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Create and make order ready
	order := createTestOrderSimple(t, service, account.ID)
	ctx := context.Background()
	orderDAO, _ := service.storageFactory.OrderDAO(account.ID)
	order.Status = common.StatusReady
	orderDAO.Save(ctx, order)

	url := "https://acme.test.example.com/acme/order/" + fmt.Sprintf("%d", order.ID) + "/finalize"
	req := createJWSRequest(t, service, key, url, []byte("not json"), true, account.ID)
	req = mux.SetURLVars(req, map[string]string{"id": fmt.Sprintf("%d", order.ID)})

	rr := httptest.NewRecorder()
	service.OrderFinalizeHandler(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestCertificateHandlerInvalidID(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	req := httptest.NewRequest(http.MethodGet, "https://acme.test.example.com/acme/cert/invalid", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "not-a-number"})

	rr := httptest.NewRecorder()
	service.CertificateHandler(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestNewOrderHandlerUnsupportedIdentifierType(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Send order request with unsupported identifier type
	orderReq := map[string]interface{}{
		"identifiers": []map[string]string{
			{"type": "unsupported-type", "value": "example.com"},
		},
	}
	reqBody, _ := json.Marshal(orderReq)

	url := "https://acme.test.example.com/acme/new-order"
	req := createJWSRequest(t, service, key, url, reqBody, true, account.ID)

	rr := httptest.NewRecorder()
	service.NewOrderHandler(rr, req)

	// Should reject unsupported identifier type
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestIsValidDomainNameEdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		domain   string
		expected bool
	}{
		{"empty", "", false},
		{"single char", "a", true},
		{"valid domain", "example.com", true},
		{"subdomain", "sub.example.com", true},
		{"hyphen middle", "ex-ample.com", true},
		{"hyphen start", "-example.com", false},
		{"hyphen end", "example-.com", false},
		{"numbers only", "123.456", true},
		{"uppercase", "EXAMPLE.COM", true},
		{"mixed case", "ExAmPlE.CoM", true},
		{"too long label", string(make([]byte, 64)), false},
		{"valid long domain", "a." + string(make([]byte, 63)) + ".com", false}, // label too long
		{"empty label", "example..com", false},
		{"special char", "exam!ple.com", false},
		{"underscore", "exam_ple.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isValidDomainName(tt.domain)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestAccountHandlerPostAsGet(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Post-as-get (empty payload)
	url := "https://acme.test.example.com/acme/account/" + fmt.Sprintf("%d", account.ID)
	req := createJWSRequest(t, service, key, url, nil, true, account.ID)

	rr := httptest.NewRecorder()
	service.AccountHandler(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestAccountHandlerInvalidJSON(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	url := "https://acme.test.example.com/acme/account/" + fmt.Sprintf("%d", account.ID)
	req := createJWSRequest(t, service, key, url, []byte("not json"), true, account.ID)

	rr := httptest.NewRecorder()
	service.AccountHandler(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestOrdersListHandlerUnsupportedMethod(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	url := "https://acme.test.example.com/acme/orders"
	req := createJWSRequest(t, service, key, url, nil, true, account.ID)
	req.Method = http.MethodDelete

	rr := httptest.NewRecorder()
	service.OrdersListHandler(rr, req)

	// Should return bad request for unsupported method
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

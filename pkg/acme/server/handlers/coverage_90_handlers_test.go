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

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
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
	"github.com/stretchr/testify/assert"
)

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

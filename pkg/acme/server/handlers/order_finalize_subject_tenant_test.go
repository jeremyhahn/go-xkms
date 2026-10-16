// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

//go:build codec_json

package handlers

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
)

func TestIssuanceTenant_IsTheAccountsTenant(t *testing.T) {
	assert.Equal(t, "tenant-a", issuanceTenant(&entities.ACMEAccount{TenantID: "tenant-a"}))
}

func TestIssuanceTenant_TenantlessAccountIsTheSystemTenants(t *testing.T) {
	assert.Equal(t, qrdbsdk.SystemTenantID, issuanceTenant(&entities.ACMEAccount{}))
}

// TestOrderFinalizeHandler_SignsForTheAccountsTenantNotTheCSRs pins that the
// tenant the CA stamps comes from the account, never from the OU the CSR
// asserts.
func TestOrderFinalizeHandler_SignsForTheAccountsTenantNotTheCSRs(t *testing.T) {
	service, mockCA, cleanup := setupTestServiceWithMockCA(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)
	order := createTestOrderSimple(t, service, account.ID)
	order.Status = common.StatusReady
	orderDAO, err := service.storageFactory.OrderDAO(account.ID)
	require.NoError(t, err)
	require.NoError(t, orderDAO.Save(context.Background(), order))

	csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "example.com", OrganizationalUnit: []string{"another-tenant"}},
		DNSNames: []string{"example.com"},
	}, csrKey)
	require.NoError(t, err)

	url := fmt.Sprintf("%s/acme/orders/%d/finalize", service.baseRESTURI, order.ID)
	req := createJWSRequest(t, service, key, url, OrderFinalizeRequest{CSR: base64.RawURLEncoding.EncodeToString(csrDER)}, true, account.ID)
	req = mux.SetURLVars(req, map[string]string{"id": fmt.Sprintf("%d", order.ID)})
	resp := httptest.NewRecorder()
	service.OrderFinalizeHandler(resp, req)

	require.Equal(t, http.StatusOK, resp.Code)
	require.NotNil(t, mockCA.lastSignOptions)
	assert.Equal(t, qrdbsdk.SystemTenantID, mockCA.lastSignOptions.TenantID)
}

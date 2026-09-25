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
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	caerrors "github.com/jeremyhahn/go-xkms/pkg/acme/errors"
	"github.com/jeremyhahn/go-xkms/pkg/acme/server/metrics"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// This file verifies that the ACME protocol handlers actually record the
// events issue #734 wired: order creation and status transitions, challenge
// validation, finalize/issuance, revocation, and account creation. Each test
// reads the relevant metric before and after the handler call and asserts
// the delta, since the metrics package's counters and gauges are
// process-global and accumulate across the whole test binary.

func TestNewOrderHandler_Metrics_ActiveOrdersAndPendingChallenges(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	service.challengeMap["http-01"] = func(resolver *net.Resolver, ca common.CertificateAuthority, authzValue, challengePort, challengeToken, expectedKeyAuth string) error {
		return nil
	}

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	activeBefore := testutil.ToFloat64(metrics.GetActiveOrders())
	pendingBefore := testutil.ToFloat64(metrics.GetPendingChallenges())

	payload := NewOrderRequest{
		Identifiers: []entities.ACMEIdentifier{
			{Type: common.AuthzTypeDNS, Value: "example.com"},
		},
	}
	url := service.baseRESTURI + "/acme/new-order"
	req := createJWSRequest(t, service, key, url, payload, true, account.ID)

	resp := httptest.NewRecorder()
	service.NewOrderHandler(resp, req)
	require.Equal(t, http.StatusCreated, resp.Code)

	// One order was created (activeOrders +1) with one DNS identifier, which
	// yields one authorization carrying one http-01 challenge
	// (pendingChallenges +1).
	assert.Equal(t, activeBefore+1, testutil.ToFloat64(metrics.GetActiveOrders()))
	assert.Equal(t, pendingBefore+1, testutil.ToFloat64(metrics.GetPendingChallenges()))
}

func TestNewOrderHandler_Metrics_TenantActiveOrders(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	service.challengeMap["http-01"] = func(resolver *net.Resolver, ca common.CertificateAuthority, authzValue, challengePort, challengeToken, expectedKeyAuth string) error {
		return nil
	}

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)
	account.TenantID = "tenant-metrics-test"
	accountDAO, err := service.storageFactory.AccountDAO()
	require.NoError(t, err)
	require.NoError(t, accountDAO.Save(context.Background(), account))

	before := testutil.ToFloat64(metrics.GetActiveOrdersByTenant().WithLabelValues(account.TenantID))

	payload := NewOrderRequest{
		Identifiers: []entities.ACMEIdentifier{
			{Type: common.AuthzTypeDNS, Value: "example.com"},
		},
	}
	url := service.baseRESTURI + "/acme/new-order"
	req := createJWSRequest(t, service, key, url, payload, true, account.ID)

	resp := httptest.NewRecorder()
	service.NewOrderHandler(resp, req)
	require.Equal(t, http.StatusCreated, resp.Code)

	assert.Equal(t, before+1, testutil.ToFloat64(metrics.GetActiveOrdersByTenant().WithLabelValues(account.TenantID)))
}

func TestChallengeHandler_Metrics_ValidationSuccess(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	service.challengeMap["http-01"] = func(resolver *net.Resolver, ca common.CertificateAuthority, domain, port, token, keyAuth string) error {
		return nil
	}

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	identifier := entities.ACMEIdentifier{Type: common.AuthzTypeDNS, Value: "example.com"}
	order := createTestOrderWithIdentifiers(t, service, account, []entities.ACMEIdentifier{identifier})
	authz := createTestAuthorizationWithChallenges(t, service, account, order, identifier, []string{"http-01"})

	pendingBefore := testutil.ToFloat64(metrics.GetPendingChallenges())
	completedBefore := testutil.ToFloat64(metrics.GetChallengesCompletedTotal().WithLabelValues("http-01", common.StatusValid))

	url := fmt.Sprintf("%s/acme/challenge/%d", service.baseRESTURI, authz.Challenges[0].ID)
	req := createJWSRequest(t, service, key, url, map[string]interface{}{}, true, account.ID)

	resp := httptest.NewRecorder()
	service.ChallengeHandler(resp, req)
	require.Equal(t, http.StatusOK, resp.Code)

	assert.Equal(t, pendingBefore-1, testutil.ToFloat64(metrics.GetPendingChallenges()))
	assert.Equal(t, completedBefore+1, testutil.ToFloat64(metrics.GetChallengesCompletedTotal().WithLabelValues("http-01", common.StatusValid)))
}

func TestChallengeHandler_Metrics_ValidationFailureDecrementsActiveOrders(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	service.challengeMap["http-01"] = func(resolver *net.Resolver, ca common.CertificateAuthority, domain, port, token, keyAuth string) error {
		return caerrors.VerificationFailureError("validation failed")
	}

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	identifier := entities.ACMEIdentifier{Type: common.AuthzTypeDNS, Value: "example.com"}
	order := createTestOrderWithIdentifiers(t, service, account, []entities.ACMEIdentifier{identifier})
	authz := createTestAuthorizationWithChallenges(t, service, account, order, identifier, []string{"http-01"})

	activeBefore := testutil.ToFloat64(metrics.GetActiveOrders())
	completedBefore := testutil.ToFloat64(metrics.GetChallengesCompletedTotal().WithLabelValues("http-01", common.StatusInvalid))

	url := fmt.Sprintf("%s/acme/challenge/%d", service.baseRESTURI, authz.Challenges[0].ID)
	req := createJWSRequest(t, service, key, url, map[string]interface{}{}, true, account.ID)

	resp := httptest.NewRecorder()
	service.ChallengeHandler(resp, req)
	require.Equal(t, http.StatusOK, resp.Code)

	// A failed challenge fails the order's only authorization, which drives
	// the order straight to the terminal "invalid" state.
	assert.Equal(t, activeBefore-1, testutil.ToFloat64(metrics.GetActiveOrders()))
	assert.Equal(t, completedBefore+1, testutil.ToFloat64(metrics.GetChallengesCompletedTotal().WithLabelValues("http-01", common.StatusInvalid)))
}

func TestOrderFinalizeHandler_Metrics_Success(t *testing.T) {
	service, mockCA, cleanup := setupTestServiceWithMockCA(t)
	defer cleanup()

	mockCA.returnedSerialNum = big.NewInt(99999)

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	order := createTestOrderSimple(t, service, account.ID)
	order.Status = common.StatusReady

	ctx := context.Background()
	orderDAO, err := service.storageFactory.OrderDAO(account.ID)
	require.NoError(t, err)
	require.NoError(t, orderDAO.Save(ctx, order))

	csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "example.com"},
		DNSNames: []string{"example.com"},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, csrKey)
	require.NoError(t, err)

	activeBefore := testutil.ToFloat64(metrics.GetActiveOrders())
	issuedBefore := testutil.ToFloat64(metrics.GetCertificatesIssuedTotal())

	payload := OrderFinalizeRequest{CSR: base64.RawURLEncoding.EncodeToString(csrDER)}
	url := fmt.Sprintf("%s/acme/orders/%d/finalize", service.baseRESTURI, order.ID)
	req := createJWSRequest(t, service, key, url, payload, true, account.ID)
	req = mux.SetURLVars(req, map[string]string{"id": fmt.Sprintf("%d", order.ID)})

	resp := httptest.NewRecorder()
	service.OrderFinalizeHandler(resp, req)
	require.Equal(t, http.StatusOK, resp.Code)

	assert.Equal(t, activeBefore-1, testutil.ToFloat64(metrics.GetActiveOrders()))
	assert.Equal(t, issuedBefore+1, testutil.ToFloat64(metrics.GetCertificatesIssuedTotal()))
}

func TestOrderFinalizeHandler_Metrics_SignCSRFailure(t *testing.T) {
	service, mockCA, cleanup := setupTestServiceWithMockCA(t)
	defer cleanup()

	mockCA.shouldFailSignCSR = true

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	order := createTestOrderSimple(t, service, account.ID)
	order.Status = common.StatusReady

	ctx := context.Background()
	orderDAO, err := service.storageFactory.OrderDAO(account.ID)
	require.NoError(t, err)
	require.NoError(t, orderDAO.Save(ctx, order))

	csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "example.com"},
		DNSNames: []string{"example.com"},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, csrKey)
	require.NoError(t, err)

	activeBefore := testutil.ToFloat64(metrics.GetActiveOrders())
	errorsBefore := testutil.ToFloat64(metrics.GetErrorsTotal().WithLabelValues("issuance_failed"))

	payload := OrderFinalizeRequest{CSR: base64.RawURLEncoding.EncodeToString(csrDER)}
	url := fmt.Sprintf("%s/acme/orders/%d/finalize", service.baseRESTURI, order.ID)
	req := createJWSRequest(t, service, key, url, payload, true, account.ID)
	req = mux.SetURLVars(req, map[string]string{"id": fmt.Sprintf("%d", order.ID)})

	resp := httptest.NewRecorder()
	service.OrderFinalizeHandler(resp, req)
	assertErrorType(t, resp, common.ErrTypeServerInternal, http.StatusInternalServerError)

	assert.Equal(t, activeBefore-1, testutil.ToFloat64(metrics.GetActiveOrders()))
	assert.Equal(t, errorsBefore+1, testutil.ToFloat64(metrics.GetErrorsTotal().WithLabelValues("issuance_failed")))
}

func TestRevokeCertHandler_Metrics_Success(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)
	_, x509Cert := createTestCertificateWithAuthorization(t, service, key, account.ID)

	before := testutil.ToFloat64(metrics.GetCertificatesRevokedTotal())

	certB64 := base64.RawURLEncoding.EncodeToString(x509Cert.Raw)
	payload := RevokeCertRequest{Certificate: certB64, Reason: RevocationReasonKeyCompromise}
	url := service.baseRESTURI + "/acme/revoke-cert"
	req := createJWSRequest(t, service, key, url, payload, true, account.ID)

	resp := httptest.NewRecorder()
	service.RevokeCertHandler(resp, req)
	require.Equal(t, http.StatusOK, resp.Code)

	assert.Equal(t, before+1, testutil.ToFloat64(metrics.GetCertificatesRevokedTotal()))
}

func TestNewAccountHandler_Metrics_AccountsCreatedTotal(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	before := testutil.ToFloat64(metrics.GetAccountsCreatedTotal())

	payload := NewAccountRequest{
		Contact:              []string{"mailto:test@example.com"},
		TermsOfServiceAgreed: true,
	}
	url := service.baseRESTURI + "/acme/new-account"
	req := createJWSRequest(t, service, key, url, payload, false, 0)

	resp := httptest.NewRecorder()
	service.NewAccountHandler(resp, req)
	require.Equal(t, http.StatusCreated, resp.Code)

	assert.Equal(t, before+1, testutil.ToFloat64(metrics.GetAccountsCreatedTotal()))
}

func TestNewAccountHandler_Metrics_ExistingAccountDoesNotDoubleCount(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	before := testutil.ToFloat64(metrics.GetAccountsCreatedTotal())

	// Re-registering the same key returns the existing account (RFC 8555
	// Section 7.3) and must not be counted as a new creation.
	payload := NewAccountRequest{Contact: account.Contact}
	url := service.baseRESTURI + "/acme/new-account"
	req := createJWSRequest(t, service, key, url, payload, false, 0)

	resp := httptest.NewRecorder()
	service.NewAccountHandler(resp, req)
	require.Equal(t, http.StatusOK, resp.Code)

	assert.Equal(t, before, testutil.ToFloat64(metrics.GetAccountsCreatedTotal()))
}

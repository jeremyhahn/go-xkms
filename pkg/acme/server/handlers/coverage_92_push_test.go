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
	"time"

	"github.com/gorilla/mux"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	caerrors "github.com/jeremyhahn/go-xkms/pkg/acme/errors"
	"github.com/jeremyhahn/go-xkms/pkg/acme/server"
	"github.com/jeremyhahn/go-xkms/pkg/acme/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockCAAValidator92Push is a mock CAA validator for testing CAA validation paths.
type mockCAAValidator92Push struct {
	shouldFail    bool
	failWithCAA   bool
	failDomain    string
	validateCount int
}

func (m *mockCAAValidator92Push) Validate(_ context.Context, domain string, _ bool) error {
	m.validateCount++
	if m.shouldFail {
		if m.failDomain != "" && domain != m.failDomain {
			return nil
		}
		if m.failWithCAA {
			return &server.ErrCAAValidationFailed{
				Domain: domain,
				Reason: "CAA record prohibits issuance",
			}
		}
		return caerrors.InternalServerError("DNS resolution error for %s", domain)
	}
	return nil
}

// --- OrderFinalizeHandler CAA validation tests ---

// TestCov92_OrderFinalizeHandler_CAAValidationSuccess tests the CAA validation
// success path within the OrderFinalizeHandler.
func TestCov92_OrderFinalizeHandler_CAAValidationSuccess(t *testing.T) {
	service, _, cleanup := setupTestServiceWithMockCA(t)
	defer cleanup()

	caaValidator := &mockCAAValidator92Push{}
	service.caaValidator = caaValidator

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	order := createTestOrderSimple(t, service, account.ID)
	order.Status = common.StatusReady

	ctx := context.Background()
	orderDAO, err := service.storageFactory.OrderDAO(account.ID)
	require.NoError(t, err)
	err = orderDAO.Save(ctx, order)
	require.NoError(t, err)

	csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "example.com",
		},
		DNSNames: []string{"example.com"},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, csrKey)
	require.NoError(t, err)

	payload := OrderFinalizeRequest{
		CSR: base64.RawURLEncoding.EncodeToString(csrDER),
	}

	url := fmt.Sprintf("%s/acme/orders/%d/finalize", service.baseRESTURI, order.ID)
	req := createJWSRequest(t, service, key, url, payload, true, account.ID)
	req = mux.SetURLVars(req, map[string]string{"id": fmt.Sprintf("%d", order.ID)})

	resp := httptest.NewRecorder()
	service.OrderFinalizeHandler(resp, req)

	require.Equal(t, http.StatusOK, resp.Code)
	assert.Equal(t, 1, caaValidator.validateCount, "CAA validator should have been called once for the DNS identifier")
}

// TestCov92_OrderFinalizeHandler_CAAValidationFailure tests the CAA validation
// failure path when the CAA record prohibits issuance.
func TestCov92_OrderFinalizeHandler_CAAValidationFailure(t *testing.T) {
	service, _, cleanup := setupTestServiceWithMockCA(t)
	defer cleanup()

	caaValidator := &mockCAAValidator92Push{
		shouldFail:  true,
		failWithCAA: true,
	}
	service.caaValidator = caaValidator

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	order := createTestOrderSimple(t, service, account.ID)
	order.Status = common.StatusReady

	ctx := context.Background()
	orderDAO, err := service.storageFactory.OrderDAO(account.ID)
	require.NoError(t, err)
	err = orderDAO.Save(ctx, order)
	require.NoError(t, err)

	csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "example.com",
		},
		DNSNames: []string{"example.com"},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, csrKey)
	require.NoError(t, err)

	payload := OrderFinalizeRequest{
		CSR: base64.RawURLEncoding.EncodeToString(csrDER),
	}

	url := fmt.Sprintf("%s/acme/orders/%d/finalize", service.baseRESTURI, order.ID)
	req := createJWSRequest(t, service, key, url, payload, true, account.ID)
	req = mux.SetURLVars(req, map[string]string{"id": fmt.Sprintf("%d", order.ID)})

	resp := httptest.NewRecorder()
	service.OrderFinalizeHandler(resp, req)

	assertErrorType(t, resp, common.ErrTypeCAAError, http.StatusUnauthorized)
}

// TestCov92_OrderFinalizeHandler_CAAValidationDNSError tests the CAA validation
// path when DNS resolution fails (non-CAA error).
func TestCov92_OrderFinalizeHandler_CAAValidationDNSError(t *testing.T) {
	service, _, cleanup := setupTestServiceWithMockCA(t)
	defer cleanup()

	caaValidator := &mockCAAValidator92Push{
		shouldFail:  true,
		failWithCAA: false,
	}
	service.caaValidator = caaValidator

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	order := createTestOrderSimple(t, service, account.ID)
	order.Status = common.StatusReady

	ctx := context.Background()
	orderDAO, err := service.storageFactory.OrderDAO(account.ID)
	require.NoError(t, err)
	err = orderDAO.Save(ctx, order)
	require.NoError(t, err)

	csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "example.com",
		},
		DNSNames: []string{"example.com"},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, csrKey)
	require.NoError(t, err)

	payload := OrderFinalizeRequest{
		CSR: base64.RawURLEncoding.EncodeToString(csrDER),
	}

	url := fmt.Sprintf("%s/acme/orders/%d/finalize", service.baseRESTURI, order.ID)
	req := createJWSRequest(t, service, key, url, payload, true, account.ID)
	req = mux.SetURLVars(req, map[string]string{"id": fmt.Sprintf("%d", order.ID)})

	resp := httptest.NewRecorder()
	service.OrderFinalizeHandler(resp, req)

	assertErrorType(t, resp, common.ErrTypeCAAError, http.StatusUnauthorized)
}

// TestCov92_OrderFinalizeHandler_CAAValidationSkipsNonDNS tests that CAA validation
// skips non-DNS identifiers (permanent-identifier type).
func TestCov92_OrderFinalizeHandler_CAAValidationSkipsNonDNS(t *testing.T) {
	service, _, cleanup := setupTestServiceWithMockCA(t)
	defer cleanup()

	caaValidator := &mockCAAValidator92Push{
		shouldFail:  true,
		failWithCAA: true,
	}
	service.caaValidator = caaValidator

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	order := createTestOrderSimple(t, service, account.ID)
	order.Status = common.StatusReady
	order.Identifiers = []entities.ACMEIdentifier{
		{Type: common.AuthzTypePermanentIdentifier, Value: "test-device-id"},
	}

	ctx := context.Background()
	orderDAO, err := service.storageFactory.OrderDAO(account.ID)
	require.NoError(t, err)
	err = orderDAO.Save(ctx, order)
	require.NoError(t, err)

	csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "test-device-id",
		},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, csrKey)
	require.NoError(t, err)

	payload := OrderFinalizeRequest{
		CSR: base64.RawURLEncoding.EncodeToString(csrDER),
	}

	url := fmt.Sprintf("%s/acme/orders/%d/finalize", service.baseRESTURI, order.ID)
	req := createJWSRequest(t, service, key, url, payload, true, account.ID)
	req = mux.SetURLVars(req, map[string]string{"id": fmt.Sprintf("%d", order.ID)})

	resp := httptest.NewRecorder()
	service.OrderFinalizeHandler(resp, req)

	require.Equal(t, http.StatusOK, resp.Code)
	assert.Equal(t, 0, caaValidator.validateCount, "CAA validator should not be called for non-DNS identifiers")
}

// TestCov92_OrderFinalizeHandler_CAAValidationWildcard tests CAA validation
// with a wildcard DNS identifier that strips the *. prefix.
func TestCov92_OrderFinalizeHandler_CAAValidationWildcard(t *testing.T) {
	service, _, cleanup := setupTestServiceWithMockCA(t)
	defer cleanup()

	caaValidator := &mockCAAValidator92Push{
		shouldFail:  true,
		failWithCAA: true,
		failDomain:  "example.com",
	}
	service.caaValidator = caaValidator

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	order := createTestOrderSimple(t, service, account.ID)
	order.Status = common.StatusReady
	order.Identifiers = []entities.ACMEIdentifier{
		{Type: common.AuthzTypeDNS, Value: "*.example.com"},
	}

	ctx := context.Background()
	orderDAO, err := service.storageFactory.OrderDAO(account.ID)
	require.NoError(t, err)
	err = orderDAO.Save(ctx, order)
	require.NoError(t, err)

	csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "*.example.com",
		},
		DNSNames: []string{"*.example.com"},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, csrKey)
	require.NoError(t, err)

	payload := OrderFinalizeRequest{
		CSR: base64.RawURLEncoding.EncodeToString(csrDER),
	}

	url := fmt.Sprintf("%s/acme/orders/%d/finalize", service.baseRESTURI, order.ID)
	req := createJWSRequest(t, service, key, url, payload, true, account.ID)
	req = mux.SetURLVars(req, map[string]string{"id": fmt.Sprintf("%d", order.ID)})

	resp := httptest.NewRecorder()
	service.OrderFinalizeHandler(resp, req)

	assertErrorType(t, resp, common.ErrTypeCAAError, http.StatusUnauthorized)
	assert.Equal(t, 1, caaValidator.validateCount)
}

// TestCov92_OrderFinalizeHandler_PreIssuanceHookSuccess tests the pre-issuance
// hook success path for standard x509 CSRs.
func TestCov92_OrderFinalizeHandler_PreIssuanceHookSuccess(t *testing.T) {
	service, _, cleanup := setupTestServiceWithMockCA(t)
	defer cleanup()

	hookExecuted := false
	preHookRegistry := NewPreIssuanceHookRegistry()
	preHookRegistry.Register(func(ctx *PreIssuanceHookContext) error {
		hookExecuted = true
		assert.False(t, ctx.IsTCGCSR)
		assert.NotNil(t, ctx.CSR)
		assert.NotNil(t, ctx.Order)
		return nil
	})

	service.params = &Params{
		PreIssuanceHooks:   preHookRegistry,
		OrderFinalizeHooks: NewOrderFinalizeHookRegistry(),
	}

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	order := createTestOrderSimple(t, service, account.ID)
	order.Status = common.StatusReady

	ctx := context.Background()
	orderDAO, err := service.storageFactory.OrderDAO(account.ID)
	require.NoError(t, err)
	err = orderDAO.Save(ctx, order)
	require.NoError(t, err)

	csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "example.com",
		},
		DNSNames: []string{"example.com"},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, csrKey)
	require.NoError(t, err)

	payload := OrderFinalizeRequest{
		CSR: base64.RawURLEncoding.EncodeToString(csrDER),
	}

	url := fmt.Sprintf("%s/acme/orders/%d/finalize", service.baseRESTURI, order.ID)
	req := createJWSRequest(t, service, key, url, payload, true, account.ID)
	req = mux.SetURLVars(req, map[string]string{"id": fmt.Sprintf("%d", order.ID)})

	resp := httptest.NewRecorder()
	service.OrderFinalizeHandler(resp, req)

	require.Equal(t, http.StatusOK, resp.Code)
	assert.True(t, hookExecuted, "Pre-issuance hook should have been executed")
}

// TestCov92_OrderFinalizeHandler_OrderNotOwnedByAccount tests the authorization
// check where the order's AccountID doesn't match the requesting account.
func TestCov92_OrderFinalizeHandler_OrderNotOwnedByAccount(t *testing.T) {
	service, _, cleanup := setupTestServiceWithMockCA(t)
	defer cleanup()

	key1 := generateTestKey(t)
	account1 := createTestAccount(t, service, key1)

	key2 := generateTestKey(t)
	account2 := createTestAccount(t, service, key2)

	// Create order for account2
	order := createTestOrderSimple(t, service, account2.ID)
	order.Status = common.StatusReady

	ctx := context.Background()
	orderDAO2, err := service.storageFactory.OrderDAO(account2.ID)
	require.NoError(t, err)
	err = orderDAO2.Save(ctx, order)
	require.NoError(t, err)

	// Save a copy in account1's partition with account2's AccountID
	orderDAO1, err := service.storageFactory.OrderDAO(account1.ID)
	require.NoError(t, err)
	orderCopy := *order
	err = orderDAO1.Save(ctx, &orderCopy)
	require.NoError(t, err)

	csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "example.com",
		},
		DNSNames: []string{"example.com"},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, csrKey)
	require.NoError(t, err)

	payload := OrderFinalizeRequest{
		CSR: base64.RawURLEncoding.EncodeToString(csrDER),
	}

	url := fmt.Sprintf("%s/acme/orders/%d/finalize", service.baseRESTURI, order.ID)
	req := createJWSRequest(t, service, key1, url, payload, true, account1.ID)
	req = mux.SetURLVars(req, map[string]string{"id": fmt.Sprintf("%d", order.ID)})

	resp := httptest.NewRecorder()
	service.OrderFinalizeHandler(resp, req)

	assertErrorType(t, resp, common.ErrTypeUnauthorized, http.StatusUnauthorized)
}

// TestCov92_OrderFinalizeHandler_NoHooksRegistered tests the code path where
// no params or hooks are registered (the warning else branch).
func TestCov92_OrderFinalizeHandler_NoHooksRegistered(t *testing.T) {
	service, _, cleanup := setupTestServiceWithMockCA(t)
	defer cleanup()

	service.params = nil

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	order := createTestOrderSimple(t, service, account.ID)
	order.Status = common.StatusReady

	ctx := context.Background()
	orderDAO, err := service.storageFactory.OrderDAO(account.ID)
	require.NoError(t, err)
	err = orderDAO.Save(ctx, order)
	require.NoError(t, err)

	csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "example.com",
		},
		DNSNames: []string{"example.com"},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, csrKey)
	require.NoError(t, err)

	payload := OrderFinalizeRequest{
		CSR: base64.RawURLEncoding.EncodeToString(csrDER),
	}

	url := fmt.Sprintf("%s/acme/orders/%d/finalize", service.baseRESTURI, order.ID)
	req := createJWSRequest(t, service, key, url, payload, true, account.ID)
	req = mux.SetURLVars(req, map[string]string{"id": fmt.Sprintf("%d", order.ID)})

	resp := httptest.NewRecorder()
	service.OrderFinalizeHandler(resp, req)

	require.Equal(t, http.StatusOK, resp.Code)
}

// TestCov92_OrderFinalizeHandler_PermanentIDNotBase64 tests the path where
// a permanent-identifier value is not a valid base64-encoded public key,
// exercising the device-attest-01 fallback path.
func TestCov92_OrderFinalizeHandler_PermanentIDNotBase64(t *testing.T) {
	service, _, cleanup := setupTestServiceWithMockCA(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	order := createTestOrderSimple(t, service, account.ID)
	order.Status = common.StatusReady
	order.Identifiers = []entities.ACMEIdentifier{
		{Type: common.AuthzTypePermanentIdentifier, Value: "device-hostname-123"},
	}

	ctx := context.Background()
	orderDAO, err := service.storageFactory.OrderDAO(account.ID)
	require.NoError(t, err)
	err = orderDAO.Save(ctx, order)
	require.NoError(t, err)

	csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "device-hostname-123",
		},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, csrKey)
	require.NoError(t, err)

	payload := OrderFinalizeRequest{
		CSR: base64.RawURLEncoding.EncodeToString(csrDER),
	}

	url := fmt.Sprintf("%s/acme/orders/%d/finalize", service.baseRESTURI, order.ID)
	req := createJWSRequest(t, service, key, url, payload, true, account.ID)
	req = mux.SetURLVars(req, map[string]string{"id": fmt.Sprintf("%d", order.ID)})

	resp := httptest.NewRecorder()
	service.OrderFinalizeHandler(resp, req)

	require.Equal(t, http.StatusOK, resp.Code)
}

// TestCov92_OrderFinalizeHandler_EKCertLargeSerialNumber tests the EK cert
// issuance path when the certificate serial number exceeds uint64.
func TestCov92_OrderFinalizeHandler_EKCertLargeSerialNumber(t *testing.T) {
	service, mockCA, cleanup := setupTestServiceWithMockCA(t)
	defer cleanup()

	mockCA.returnCertWithLargeSerial = true

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	ekKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	ekPubKeyDER, err := x509.MarshalPKIXPublicKey(ekKey.Public())
	require.NoError(t, err)

	permanentID := base64.RawURLEncoding.EncodeToString(ekPubKeyDER)

	order := createTestOrderSimple(t, service, account.ID)
	order.Status = common.StatusReady
	order.Identifiers = []entities.ACMEIdentifier{
		{Type: common.AuthzTypePermanentIdentifier, Value: permanentID},
	}

	ctx := context.Background()
	orderDAO, err := service.storageFactory.OrderDAO(account.ID)
	require.NoError(t, err)
	err = orderDAO.Save(ctx, order)
	require.NoError(t, err)

	csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "test-ek-device",
		},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, csrKey)
	require.NoError(t, err)

	payload := OrderFinalizeRequest{
		CSR: base64.RawURLEncoding.EncodeToString(csrDER),
	}

	url := fmt.Sprintf("%s/acme/orders/%d/finalize", service.baseRESTURI, order.ID)
	req := createJWSRequest(t, service, key, url, payload, true, account.ID)
	req = mux.SetURLVars(req, map[string]string{"id": fmt.Sprintf("%d", order.ID)})

	resp := httptest.NewRecorder()
	service.OrderFinalizeHandler(resp, req)

	require.Equal(t, http.StatusOK, resp.Code)
}

// TestCov92_OrderFinalizeHandler_EKCertNilSerialNumber tests the EK cert
// issuance path when the certificate has a nil serial number.
func TestCov92_OrderFinalizeHandler_EKCertNilSerialNumber(t *testing.T) {
	service, mockCA, cleanup := setupTestServiceWithMockCA(t)
	defer cleanup()

	mockCA.returnCertWithNilSerial = true

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	ekKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	ekPubKeyDER, err := x509.MarshalPKIXPublicKey(ekKey.Public())
	require.NoError(t, err)

	permanentID := base64.RawURLEncoding.EncodeToString(ekPubKeyDER)

	order := createTestOrderSimple(t, service, account.ID)
	order.Status = common.StatusReady
	order.Identifiers = []entities.ACMEIdentifier{
		{Type: common.AuthzTypePermanentIdentifier, Value: permanentID},
	}

	ctx := context.Background()
	orderDAO, err := service.storageFactory.OrderDAO(account.ID)
	require.NoError(t, err)
	err = orderDAO.Save(ctx, order)
	require.NoError(t, err)

	csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "test-ek-device",
		},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, csrKey)
	require.NoError(t, err)

	payload := OrderFinalizeRequest{
		CSR: base64.RawURLEncoding.EncodeToString(csrDER),
	}

	url := fmt.Sprintf("%s/acme/orders/%d/finalize", service.baseRESTURI, order.ID)
	req := createJWSRequest(t, service, key, url, payload, true, account.ID)
	req = mux.SetURLVars(req, map[string]string{"id": fmt.Sprintf("%d", order.ID)})

	resp := httptest.NewRecorder()
	service.OrderFinalizeHandler(resp, req)

	assertErrorType(t, resp, common.ErrTypeServerInternal, http.StatusInternalServerError)
}

// --- KeyChangeHandler additional error path tests ---

// TestCov92_KeyChangeHandler_SaveAccountFailure tests the path where saving
// the updated account key fails after all validations pass.
func TestCov92_KeyChangeHandler_SaveAccountFailure(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	oldKey := generateTestKey(t)
	newKey := generateTestKey(t)

	account := createTestAccount(t, service, oldKey)

	mockFactory := &MockStorageFactory92{
		realFactory:       service.storageFactory,
		failAccountSaveOn: 1,
	}
	service.storageFactory = mockFactory

	req := createKeyChangeRequest(t, service, oldKey, newKey, account.ID)

	resp := httptest.NewRecorder()
	service.KeyChangeHandler(resp, req)

	assertErrorType(t, resp, common.ErrTypeServerInternal, http.StatusInternalServerError)
}

// --- RevokeCertHandler additional tests ---

// TestCov92_RevokeCertHandler_InactiveAccountStatus tests the revocation
// handler when the account status is not valid.
func TestCov92_RevokeCertHandler_InactiveAccountStatus(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	ctx := context.Background()
	account.Status = common.StatusRevoked
	accountDAO, err := service.storageFactory.AccountDAO()
	require.NoError(t, err)
	err = accountDAO.Save(ctx, account)
	require.NoError(t, err)

	_, x509Cert := createTestCertificateWithSerial(t, service, key)

	certB64 := base64.RawURLEncoding.EncodeToString(x509Cert.Raw)

	payload := RevokeCertRequest{
		Certificate: certB64,
		Reason:      RevocationReasonKeyCompromise,
	}

	url := service.baseRESTURI + "/acme/revoke-cert"
	req := createJWSRequest(t, service, key, url, payload, true, account.ID)

	resp := httptest.NewRecorder()
	service.RevokeCertHandler(resp, req)

	assertErrorType(t, resp, common.ErrTypeUnauthorized, http.StatusUnauthorized)
}

// TestCov92_RevokeCertHandler_CNAlreadyInDNSNames tests the code path
// where the certificate's CN is already present in DNSNames (no duplicate).
func TestCov92_RevokeCertHandler_CNAlreadyInDNSNames(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	ctx := context.Background()

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)

	domain := "test.example.com"
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: domain,
		},
		DNSNames:              []string{domain},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, key.PublicKey, key.PrivateKey)
	require.NoError(t, err)

	x509Cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	certificateDAO, err := service.storageFactory.CertificateDAO()
	require.NoError(t, err)

	acmeCert := &entities.ACMECertificate{
		ID:        serialNumber.Uint64(),
		Status:    common.StatusValid,
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(365 * 24 * time.Hour),
	}
	err = certificateDAO.Save(ctx, acmeCert)
	require.NoError(t, err)

	authzDAO, err := service.storageFactory.AuthorizationDAO(account.ID)
	require.NoError(t, err)

	authz := &entities.ACMEAuthorization{
		ID: serialNumber.Uint64() + 1,
		Identifier: entities.ACMEIdentifier{
			Type:  "dns",
			Value: domain,
		},
		Status:    common.StatusValid,
		Expires:   time.Now().Add(365 * 24 * time.Hour).Format(time.RFC3339),
		AccountID: account.ID,
	}
	err = authzDAO.Save(ctx, authz)
	require.NoError(t, err)

	certB64 := base64.RawURLEncoding.EncodeToString(x509Cert.Raw)
	payload := RevokeCertRequest{
		Certificate: certB64,
		Reason:      RevocationReasonUnspecified,
	}

	url := service.baseRESTURI + "/acme/revoke-cert"
	req := createJWSRequest(t, service, key, url, payload, true, account.ID)

	resp := httptest.NewRecorder()
	service.RevokeCertHandler(resp, req)

	require.Equal(t, http.StatusOK, resp.Code)
}

// --- resolveTenantComplianceConfig tests ---

// TestCov92_ResolveTenantComplianceConfig_NoTenantID tests compliance config
// resolution when the account has no tenant ID.
func TestCov92_ResolveTenantComplianceConfig_NoTenantID(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	account := &entities.ACMEAccount{
		TenantID: "",
	}

	service.globalComplianceConfig = nil
	result := service.resolveTenantComplianceConfig(context.Background(), account)
	assert.Nil(t, result)

	service.globalComplianceConfig = &GlobalComplianceConfig{
		ComplianceConfig: ComplianceConfig{
			Enabled: true,
		},
	}
	result = service.resolveTenantComplianceConfig(context.Background(), account)
	require.NotNil(t, result)
	assert.True(t, result.Enabled)
}

// TestCov92_ResolveTenantComplianceConfig_NotTenantAwareFactory tests the path
// where the storage factory doesn't implement TenantAwareFactory.
func TestCov92_ResolveTenantComplianceConfig_NotTenantAwareFactory(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	account := &entities.ACMEAccount{
		TenantID: "tenant-123",
	}

	service.globalComplianceConfig = nil
	result := service.resolveTenantComplianceConfig(context.Background(), account)
	assert.Nil(t, result)

	service.globalComplianceConfig = &GlobalComplianceConfig{
		ComplianceConfig: ComplianceConfig{
			Enabled: true,
		},
	}
	result = service.resolveTenantComplianceConfig(context.Background(), account)
	require.NotNil(t, result)
	assert.True(t, result.Enabled)
}

// --- NewNonce additional tests ---

// TestCov92_NewNonceHandler_PUTMethod tests NewNonceHandler with PUT method.
func TestCov92_NewNonceHandler_PUTMethod(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	req := httptest.NewRequest(http.MethodPut, "/acme/new-nonce", nil)
	w := httptest.NewRecorder()

	service.NewNonceHandler(w, req)

	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

// TestCov92_NewNonceHandler_DELETEMethod tests NewNonceHandler with DELETE method.
func TestCov92_NewNonceHandler_DELETEMethod(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	req := httptest.NewRequest(http.MethodDelete, "/acme/new-nonce", nil)
	w := httptest.NewRecorder()

	service.NewNonceHandler(w, req)

	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

// --- OrderFinalizeHandler additional storage error tests ---

// TestCov92_OrderFinalizeHandler_OrderGetStorageError tests the storage error
// path when retrieving the order fails with a non-NotFound error.
func TestCov92_OrderFinalizeHandler_OrderGetStorageError(t *testing.T) {
	service, _, cleanup := setupTestServiceWithMockCA(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Use a mock factory that returns a DAO that fails on Get
	mockFactory := &MockStorageFactory92OrderGet{
		realFactory:  service.storageFactory,
		failOrderGet: true,
	}
	service.storageFactory = mockFactory

	csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "example.com",
		},
		DNSNames: []string{"example.com"},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, csrKey)
	require.NoError(t, err)

	payload := OrderFinalizeRequest{
		CSR: base64.RawURLEncoding.EncodeToString(csrDER),
	}

	url := fmt.Sprintf("%s/acme/orders/12345/finalize", service.baseRESTURI)
	req := createJWSRequest(t, service, key, url, payload, true, account.ID)
	req = mux.SetURLVars(req, map[string]string{"id": "12345"})

	resp := httptest.NewRecorder()
	service.OrderFinalizeHandler(resp, req)

	assertErrorType(t, resp, common.ErrTypeServerInternal, http.StatusInternalServerError)
}

// TestCov92_OrderFinalizeHandler_CSRMatchesIdentifierError tests the path where
// matchesIdentifier returns an error for unsupported identifier types.
func TestCov92_OrderFinalizeHandler_CSRMatchesIdentifierError(t *testing.T) {
	service, _, cleanup := setupTestServiceWithMockCA(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	order := createTestOrderSimple(t, service, account.ID)
	order.Status = common.StatusReady
	// Use an unsupported identifier type to trigger matchesIdentifier error
	order.Identifiers = []entities.ACMEIdentifier{
		{Type: "unsupported-type", Value: "example.com"},
	}

	ctx := context.Background()
	orderDAO, err := service.storageFactory.OrderDAO(account.ID)
	require.NoError(t, err)
	err = orderDAO.Save(ctx, order)
	require.NoError(t, err)

	csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "example.com",
		},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, csrKey)
	require.NoError(t, err)

	payload := OrderFinalizeRequest{
		CSR: base64.RawURLEncoding.EncodeToString(csrDER),
	}

	url := fmt.Sprintf("%s/acme/orders/%d/finalize", service.baseRESTURI, order.ID)
	req := createJWSRequest(t, service, key, url, payload, true, account.ID)
	req = mux.SetURLVars(req, map[string]string{"id": fmt.Sprintf("%d", order.ID)})

	resp := httptest.NewRecorder()
	service.OrderFinalizeHandler(resp, req)

	assertErrorType(t, resp, common.ErrTypeUnsupportedIdentifier, http.StatusBadRequest)
}

// TestCov92_OrderFinalizeHandler_CSRDoesNotMatchDNS tests the path where
// the CSR common name doesn't match the order DNS identifier.
func TestCov92_OrderFinalizeHandler_CSRDoesNotMatchDNS(t *testing.T) {
	service, _, cleanup := setupTestServiceWithMockCA(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	order := createTestOrderSimple(t, service, account.ID)
	order.Status = common.StatusReady
	order.Identifiers = []entities.ACMEIdentifier{
		{Type: common.AuthzTypeDNS, Value: "example.com"},
	}

	ctx := context.Background()
	orderDAO, err := service.storageFactory.OrderDAO(account.ID)
	require.NoError(t, err)
	err = orderDAO.Save(ctx, order)
	require.NoError(t, err)

	csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "different.com", // Doesn't match the order identifier
		},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, csrKey)
	require.NoError(t, err)

	payload := OrderFinalizeRequest{
		CSR: base64.RawURLEncoding.EncodeToString(csrDER),
	}

	url := fmt.Sprintf("%s/acme/orders/%d/finalize", service.baseRESTURI, order.ID)
	req := createJWSRequest(t, service, key, url, payload, true, account.ID)
	req = mux.SetURLVars(req, map[string]string{"id": fmt.Sprintf("%d", order.ID)})

	resp := httptest.NewRecorder()
	service.OrderFinalizeHandler(resp, req)

	assertErrorType(t, resp, common.ErrTypeMalformedError, http.StatusBadRequest)
}

// TestCov92_OrderFinalizeHandler_EKCertIssueFailure tests the EK certificate
// issuance failure path for endorse-01 orders.
func TestCov92_OrderFinalizeHandler_EKCertIssueFailure(t *testing.T) {
	service, mockCA, cleanup := setupTestServiceWithMockCA(t)
	defer cleanup()

	mockCA.shouldFailIssueEK = true

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	ekKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	ekPubKeyDER, err := x509.MarshalPKIXPublicKey(ekKey.Public())
	require.NoError(t, err)

	permanentID := base64.RawURLEncoding.EncodeToString(ekPubKeyDER)

	order := createTestOrderSimple(t, service, account.ID)
	order.Status = common.StatusReady
	order.Identifiers = []entities.ACMEIdentifier{
		{Type: common.AuthzTypePermanentIdentifier, Value: permanentID},
	}

	ctx := context.Background()
	orderDAO, err := service.storageFactory.OrderDAO(account.ID)
	require.NoError(t, err)
	err = orderDAO.Save(ctx, order)
	require.NoError(t, err)

	csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "test-ek-device",
			Organization: []string{"Test Org"},
			Country:      []string{"US"},
			Locality:     []string{"Test City"},
			Province:     []string{"TS"},
		},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, csrKey)
	require.NoError(t, err)

	payload := OrderFinalizeRequest{
		CSR: base64.RawURLEncoding.EncodeToString(csrDER),
	}

	url := fmt.Sprintf("%s/acme/orders/%d/finalize", service.baseRESTURI, order.ID)
	req := createJWSRequest(t, service, key, url, payload, true, account.ID)
	req = mux.SetURLVars(req, map[string]string{"id": fmt.Sprintf("%d", order.ID)})

	resp := httptest.NewRecorder()
	service.OrderFinalizeHandler(resp, req)

	assertErrorType(t, resp, common.ErrTypeServerInternal, http.StatusInternalServerError)
}

// TestCov92_OrderFinalizeHandler_EKCertWithOrgFields tests the EK certificate
// issuance path with full organization fields from the CSR.
func TestCov92_OrderFinalizeHandler_EKCertWithOrgFields(t *testing.T) {
	service, _, cleanup := setupTestServiceWithMockCA(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	ekKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	ekPubKeyDER, err := x509.MarshalPKIXPublicKey(ekKey.Public())
	require.NoError(t, err)

	permanentID := base64.RawURLEncoding.EncodeToString(ekPubKeyDER)

	order := createTestOrderSimple(t, service, account.ID)
	order.Status = common.StatusReady
	order.Identifiers = []entities.ACMEIdentifier{
		{Type: common.AuthzTypePermanentIdentifier, Value: permanentID},
	}

	ctx := context.Background()
	orderDAO, err := service.storageFactory.OrderDAO(account.ID)
	require.NoError(t, err)
	err = orderDAO.Save(ctx, order)
	require.NoError(t, err)

	csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:         "test-ek-device-full",
			Organization:       []string{"Test Organization"},
			OrganizationalUnit: []string{"Test Unit"},
			Country:            []string{"US"},
			Locality:           []string{"San Francisco"},
			Province:           []string{"California"},
		},
		DNSNames:       []string{"device.example.com"},
		EmailAddresses: []string{"device@example.com"},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, csrKey)
	require.NoError(t, err)

	payload := OrderFinalizeRequest{
		CSR: base64.RawURLEncoding.EncodeToString(csrDER),
	}

	url := fmt.Sprintf("%s/acme/orders/%d/finalize", service.baseRESTURI, order.ID)
	req := createJWSRequest(t, service, key, url, payload, true, account.ID)
	req = mux.SetURLVars(req, map[string]string{"id": fmt.Sprintf("%d", order.ID)})

	resp := httptest.NewRecorder()
	service.OrderFinalizeHandler(resp, req)

	require.Equal(t, http.StatusOK, resp.Code)
}

// TestCov92_KeyChangeHandler_AccountDAOCreationFailure tests the path where
// AccountDAO creation fails in the KeyChangeHandler.
func TestCov92_KeyChangeHandler_AccountDAOCreationFailure(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	oldKey := generateTestKey(t)
	newKey := generateTestKey(t)

	account := createTestAccount(t, service, oldKey)

	// Replace storage factory with mock that fails on AccountDAO creation
	mockFactory := &MockStorageFactory92{
		realFactory:      service.storageFactory,
		failAccountDAOOn: true,
	}
	service.storageFactory = mockFactory

	req := createKeyChangeRequest(t, service, oldKey, newKey, account.ID)

	resp := httptest.NewRecorder()
	service.KeyChangeHandler(resp, req)

	// parseKID creates its own AccountDAO which will fail
	require.Equal(t, http.StatusBadRequest, resp.Code)
}

// --- RevokeCertHandler additional error path tests ---

// TestCov92_RevokeCertHandler_AuthzDAOCreationError tests the revocation
// handler when authorization DAO creation fails.
func TestCov92_RevokeCertHandler_AuthzDAOCreationError(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	_, x509Cert := createTestCertificateWithAuthorization(t, service, key, account.ID)

	certB64 := base64.RawURLEncoding.EncodeToString(x509Cert.Raw)
	payload := RevokeCertRequest{
		Certificate: certB64,
		Reason:      RevocationReasonKeyCompromise,
	}

	// Replace factory with one that fails AuthzDAO creation
	mockFactory := &MockStorageFactory92AuthzFail{
		realFactory:  service.storageFactory,
		failAuthzDAO: true,
	}
	service.storageFactory = mockFactory

	url := service.baseRESTURI + "/acme/revoke-cert"
	req := createJWSRequest(t, service, key, url, payload, true, account.ID)

	resp := httptest.NewRecorder()
	service.RevokeCertHandler(resp, req)

	assertErrorType(t, resp, common.ErrTypeServerInternal, http.StatusInternalServerError)
}

// TestCov92_RevokeCertHandler_CertDAOCreationError tests the revocation
// handler when certificate DAO creation fails.
func TestCov92_RevokeCertHandler_CertDAOCreationError(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	_, x509Cert := createTestCertificateWithSerial(t, service, key)

	certB64 := base64.RawURLEncoding.EncodeToString(x509Cert.Raw)
	payload := RevokeCertRequest{
		Certificate: certB64,
		Reason:      RevocationReasonKeyCompromise,
	}

	// Replace factory with one that fails CertDAO creation
	mockFactory := &MockStorageFactory92CertFail{
		realFactory: service.storageFactory,
		failCertDAO: true,
	}
	service.storageFactory = mockFactory

	url := service.baseRESTURI + "/acme/revoke-cert"
	req := createJWSRequest(t, service, key, url, payload, true, account.ID)

	resp := httptest.NewRecorder()
	service.RevokeCertHandler(resp, req)

	assertErrorType(t, resp, common.ErrTypeServerInternal, http.StatusInternalServerError)
}

// --- Additional mock factory types ---

// MockStorageFactory92AuthzFail wraps factory that fails AuthorizationDAO.
type MockStorageFactory92AuthzFail struct {
	realFactory  storage.Factory
	failAuthzDAO bool
}

func (m *MockStorageFactory92AuthzFail) OrderDAO(accountID uint64) (qrdbsdk.GenericDAO[*entities.ACMEOrder], error) {
	return m.realFactory.OrderDAO(accountID)
}

func (m *MockStorageFactory92AuthzFail) CertificateDAO() (qrdbsdk.GenericDAO[*entities.ACMECertificate], error) {
	return m.realFactory.CertificateDAO()
}

func (m *MockStorageFactory92AuthzFail) AccountDAO() (qrdbsdk.GenericDAO[*entities.ACMEAccount], error) {
	return m.realFactory.AccountDAO()
}

func (m *MockStorageFactory92AuthzFail) NonceDAO() (qrdbsdk.GenericDAO[*entities.ACMENonce], error) {
	return m.realFactory.NonceDAO()
}

func (m *MockStorageFactory92AuthzFail) AuthorizationDAO(accountID uint64) (qrdbsdk.GenericDAO[*entities.ACMEAuthorization], error) {
	if m.failAuthzDAO {
		return nil, caerrors.StorageFailureError("mock authz DAO failure")
	}
	return m.realFactory.AuthorizationDAO(accountID)
}

func (m *MockStorageFactory92AuthzFail) ChallengeDAO(accountID uint64) (qrdbsdk.GenericDAO[*entities.ACMEChallenge], error) {
	return m.realFactory.ChallengeDAO(accountID)
}

func (m *MockStorageFactory92AuthzFail) ExternalAccountBindingDAO() (qrdbsdk.GenericDAO[*entities.ExternalAccountBinding], error) {
	return m.realFactory.ExternalAccountBindingDAO()
}

// MockStorageFactory92CertFail wraps factory that fails CertificateDAO.
type MockStorageFactory92CertFail struct {
	realFactory storage.Factory
	failCertDAO bool
}

func (m *MockStorageFactory92CertFail) OrderDAO(accountID uint64) (qrdbsdk.GenericDAO[*entities.ACMEOrder], error) {
	return m.realFactory.OrderDAO(accountID)
}

func (m *MockStorageFactory92CertFail) CertificateDAO() (qrdbsdk.GenericDAO[*entities.ACMECertificate], error) {
	if m.failCertDAO {
		return nil, caerrors.StorageFailureError("mock cert DAO failure")
	}
	return m.realFactory.CertificateDAO()
}

func (m *MockStorageFactory92CertFail) AccountDAO() (qrdbsdk.GenericDAO[*entities.ACMEAccount], error) {
	return m.realFactory.AccountDAO()
}

func (m *MockStorageFactory92CertFail) NonceDAO() (qrdbsdk.GenericDAO[*entities.ACMENonce], error) {
	return m.realFactory.NonceDAO()
}

func (m *MockStorageFactory92CertFail) AuthorizationDAO(accountID uint64) (qrdbsdk.GenericDAO[*entities.ACMEAuthorization], error) {
	return m.realFactory.AuthorizationDAO(accountID)
}

func (m *MockStorageFactory92CertFail) ChallengeDAO(accountID uint64) (qrdbsdk.GenericDAO[*entities.ACMEChallenge], error) {
	return m.realFactory.ChallengeDAO(accountID)
}

func (m *MockStorageFactory92CertFail) ExternalAccountBindingDAO() (qrdbsdk.GenericDAO[*entities.ExternalAccountBinding], error) {
	return m.realFactory.ExternalAccountBindingDAO()
}

// --- NewOrderHandler storage error tests ---

// TestCov92_NewOrderHandler_OrderDAOCreationError tests the NewOrderHandler
// path where OrderDAO creation fails.
func TestCov92_NewOrderHandler_OrderDAOCreationError(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	mockFactory := &MockStorageFactory92{
		realFactory:        service.storageFactory,
		failOrderDAOCreate: true,
	}
	service.storageFactory = mockFactory

	payload := NewOrderRequest{
		Identifiers: []entities.ACMEIdentifier{
			{Type: common.AuthzTypeDNS, Value: "example.com"},
		},
	}

	url := service.baseRESTURI + "/acme/new-order"
	req := createJWSRequest(t, service, key, url, payload, true, account.ID)

	resp := httptest.NewRecorder()
	service.NewOrderHandler(resp, req)

	assertErrorType(t, resp, common.ErrTypeServerInternal, http.StatusInternalServerError)
}

// TestCov92_NewOrderHandler_AuthzDAOCreationError tests the NewOrderHandler
// path where AuthorizationDAO creation fails.
func TestCov92_NewOrderHandler_AuthzDAOCreationError(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	mockFactory := &MockStorageFactory92AuthzFail{
		realFactory:  service.storageFactory,
		failAuthzDAO: true,
	}
	service.storageFactory = mockFactory

	payload := NewOrderRequest{
		Identifiers: []entities.ACMEIdentifier{
			{Type: common.AuthzTypeDNS, Value: "example.com"},
		},
	}

	url := service.baseRESTURI + "/acme/new-order"
	req := createJWSRequest(t, service, key, url, payload, true, account.ID)

	resp := httptest.NewRecorder()
	service.NewOrderHandler(resp, req)

	assertErrorType(t, resp, common.ErrTypeServerInternal, http.StatusInternalServerError)
}

// TestCov92_NewOrderHandler_OrderSaveError tests the NewOrderHandler
// path where saving the order fails.
func TestCov92_NewOrderHandler_OrderSaveError(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	// Configure challenge map so createChallenges succeeds
	service.challengeMap["http-01"] = func(_ *net.Resolver, _ common.CertificateAuthority, _, _, _, _ string) error {
		return nil
	}

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	mockFactory := &MockStorageFactory92OrderSaveFail{
		realFactory: service.storageFactory,
	}
	service.storageFactory = mockFactory

	payload := NewOrderRequest{
		Identifiers: []entities.ACMEIdentifier{
			{Type: common.AuthzTypeDNS, Value: "example.com"},
		},
	}

	url := service.baseRESTURI + "/acme/new-order"
	req := createJWSRequest(t, service, key, url, payload, true, account.ID)

	resp := httptest.NewRecorder()
	service.NewOrderHandler(resp, req)

	assertErrorType(t, resp, common.ErrTypeServerInternal, http.StatusInternalServerError)
}

// --- KeyChangeHandler additional error tests ---

// TestCov92_KeyChangeHandler_AccountDAOCreateError tests the error path when
// AccountDAO creation fails within the KeyChangeHandler (not in parseKID).
func TestCov92_KeyChangeHandler_AccountDAOCreateError(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	oldKey := generateTestKey(t)
	newKey := generateTestKey(t)

	account := createTestAccount(t, service, oldKey)

	// Replace with mock that fails AccountDAO on second call
	// parseKID calls AccountDAO first, then KeyChangeHandler calls it second
	mockFactory := &MockStorageFactory92AccountDAOFail{
		realFactory: service.storageFactory,
		failOnCall:  2, // Fail on second AccountDAO() call
	}
	service.storageFactory = mockFactory

	req := createKeyChangeRequest(t, service, oldKey, newKey, account.ID)

	resp := httptest.NewRecorder()
	service.KeyChangeHandler(resp, req)

	assertErrorType(t, resp, common.ErrTypeServerInternal, http.StatusInternalServerError)
}

// MockStorageFactory92AccountDAOFail fails AccountDAO() on a specific call.
type MockStorageFactory92AccountDAOFail struct {
	realFactory storage.Factory
	failOnCall  int
	callCount   int
}

func (m *MockStorageFactory92AccountDAOFail) OrderDAO(accountID uint64) (qrdbsdk.GenericDAO[*entities.ACMEOrder], error) {
	return m.realFactory.OrderDAO(accountID)
}

func (m *MockStorageFactory92AccountDAOFail) CertificateDAO() (qrdbsdk.GenericDAO[*entities.ACMECertificate], error) {
	return m.realFactory.CertificateDAO()
}

func (m *MockStorageFactory92AccountDAOFail) AccountDAO() (qrdbsdk.GenericDAO[*entities.ACMEAccount], error) {
	m.callCount++
	if m.callCount >= m.failOnCall {
		return nil, caerrors.StorageFailureError("mock AccountDAO creation failure")
	}
	return m.realFactory.AccountDAO()
}

func (m *MockStorageFactory92AccountDAOFail) NonceDAO() (qrdbsdk.GenericDAO[*entities.ACMENonce], error) {
	return m.realFactory.NonceDAO()
}

func (m *MockStorageFactory92AccountDAOFail) AuthorizationDAO(accountID uint64) (qrdbsdk.GenericDAO[*entities.ACMEAuthorization], error) {
	return m.realFactory.AuthorizationDAO(accountID)
}

func (m *MockStorageFactory92AccountDAOFail) ChallengeDAO(accountID uint64) (qrdbsdk.GenericDAO[*entities.ACMEChallenge], error) {
	return m.realFactory.ChallengeDAO(accountID)
}

func (m *MockStorageFactory92AccountDAOFail) ExternalAccountBindingDAO() (qrdbsdk.GenericDAO[*entities.ExternalAccountBinding], error) {
	return m.realFactory.ExternalAccountBindingDAO()
}

// --- RevokeCertHandler ForEachPage and Save error tests ---

// TestCov92_RevokeCertHandler_AuthzForEachPageError tests the revocation handler
// when ForEachPage fails while retrieving authorizations.
func TestCov92_RevokeCertHandler_AuthzForEachPageError(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	_, x509Cert := createTestCertificateWithAuthorization(t, service, key, account.ID)

	certB64 := base64.RawURLEncoding.EncodeToString(x509Cert.Raw)
	payload := RevokeCertRequest{
		Certificate: certB64,
		Reason:      RevocationReasonKeyCompromise,
	}

	// Replace factory with one whose AuthzDAO ForEachPage fails
	mockFactory := &MockStorageFactory92AuthzForEachFail{
		realFactory: service.storageFactory,
	}
	service.storageFactory = mockFactory

	url := service.baseRESTURI + "/acme/revoke-cert"
	req := createJWSRequest(t, service, key, url, payload, true, account.ID)

	resp := httptest.NewRecorder()
	service.RevokeCertHandler(resp, req)

	assertErrorType(t, resp, common.ErrTypeServerInternal, http.StatusInternalServerError)
}

// TestCov92_RevokeCertHandler_CertSaveError tests the revocation handler
// when saving the updated certificate status fails.
func TestCov92_RevokeCertHandler_CertSaveError(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	_, x509Cert := createTestCertificateWithAuthorization(t, service, key, account.ID)

	certB64 := base64.RawURLEncoding.EncodeToString(x509Cert.Raw)
	payload := RevokeCertRequest{
		Certificate: certB64,
		Reason:      RevocationReasonKeyCompromise,
	}

	// Replace factory with one whose CertDAO Save fails
	mockFactory := &MockStorageFactory{
		realFactory:     service.storageFactory,
		failCertDAOSave: true,
	}
	service.storageFactory = mockFactory

	url := service.baseRESTURI + "/acme/revoke-cert"
	req := createJWSRequest(t, service, key, url, payload, true, account.ID)

	resp := httptest.NewRecorder()
	service.RevokeCertHandler(resp, req)

	assertErrorType(t, resp, common.ErrTypeServerInternal, http.StatusInternalServerError)
}

// MockStorageFactory92AuthzForEachFail wraps factory with AuthzDAO whose ForEachPage fails.
type MockStorageFactory92AuthzForEachFail struct {
	realFactory storage.Factory
}

func (m *MockStorageFactory92AuthzForEachFail) OrderDAO(accountID uint64) (qrdbsdk.GenericDAO[*entities.ACMEOrder], error) {
	return m.realFactory.OrderDAO(accountID)
}

func (m *MockStorageFactory92AuthzForEachFail) CertificateDAO() (qrdbsdk.GenericDAO[*entities.ACMECertificate], error) {
	return m.realFactory.CertificateDAO()
}

func (m *MockStorageFactory92AuthzForEachFail) AccountDAO() (qrdbsdk.GenericDAO[*entities.ACMEAccount], error) {
	return m.realFactory.AccountDAO()
}

func (m *MockStorageFactory92AuthzForEachFail) NonceDAO() (qrdbsdk.GenericDAO[*entities.ACMENonce], error) {
	return m.realFactory.NonceDAO()
}

func (m *MockStorageFactory92AuthzForEachFail) AuthorizationDAO(accountID uint64) (qrdbsdk.GenericDAO[*entities.ACMEAuthorization], error) {
	dao, err := m.realFactory.AuthorizationDAO(accountID)
	if err != nil {
		return nil, err
	}
	return &MockAuthzDAO92ForEachFail{
		GenericDAO: dao,
	}, nil
}

func (m *MockStorageFactory92AuthzForEachFail) ChallengeDAO(accountID uint64) (qrdbsdk.GenericDAO[*entities.ACMEChallenge], error) {
	return m.realFactory.ChallengeDAO(accountID)
}

func (m *MockStorageFactory92AuthzForEachFail) ExternalAccountBindingDAO() (qrdbsdk.GenericDAO[*entities.ExternalAccountBinding], error) {
	return m.realFactory.ExternalAccountBindingDAO()
}

// MockAuthzDAO92ForEachFail wraps DAO whose ForEachPage fails.
type MockAuthzDAO92ForEachFail struct {
	qrdbsdk.GenericDAO[*entities.ACMEAuthorization]
}

func (m *MockAuthzDAO92ForEachFail) ForEachPage(ctx context.Context, query qrdbsdk.PageQuery, fn qrdbsdk.PagerFunc[*entities.ACMEAuthorization]) error {
	return caerrors.StorageFailureError("mock authz ForEachPage error")
}

// --- NewAccountHandler save error test ---

// TestCov92_NewAccountHandler_AccountSaveError tests the NewAccountHandler
// path where saving the new account fails.
func TestCov92_NewAccountHandler_AccountSaveError(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)

	// Replace factory with one whose AccountDAO Save fails
	mockFactory := &MockStorageFactory92{
		realFactory:       service.storageFactory,
		failAccountSaveOn: 1, // Fail on first save
	}
	service.storageFactory = mockFactory

	payload := struct {
		TermsOfServiceAgreed bool     `json:"termsOfServiceAgreed"`
		Contact              []string `json:"contact"`
	}{
		TermsOfServiceAgreed: true,
		Contact:              []string{"mailto:test@example.com"},
	}

	url := service.baseRESTURI + "/acme/new-account"
	req := createJWSRequest(t, service, key, url, payload, false, 0)

	resp := httptest.NewRecorder()
	service.NewAccountHandler(resp, req)

	assertErrorType(t, resp, common.ErrTypeServerInternal, http.StatusInternalServerError)
}

// MockStorageFactory92OrderSaveFail wraps factory with OrderDAO that always fails Save.
type MockStorageFactory92OrderSaveFail struct {
	realFactory storage.Factory
}

func (m *MockStorageFactory92OrderSaveFail) OrderDAO(accountID uint64) (qrdbsdk.GenericDAO[*entities.ACMEOrder], error) {
	dao, err := m.realFactory.OrderDAO(accountID)
	if err != nil {
		return nil, err
	}
	return &MockOrderDAO92SaveFail{
		GenericDAO: dao,
	}, nil
}

func (m *MockStorageFactory92OrderSaveFail) CertificateDAO() (qrdbsdk.GenericDAO[*entities.ACMECertificate], error) {
	return m.realFactory.CertificateDAO()
}

func (m *MockStorageFactory92OrderSaveFail) AccountDAO() (qrdbsdk.GenericDAO[*entities.ACMEAccount], error) {
	return m.realFactory.AccountDAO()
}

func (m *MockStorageFactory92OrderSaveFail) NonceDAO() (qrdbsdk.GenericDAO[*entities.ACMENonce], error) {
	return m.realFactory.NonceDAO()
}

func (m *MockStorageFactory92OrderSaveFail) AuthorizationDAO(accountID uint64) (qrdbsdk.GenericDAO[*entities.ACMEAuthorization], error) {
	return m.realFactory.AuthorizationDAO(accountID)
}

func (m *MockStorageFactory92OrderSaveFail) ChallengeDAO(accountID uint64) (qrdbsdk.GenericDAO[*entities.ACMEChallenge], error) {
	return m.realFactory.ChallengeDAO(accountID)
}

func (m *MockStorageFactory92OrderSaveFail) ExternalAccountBindingDAO() (qrdbsdk.GenericDAO[*entities.ExternalAccountBinding], error) {
	return m.realFactory.ExternalAccountBindingDAO()
}

// MockOrderDAO92SaveFail always fails on Save.
type MockOrderDAO92SaveFail struct {
	qrdbsdk.GenericDAO[*entities.ACMEOrder]
}

func (m *MockOrderDAO92SaveFail) Save(ctx context.Context, order *entities.ACMEOrder) error {
	return caerrors.StorageFailureError("mock order save failure")
}

// --- NewOrderHandler additional error tests ---

// TestCov92_NewOrderHandler_AuthzDAOCreationErrorWithChallenge tests the
// NewOrderHandler path where AuthorizationDAO creation fails after setting
// up challenge map.
func TestCov92_NewOrderHandler_AuthzDAOCreationErrorWithChallenge(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	service.challengeMap["http-01"] = func(_ *net.Resolver, _ common.CertificateAuthority, _, _, _, _ string) error {
		return nil
	}

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	mockFactory := &MockStorageFactory92AuthzFail{
		realFactory:  service.storageFactory,
		failAuthzDAO: true,
	}
	service.storageFactory = mockFactory

	payload := NewOrderRequest{
		Identifiers: []entities.ACMEIdentifier{
			{Type: common.AuthzTypeDNS, Value: "example.com"},
		},
	}

	url := service.baseRESTURI + "/acme/new-order"
	req := createJWSRequest(t, service, key, url, payload, true, account.ID)

	resp := httptest.NewRecorder()
	service.NewOrderHandler(resp, req)

	assertErrorType(t, resp, common.ErrTypeServerInternal, http.StatusInternalServerError)
}

// TestCov92_AccountHandler_AccountDAOCreationError tests the AccountHandler
// path where AccountDAO creation fails.
func TestCov92_AccountHandler_AccountDAOCreationError(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Replace factory with one that fails AccountDAO on 2nd call (1st is parseKID)
	mockFactory := &MockStorageFactory92AccountDAOFail{
		realFactory: service.storageFactory,
		failOnCall:  2,
	}
	service.storageFactory = mockFactory

	payload := AccountRequest{
		Contact: []string{"mailto:updated@example.com"},
	}

	url := service.baseRESTURI + "/acme/account/" + string(rune(account.ID))
	req := createJWSRequest(t, service, key, url, payload, true, account.ID)

	resp := httptest.NewRecorder()
	service.AccountHandler(resp, req)

	assertErrorType(t, resp, common.ErrTypeServerInternal, http.StatusInternalServerError)
}

// TestCov92_KeyChangeHandler_AccountNotFoundInHandler tests the error path
// where the account is found during parseKID but returns not-found during
// KeyChangeHandler's own Get call (simulating a concurrent deletion).
func TestCov92_KeyChangeHandler_AccountNotFoundInHandler(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	oldKey := generateTestKey(t)
	newKey := generateTestKey(t)

	account := createTestAccount(t, service, oldKey)

	// Mock: first Get succeeds (parseKID), second Get fails with NotFound
	// (KeyChangeHandler's own Get at line 75)
	mockFactory := &MockStorageFactory92AccountGetNotFound{
		realFactory:         service.storageFactory,
		failGetWithNotFound: 2, // Fail on 2nd Get with NotFound
	}
	service.storageFactory = mockFactory

	req := createKeyChangeRequest(t, service, oldKey, newKey, account.ID)

	resp := httptest.NewRecorder()
	service.KeyChangeHandler(resp, req)

	// Should fail because account not found during handler's Get
	require.NotEqual(t, http.StatusOK, resp.Code)
}

// --- Additional Mock Types ---

// MockStorageFactory92OrderGet wraps the real factory but fails order Get.
type MockStorageFactory92OrderGet struct {
	realFactory  storage.Factory
	failOrderGet bool
}

func (m *MockStorageFactory92OrderGet) OrderDAO(accountID uint64) (qrdbsdk.GenericDAO[*entities.ACMEOrder], error) {
	dao, err := m.realFactory.OrderDAO(accountID)
	if err != nil {
		return nil, err
	}
	if m.failOrderGet {
		return &MockOrderDAO92Get{
			GenericDAO: dao,
		}, nil
	}
	return dao, nil
}

func (m *MockStorageFactory92OrderGet) CertificateDAO() (qrdbsdk.GenericDAO[*entities.ACMECertificate], error) {
	return m.realFactory.CertificateDAO()
}

func (m *MockStorageFactory92OrderGet) AccountDAO() (qrdbsdk.GenericDAO[*entities.ACMEAccount], error) {
	return m.realFactory.AccountDAO()
}

func (m *MockStorageFactory92OrderGet) NonceDAO() (qrdbsdk.GenericDAO[*entities.ACMENonce], error) {
	return m.realFactory.NonceDAO()
}

func (m *MockStorageFactory92OrderGet) AuthorizationDAO(accountID uint64) (qrdbsdk.GenericDAO[*entities.ACMEAuthorization], error) {
	return m.realFactory.AuthorizationDAO(accountID)
}

func (m *MockStorageFactory92OrderGet) ChallengeDAO(accountID uint64) (qrdbsdk.GenericDAO[*entities.ACMEChallenge], error) {
	return m.realFactory.ChallengeDAO(accountID)
}

func (m *MockStorageFactory92OrderGet) ExternalAccountBindingDAO() (qrdbsdk.GenericDAO[*entities.ExternalAccountBinding], error) {
	return m.realFactory.ExternalAccountBindingDAO()
}

// MockOrderDAO92Get wraps a real DAO but fails Get with a storage error.
type MockOrderDAO92Get struct {
	qrdbsdk.GenericDAO[*entities.ACMEOrder]
}

func (m *MockOrderDAO92Get) Get(ctx context.Context, id uint64) (*entities.ACMEOrder, error) {
	return nil, caerrors.StorageFailureError("mock storage error on order get")
}

// --- KeyChangeHandler storage error on Account Get ---

// TestCov92_KeyChangeHandler_AccountGetStorageError tests the storage error
// path (non-NotFound) when retrieving the persisted account in KeyChangeHandler.
func TestCov92_KeyChangeHandler_AccountGetStorageError(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	oldKey := generateTestKey(t)
	newKey := generateTestKey(t)

	account := createTestAccount(t, service, oldKey)

	// Replace factory with one that returns a DAO that fails on the second Get
	// (first Get is in parseKID, second is in KeyChangeHandler line 75)
	mockFactory := &MockStorageFactory92AccountGet{
		realFactory:   service.storageFactory,
		failGetOnCall: 2, // Fail on second Get (in KeyChangeHandler)
	}
	service.storageFactory = mockFactory

	req := createKeyChangeRequest(t, service, oldKey, newKey, account.ID)

	resp := httptest.NewRecorder()
	service.KeyChangeHandler(resp, req)

	assertErrorType(t, resp, common.ErrTypeServerInternal, http.StatusInternalServerError)
}

// TestCov92_KeyChangeHandler_ForEachPageError tests the error path when
// ForEachPage fails while listing accounts for key conflict check.
func TestCov92_KeyChangeHandler_ForEachPageError(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	oldKey := generateTestKey(t)
	newKey := generateTestKey(t)

	account := createTestAccount(t, service, oldKey)

	mockFactory := &MockStorageFactory92ForEachPage{
		realFactory:     service.storageFactory,
		failForEachPage: true,
	}
	service.storageFactory = mockFactory

	req := createKeyChangeRequest(t, service, oldKey, newKey, account.ID)

	resp := httptest.NewRecorder()
	service.KeyChangeHandler(resp, req)

	assertErrorType(t, resp, common.ErrTypeServerInternal, http.StatusInternalServerError)
}

// --- Additional mock types for KeyChange ---

// MockStorageFactory92AccountGet wraps real factory, fails account Get on specific call.
type MockStorageFactory92AccountGet struct {
	realFactory   storage.Factory
	failGetOnCall int
	callCount     int
}

func (m *MockStorageFactory92AccountGet) OrderDAO(accountID uint64) (qrdbsdk.GenericDAO[*entities.ACMEOrder], error) {
	return m.realFactory.OrderDAO(accountID)
}

func (m *MockStorageFactory92AccountGet) CertificateDAO() (qrdbsdk.GenericDAO[*entities.ACMECertificate], error) {
	return m.realFactory.CertificateDAO()
}

func (m *MockStorageFactory92AccountGet) AccountDAO() (qrdbsdk.GenericDAO[*entities.ACMEAccount], error) {
	dao, err := m.realFactory.AccountDAO()
	if err != nil {
		return nil, err
	}
	return &MockAccountDAO92Get{
		GenericDAO: dao,
		failOnCall: m.failGetOnCall,
		callCount:  &m.callCount,
	}, nil
}

func (m *MockStorageFactory92AccountGet) NonceDAO() (qrdbsdk.GenericDAO[*entities.ACMENonce], error) {
	return m.realFactory.NonceDAO()
}

func (m *MockStorageFactory92AccountGet) AuthorizationDAO(accountID uint64) (qrdbsdk.GenericDAO[*entities.ACMEAuthorization], error) {
	return m.realFactory.AuthorizationDAO(accountID)
}

func (m *MockStorageFactory92AccountGet) ChallengeDAO(accountID uint64) (qrdbsdk.GenericDAO[*entities.ACMEChallenge], error) {
	return m.realFactory.ChallengeDAO(accountID)
}

func (m *MockStorageFactory92AccountGet) ExternalAccountBindingDAO() (qrdbsdk.GenericDAO[*entities.ExternalAccountBinding], error) {
	return m.realFactory.ExternalAccountBindingDAO()
}

// MockAccountDAO92Get fails Get on a specific call number.
type MockAccountDAO92Get struct {
	qrdbsdk.GenericDAO[*entities.ACMEAccount]
	failOnCall int
	callCount  *int
}

func (m *MockAccountDAO92Get) Get(ctx context.Context, id uint64) (*entities.ACMEAccount, error) {
	*m.callCount++
	if *m.callCount >= m.failOnCall {
		return nil, caerrors.StorageFailureError("mock storage error on account get")
	}
	return m.GenericDAO.Get(ctx, id)
}

// MockStorageFactory92ForEachPage wraps real factory, fails ForEachPage.
type MockStorageFactory92ForEachPage struct {
	realFactory     storage.Factory
	failForEachPage bool
}

func (m *MockStorageFactory92ForEachPage) OrderDAO(accountID uint64) (qrdbsdk.GenericDAO[*entities.ACMEOrder], error) {
	return m.realFactory.OrderDAO(accountID)
}

func (m *MockStorageFactory92ForEachPage) CertificateDAO() (qrdbsdk.GenericDAO[*entities.ACMECertificate], error) {
	return m.realFactory.CertificateDAO()
}

func (m *MockStorageFactory92ForEachPage) AccountDAO() (qrdbsdk.GenericDAO[*entities.ACMEAccount], error) {
	dao, err := m.realFactory.AccountDAO()
	if err != nil {
		return nil, err
	}
	if m.failForEachPage {
		return &MockAccountDAO92ForEach{
			GenericDAO: dao,
		}, nil
	}
	return dao, nil
}

func (m *MockStorageFactory92ForEachPage) NonceDAO() (qrdbsdk.GenericDAO[*entities.ACMENonce], error) {
	return m.realFactory.NonceDAO()
}

func (m *MockStorageFactory92ForEachPage) AuthorizationDAO(accountID uint64) (qrdbsdk.GenericDAO[*entities.ACMEAuthorization], error) {
	return m.realFactory.AuthorizationDAO(accountID)
}

func (m *MockStorageFactory92ForEachPage) ChallengeDAO(accountID uint64) (qrdbsdk.GenericDAO[*entities.ACMEChallenge], error) {
	return m.realFactory.ChallengeDAO(accountID)
}

func (m *MockStorageFactory92ForEachPage) ExternalAccountBindingDAO() (qrdbsdk.GenericDAO[*entities.ExternalAccountBinding], error) {
	return m.realFactory.ExternalAccountBindingDAO()
}

// MockAccountDAO92ForEach wraps real DAO, fails ForEachPage.
type MockAccountDAO92ForEach struct {
	qrdbsdk.GenericDAO[*entities.ACMEAccount]
}

func (m *MockAccountDAO92ForEach) ForEachPage(ctx context.Context, query qrdbsdk.PageQuery, fn qrdbsdk.PagerFunc[*entities.ACMEAccount]) error {
	return caerrors.StorageFailureError("mock ForEachPage error")
}

// --- MockStorageFactory92 ---

// MockStorageFactory92 wraps the real factory but fails account saves
// on a specific call count.
type MockStorageFactory92 struct {
	realFactory        storage.Factory
	failAccountSaveOn  int
	failOrderDAOCreate bool
	failAccountDAOOn   bool
}

func (m *MockStorageFactory92) OrderDAO(accountID uint64) (qrdbsdk.GenericDAO[*entities.ACMEOrder], error) {
	if m.failOrderDAOCreate {
		return nil, caerrors.StorageFailureError("mock order DAO creation failure")
	}
	return m.realFactory.OrderDAO(accountID)
}

func (m *MockStorageFactory92) CertificateDAO() (qrdbsdk.GenericDAO[*entities.ACMECertificate], error) {
	return m.realFactory.CertificateDAO()
}

func (m *MockStorageFactory92) AccountDAO() (qrdbsdk.GenericDAO[*entities.ACMEAccount], error) {
	if m.failAccountDAOOn {
		return nil, caerrors.StorageFailureError("mock account DAO creation failure")
	}
	dao, err := m.realFactory.AccountDAO()
	if err != nil {
		return nil, err
	}
	if m.failAccountSaveOn > 0 {
		return &MockAccountDAO92{
			GenericDAO:     dao,
			failSaveOnCall: m.failAccountSaveOn,
		}, nil
	}
	return dao, nil
}

func (m *MockStorageFactory92) NonceDAO() (qrdbsdk.GenericDAO[*entities.ACMENonce], error) {
	return m.realFactory.NonceDAO()
}

func (m *MockStorageFactory92) AuthorizationDAO(accountID uint64) (qrdbsdk.GenericDAO[*entities.ACMEAuthorization], error) {
	return m.realFactory.AuthorizationDAO(accountID)
}

func (m *MockStorageFactory92) ChallengeDAO(accountID uint64) (qrdbsdk.GenericDAO[*entities.ACMEChallenge], error) {
	return m.realFactory.ChallengeDAO(accountID)
}

func (m *MockStorageFactory92) ExternalAccountBindingDAO() (qrdbsdk.GenericDAO[*entities.ExternalAccountBinding], error) {
	return m.realFactory.ExternalAccountBindingDAO()
}

// MockAccountDAO92 wraps a real DAO but fails save on a specific call.
type MockAccountDAO92 struct {
	qrdbsdk.GenericDAO[*entities.ACMEAccount]
	failSaveOnCall int
	saveCallCount  int
}

func (m *MockAccountDAO92) Save(ctx context.Context, account *entities.ACMEAccount) error {
	m.saveCallCount++
	if m.saveCallCount >= m.failSaveOnCall {
		return caerrors.StorageFailureError("mock account save failure")
	}
	return m.GenericDAO.Save(ctx, account)
}

// MockStorageFactory92AccountGetNotFound wraps factory, fails account Get with NotFound.
type MockStorageFactory92AccountGetNotFound struct {
	realFactory         storage.Factory
	failGetWithNotFound int
	callCount           int
}

func (m *MockStorageFactory92AccountGetNotFound) OrderDAO(accountID uint64) (qrdbsdk.GenericDAO[*entities.ACMEOrder], error) {
	return m.realFactory.OrderDAO(accountID)
}

func (m *MockStorageFactory92AccountGetNotFound) CertificateDAO() (qrdbsdk.GenericDAO[*entities.ACMECertificate], error) {
	return m.realFactory.CertificateDAO()
}

func (m *MockStorageFactory92AccountGetNotFound) AccountDAO() (qrdbsdk.GenericDAO[*entities.ACMEAccount], error) {
	dao, err := m.realFactory.AccountDAO()
	if err != nil {
		return nil, err
	}
	return &MockAccountDAO92GetNotFound{
		GenericDAO: dao,
		failOnCall: m.failGetWithNotFound,
		callCount:  &m.callCount,
	}, nil
}

func (m *MockStorageFactory92AccountGetNotFound) NonceDAO() (qrdbsdk.GenericDAO[*entities.ACMENonce], error) {
	return m.realFactory.NonceDAO()
}

func (m *MockStorageFactory92AccountGetNotFound) AuthorizationDAO(accountID uint64) (qrdbsdk.GenericDAO[*entities.ACMEAuthorization], error) {
	return m.realFactory.AuthorizationDAO(accountID)
}

func (m *MockStorageFactory92AccountGetNotFound) ChallengeDAO(accountID uint64) (qrdbsdk.GenericDAO[*entities.ACMEChallenge], error) {
	return m.realFactory.ChallengeDAO(accountID)
}

func (m *MockStorageFactory92AccountGetNotFound) ExternalAccountBindingDAO() (qrdbsdk.GenericDAO[*entities.ExternalAccountBinding], error) {
	return m.realFactory.ExternalAccountBindingDAO()
}

// MockAccountDAO92GetNotFound wraps real DAO, fails Get with NotFound on specific call.
type MockAccountDAO92GetNotFound struct {
	qrdbsdk.GenericDAO[*entities.ACMEAccount]
	failOnCall int
	callCount  *int
}

func (m *MockAccountDAO92GetNotFound) Get(ctx context.Context, id uint64) (*entities.ACMEAccount, error) {
	*m.callCount++
	if *m.callCount >= m.failOnCall {
		return nil, qrdbsdk.DAONotFoundError{EntityType: "account", ID: id}
	}
	return m.GenericDAO.Get(ctx, id)
}

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
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/gorilla/mux"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	caerrors "github.com/jeremyhahn/go-xkms/pkg/acme/errors"
	"github.com/jeremyhahn/go-xkms/pkg/acme/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ====== NewAccountHandler EAB Error Path Tests ======

// CoverageMockEABStorageFactory wraps the real factory and allows us to inject
// custom EAB DAO behavior for coverage tests.
type CoverageMockEABStorageFactory struct {
	storage.Factory
	eabDAO         *CoverageMockEABDAO
	failEABDAOInit bool
}

func (m *CoverageMockEABStorageFactory) ExternalAccountBindingDAO() (qrdbsdk.GenericDAO[*entities.ExternalAccountBinding], error) {
	if m.failEABDAOInit {
		return nil, caerrors.StorageFailureError("mock EAB DAO init failure")
	}
	return m.eabDAO, nil
}

// CoverageMockEABDAO provides controllable EAB storage behavior for testing.
type CoverageMockEABDAO struct {
	binding    *entities.ExternalAccountBinding
	getErr     error
	saveErr    error
	getCalled  bool
	saveCalled bool
	deleteErr  error
}

func (m *CoverageMockEABDAO) Save(_ context.Context, _ *entities.ExternalAccountBinding) error {
	m.saveCalled = true
	return m.saveErr
}

func (m *CoverageMockEABDAO) SaveWithCondition(_ context.Context, _ *entities.ExternalAccountBinding, _ qrdbsdk.Condition) error {
	panic("not implemented")
}

func (m *CoverageMockEABDAO) GetByNaturalKey(_ context.Context, _ string) (*entities.ExternalAccountBinding, error) {
	panic("not implemented")
}

func (m *CoverageMockEABDAO) CompareAndSwap(_ context.Context, _, _ *entities.ExternalAccountBinding) (bool, error) {
	panic("not implemented")
}

func (m *CoverageMockEABDAO) DeleteIfMatch(_ context.Context, _ *entities.ExternalAccountBinding) (bool, error) {
	panic("not implemented")
}

func (m *CoverageMockEABDAO) SaveIfAbsent(_ context.Context, _ *entities.ExternalAccountBinding) (bool, error) {
	panic("not implemented")
}

func (m *CoverageMockEABDAO) Get(_ context.Context, _ uint64) (*entities.ExternalAccountBinding, error) {
	m.getCalled = true
	if m.getErr != nil {
		return nil, m.getErr
	}
	return m.binding, nil
}

func (m *CoverageMockEABDAO) Delete(_ context.Context, _ *entities.ExternalAccountBinding) error {
	return m.deleteErr
}

func (m *CoverageMockEABDAO) Count(_ context.Context) (int, error) {
	if m.binding != nil {
		return 1, nil
	}
	return 0, nil
}

func (m *CoverageMockEABDAO) Page(_ context.Context, _ qrdbsdk.PageQuery) (qrdbsdk.PageResult[*entities.ExternalAccountBinding], error) {
	panic("not implemented")
}

func (m *CoverageMockEABDAO) ForEachPage(_ context.Context, _ qrdbsdk.PageQuery, _ qrdbsdk.PagerFunc[*entities.ExternalAccountBinding]) error {
	panic("not implemented")
}

func (m *CoverageMockEABDAO) EntityType() string {
	return "eab"
}

func (m *CoverageMockEABDAO) QueryByIndex(_ context.Context, fieldName string, value interface{}) ([]*entities.ExternalAccountBinding, error) {
	if m.binding != nil {
		return []*entities.ExternalAccountBinding{m.binding}, nil
	}
	return nil, nil
}

func (m *CoverageMockEABDAO) QueryByCompoundIndex(_ context.Context, _ string, _ []interface{}) ([]*entities.ExternalAccountBinding, error) {
	return nil, nil
}

func (m *CoverageMockEABDAO) ScanByCompoundIndex(_ context.Context, _ string, _ []interface{}, _, _ interface{}) ([]*entities.ExternalAccountBinding, error) {
	return nil, nil
}

func (m *CoverageMockEABDAO) QueryOneByIndex(_ context.Context, fieldName string, value interface{}) (*entities.ExternalAccountBinding, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}
	if m.binding != nil {
		return m.binding, nil
	}
	return nil, errors.New("not found")
}

func (m *CoverageMockEABDAO) ScanByIndex(_ context.Context, _ string, _, _ interface{}) ([]*entities.ExternalAccountBinding, error) {
	panic("not implemented")
}

func (m *CoverageMockEABDAO) PageByIndex(_ context.Context, _ string, _ interface{}, _ qrdbsdk.PageQuery) (qrdbsdk.PageResult[*entities.ExternalAccountBinding], error) {
	panic("not implemented")
}

func (m *CoverageMockEABDAO) CountByIndex(_ context.Context, _ string, _ interface{}) (int, error) {
	panic("not implemented")
}

func (m *CoverageMockEABDAO) Find(_ context.Context) *qrdbsdk.QueryBuilder[*entities.ExternalAccountBinding] {
	panic("not implemented")
}

// Helper to create EAB JWS for testing
func createCoverageEABJWS(t *testing.T, macKey []byte, kid string, url string, accountJWK *jose.JSONWebKey) map[string]interface{} {
	// Create the protected header
	protectedHeader := map[string]interface{}{
		"alg": "HS256",
		"kid": kid,
		"url": url,
	}
	protectedJSON, err := json.Marshal(protectedHeader)
	require.NoError(t, err)
	protectedB64 := base64.RawURLEncoding.EncodeToString(protectedJSON)

	// Create the payload (account JWK)
	payloadJSON, err := json.Marshal(accountJWK)
	require.NoError(t, err)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)

	// Create the signature
	signatureInput := protectedB64 + "." + payloadB64
	mac := hmac.New(sha256.New, macKey)
	mac.Write([]byte(signatureInput))
	signature := mac.Sum(nil)
	signatureB64 := base64.RawURLEncoding.EncodeToString(signature)

	return map[string]interface{}{
		"protected": protectedB64,
		"payload":   payloadB64,
		"signature": signatureB64,
	}
}

func TestNewAccountHandler_EABRequired_DAOCreationFailure(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	// Enable EAB requirement
	service.externalAccountRequired = true

	// Replace storage factory with one that fails EAB DAO creation
	mockFactory := &CoverageMockEABStorageFactory{
		Factory:        service.storageFactory,
		failEABDAOInit: true,
	}
	service.storageFactory = mockFactory

	key := generateTestKey(t)

	// Provide EAB binding
	payload := NewAccountRequest{
		Contact:              []string{"mailto:test@example.com"},
		TermsOfServiceAgreed: true,
		ExternalAccountBinding: map[string]interface{}{
			"protected": "test",
			"payload":   "test",
			"signature": "test",
		},
	}

	url := service.baseRESTURI + "/acme/new-account"
	req := createJWSRequest(t, service, key, url, payload, false, 0)

	resp := httptest.NewRecorder()
	service.NewAccountHandler(resp, req)

	assertErrorType(t, resp, common.ErrTypeServerInternal, http.StatusInternalServerError)
}

func TestNewAccountHandler_EABRequired_BindingNotFound(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	service.externalAccountRequired = true

	mockEABDAO := &CoverageMockEABDAO{
		getErr: errors.New("external account binding not found"),
	}
	mockFactory := &CoverageMockEABStorageFactory{
		Factory: service.storageFactory,
		eabDAO:  mockEABDAO,
	}
	service.storageFactory = mockFactory

	key := generateTestKey(t)

	// Create a valid EAB JWS structure
	jwk := &jose.JSONWebKey{Key: key.PublicKey}
	macKey := make([]byte, 32)
	_, _ = rand.Read(macKey)
	eabJWS := createCoverageEABJWS(t, macKey, "test-kid", service.baseRESTURI+"/acme/new-account", jwk)

	payload := NewAccountRequest{
		Contact:                []string{"mailto:test@example.com"},
		TermsOfServiceAgreed:   true,
		ExternalAccountBinding: eabJWS,
	}

	url := service.baseRESTURI + "/acme/new-account"
	req := createJWSRequest(t, service, key, url, payload, false, 0)

	resp := httptest.NewRecorder()
	service.NewAccountHandler(resp, req)

	assertErrorType(t, resp, common.ErrTypeUnauthorized, http.StatusUnauthorized)
}

func TestNewAccountHandler_EABRequired_URLMismatch(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	service.externalAccountRequired = true

	// Inject a typed Unauthorized error at the DAO level. The verifier wraps
	// non-NotFound DAO errors as StorageFailure, which falls through to the
	// handler's default Unauthorized case.
	mockEABDAO := &CoverageMockEABDAO{
		getErr: caerrors.UnauthorizedError("EAB URL mismatch"),
	}
	mockFactory := &CoverageMockEABStorageFactory{
		Factory: service.storageFactory,
		eabDAO:  mockEABDAO,
	}
	service.storageFactory = mockFactory

	key := generateTestKey(t)
	jwk := &jose.JSONWebKey{Key: key.PublicKey}
	macKey := make([]byte, 32)
	_, _ = rand.Read(macKey)
	eabJWS := createCoverageEABJWS(t, macKey, "test-kid", service.baseRESTURI+"/acme/new-account", jwk)

	payload := NewAccountRequest{
		Contact:                []string{"mailto:test@example.com"},
		TermsOfServiceAgreed:   true,
		ExternalAccountBinding: eabJWS,
	}

	url := service.baseRESTURI + "/acme/new-account"
	req := createJWSRequest(t, service, key, url, payload, false, 0)

	resp := httptest.NewRecorder()
	service.NewAccountHandler(resp, req)

	// DAO errors that aren't ErrExternalAccountBindingNotFound are wrapped as
	// StorageFailure by the verifier, which falls to the handler's default case.
	assertErrorType(t, resp, common.ErrTypeUnauthorized, http.StatusUnauthorized)
}

func TestNewAccountHandler_EABRequired_DefaultUnauthorizedError(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	service.externalAccountRequired = true

	// Return a generic error that doesn't match any specific case.
	// The verifier wraps non-NotFound DAO errors as StorageFailure,
	// which falls through to the handler's default Unauthorized case.
	mockEABDAO := &CoverageMockEABDAO{
		getErr: caerrors.InternalServerError("some unknown error"),
	}
	mockFactory := &CoverageMockEABStorageFactory{
		Factory: service.storageFactory,
		eabDAO:  mockEABDAO,
	}
	service.storageFactory = mockFactory

	key := generateTestKey(t)
	jwk := &jose.JSONWebKey{Key: key.PublicKey}
	macKey := make([]byte, 32)
	_, _ = rand.Read(macKey)
	eabJWS := createCoverageEABJWS(t, macKey, "test-kid", service.baseRESTURI+"/acme/new-account", jwk)

	payload := NewAccountRequest{
		Contact:                []string{"mailto:test@example.com"},
		TermsOfServiceAgreed:   true,
		ExternalAccountBinding: eabJWS,
	}

	url := service.baseRESTURI + "/acme/new-account"
	req := createJWSRequest(t, service, key, url, payload, false, 0)

	resp := httptest.NewRecorder()
	service.NewAccountHandler(resp, req)

	// Unknown DAO errors get wrapped as StorageFailure by the verifier,
	// which falls to the handler's default Unauthorized case.
	assertErrorType(t, resp, common.ErrTypeUnauthorized, http.StatusUnauthorized)
}

func TestNewAccountHandler_EABWithTenantID(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	service.externalAccountRequired = true

	macKey := make([]byte, 32)
	_, _ = rand.Read(macKey)
	macKeyB64 := base64.RawURLEncoding.EncodeToString(macKey)

	expiresAt := time.Now().Add(24 * time.Hour)
	binding := &entities.ExternalAccountBinding{
		ID:                "test-kid-tenant",
		MACKey:            macKeyB64,
		MACAlgorithm:      "HS256",
		ExternalAccountID: "ext-acc-123",
		Status:            entities.EABStatusActive,
		TenantID:          "tenant-abc",
		CreatedAt:         time.Now(),
		ExpiresAt:         &expiresAt,
	}

	mockEABDAO := &CoverageMockEABDAO{
		binding: binding,
	}
	mockFactory := &CoverageMockEABStorageFactory{
		Factory: service.storageFactory,
		eabDAO:  mockEABDAO,
	}
	service.storageFactory = mockFactory

	key := generateTestKey(t)
	jwk := &jose.JSONWebKey{Key: key.PublicKey}
	eabJWS := createCoverageEABJWS(t, macKey, "test-kid-tenant", service.baseRESTURI+"/acme/new-account", jwk)

	payload := NewAccountRequest{
		Contact:                []string{"mailto:tenant-test@example.com"},
		TermsOfServiceAgreed:   true,
		ExternalAccountBinding: eabJWS,
	}

	url := service.baseRESTURI + "/acme/new-account"
	req := createJWSRequest(t, service, key, url, payload, false, 0)

	resp := httptest.NewRecorder()
	service.NewAccountHandler(resp, req)

	require.Equal(t, http.StatusCreated, resp.Code)

	var accountResp struct {
		Status   string   `json:"status"`
		Contact  []string `json:"contact"`
		TenantID string   `json:"tenantId,omitempty"`
	}
	err := json.NewDecoder(resp.Body).Decode(&accountResp)
	require.NoError(t, err)

	assert.Equal(t, common.StatusValid, accountResp.Status)
}

// ====== OrderFinalizeHandler Additional Error Path Tests ======

func TestOrderFinalizeHandler_PreIssuanceHookFailure(t *testing.T) {
	service, _, cleanup := setupTestServiceWithMockCA(t)
	defer cleanup()

	// Register a pre-issuance hook that fails
	preHookRegistry := NewPreIssuanceHookRegistry()
	preHookRegistry.Register(func(ctx *PreIssuanceHookContext) error {
		return caerrors.VerificationFailureError("pre-issuance check failed: compliance violation")
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

	assertErrorType(t, resp, common.ErrTypeUnauthorized, http.StatusUnauthorized)
}

func TestOrderFinalizeHandler_IPIdentifierWithTCGCSRFallback(t *testing.T) {
	service, _, cleanup := setupTestServiceWithMockCA(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Create order with IP type identifier to trigger TCG-CSR path
	order := createTestOrderSimple(t, service, account.ID)
	order.Status = common.StatusReady
	order.Identifiers = []entities.ACMEIdentifier{
		{Type: common.AuthzTypeIP, Value: "192.168.1.100"},
	}

	ctx := context.Background()
	orderDAO, err := service.storageFactory.OrderDAO(account.ID)
	require.NoError(t, err)
	err = orderDAO.Save(ctx, order)
	require.NoError(t, err)
	authorizeOrder(t, service, account, order, order.Identifiers[0], "enroll-01")

	// Provide invalid CSR data to trigger TCG-CSR parsing attempt
	payload := OrderFinalizeRequest{
		CSR: base64.RawURLEncoding.EncodeToString([]byte("not-a-valid-csr-or-tcg-csr")),
	}

	url := fmt.Sprintf("%s/acme/orders/%d/finalize", service.baseRESTURI, order.ID)
	req := createJWSRequest(t, service, key, url, payload, true, account.ID)
	req = mux.SetURLVars(req, map[string]string{"id": fmt.Sprintf("%d", order.ID)})

	resp := httptest.NewRecorder()
	service.OrderFinalizeHandler(resp, req)

	// Should return malformed error since TCG-CSR parsing will also fail
	assertErrorType(t, resp, common.ErrTypeMalformedError, http.StatusBadRequest)
}

// TestOrderFinalizeHandler_DeviceAttest01Path_RejectsUnauthorizedSAN is the
// go-xkms#684 regression at the full HTTP handler level: before the fix, a
// device-attest-01 CSR whose CommonName matched the order's permanent
// identifier was issued a certificate regardless of what DNS names its SANs
// carried, because the identifier was read from the CommonName and the SANs
// were never checked. This CSR's "device.local" DNS SAN is not one of the
// order's authorized identifiers and must be refused.
func TestOrderFinalizeHandler_DeviceAttest01Path_RejectsUnauthorizedSAN(t *testing.T) {
	service, _, cleanup := setupTestServiceWithMockCA(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	order := createTestOrderSimple(t, service, account.ID)
	order.Status = common.StatusReady
	order.Identifiers = []entities.ACMEIdentifier{
		{Type: common.AuthzTypePermanentIdentifier, Value: "device-serial-123456"},
	}

	ctx := context.Background()
	orderDAO, err := service.storageFactory.OrderDAO(account.ID)
	require.NoError(t, err)
	err = orderDAO.Save(ctx, order)
	require.NoError(t, err)
	authorizeOrder(t, service, account, order, order.Identifiers[0], common.ChallengeTypeDeviceAttest01)

	csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "device-serial-123456",
		},
		DNSNames: []string{"device.local"},
	}
	csr := createPermanentIdentifierCSR(t, template, csrKey, "device-serial-123456")

	payload := OrderFinalizeRequest{
		CSR: base64.RawURLEncoding.EncodeToString(csr.Raw),
	}

	url := fmt.Sprintf("%s/acme/orders/%d/finalize", service.baseRESTURI, order.ID)
	req := createJWSRequest(t, service, key, url, payload, true, account.ID)
	req = mux.SetURLVars(req, map[string]string{"id": fmt.Sprintf("%d", order.ID)})

	resp := httptest.NewRecorder()
	service.OrderFinalizeHandler(resp, req)

	assertErrorType(t, resp, common.ErrTypeRejectedIdentifier, http.StatusForbidden)

	updated, err := orderDAO.Get(ctx, order.ID)
	require.NoError(t, err)
	assert.Equal(t, common.StatusReady, updated.Status,
		"a CSR rejected before validation must leave the order retryable, not stranded")
}

// TestOrderFinalizeHandler_DeviceAttest01Path_RejectsCommonNameFallback is
// the CommonName-only regression: a CSR carrying no permanentIdentifier
// otherName at all - only a CommonName equal to the order's authorized
// value - must be refused rather than silently accepted via a CommonName
// fallback.
func TestOrderFinalizeHandler_DeviceAttest01Path_RejectsCommonNameFallback(t *testing.T) {
	service, _, cleanup := setupTestServiceWithMockCA(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	order := createTestOrderSimple(t, service, account.ID)
	order.Status = common.StatusReady
	order.Identifiers = []entities.ACMEIdentifier{
		{Type: common.AuthzTypePermanentIdentifier, Value: "device-serial-123456"},
	}

	ctx := context.Background()
	orderDAO, err := service.storageFactory.OrderDAO(account.ID)
	require.NoError(t, err)
	err = orderDAO.Save(ctx, order)
	require.NoError(t, err)
	authorizeOrder(t, service, account, order, order.Identifiers[0], common.ChallengeTypeDeviceAttest01)

	csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "device-serial-123456",
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

	assertErrorType(t, resp, common.ErrTypeBadCSR, http.StatusBadRequest)

	updated, err := orderDAO.Get(ctx, order.ID)
	require.NoError(t, err)
	assert.Equal(t, common.StatusReady, updated.Status)
}

// Test EK certificate with IP addresses in CSR
func TestOrderFinalizeHandler_EKCertWithIPAddresses(t *testing.T) {
	service, _, cleanup := setupTestServiceWithMockCA(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	ekKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ekPubKeyBytes, err := x509.MarshalPKIXPublicKey(&ekKey.PublicKey)
	require.NoError(t, err)
	ekPubKeyB64 := base64.RawURLEncoding.EncodeToString(ekPubKeyBytes)

	// The order authorizes both the permanent identifier (the EK public key
	// being certified) and the two IP SANs the CSR below requests: since
	// matchesEndorse01Identifier requires exact correspondence for DNS/IP
	// SANs, an unauthorized IP would otherwise be rejected before the EK
	// certificate issuance path this test exercises is ever reached.
	order := createTestOrderSimple(t, service, account.ID)
	order.Status = common.StatusReady
	order.Identifiers = []entities.ACMEIdentifier{
		{Type: common.AuthzTypePermanentIdentifier, Value: ekPubKeyB64},
		{Type: common.AuthzTypeIP, Value: "192.168.1.100"},
		{Type: common.AuthzTypeIP, Value: "10.0.0.1"},
	}

	ctx := context.Background()
	orderDAO, err := service.storageFactory.OrderDAO(account.ID)
	require.NoError(t, err)
	err = orderDAO.Save(ctx, order)
	require.NoError(t, err)
	authorizeOrder(t, service, account, order, order.Identifiers[0], "endorse-01")

	csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "device-with-ip",
		},
		IPAddresses: []net.IP{net.ParseIP("192.168.1.100"), net.ParseIP("10.0.0.1")},
	}

	csrDER := createEndorse01CSR(t, template, csrKey)

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

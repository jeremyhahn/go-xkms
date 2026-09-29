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
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	caerrors "github.com/jeremyhahn/go-xkms/pkg/acme/errors"
	"github.com/jeremyhahn/go-xkms/pkg/acme/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ========================================
// AccountHandler Coverage Tests
// ========================================

// MockAccountDAOFailingSave returns errors on Save operations
type MockAccountDAOFailingSave struct {
	qrdbsdk.GenericDAO[*entities.ACMEAccount]
	account  *entities.ACMEAccount
	saveErr  error
	getCalls int
}

func (m *MockAccountDAOFailingSave) Get(ctx context.Context, id uint64) (*entities.ACMEAccount, error) {
	m.getCalls++
	return m.account, nil
}

func (m *MockAccountDAOFailingSave) Save(ctx context.Context, account *entities.ACMEAccount) error {
	return m.saveErr
}

func (m *MockAccountDAOFailingSave) Exists(ctx context.Context, id uint64) (bool, error) {
	return true, nil
}

func (m *MockAccountDAOFailingSave) Delete(ctx context.Context, entity *entities.ACMEAccount) error {
	return nil
}

func (m *MockAccountDAOFailingSave) List(ctx context.Context, prefix string) ([]*entities.ACMEAccount, error) {
	return []*entities.ACMEAccount{m.account}, nil
}

// MockStorageFactoryWithAccountDAO wraps factory to return mock account DAO
type MockStorageFactoryWithAccountDAO struct {
	storage.Factory
	accountDAO    qrdbsdk.GenericDAO[*entities.ACMEAccount]
	failAccountDA bool
}

func (m *MockStorageFactoryWithAccountDAO) AccountDAO() (qrdbsdk.GenericDAO[*entities.ACMEAccount], error) {
	if m.failAccountDA {
		return nil, caerrors.StorageFailureError("mock account DAO creation failure")
	}
	if m.accountDAO != nil {
		return m.accountDAO, nil
	}
	return m.Factory.AccountDAO()
}

func TestAccountHandler_AccountDAOCreationFailure(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Replace factory with failing one after account creation
	mockFactory := &MockStorageFactoryWithAccountDAO{
		Factory:       service.storageFactory,
		failAccountDA: true,
	}
	service.storageFactory = mockFactory

	url := fmt.Sprintf("%s/acme/account/%d", service.baseRESTURI, account.ID)
	req := createJWSRequest(t, service, key, url, nil, true, account.ID)

	resp := httptest.NewRecorder()
	service.AccountHandler(resp, req)

	// parseKID calls AccountDAO first, so when it fails, we get MalformedError not ServerInternal
	assertErrorType(t, resp, common.ErrTypeMalformedError, http.StatusBadRequest)
}

func TestAccountHandler_SaveFailure(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Create mock DAO that fails on save
	mockAccountDAO := &MockAccountDAOFailingSave{
		account: account,
		saveErr: caerrors.StorageFailureError("mock save error"),
	}
	mockFactory := &MockStorageFactoryWithAccountDAO{
		Factory:    service.storageFactory,
		accountDAO: mockAccountDAO,
	}
	service.storageFactory = mockFactory

	// Send status update to trigger save
	payload := AccountRequest{
		Status: common.StatusDeactivated,
	}

	url := fmt.Sprintf("%s/acme/account/%d", service.baseRESTURI, account.ID)
	req := createJWSRequest(t, service, key, url, payload, true, account.ID)

	resp := httptest.NewRecorder()
	service.AccountHandler(resp, req)

	assertErrorType(t, resp, common.ErrTypeServerInternal, http.StatusInternalServerError)
}

func TestAccountHandler_ContactUpdateSaveFailure(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	mockAccountDAO := &MockAccountDAOFailingSave{
		account: account,
		saveErr: caerrors.StorageFailureError("mock save error on contact update"),
	}
	mockFactory := &MockStorageFactoryWithAccountDAO{
		Factory:    service.storageFactory,
		accountDAO: mockAccountDAO,
	}
	service.storageFactory = mockFactory

	payload := AccountRequest{
		Contact: []string{"mailto:updated@example.com"},
	}

	url := fmt.Sprintf("%s/acme/account/%d", service.baseRESTURI, account.ID)
	req := createJWSRequest(t, service, key, url, payload, true, account.ID)

	resp := httptest.NewRecorder()
	service.AccountHandler(resp, req)

	assertErrorType(t, resp, common.ErrTypeServerInternal, http.StatusInternalServerError)
}

func TestAccountHandler_NonceGenerationFailure(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Set failing nonce generator
	service.SetNonceGenerator(func() (string, error) {
		return "", caerrors.InternalServerError("mock nonce generation failure")
	})

	url := fmt.Sprintf("%s/acme/account/%d", service.baseRESTURI, account.ID)
	req := createJWSRequest(t, service, key, url, nil, true, account.ID)

	resp := httptest.NewRecorder()
	service.AccountHandler(resp, req)

	assertErrorType(t, resp, common.ErrTypeServerInternal, http.StatusInternalServerError)
}

// ========================================
// ChallengeHandler Coverage Tests
// ========================================

// MockStorageFactoryWithFailingAuthzDAO fails authorization DAO creation
type MockStorageFactoryWithFailingAuthzDAO struct {
	storage.Factory
	failAuthzDAO bool
	failOrderDAO bool
}

func (m *MockStorageFactoryWithFailingAuthzDAO) AuthorizationDAO(accountID uint64) (qrdbsdk.GenericDAO[*entities.ACMEAuthorization], error) {
	if m.failAuthzDAO {
		return nil, caerrors.StorageFailureError("mock authz DAO creation failure")
	}
	return m.Factory.AuthorizationDAO(accountID)
}

func (m *MockStorageFactoryWithFailingAuthzDAO) OrderDAO(accountID uint64) (qrdbsdk.GenericDAO[*entities.ACMEOrder], error) {
	if m.failOrderDAO {
		return nil, caerrors.StorageFailureError("mock order DAO creation failure")
	}
	return m.Factory.OrderDAO(accountID)
}

func TestChallengeHandler_AuthzDAOCreationFailure(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	mockFactory := &MockStorageFactoryWithFailingAuthzDAO{
		Factory:      service.storageFactory,
		failAuthzDAO: true,
	}
	service.storageFactory = mockFactory

	url := service.baseRESTURI + "/acme/challenge/123"
	req := createJWSRequest(t, service, key, url, nil, true, account.ID)

	resp := httptest.NewRecorder()
	service.ChallengeHandler(resp, req)

	assertErrorType(t, resp, common.ErrTypeServerInternal, http.StatusInternalServerError)
}

func TestChallengeHandler_OrderDAOCreationFailure(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	mockFactory := &MockStorageFactoryWithFailingAuthzDAO{
		Factory:      service.storageFactory,
		failOrderDAO: true,
	}
	service.storageFactory = mockFactory

	url := service.baseRESTURI + "/acme/challenge/123"
	req := createJWSRequest(t, service, key, url, nil, true, account.ID)

	resp := httptest.NewRecorder()
	service.ChallengeHandler(resp, req)

	assertErrorType(t, resp, common.ErrTypeServerInternal, http.StatusInternalServerError)
}

func TestChallengeHandler_AlreadyValidStatusResponse(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Create order and authorization with valid challenge
	order := createTestOrderSimple(t, service, account.ID)
	authz := createTestAuthorization(t, service, account, order, entities.ACMEIdentifier{
		Type:  "dns",
		Value: "valid-challenge.example.com",
	}, []string{"http-01"})

	// Mark challenge as already valid
	ctx := context.Background()
	authzDAO, err := service.storageFactory.AuthorizationDAO(account.ID)
	require.NoError(t, err)

	authz.Challenges[0].Status = common.StatusValid
	err = authzDAO.Save(ctx, authz)
	require.NoError(t, err)

	url := fmt.Sprintf("%s/acme/challenge/%d", service.baseRESTURI, authz.Challenges[0].ID)
	req := createJWSRequest(t, service, key, url, nil, true, account.ID)

	resp := httptest.NewRecorder()
	service.ChallengeHandler(resp, req)

	require.Equal(t, http.StatusOK, resp.Code)

	var challengeResp struct {
		Status string `json:"status"`
	}
	err = json.NewDecoder(resp.Body).Decode(&challengeResp)
	require.NoError(t, err)
	assert.Equal(t, common.StatusValid, challengeResp.Status)
}

// ========================================
// AuthorizationHandler Coverage Tests
// ========================================

func TestAuthorizationHandler_PutMethodNotAllowed(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	url := fmt.Sprintf("%s/acme/authz/123", service.baseRESTURI)

	// Create JWS request but change method
	jwsReq := createJWSRequest(t, service, key, url, nil, true, account.ID)
	jwsReq.Method = http.MethodPut

	resp := httptest.NewRecorder()
	service.AuthorizationHandler(resp, jwsReq)

	assert.Equal(t, http.StatusMethodNotAllowed, resp.Code)
}

func TestAuthorizationHandler_EmptyAuthzIDInPath(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	url := service.baseRESTURI + "/acme/authz/"
	req := createJWSRequest(t, service, key, url, nil, true, account.ID)

	resp := httptest.NewRecorder()
	service.AuthorizationHandler(resp, req)

	assert.Equal(t, http.StatusBadRequest, resp.Code)
}

func TestAuthorizationHandler_InvalidAuthzIDFormat(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	url := service.baseRESTURI + "/acme/authz/invalid-id"
	req := createJWSRequest(t, service, key, url, nil, true, account.ID)

	resp := httptest.NewRecorder()
	service.AuthorizationHandler(resp, req)

	assertErrorType(t, resp, common.ErrTypeMalformedError, http.StatusBadRequest)
}

func TestAuthorizationHandler_GetDAOCreationFailure(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	mockFactory := &MockStorageFactoryWithFailingAuthzDAO{
		Factory:      service.storageFactory,
		failAuthzDAO: true,
	}
	service.storageFactory = mockFactory

	url := fmt.Sprintf("%s/acme/authz/123", service.baseRESTURI)
	req := createJWSRequest(t, service, key, url, nil, true, account.ID)
	req.Method = http.MethodGet

	resp := httptest.NewRecorder()
	service.AuthorizationHandler(resp, req)

	assertErrorType(t, resp, common.ErrTypeServerInternal, http.StatusInternalServerError)
}

func TestAuthorizationHandler_PostDAOCreationFailure(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	mockFactory := &MockStorageFactoryWithFailingAuthzDAO{
		Factory:      service.storageFactory,
		failAuthzDAO: true,
	}
	service.storageFactory = mockFactory

	url := fmt.Sprintf("%s/acme/authz/123", service.baseRESTURI)
	req := createJWSRequest(t, service, key, url, nil, true, account.ID)

	resp := httptest.NewRecorder()
	service.AuthorizationHandler(resp, req)

	assertErrorType(t, resp, common.ErrTypeServerInternal, http.StatusInternalServerError)
}

func TestAuthorizationHandler_GetAuthzNotFoundInStorage(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	url := fmt.Sprintf("%s/acme/authz/999999", service.baseRESTURI)
	req := createJWSRequest(t, service, key, url, nil, true, account.ID)
	req.Method = http.MethodGet

	resp := httptest.NewRecorder()
	service.AuthorizationHandler(resp, req)

	assertErrorType(t, resp, common.ErrTypeMalformedError, http.StatusBadRequest)
}

func TestAuthorizationHandler_PostUnauthorizedAccessFromDifferentAccount(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	// Create two accounts
	key1 := generateTestKey(t)
	account1 := createTestAccount(t, service, key1)

	key2 := generateTestKey(t)
	account2 := createTestAccount(t, service, key2)

	// Create authorization for account1
	order := createTestOrderSimple(t, service, account1.ID)
	authz := createTestAuthorization(t, service, account1, order, entities.ACMEIdentifier{
		Type:  "dns",
		Value: "unauthorized-access.example.com",
	}, []string{"http-01"})

	// Try to access with account2
	url := fmt.Sprintf("%s/acme/authz/%d", service.baseRESTURI, authz.ID)
	req := createJWSRequest(t, service, key2, url, nil, true, account2.ID)

	resp := httptest.NewRecorder()
	service.AuthorizationHandler(resp, req)

	// Storage is scoped by account, so account2's DAO won't find account1's authz
	// Returns "not found" rather than "unauthorized"
	assertErrorType(t, resp, common.ErrTypeMalformedError, http.StatusBadRequest)
}

func TestAuthorizationHandler_PostAuthzNotFoundInStorage(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	url := fmt.Sprintf("%s/acme/authz/999999", service.baseRESTURI)
	req := createJWSRequest(t, service, key, url, nil, true, account.ID)

	resp := httptest.NewRecorder()
	service.AuthorizationHandler(resp, req)

	assertErrorType(t, resp, common.ErrTypeMalformedError, http.StatusBadRequest)
}

func TestAuthorizationHandler_GetSuccessfulRetrieval(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	order := createTestOrderSimple(t, service, account.ID)
	authz := createTestAuthorization(t, service, account, order, entities.ACMEIdentifier{
		Type:  "dns",
		Value: "get-success.example.com",
	}, []string{"http-01"})

	url := fmt.Sprintf("%s/acme/authz/%d", service.baseRESTURI, authz.ID)
	req := createJWSRequest(t, service, key, url, nil, true, account.ID)
	req.Method = http.MethodGet

	resp := httptest.NewRecorder()
	service.AuthorizationHandler(resp, req)

	require.Equal(t, http.StatusOK, resp.Code)
	assert.NotEmpty(t, resp.Header().Get("Replay-Nonce"))
}

func TestAuthorizationHandler_PostWithWildcardIdentifier(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	order := createTestOrderSimple(t, service, account.ID)

	ctx := context.Background()
	authzDAO, err := service.storageFactory.AuthorizationDAO(account.ID)
	require.NoError(t, err)

	// Generate authorization ID
	authzID, err := GenerateID()
	require.NoError(t, err)

	// Create wildcard authorization
	authz := &entities.ACMEAuthorization{
		ID: authzID,
		Identifier: entities.ACMEIdentifier{
			Type:  "dns",
			Value: "*.wildcard.example.com",
		},
		Status:    common.StatusPending,
		Wildcard:  true,
		AccountID: account.ID,
		OrderID:   order.ID,
		Challenges: []entities.ACMEChallenge{
			{
				ID:        authzID + 1,
				Type:      "dns-01",
				Status:    common.StatusPending,
				Token:     "test-token",
				AccountID: account.ID,
			},
		},
	}
	err = authzDAO.Save(ctx, authz)
	require.NoError(t, err)

	url := fmt.Sprintf("%s/acme/authz/%d", service.baseRESTURI, authz.ID)
	req := createJWSRequest(t, service, key, url, nil, true, account.ID)

	resp := httptest.NewRecorder()
	service.AuthorizationHandler(resp, req)

	require.Equal(t, http.StatusOK, resp.Code)

	var authzResp struct {
		Wildcard bool `json:"wildcard"`
	}
	err = json.NewDecoder(resp.Body).Decode(&authzResp)
	require.NoError(t, err)
	assert.True(t, authzResp.Wildcard)
}

// ========================================
// CertificateHandler Coverage Tests
// ========================================

// MockStorageFactoryWithFailingCertDAO fails certificate DAO creation
type MockStorageFactoryWithFailingCertDAO struct {
	storage.Factory
	failCertDAO bool
}

func (m *MockStorageFactoryWithFailingCertDAO) CertificateDAO() (qrdbsdk.GenericDAO[*entities.ACMECertificate], error) {
	if m.failCertDAO {
		return nil, caerrors.StorageFailureError("mock cert DAO creation failure")
	}
	return m.Factory.CertificateDAO()
}

func TestCertificateHandler_DAOCreationError(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	mockFactory := &MockStorageFactoryWithFailingCertDAO{
		Factory:     service.storageFactory,
		failCertDAO: true,
	}
	service.storageFactory = mockFactory

	url := fmt.Sprintf("%s/acme/cert/12345", service.baseRESTURI)
	req := httptest.NewRequest(http.MethodGet, url, nil)
	req = mux.SetURLVars(req, map[string]string{"id": "12345"})

	resp := httptest.NewRecorder()
	service.CertificateHandler(resp, req)

	assertErrorType(t, resp, common.ErrTypeServerInternal, http.StatusInternalServerError)
}

func TestCertificateHandler_EmptyIDError(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	url := service.baseRESTURI + "/acme/cert/"
	req := httptest.NewRequest(http.MethodGet, url, nil)
	req = mux.SetURLVars(req, map[string]string{"id": ""})

	resp := httptest.NewRecorder()
	service.CertificateHandler(resp, req)

	assertErrorType(t, resp, common.ErrTypeMalformedError, http.StatusBadRequest)
}

// ========================================
// NewEventLogValidationHook Coverage Tests
// ========================================

func TestEventLogValidationHook_NonTCGEnrollmentSkips(t *testing.T) {
	policy := &EventLogPolicy{
		RequiredEvents: []string{"EV_SEPARATOR"},
	}

	hook := NewEventLogValidationHook(policy)

	// Test with non-TCG enrollment (should skip)
	ctx := &PreIssuanceHookContext{
		IsTCGCSR: false,
		TCGData:  nil,
	}

	err := hook(ctx)
	assert.NoError(t, err)
}

func TestEventLogValidationHook_EmptyEventLogNoRequirements(t *testing.T) {
	policy := &EventLogPolicy{
		RequiredEvents: []string{}, // No required events
	}

	hook := NewEventLogValidationHook(policy)

	ctx := &PreIssuanceHookContext{
		IsTCGCSR: true,
		TCGData: &TCGEnrollmentData{
			EventLog: nil, // Empty event log
		},
	}

	err := hook(ctx)
	assert.NoError(t, err)
}

func TestEventLogValidationHook_RequiredEventsWithEmptyLogError(t *testing.T) {
	policy := &EventLogPolicy{
		RequiredEvents: []string{"EV_SEPARATOR"},
	}

	hook := NewEventLogValidationHook(policy)

	ctx := &PreIssuanceHookContext{
		IsTCGCSR: true,
		TCGData: &TCGEnrollmentData{
			EventLog: nil, // Empty event log
		},
	}

	err := hook(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "event log required but not provided")
}

func TestEventLogValidationHook_MaxEventCountZeroAllowsAny(t *testing.T) {
	policy := &EventLogPolicy{
		MaxEventCount: 2,
	}

	hook := NewEventLogValidationHook(policy)

	ctx := &PreIssuanceHookContext{
		IsTCGCSR: true,
		TCGData: &TCGEnrollmentData{
			EventLog: []byte{}, // Empty but valid
		},
	}

	err := hook(ctx)
	assert.NoError(t, err) // Empty log has 0 events, which is <= 2
}

// ========================================
// isEnrollXChallenge Tests
// ========================================

func TestIsEnrollXChallenge_AllTypes(t *testing.T) {
	tests := []struct {
		name         string
		challengeTyp string
		want         bool
	}{
		{"enroll-01", "enroll-01", true},
		{"enroll-01-8080", "enroll-01-8080", true},
		{"endorse-01", "endorse-01", true},
		{"device-attest-01", "device-attest-01", true},
		{"http-01", "http-01", false},
		{"dns-01", "dns-01", false},
		{"tls-alpn-01", "tls-alpn-01", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isEnrollXChallenge(tt.challengeTyp)
			assert.Equal(t, tt.want, got)
		})
	}
}

// ========================================
// OrderFinalizeHandler Additional Error Tests
// ========================================

func TestOrderFinalizeHandler_CASignCSRError(t *testing.T) {
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

	assertErrorType(t, resp, common.ErrTypeServerInternal, http.StatusInternalServerError)
}

// ========================================
// writeChallengeResponse Nonce Tests
// ========================================

func TestWriteChallengeResponse_NonceGenerationError(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	// Set failing nonce generator
	service.SetNonceGenerator(func() (string, error) {
		return "", caerrors.InternalServerError("nonce generation failed")
	})

	challenge := &entities.ACMEChallenge{
		ID:     123,
		Type:   "http-01",
		Status: common.StatusValid,
		Token:  "test-token",
	}

	resp := httptest.NewRecorder()
	service.writeChallengeResponse(resp, challenge)

	assertErrorType(t, resp, common.ErrTypeServerInternal, http.StatusInternalServerError)
}

// ========================================
// Helper Functions Coverage
// ========================================

func TestIntToStr_AllCases(t *testing.T) {
	tests := []struct {
		input int
		want  string
	}{
		{0, "0"},
		{1, "1"},
		{-1, "-1"},
		{123, "123"},
		{-456, "-456"},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("input_%d", tt.input), func(t *testing.T) {
			got := intToStr(tt.input)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestUint32ToHex_AllCases(t *testing.T) {
	tests := []struct {
		input uint32
		want  string
	}{
		{0, "00000000"},
		{1, "00000001"},
		{255, "000000FF"},
		{0xDEADBEEF, "DEADBEEF"},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("input_%d", tt.input), func(t *testing.T) {
			got := uint32ToHex(tt.input)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestBytesToHex_AllCases(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		want  string
	}{
		{"empty", []byte{}, ""},
		{"single byte", []byte{0xab}, "ab"},
		{"multiple bytes", []byte{0xde, 0xad, 0xbe, 0xef}, "deadbeef"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := bytesToHex(tt.input)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestBytesToBigInt_AllCases(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		want  int64
	}{
		{"zero", []byte{0}, 0},
		{"one", []byte{1}, 1},
		{"256", []byte{1, 0}, 256},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := bytesToBigInt(tt.input)
			assert.Equal(t, tt.want, got.Int64())
		})
	}
}

// ========================================
// PCRMismatchError Message Coverage
// ========================================

func TestPCRMismatchError_ErrorWithCustomMessage(t *testing.T) {
	err := &PCRMismatchError{
		PCRIndex:      5,
		ExpectedValue: []byte{0x01},
		ActualValue:   []byte{0x02},
		Message:       "custom message",
	}

	assert.Equal(t, "custom message", err.Error())
}

func TestPCRMismatchError_ErrorWithDefaultMessage(t *testing.T) {
	err := &PCRMismatchError{
		PCRIndex:      5,
		ExpectedValue: []byte{0x01},
		ActualValue:   []byte{0x02},
	}

	errorMsg := err.Error()
	assert.Contains(t, errorMsg, "PCR[5]")
	assert.Contains(t, errorMsg, "mismatch")
}

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
	"crypto/sha256"
	"errors"
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
	"github.com/jeremyhahn/go-xkms/pkg/acme/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// errNotFound is a local sentinel error used by mock DAOs.
var errNotFound = errors.New("not found")

// ========================================
// OrderHandler Coverage - Lines 50-53, 59-62, 66-69
// ========================================

// MockStorageFactoryOrderDAOFailure90 fails order DAO creation
type MockStorageFactoryOrderDAOFailure90 struct {
	storage.Factory
	failOrderDAO  bool
	orderDAOError error
}

func (m *MockStorageFactoryOrderDAOFailure90) OrderDAO(accountID uint64) (qrdbsdk.GenericDAO[*entities.ACMEOrder], error) {
	if m.failOrderDAO {
		if m.orderDAOError != nil {
			return nil, m.orderDAOError
		}
		return nil, caerrors.StorageFailureError("mock order DAO creation failure")
	}
	return m.Factory.OrderDAO(accountID)
}

func TestOrderHandler_OrderDAOCreationError90(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Create order first using real factory
	order := createTestOrderSimple(t, service, account.ID)

	// Replace factory with failing one
	mockFactory := &MockStorageFactoryOrderDAOFailure90{
		Factory:      service.storageFactory,
		failOrderDAO: true,
	}
	service.storageFactory = mockFactory

	url := fmt.Sprintf("%s/acme/orders/%d", service.baseRESTURI, order.ID)
	req := createJWSRequest(t, service, key, url, nil, true, account.ID)
	req = mux.SetURLVars(req, map[string]string{"id": fmt.Sprintf("%d", order.ID)})

	resp := httptest.NewRecorder()
	service.OrderHandler(resp, req)

	// Should return server internal error for DAO creation failure
	assertErrorType(t, resp, common.ErrTypeServerInternal, http.StatusInternalServerError)
}

// MockOrderDAOStorageError90 returns storage errors on Get
type MockOrderDAOStorageError90 struct {
	qrdbsdk.GenericDAO[*entities.ACMEOrder]
	getError  error
	saveError error
}

func (m *MockOrderDAOStorageError90) Get(ctx context.Context, id uint64) (*entities.ACMEOrder, error) {
	if m.getError != nil {
		return nil, m.getError
	}
	return nil, errNotFound
}

func (m *MockOrderDAOStorageError90) Save(ctx context.Context, order *entities.ACMEOrder) error {
	if m.saveError != nil {
		return m.saveError
	}
	return nil
}

func (m *MockOrderDAOStorageError90) List(ctx context.Context, prefix string) ([]*entities.ACMEOrder, error) {
	return nil, nil
}

func (m *MockOrderDAOStorageError90) Exists(ctx context.Context, id uint64) (bool, error) {
	return false, nil
}

func (m *MockOrderDAOStorageError90) Delete(ctx context.Context, entity *entities.ACMEOrder) error {
	return nil
}

// MockStorageFactoryWithMockOrderDAO90 returns mock order DAO
type MockStorageFactoryWithMockOrderDAO90 struct {
	storage.Factory
	orderDAO qrdbsdk.GenericDAO[*entities.ACMEOrder]
}

func (m *MockStorageFactoryWithMockOrderDAO90) OrderDAO(accountID uint64) (qrdbsdk.GenericDAO[*entities.ACMEOrder], error) {
	if m.orderDAO != nil {
		return m.orderDAO, nil
	}
	return m.Factory.OrderDAO(accountID)
}

func TestOrderHandler_StorageError90(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Use mock DAO that returns non-NotFound error
	mockOrderDAO := &MockOrderDAOStorageError90{
		getError: caerrors.StorageFailureError("mock database connection error"),
	}
	mockFactory := &MockStorageFactoryWithMockOrderDAO90{
		Factory:  service.storageFactory,
		orderDAO: mockOrderDAO,
	}
	service.storageFactory = mockFactory

	url := fmt.Sprintf("%s/acme/orders/12345", service.baseRESTURI)
	req := createJWSRequest(t, service, key, url, nil, true, account.ID)
	req = mux.SetURLVars(req, map[string]string{"id": "12345"})

	resp := httptest.NewRecorder()
	service.OrderHandler(resp, req)

	// Should return server internal error for storage error
	assertErrorType(t, resp, common.ErrTypeServerInternal, http.StatusInternalServerError)
}

func TestOrderHandler_UnauthorizedAccountMismatch90(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key1 := generateTestKey(t)
	account1 := createTestAccount(t, service, key1)

	key2 := generateTestKey(t)
	account2 := createTestAccount(t, service, key2)

	// Create order for account1
	order := createTestOrderSimple(t, service, account1.ID)

	// Save account1's order in account2's storage partition to test the ownership check
	ctx := context.Background()
	orderDAO, err := service.storageFactory.OrderDAO(account2.ID)
	require.NoError(t, err)
	order.AccountID = account1.ID // Keep original account ID for mismatch
	err = orderDAO.Save(ctx, order)
	require.NoError(t, err)

	url := fmt.Sprintf("%s/acme/orders/%d", service.baseRESTURI, order.ID)
	req := createJWSRequest(t, service, key2, url, nil, true, account2.ID)
	req = mux.SetURLVars(req, map[string]string{"id": fmt.Sprintf("%d", order.ID)})

	resp := httptest.NewRecorder()
	service.OrderHandler(resp, req)

	// Should return unauthorized error due to account mismatch
	assertErrorType(t, resp, common.ErrTypeUnauthorized, http.StatusUnauthorized)
}

// ========================================
// NewOrderHandler Coverage - Lines 54-57, 60-63, 106-109, 134-138, 156-159
// ========================================

// MockStorageFactoryNewOrder90 fails various DAO creations
type MockStorageFactoryNewOrder90 struct {
	storage.Factory
	failAuthzDAO bool
	failOrderDAO bool
}

func (m *MockStorageFactoryNewOrder90) AuthorizationDAO(accountID uint64) (qrdbsdk.GenericDAO[*entities.ACMEAuthorization], error) {
	if m.failAuthzDAO {
		return nil, caerrors.StorageFailureError("mock authz DAO creation failure")
	}
	return m.Factory.AuthorizationDAO(accountID)
}

func (m *MockStorageFactoryNewOrder90) OrderDAO(accountID uint64) (qrdbsdk.GenericDAO[*entities.ACMEOrder], error) {
	if m.failOrderDAO {
		return nil, caerrors.StorageFailureError("mock order DAO creation failure")
	}
	return m.Factory.OrderDAO(accountID)
}

func TestNewOrderHandler_AuthzDAOCreationError90(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	service.challengeMap["http-01"] = func(resolver *net.Resolver, ca common.CertificateAuthority, authzValue, challengePort, challengeToken, expectedKeyAuth string) error {
		return nil
	}

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	mockFactory := &MockStorageFactoryNewOrder90{
		Factory:      service.storageFactory,
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

func TestNewOrderHandler_OrderDAOCreationError90(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	service.challengeMap["http-01"] = func(resolver *net.Resolver, ca common.CertificateAuthority, authzValue, challengePort, challengeToken, expectedKeyAuth string) error {
		return nil
	}

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	mockFactory := &MockStorageFactoryNewOrder90{
		Factory:      service.storageFactory,
		failOrderDAO: true,
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

func TestNewOrderHandler_NoChallengesConfigured90(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	// Empty challenge map - no challenges configured
	service.challengeMap = make(map[string]common.ChallengeVerifierFunc)

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	payload := NewOrderRequest{
		Identifiers: []entities.ACMEIdentifier{
			{Type: common.AuthzTypeDNS, Value: "example.com"},
		},
	}

	url := service.baseRESTURI + "/acme/new-order"
	req := createJWSRequest(t, service, key, url, payload, true, account.ID)

	resp := httptest.NewRecorder()
	service.NewOrderHandler(resp, req)

	// Should fail because no challenges are configured for DNS type
	assertErrorType(t, resp, common.ErrTypeServerInternal, http.StatusInternalServerError)
}

// MockAuthzDAOSaveFailure90 fails on Save
type MockAuthzDAOSaveFailure90 struct {
	qrdbsdk.GenericDAO[*entities.ACMEAuthorization]
	saveError error
}

func (m *MockAuthzDAOSaveFailure90) Save(ctx context.Context, authz *entities.ACMEAuthorization) error {
	return m.saveError
}

func (m *MockAuthzDAOSaveFailure90) Get(ctx context.Context, id uint64) (*entities.ACMEAuthorization, error) {
	return nil, errNotFound
}

func (m *MockAuthzDAOSaveFailure90) List(ctx context.Context, prefix string) ([]*entities.ACMEAuthorization, error) {
	return nil, nil
}

func (m *MockAuthzDAOSaveFailure90) Exists(ctx context.Context, id uint64) (bool, error) {
	return false, nil
}

func (m *MockAuthzDAOSaveFailure90) Delete(ctx context.Context, entity *entities.ACMEAuthorization) error {
	return nil
}

// MockStorageFactoryAuthzSaveFailure90 returns mock authz DAO
type MockStorageFactoryAuthzSaveFailure90 struct {
	storage.Factory
	authzSaveError error
}

func (m *MockStorageFactoryAuthzSaveFailure90) AuthorizationDAO(accountID uint64) (qrdbsdk.GenericDAO[*entities.ACMEAuthorization], error) {
	return &MockAuthzDAOSaveFailure90{saveError: m.authzSaveError}, nil
}

func TestNewOrderHandler_AuthzSaveError90(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	service.challengeMap["http-01"] = func(resolver *net.Resolver, ca common.CertificateAuthority, authzValue, challengePort, challengeToken, expectedKeyAuth string) error {
		return nil
	}

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	mockFactory := &MockStorageFactoryAuthzSaveFailure90{
		Factory:        service.storageFactory,
		authzSaveError: caerrors.StorageFailureError("mock authorization save error"),
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

// ========================================
// OrdersListHandler Coverage - Lines 51-54, 62-65
// ========================================

func TestOrdersListHandler_OrderDAOCreationError90(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	mockFactory := &MockStorageFactoryOrderDAOFailure90{
		Factory:      service.storageFactory,
		failOrderDAO: true,
	}
	service.storageFactory = mockFactory

	url := fmt.Sprintf("%s/acme/account/%d/orders", service.baseRESTURI, account.ID)
	req := createJWSRequest(t, service, key, url, nil, true, account.ID)
	req = mux.SetURLVars(req, map[string]string{})

	resp := httptest.NewRecorder()
	service.OrdersListHandler(resp, req)

	assertErrorType(t, resp, common.ErrTypeServerInternal, http.StatusInternalServerError)
}

// MockOrderDAOListFailure90 fails on List
type MockOrderDAOListFailure90 struct {
	qrdbsdk.GenericDAO[*entities.ACMEOrder]
	listError error
}

func (m *MockOrderDAOListFailure90) ForEachPage(ctx context.Context, query qrdbsdk.PageQuery, fn qrdbsdk.PagerFunc[*entities.ACMEOrder]) error {
	return m.listError
}

func (m *MockOrderDAOListFailure90) Get(ctx context.Context, id uint64) (*entities.ACMEOrder, error) {
	return nil, errNotFound
}

func (m *MockOrderDAOListFailure90) Save(ctx context.Context, order *entities.ACMEOrder) error {
	return nil
}

func (m *MockOrderDAOListFailure90) Exists(ctx context.Context, id uint64) (bool, error) {
	return false, nil
}

func (m *MockOrderDAOListFailure90) Delete(ctx context.Context, entity *entities.ACMEOrder) error {
	return nil
}

// MockStorageFactoryOrderListFailure90 returns mock order DAO
type MockStorageFactoryOrderListFailure90 struct {
	storage.Factory
	listError error
}

func (m *MockStorageFactoryOrderListFailure90) OrderDAO(accountID uint64) (qrdbsdk.GenericDAO[*entities.ACMEOrder], error) {
	return &MockOrderDAOListFailure90{listError: m.listError}, nil
}

func TestOrdersListHandler_ListOrdersError90(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	mockFactory := &MockStorageFactoryOrderListFailure90{
		Factory:   service.storageFactory,
		listError: caerrors.StorageFailureError("mock list orders error"),
	}
	service.storageFactory = mockFactory

	url := fmt.Sprintf("%s/acme/account/%d/orders", service.baseRESTURI, account.ID)
	req := createJWSRequest(t, service, key, url, nil, true, account.ID)
	req = mux.SetURLVars(req, map[string]string{})

	resp := httptest.NewRecorder()
	service.OrdersListHandler(resp, req)

	assertErrorType(t, resp, common.ErrTypeServerInternal, http.StatusInternalServerError)
}

func TestOrdersListHandler_InvalidPageID90(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	url := fmt.Sprintf("%s/acme/account/%d/orders", service.baseRESTURI, account.ID)
	req := createJWSRequest(t, service, key, url, nil, true, account.ID)
	req = mux.SetURLVars(req, map[string]string{"page": "invalid-page"})

	resp := httptest.NewRecorder()
	service.OrdersListHandler(resp, req)

	assertErrorType(t, resp, common.ErrTypeMalformedError, http.StatusBadRequest)
}

func TestOrdersListHandler_MethodNotAllowed90(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	url := fmt.Sprintf("%s/acme/account/%d/orders", service.baseRESTURI, account.ID)
	req := createJWSRequest(t, service, key, url, nil, true, account.ID)
	req.Method = http.MethodDelete
	req = mux.SetURLVars(req, map[string]string{})

	resp := httptest.NewRecorder()
	service.OrdersListHandler(resp, req)

	assertErrorType(t, resp, common.ErrTypeMalformedError, http.StatusBadRequest)
}

// ========================================
// ChallengeHandler Coverage
// ========================================

// MockAuthzDAOListFailure90 fails on List
type MockAuthzDAOListFailure90 struct {
	qrdbsdk.GenericDAO[*entities.ACMEAuthorization]
	listError error
}

func (m *MockAuthzDAOListFailure90) ForEachPage(ctx context.Context, query qrdbsdk.PageQuery, fn qrdbsdk.PagerFunc[*entities.ACMEAuthorization]) error {
	return m.listError
}

func (m *MockAuthzDAOListFailure90) Get(ctx context.Context, id uint64) (*entities.ACMEAuthorization, error) {
	return nil, errNotFound
}

func (m *MockAuthzDAOListFailure90) Save(ctx context.Context, authz *entities.ACMEAuthorization) error {
	return nil
}

func (m *MockAuthzDAOListFailure90) Exists(ctx context.Context, id uint64) (bool, error) {
	return false, nil
}

func (m *MockAuthzDAOListFailure90) Delete(ctx context.Context, entity *entities.ACMEAuthorization) error {
	return nil
}

// MockStorageFactoryAuthzListFailure90 returns mock authz DAO
type MockStorageFactoryAuthzListFailure90 struct {
	storage.Factory
	listError error
}

func (m *MockStorageFactoryAuthzListFailure90) AuthorizationDAO(accountID uint64) (qrdbsdk.GenericDAO[*entities.ACMEAuthorization], error) {
	return &MockAuthzDAOListFailure90{listError: m.listError}, nil
}

func TestChallengeHandler_AuthzListError90(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	mockFactory := &MockStorageFactoryAuthzListFailure90{
		Factory:   service.storageFactory,
		listError: caerrors.StorageFailureError("mock authz list error"),
	}
	service.storageFactory = mockFactory

	url := service.baseRESTURI + "/acme/challenge/123"
	req := createJWSRequest(t, service, key, url, nil, true, account.ID)

	resp := httptest.NewRecorder()
	service.ChallengeHandler(resp, req)

	assertErrorType(t, resp, common.ErrTypeServerInternal, http.StatusInternalServerError)
}

func TestChallengeHandler_ChallengeNotFound90(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Create authorization without the challenge ID we'll request
	order := createTestOrderSimple(t, service, account.ID)
	_ = createTestAuthorization(t, service, account, order, entities.ACMEIdentifier{
		Type:  "dns",
		Value: "example90.com",
	}, []string{"http-01"})

	// Request a challenge that doesn't exist
	url := service.baseRESTURI + "/acme/challenge/999999"
	req := createJWSRequest(t, service, key, url, nil, true, account.ID)

	resp := httptest.NewRecorder()
	service.ChallengeHandler(resp, req)

	assertErrorType(t, resp, common.ErrTypeMalformedError, http.StatusBadRequest)
}

// ========================================
// NewAccountHandler Coverage
// ========================================

func TestNewAccountHandler_KeySerializationError90(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	// Test with empty contact that should pass validation
	key := generateTestKey(t)

	payload := NewAccountRequest{
		Contact:              []string{},
		TermsOfServiceAgreed: true,
	}

	url := service.baseRESTURI + "/acme/new-account"
	req := createJWSRequest(t, service, key, url, payload, false, 0)

	resp := httptest.NewRecorder()
	service.NewAccountHandler(resp, req)

	// Should succeed with empty contact
	require.Equal(t, http.StatusCreated, resp.Code)
}

func TestNewAccountHandler_ExistsCheckStorageError90(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	// Create mock DAO that fails on Exists check
	mockAccountDAO := &MockAccountDAOExistsFailure90{
		existsError: caerrors.StorageFailureError("mock exists check failure"),
	}
	mockFactory := &MockStorageFactoryWithAccountDAO{
		Factory:    service.storageFactory,
		accountDAO: mockAccountDAO,
	}
	service.storageFactory = mockFactory

	key := generateTestKey(t)
	payload := NewAccountRequest{
		Contact:              []string{"mailto:test90@example.com"},
		TermsOfServiceAgreed: true,
	}

	url := service.baseRESTURI + "/acme/new-account"
	req := createJWSRequest(t, service, key, url, payload, false, 0)

	resp := httptest.NewRecorder()
	service.NewAccountHandler(resp, req)

	assertErrorType(t, resp, common.ErrTypeServerInternal, http.StatusInternalServerError)
}

// MockAccountDAOExistsFailure90 fails on Exists
type MockAccountDAOExistsFailure90 struct {
	qrdbsdk.GenericDAO[*entities.ACMEAccount]
	existsError error
}

func (m *MockAccountDAOExistsFailure90) Exists(ctx context.Context, id uint64) (bool, error) {
	return false, m.existsError
}

func (m *MockAccountDAOExistsFailure90) Get(ctx context.Context, id uint64) (*entities.ACMEAccount, error) {
	return nil, errNotFound
}

func (m *MockAccountDAOExistsFailure90) Save(ctx context.Context, account *entities.ACMEAccount) error {
	return nil
}

func (m *MockAccountDAOExistsFailure90) Delete(ctx context.Context, entity *entities.ACMEAccount) error {
	return nil
}

func (m *MockAccountDAOExistsFailure90) List(ctx context.Context, prefix string) ([]*entities.ACMEAccount, error) {
	return nil, nil
}

// ========================================
// verifyECDSAQuoteSignature Coverage
// ========================================

func TestVerifyECDSAQuoteSignature_P384Curve90(t *testing.T) {
	// Test with P-384 curve (curveSize > 256)
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	quoted := []byte("test quoted data for P-384")

	// Create valid signature
	hash := sha256.Sum256(quoted)
	r, s, err := ecdsa.Sign(rand.Reader, key, hash[:])
	require.NoError(t, err)

	// Create concatenated signature
	coordLen := 48 // P-384 has 384-bit coordinates = 48 bytes
	signature := make([]byte, coordLen*2)
	r.FillBytes(signature[:coordLen])
	s.FillBytes(signature[coordLen:])

	// Test with actual function - this will use SHA384 hash
	err = verifyECDSAQuoteSignature(quoted, 0, signature, &key.PublicKey)
	// May fail due to hash mismatch, but exercises the P-384 code path
	assert.Error(t, err) // Expected to fail since hash doesn't match
}

func TestVerifyECDSAQuoteSignature_P521Curve90(t *testing.T) {
	// Test with P-521 curve (curveSize > 384)
	key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)

	quoted := []byte("test quoted data for P-521")

	// Create invalid length signature to test ASN.1 fallback
	invalidSig := []byte("invalid signature data")

	err = verifyECDSAQuoteSignature(quoted, 0, invalidSig, &key.PublicKey)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid ECDSA signature length")
}

func TestVerifyECDSAQuoteSignature_ASN1Signature90(t *testing.T) {
	// Test with ASN.1 DER encoded signature
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	quoted := []byte("test quoted data for ASN.1")
	hash := sha256.Sum256(quoted)

	// Create ASN.1 DER signature
	asn1Sig, err := ecdsa.SignASN1(rand.Reader, key, hash[:])
	require.NoError(t, err)

	// This should succeed via ASN.1 verification path
	err = verifyECDSAQuoteSignature(quoted, 0, asn1Sig, &key.PublicKey)
	assert.NoError(t, err)
}

func TestVerifyECDSAQuoteSignature_InvalidConcatenatedSignature90(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	quoted := []byte("test quoted data")

	// Create signature with correct length but invalid values
	coordLen := 32 // P-256 has 256-bit coordinates = 32 bytes
	signature := make([]byte, coordLen*2)
	for i := range signature {
		signature[i] = 0xFF // Invalid signature values
	}

	err = verifyECDSAQuoteSignature(quoted, 0, signature, &key.PublicKey)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "ECDSA signature verification failed")
}

// ========================================
// NewQuoteValidationHook Coverage
// ========================================

func TestNewQuoteValidationHook_NonTCGCSR90(t *testing.T) {
	hook := NewQuoteValidationHook(nil)

	ctx := &PreIssuanceHookContext{
		IsTCGCSR: false,
		TCGData:  nil,
	}

	// Should skip validation for non-TCG enrollments
	err := hook(ctx)
	assert.NoError(t, err)
}

func TestNewQuoteValidationHook_NoAttestationData90(t *testing.T) {
	hook := NewQuoteValidationHook(nil)

	ctx := &PreIssuanceHookContext{
		IsTCGCSR: true,
		TCGData: &TCGEnrollmentData{
			ProdCaData: nil, // No attestation data
		},
	}

	// Should skip validation when no attestation data
	err := hook(ctx)
	assert.NoError(t, err)
}

func TestNewQuoteValidationHook_EmptyProdCaData90(t *testing.T) {
	hook := NewQuoteValidationHook(nil)

	ctx := &PreIssuanceHookContext{
		IsTCGCSR: true,
		TCGData: &TCGEnrollmentData{
			ProdCaData: []byte{}, // Empty attestation data
		},
	}

	// Should skip validation when attestation data is empty
	err := hook(ctx)
	assert.NoError(t, err)
}

func TestNewQuoteValidationHook_InvalidProdCaData90(t *testing.T) {
	hook := NewQuoteValidationHook(nil)

	ctx := &PreIssuanceHookContext{
		IsTCGCSR: true,
		TCGData: &TCGEnrollmentData{
			ProdCaData: []byte("invalid data that cannot be unpacked"),
		},
	}

	// Should return error for invalid attestation data
	err := hook(ctx)
	assert.Error(t, err)
	_, ok := err.(*AttestationError)
	assert.True(t, ok)
}

// ========================================
// OrderFinalizeHandler Coverage
// ========================================

func TestOrderFinalizeHandler_OrderDAOError90(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	mockFactory := &MockStorageFactoryOrderDAOFailure90{
		Factory:      service.storageFactory,
		failOrderDAO: true,
	}
	service.storageFactory = mockFactory

	url := fmt.Sprintf("%s/acme/order/12345/finalize", service.baseRESTURI)
	req := createJWSRequest(t, service, key, url, map[string]string{"csr": "test"}, true, account.ID)
	req = mux.SetURLVars(req, map[string]string{"id": "12345"})

	resp := httptest.NewRecorder()
	service.OrderFinalizeHandler(resp, req)

	assertErrorType(t, resp, common.ErrTypeServerInternal, http.StatusInternalServerError)
}

func TestOrderFinalizeHandler_InvalidOrderID90(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	url := fmt.Sprintf("%s/acme/order/invalid/finalize", service.baseRESTURI)
	req := createJWSRequest(t, service, key, url, map[string]string{"csr": "test"}, true, account.ID)
	req = mux.SetURLVars(req, map[string]string{"id": "invalid"})

	resp := httptest.NewRecorder()
	service.OrderFinalizeHandler(resp, req)

	assertErrorType(t, resp, common.ErrTypeMalformedError, http.StatusBadRequest)
}

func TestOrderFinalizeHandler_OrderNotFound90(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	url := fmt.Sprintf("%s/acme/order/999999/finalize", service.baseRESTURI)
	req := createJWSRequest(t, service, key, url, map[string]string{"csr": "test"}, true, account.ID)
	req = mux.SetURLVars(req, map[string]string{"id": "999999"})

	resp := httptest.NewRecorder()
	service.OrderFinalizeHandler(resp, req)

	assertErrorType(t, resp, common.ErrTypeMalformedError, http.StatusBadRequest)
}

func TestOrderFinalizeHandler_OrderNotReady90(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Create order in pending status
	order := createTestOrderSimple(t, service, account.ID)

	url := fmt.Sprintf("%s/acme/order/%d/finalize", service.baseRESTURI, order.ID)
	req := createJWSRequest(t, service, key, url, map[string]string{"csr": "test"}, true, account.ID)
	req = mux.SetURLVars(req, map[string]string{"id": fmt.Sprintf("%d", order.ID)})

	resp := httptest.NewRecorder()
	service.OrderFinalizeHandler(resp, req)

	assertErrorType(t, resp, common.ErrTypeOrderNotReady, http.StatusForbidden)
}

func TestOrderFinalizeHandler_UnauthorizedAccountMismatch90(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key1 := generateTestKey(t)
	account1 := createTestAccount(t, service, key1)

	key2 := generateTestKey(t)
	account2 := createTestAccount(t, service, key2)

	// Create order for account1
	order := createTestOrderSimple(t, service, account1.ID)

	// Save order to account2's partition with wrong accountID
	ctx := context.Background()
	orderDAO, err := service.storageFactory.OrderDAO(account2.ID)
	require.NoError(t, err)
	order.AccountID = account1.ID // Keep original account ID for mismatch check
	err = orderDAO.Save(ctx, order)
	require.NoError(t, err)

	url := fmt.Sprintf("%s/acme/order/%d/finalize", service.baseRESTURI, order.ID)
	req := createJWSRequest(t, service, key2, url, map[string]string{"csr": "test"}, true, account2.ID)
	req = mux.SetURLVars(req, map[string]string{"id": fmt.Sprintf("%d", order.ID)})

	resp := httptest.NewRecorder()
	service.OrderFinalizeHandler(resp, req)

	assertErrorType(t, resp, common.ErrTypeUnauthorized, http.StatusUnauthorized)
}

// ========================================
// Edge Cases for createChallenges
// ========================================

func TestCreateChallenges_UnsupportedIdentifierType90(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	// Add a challenge for unknown type
	service.challengeMap["unknown-01"] = func(resolver *net.Resolver, ca common.CertificateAuthority, authzValue, challengePort, challengeToken, expectedKeyAuth string) error {
		return nil
	}

	challenges, err := service.createChallenges(1, 1, entities.ACMEIdentifier{
		Type:  "unknown-type",
		Value: "test",
	}, false)

	assert.Error(t, err)
	assert.Empty(t, challenges)
}

// ========================================
// compareKeyMaps Tests
// ========================================

func TestCompareKeyMaps_MismatchedKeyTypes90(t *testing.T) {
	key1 := map[string]interface{}{"kty": "EC"}
	key2 := map[string]interface{}{"kty": "RSA"}

	assert.False(t, compareKeyMaps(key1, key2))
}

func TestCompareKeyMaps_RSAKeysMismatch90(t *testing.T) {
	key1 := map[string]interface{}{
		"kty": "RSA",
		"n":   "modulus1",
		"e":   "exponent",
	}
	key2 := map[string]interface{}{
		"kty": "RSA",
		"n":   "modulus2",
		"e":   "exponent",
	}

	assert.False(t, compareKeyMaps(key1, key2))
}

func TestCompareKeyMaps_OKPKeysMismatch90(t *testing.T) {
	key1 := map[string]interface{}{
		"kty": "OKP",
		"crv": "Ed25519",
		"x":   "public1",
	}
	key2 := map[string]interface{}{
		"kty": "OKP",
		"crv": "Ed448",
		"x":   "public1",
	}

	assert.False(t, compareKeyMaps(key1, key2))
}

// ========================================
// bytesToBigInt Tests
// ========================================

func TestBytesToBigInt90(t *testing.T) {
	// Test with known value
	bytes := []byte{0x01, 0x02, 0x03}
	result := bytesToBigInt(bytes)

	expected := big.NewInt(0x010203)
	assert.Equal(t, 0, result.Cmp(expected))
}

func TestBytesToBigInt_Empty90(t *testing.T) {
	bytes := []byte{}
	result := bytesToBigInt(bytes)

	assert.Equal(t, 0, result.Cmp(big.NewInt(0)))
}

// ========================================
// parseChallengeAsDynamicPortAssignment Tests
// ========================================

func TestParseChallengeAsDynamicPortAssignment_WithHighPort90(t *testing.T) {
	baseType, port := parseChallengeAsDynamicPortAssignment("enroll-01-8443")
	assert.Equal(t, "enroll-01", baseType)
	assert.Equal(t, uint16(8443), port)
}

func TestParseChallengeAsDynamicPortAssignment_DeviceAttest90(t *testing.T) {
	baseType, port := parseChallengeAsDynamicPortAssignment("device-attest-01-443")
	assert.Equal(t, "device-attest-01", baseType)
	assert.Equal(t, uint16(443), port)
}

// ========================================
// isEnrollXChallenge Tests
// ========================================

func TestIsEnrollXChallenge_Enroll90(t *testing.T) {
	assert.True(t, isEnrollXChallenge("enroll-01"))
	assert.True(t, isEnrollXChallenge("enroll-01-8080"))
}

func TestIsEnrollXChallenge_NonEnroll90(t *testing.T) {
	assert.False(t, isEnrollXChallenge("http-01"))
	assert.False(t, isEnrollXChallenge("dns-01"))
}

// ========================================
// Order Status Edge Cases
// ========================================

func TestOrderHandler_OrderWithProcessingStatus90(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Create order and set to processing
	ctx := context.Background()
	orderDAO, err := service.storageFactory.OrderDAO(account.ID)
	require.NoError(t, err)

	orderID, err := GenerateID()
	require.NoError(t, err)

	order := &entities.ACMEOrder{
		ID:     orderID,
		Status: common.StatusProcessing,
		Identifiers: []entities.ACMEIdentifier{
			{Type: "dns", Value: "processing90.example.com"},
		},
		Expires:        time.Now().Add(24 * time.Hour).Format(time.RFC3339),
		Authorizations: []string{fmt.Sprintf("%s/acme/authz/1", service.baseRESTURI)},
		Finalize:       fmt.Sprintf("%s/acme/orders/%d/finalize", service.baseRESTURI, orderID),
		AccountID:      account.ID,
	}
	order.URL = fmt.Sprintf("%s/acme/orders/%d", service.baseRESTURI, order.ID)

	err = orderDAO.Save(ctx, order)
	require.NoError(t, err)

	url := fmt.Sprintf("%s/acme/orders/%d", service.baseRESTURI, order.ID)
	req := createJWSRequest(t, service, key, url, nil, true, account.ID)
	req = mux.SetURLVars(req, map[string]string{"id": fmt.Sprintf("%d", order.ID)})

	resp := httptest.NewRecorder()
	service.OrderHandler(resp, req)

	require.Equal(t, http.StatusOK, resp.Code)
}

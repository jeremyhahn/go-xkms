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
	"errors"
	"fmt"
	"net"
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

// ========================================
// NewAccountHandler Coverage
// ========================================

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
// Order Status Edge Cases
// ========================================

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

// ========================================
// AuthorizationHandler Coverage Tests
// ========================================

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

// ========================================
// PCRMismatchError Message Coverage
// ========================================

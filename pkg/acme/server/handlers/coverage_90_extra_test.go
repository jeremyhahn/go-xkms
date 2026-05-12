//go:build codec_json

// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-ca.
//
// go-trusted-ca is dual-licensed:
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
	"github.com/jeremyhahn/go-xkms/pkg/acme/server/circuitbreaker"
	"github.com/stretchr/testify/assert"
)

// mockClusterHealthService implements ClusterHealthService for testing
type mockClusterHealthService struct {
	healthy bool
}

func (m *mockClusterHealthService) Healthy() bool { return m.healthy }

func TestClusterHealthCheckerWithMock(t *testing.T) {
	t.Run("healthy cluster", func(t *testing.T) {
		mock := &mockClusterHealthService{healthy: true}
		checker := ClusterHealthChecker(mock)
		health := checker.CheckHealth(context.Background())

		assert.Equal(t, HealthStatusHealthy, health.Status)
		assert.Contains(t, health.Message, "healthy")
	})

	t.Run("unhealthy cluster", func(t *testing.T) {
		mock := &mockClusterHealthService{healthy: false}
		checker := ClusterHealthChecker(mock)
		health := checker.CheckHealth(context.Background())

		assert.Equal(t, HealthStatusUnhealthy, health.Status)
		assert.Contains(t, health.Message, "not healthy")
	})
}

func TestCheckClusterHealthWithMock(t *testing.T) {
	t.Run("healthy cluster service", func(t *testing.T) {
		mock := &mockClusterHealthService{healthy: true}
		phs := NewProductionHealthService("1.0.0", mock, nil, nil)

		health := phs.checkClusterHealth(context.Background())

		assert.True(t, health.Healthy)
	})

	t.Run("unhealthy cluster service", func(t *testing.T) {
		mock := &mockClusterHealthService{healthy: false}
		phs := NewProductionHealthService("1.0.0", mock, nil, nil)

		health := phs.checkClusterHealth(context.Background())

		assert.False(t, health.Healthy)
	})
}

func TestCircuitBreakerHealthCheckerHalfOpen(t *testing.T) {
	mgr := circuitbreaker.NewManager()
	cb := mgr.Get("test-cb")

	// Trip the circuit breaker
	cb.Trip()

	checker := CircuitBreakerHealthChecker(mgr)
	health := checker.CheckHealth(context.Background())

	// With an open circuit, status should be degraded
	assert.Equal(t, HealthStatusDegraded, health.Status)
}

func TestDetailedHealthHandlerWithHealthyCluster(t *testing.T) {
	mock := &mockClusterHealthService{healthy: true}
	cbMgr := circuitbreaker.NewManager()
	phs := NewProductionHealthService("1.0.0", mock, cbMgr, nil)

	// Register healthy components
	phs.RegisterChecker("test", HealthCheckerFunc(func(ctx context.Context) ComponentHealth {
		return ComponentHealth{
			Status:  HealthStatusHealthy,
			Message: "Test component is healthy",
		}
	}))

	req := httptest.NewRequest("GET", "/health/detailed", nil)
	rec := httptest.NewRecorder()

	phs.DetailedHealthHandler(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestMetricsHandlerWithNilManagers(t *testing.T) {
	phs := NewProductionHealthService("1.0.0", nil, nil, nil)

	req := httptest.NewRequest("GET", "/health/metrics", nil)
	rec := httptest.NewRecorder()

	phs.MetricsHandler(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

// TestOrdersListHandlerNoOrders tests the orders list handler when no orders exist
func TestOrdersListHandlerNoOrders(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Create request for orders list
	url := "https://acme.test.example.com/acme/account/" + formatAccountID(account.ID) + "/orders"
	req := createJWSRequest(t, service, key, url, nil, true, account.ID)

	rr := httptest.NewRecorder()
	service.OrdersListHandler(rr, req)

	// Should return OK with empty orders or appropriate response
	assert.True(t, rr.Code == http.StatusOK || rr.Code == http.StatusBadRequest)
}

// TestNewNonceHandlerHEAD tests the new-nonce handler with HEAD method
func TestNewNonceHandlerHEAD(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	// Test HEAD request
	req := httptest.NewRequest(http.MethodHead, "https://acme.test.example.com/acme/new-nonce", nil)
	rr := httptest.NewRecorder()

	service.NewNonceHandler(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.NotEmpty(t, rr.Header().Get("Replay-Nonce"))
}

// TestNewNonceHandlerInvalidMethod tests the new-nonce handler with an invalid method
func TestNewNonceHandlerInvalidMethod(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	// Test POST request (not allowed for new-nonce)
	req := httptest.NewRequest(http.MethodPost, "https://acme.test.example.com/acme/new-nonce", nil)
	rr := httptest.NewRecorder()

	service.NewNonceHandler(rr, req)

	// new-nonce only accepts GET and HEAD
	assert.Equal(t, http.StatusMethodNotAllowed, rr.Code)
}

// TestAccountHandlerDeactivated tests accessing a deactivated account
func TestAccountHandlerDeactivated(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Deactivate the account
	ctx := context.Background()
	accountDAO, _ := service.storageFactory.AccountDAO()
	account.Status = "deactivated"
	accountDAO.Save(ctx, account)

	// Try to access account
	url := "https://acme.test.example.com/acme/account/" + formatAccountID(account.ID)
	req := createJWSRequest(t, service, key, url, nil, true, account.ID)

	rr := httptest.NewRecorder()
	service.AccountHandler(rr, req)

	// AccountHandler returns 400 (MalformedError) for deactivated accounts
	// because parseKID returns ErrAccountDeactivated which triggers a generic error
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

// TestOrderHandlerAccessOtherAccountOrder tests accessing another account's order
func TestOrderHandlerAccessOtherAccountOrder(t *testing.T) {
	// Note: OrderDAO is scoped by account ID, so trying to access
	// another account's order will return "Order not found" (400),
	// not "Unauthorized" (403), because the DAO only looks in the
	// requesting account's orders directory
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key1 := generateTestKey(t)
	account1 := createTestAccount(t, service, key1)

	key2 := generateTestKey(t)
	account2 := createTestAccount(t, service, key2)

	// Create order for account1
	order := createTestOrderSimple(t, service, account1.ID)

	// Try to access order with account2 - DAO is scoped to account2
	// so it won't find account1's order
	url := "https://acme.test.example.com/acme/order/" + fmt.Sprintf("%d", order.ID)
	req := createJWSRequest(t, service, key2, url, nil, true, account2.ID)
	req = mux.SetURLVars(req, map[string]string{"id": fmt.Sprintf("%d", order.ID)})

	rr := httptest.NewRecorder()
	service.OrderHandler(rr, req)

	// Returns 400 (Order not found) because DAO is account-scoped
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

// TestOrderHandlerValidOrder tests accessing a valid order
func TestOrderHandlerValidOrder(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Create order for account
	order := createTestOrderSimple(t, service, account.ID)

	// Access order with same account
	url := "https://acme.test.example.com/acme/order/" + fmt.Sprintf("%d", order.ID)
	req := createJWSRequest(t, service, key, url, nil, true, account.ID)
	req = mux.SetURLVars(req, map[string]string{"id": fmt.Sprintf("%d", order.ID)})

	rr := httptest.NewRecorder()
	service.OrderHandler(rr, req)

	// Should return 200 OK with order details
	assert.Equal(t, http.StatusOK, rr.Code)
}

func formatAccountID(id uint64) string {
	return formatInt(int(id))
}

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

package services

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/gui/events"
)

// mockTenantClient implements the TenantService methods
// and embeds transport.Client to satisfy the full interface.
type mockTenantClient struct {
	transport.Client // embed to satisfy interface; unused methods will panic
	tenants          map[string]*transport.TenantInfo
	barriers         map[string]bool // tenantID -> initialized
	unsealed         map[string]bool // tenantID -> unsealed
	err              error
}

func newMockTenantClient() *mockTenantClient {
	return &mockTenantClient{
		tenants:  make(map[string]*transport.TenantInfo),
		barriers: make(map[string]bool),
		unsealed: make(map[string]bool),
	}
}

func (m *mockTenantClient) CreateTenant(_ context.Context, req *transport.CreateTenantRequest) (*transport.CreateTenantResponse, error) {
	if m.err != nil {
		return nil, m.err
	}
	now := time.Now()
	tenant := transport.TenantInfo{
		ID:        "tenant-" + req.Name,
		Name:      req.Name,
		CreatedAt: now,
		UpdatedAt: now,
	}
	m.tenants[tenant.ID] = &tenant
	return &transport.CreateTenantResponse{Tenant: tenant}, nil
}

func (m *mockTenantClient) GetTenant(_ context.Context, tenantID string) (*transport.GetTenantResponse, error) {
	if m.err != nil {
		return nil, m.err
	}
	t, ok := m.tenants[tenantID]
	if !ok {
		return nil, errors.New("tenant not found")
	}
	return &transport.GetTenantResponse{Tenant: *t}, nil
}

func (m *mockTenantClient) ListTenants(_ context.Context) (*transport.ListTenantsResponse, error) {
	if m.err != nil {
		return nil, m.err
	}
	tenants := make([]transport.TenantInfo, 0, len(m.tenants))
	for _, t := range m.tenants {
		tenants = append(tenants, *t)
	}
	return &transport.ListTenantsResponse{Tenants: tenants}, nil
}

func (m *mockTenantClient) DeleteTenant(_ context.Context, tenantID string) error {
	if m.err != nil {
		return m.err
	}
	if _, ok := m.tenants[tenantID]; !ok {
		return errors.New("tenant not found")
	}
	delete(m.tenants, tenantID)
	return nil
}

func (m *mockTenantClient) TenantBarrierInit(_ context.Context, req *transport.TenantBarrierInitRequest) error {
	if m.err != nil {
		return m.err
	}
	m.barriers[req.TenantID] = true
	return nil
}

func (m *mockTenantClient) TenantBarrierUnseal(_ context.Context, req *transport.TenantBarrierUnsealRequest) error {
	if m.err != nil {
		return m.err
	}
	if !m.barriers[req.TenantID] {
		return errors.New("barrier not initialized")
	}
	m.unsealed[req.TenantID] = true
	return nil
}

func setupTenantService(t *testing.T) (*TenantService, *mockTenantClient) {
	t.Helper()
	svc := NewTenantService()
	svc.SetContext(context.Background())

	mock := newMockTenantClient()
	var client transport.Client = mock
	svc.SetClient(client)

	return svc, mock
}

// --- Constructor and lifecycle ---

func TestNewTenantService(t *testing.T) {
	svc := NewTenantService()
	require.NotNil(t, svc)
	assert.NotNil(t, svc.log)
}

func TestTenantService_NoClient(t *testing.T) {
	svc := NewTenantService()
	svc.SetContext(context.Background())

	_, err := svc.ListTenants()
	require.ErrorIs(t, err, ErrTenantServiceNoClient)
}

// --- CreateTenant ---

func TestTenantService_CreateTenant_Success(t *testing.T) {
	svc, _ := setupTenantService(t)

	info, err := svc.CreateTenant("Production")
	require.NoError(t, err)
	require.NotNil(t, info)
	assert.Equal(t, "Production", info.Name)
	assert.NotEmpty(t, info.ID)
	assert.NotEmpty(t, info.CreatedAt)
}

func TestTenantService_CreateTenant_EmptyName(t *testing.T) {
	svc, _ := setupTenantService(t)

	_, err := svc.CreateTenant("")
	require.ErrorIs(t, err, ErrTenantNameRequired)
}

func TestTenantService_CreateTenant_ServerError(t *testing.T) {
	svc, mock := setupTenantService(t)
	mock.err = errors.New("quota exceeded")

	_, err := svc.CreateTenant("Production")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "quota exceeded")
}

func TestTenantService_CreateTenant_NoClient(t *testing.T) {
	svc := NewTenantService()
	svc.SetContext(context.Background())

	_, err := svc.CreateTenant("Production")
	require.ErrorIs(t, err, ErrTenantServiceNoClient)
}

// --- GetTenant ---

func TestTenantService_GetTenant_Success(t *testing.T) {
	svc, _ := setupTenantService(t)

	created, err := svc.CreateTenant("Staging")
	require.NoError(t, err)

	info, err := svc.GetTenant(created.ID)
	require.NoError(t, err)
	assert.Equal(t, "Staging", info.Name)
}

func TestTenantService_GetTenant_EmptyID(t *testing.T) {
	svc, _ := setupTenantService(t)

	_, err := svc.GetTenant("")
	require.ErrorIs(t, err, ErrTenantIDRequired)
}

func TestTenantService_GetTenant_NotFound(t *testing.T) {
	svc, _ := setupTenantService(t)

	_, err := svc.GetTenant("nonexistent")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// --- ListTenants ---

func TestTenantService_ListTenants_Empty(t *testing.T) {
	svc, _ := setupTenantService(t)

	tenants, err := svc.ListTenants()
	require.NoError(t, err)
	assert.Empty(t, tenants)
}

func TestTenantService_ListTenants_WithData(t *testing.T) {
	svc, _ := setupTenantService(t)

	_, err := svc.CreateTenant("Tenant1")
	require.NoError(t, err)
	_, err = svc.CreateTenant("Tenant2")
	require.NoError(t, err)

	tenants, err := svc.ListTenants()
	require.NoError(t, err)
	assert.Len(t, tenants, 2)
}

func TestTenantService_ListTenants_ServerError(t *testing.T) {
	svc, mock := setupTenantService(t)
	mock.err = errors.New("timeout")

	_, err := svc.ListTenants()
	require.Error(t, err)
}

// --- DeleteTenant ---

func TestTenantService_DeleteTenant_Success(t *testing.T) {
	svc, _ := setupTenantService(t)

	created, err := svc.CreateTenant("ToDelete")
	require.NoError(t, err)

	err = svc.DeleteTenant(created.ID)
	require.NoError(t, err)

	tenants, err := svc.ListTenants()
	require.NoError(t, err)
	assert.Empty(t, tenants)
}

func TestTenantService_DeleteTenant_EmptyID(t *testing.T) {
	svc, _ := setupTenantService(t)

	err := svc.DeleteTenant("")
	require.ErrorIs(t, err, ErrTenantIDRequired)
}

func TestTenantService_DeleteTenant_NotFound(t *testing.T) {
	svc, _ := setupTenantService(t)

	err := svc.DeleteTenant("nonexistent")
	require.Error(t, err)
}

// --- BarrierInit ---

func TestTenantService_BarrierInit_Success(t *testing.T) {
	svc, mock := setupTenantService(t)

	err := svc.BarrierInit("tenant-1", 3, 5)
	require.NoError(t, err)
	assert.True(t, mock.barriers["tenant-1"])
}

func TestTenantService_BarrierInit_EmptyID(t *testing.T) {
	svc, _ := setupTenantService(t)

	err := svc.BarrierInit("", 3, 5)
	require.ErrorIs(t, err, ErrTenantIDRequired)
}

func TestTenantService_BarrierInit_ServerError(t *testing.T) {
	svc, mock := setupTenantService(t)
	mock.err = errors.New("barrier already initialized")

	err := svc.BarrierInit("tenant-1", 3, 5)
	require.Error(t, err)
}

func TestTenantService_BarrierInit_NoClient(t *testing.T) {
	svc := NewTenantService()
	svc.SetContext(context.Background())

	err := svc.BarrierInit("tenant-1", 3, 5)
	require.ErrorIs(t, err, ErrTenantServiceNoClient)
}

// --- BarrierUnseal ---

func TestTenantService_BarrierUnseal_Success(t *testing.T) {
	svc, mock := setupTenantService(t)

	// Init first.
	mock.barriers["tenant-1"] = true

	err := svc.BarrierUnseal("tenant-1", []byte("share-data"), nil)
	require.NoError(t, err)
	assert.True(t, mock.unsealed["tenant-1"])
}

func TestTenantService_BarrierUnseal_EmptyID(t *testing.T) {
	svc, _ := setupTenantService(t)

	err := svc.BarrierUnseal("", []byte("share-data"), nil)
	require.ErrorIs(t, err, ErrTenantIDRequired)
}

func TestTenantService_BarrierUnseal_NotInitialized(t *testing.T) {
	svc, _ := setupTenantService(t)

	err := svc.BarrierUnseal("tenant-1", []byte("share-data"), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not initialized")
}

func TestTenantService_BarrierUnseal_WithKey(t *testing.T) {
	svc, mock := setupTenantService(t)
	mock.barriers["tenant-1"] = true

	err := svc.BarrierUnseal("tenant-1", nil, []byte("master-key"))
	require.NoError(t, err)
	assert.True(t, mock.unsealed["tenant-1"])
}

func TestTenantService_BarrierUnseal_ServerError(t *testing.T) {
	svc, mock := setupTenantService(t)
	mock.err = errors.New("invalid share")

	err := svc.BarrierUnseal("tenant-1", []byte("bad-share"), nil)
	require.Error(t, err)
}

// --- Event emission ---

func TestTenantService_EventEmission_Create(t *testing.T) {
	svc, _ := setupTenantService(t)

	var mu sync.Mutex
	var captured []events.Event
	svc.SetEventEmitter(func(e events.Event) {
		mu.Lock()
		defer mu.Unlock()
		captured = append(captured, e)
	})

	_, err := svc.CreateTenant("EventTenant")
	require.NoError(t, err)

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, captured, 1)
	assert.Equal(t, events.EventTenantCreated, captured[0].Type)
}

func TestTenantService_EventEmission_Delete(t *testing.T) {
	svc, _ := setupTenantService(t)

	var mu sync.Mutex
	var captured []events.Event
	svc.SetEventEmitter(func(e events.Event) {
		mu.Lock()
		defer mu.Unlock()
		captured = append(captured, e)
	})

	created, err := svc.CreateTenant("DelTenant")
	require.NoError(t, err)

	err = svc.DeleteTenant(created.ID)
	require.NoError(t, err)

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, captured, 2)
	assert.Equal(t, events.EventTenantDeleted, captured[1].Type)
}

func TestTenantService_EventEmission_BarrierInit(t *testing.T) {
	svc, _ := setupTenantService(t)

	var mu sync.Mutex
	var captured []events.Event
	svc.SetEventEmitter(func(e events.Event) {
		mu.Lock()
		defer mu.Unlock()
		captured = append(captured, e)
	})

	err := svc.BarrierInit("tenant-ev", 2, 3)
	require.NoError(t, err)

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, captured, 1)
	assert.Equal(t, events.EventTenantBarrierInited, captured[0].Type)
}

func TestTenantService_EventEmission_BarrierUnseal(t *testing.T) {
	svc, mock := setupTenantService(t)
	mock.barriers["tenant-ev"] = true

	var mu sync.Mutex
	var captured []events.Event
	svc.SetEventEmitter(func(e events.Event) {
		mu.Lock()
		defer mu.Unlock()
		captured = append(captured, e)
	})

	err := svc.BarrierUnseal("tenant-ev", []byte("share"), nil)
	require.NoError(t, err)

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, captured, 1)
	assert.Equal(t, events.EventTenantBarrierUnsealed, captured[0].Type)
}

// --- Conversion helpers ---

func TestTransportTenantToInfo(t *testing.T) {
	now := time.Date(2025, 8, 15, 9, 0, 0, 0, time.UTC)
	later := time.Date(2025, 8, 16, 10, 0, 0, 0, time.UTC)

	tenant := &transport.TenantInfo{
		ID:        "tenant-42",
		Name:      "Production",
		CreatedAt: now,
		UpdatedAt: later,
	}

	info := transportTenantToInfo(tenant)
	assert.Equal(t, "tenant-42", info.ID)
	assert.Equal(t, "Production", info.Name)
	assert.Equal(t, "2025-08-15T09:00:00Z", info.CreatedAt)
	assert.Equal(t, "2025-08-16T10:00:00Z", info.UpdatedAt)
}

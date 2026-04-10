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

package xkms

import (
	"context"
	"log/slog"
	"os"
	"sort"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupServiceWithRegistry creates an XKMSService with an initialized barrier
// registry backed by an in-memory storage and software sealing strategy.
// The barrier is initialized and unsealed so tenant operations can succeed.
func setupServiceWithRegistry(t *testing.T) *XKMSService {
	t.Helper()

	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	base := storage.NewMemory()

	barrier, err := seal.NewBarrier(
		logger,
		base,
		seal.BarrierConfig{
			RootKeyPath:     "core/seal",
			PreferenceOrder: []seal.StrategyID{seal.StrategySoftware},
		},
		seal.NewSoftwareStrategy(),
	)
	require.NoError(t, err)

	ctx := context.Background()
	creds := seal.Credentials{Secret: "test-password"}
	err = barrier.Initialize(ctx, creds)
	require.NoError(t, err)

	registry, err := seal.NewBarrierRegistry(barrier)
	require.NoError(t, err)

	svc.SetBarrierRegistry(registry)
	return svc
}

// ========================================================================
// CreateTenant
// ========================================================================

func TestCreateTenant_Success(t *testing.T) {
	svc := setupServiceWithRegistry(t)
	ctx := context.Background()

	resp, err := svc.CreateTenant(ctx, &transport.CreateTenantRequest{
		ID:   "acme-corp",
		Name: "Acme Corporation",
	})
	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.Equal(t, "acme-corp", resp.Tenant.ID)
	assert.Equal(t, "Acme Corporation", resp.Tenant.Name)
	assert.False(t, resp.Tenant.CreatedAt.IsZero())
	assert.False(t, resp.Tenant.UpdatedAt.IsZero())
}

func TestCreateTenant_NilRequest(t *testing.T) {
	svc := setupServiceWithRegistry(t)
	ctx := context.Background()

	resp, err := svc.CreateTenant(ctx, nil)
	assert.Nil(t, resp)
	assert.ErrorIs(t, err, ErrNilRequest)
}

func TestCreateTenant_EmptyID(t *testing.T) {
	svc := setupServiceWithRegistry(t)
	ctx := context.Background()

	resp, err := svc.CreateTenant(ctx, &transport.CreateTenantRequest{
		ID:   "",
		Name: "Acme Corporation",
	})
	assert.Nil(t, resp)
	assert.ErrorIs(t, err, ErrTenantIDRequired)
}

func TestCreateTenant_EmptyName(t *testing.T) {
	svc := setupServiceWithRegistry(t)
	ctx := context.Background()

	resp, err := svc.CreateTenant(ctx, &transport.CreateTenantRequest{
		ID:   "acme-corp",
		Name: "",
	})
	assert.Nil(t, resp)
	assert.ErrorIs(t, err, ErrTenantNameRequired)
}

func TestCreateTenant_NoRegistry(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	resp, err := svc.CreateTenant(context.Background(), &transport.CreateTenantRequest{
		ID:   "acme-corp",
		Name: "Acme Corporation",
	})
	assert.Nil(t, resp)
	assert.ErrorIs(t, err, ErrBarrierRegistryNotConfigured)
}

func TestCreateTenant_Duplicate(t *testing.T) {
	svc := setupServiceWithRegistry(t)
	ctx := context.Background()

	_, err := svc.CreateTenant(ctx, &transport.CreateTenantRequest{
		ID:   "dup-tenant",
		Name: "Duplicate",
	})
	require.NoError(t, err)

	resp, err := svc.CreateTenant(ctx, &transport.CreateTenantRequest{
		ID:   "dup-tenant",
		Name: "Duplicate Again",
	})
	assert.Nil(t, resp)
	assert.ErrorIs(t, err, seal.ErrTenantAlreadyExists)
}

// ========================================================================
// GetTenant
// ========================================================================

func TestGetTenant_Success(t *testing.T) {
	svc := setupServiceWithRegistry(t)
	ctx := context.Background()

	_, err := svc.CreateTenant(ctx, &transport.CreateTenantRequest{
		ID:   "get-tenant",
		Name: "Get Tenant Test",
	})
	require.NoError(t, err)

	resp, err := svc.GetTenant(ctx, "get-tenant")
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, "get-tenant", resp.Tenant.ID)
}

func TestGetTenant_NotFound(t *testing.T) {
	svc := setupServiceWithRegistry(t)
	ctx := context.Background()

	resp, err := svc.GetTenant(ctx, "nonexistent-tenant")
	assert.Nil(t, resp)
	assert.ErrorIs(t, err, seal.ErrTenantNotFound)
}

func TestGetTenant_EmptyID(t *testing.T) {
	svc := setupServiceWithRegistry(t)
	ctx := context.Background()

	resp, err := svc.GetTenant(ctx, "")
	assert.Nil(t, resp)
	assert.ErrorIs(t, err, ErrTenantIDRequired)
}

func TestGetTenant_NoRegistry(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	resp, err := svc.GetTenant(context.Background(), "tenant-1")
	assert.Nil(t, resp)
	assert.ErrorIs(t, err, ErrBarrierRegistryNotConfigured)
}

// ========================================================================
// ListTenants
// ========================================================================

func TestListTenants_Success(t *testing.T) {
	svc := setupServiceWithRegistry(t)
	ctx := context.Background()

	_, err := svc.CreateTenant(ctx, &transport.CreateTenantRequest{
		ID: "charlie", Name: "Charlie",
	})
	require.NoError(t, err)

	_, err = svc.CreateTenant(ctx, &transport.CreateTenantRequest{
		ID: "alpha", Name: "Alpha",
	})
	require.NoError(t, err)

	_, err = svc.CreateTenant(ctx, &transport.CreateTenantRequest{
		ID: "bravo", Name: "Bravo",
	})
	require.NoError(t, err)

	resp, err := svc.ListTenants(ctx)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Len(t, resp.Tenants, 3)

	// sync.Map iteration order is non-deterministic; sort before asserting.
	ids := make([]string, len(resp.Tenants))
	for i, t := range resp.Tenants {
		ids[i] = t.ID
	}
	sort.Strings(ids)
	assert.Equal(t, "alpha", ids[0])
	assert.Equal(t, "bravo", ids[1])
	assert.Equal(t, "charlie", ids[2])
}

func TestListTenants_Empty(t *testing.T) {
	svc := setupServiceWithRegistry(t)
	ctx := context.Background()

	resp, err := svc.ListTenants(ctx)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Empty(t, resp.Tenants)
}

func TestListTenants_NoRegistry(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	resp, err := svc.ListTenants(context.Background())
	assert.Nil(t, resp)
	assert.ErrorIs(t, err, ErrBarrierRegistryNotConfigured)
}

// ========================================================================
// DeleteTenant
// ========================================================================

func TestDeleteTenant_Success(t *testing.T) {
	svc := setupServiceWithRegistry(t)
	ctx := context.Background()

	_, err := svc.CreateTenant(ctx, &transport.CreateTenantRequest{
		ID:   "to-delete",
		Name: "Will Be Deleted",
	})
	require.NoError(t, err)

	err = svc.DeleteTenant(ctx, "to-delete")
	require.NoError(t, err)

	// Verify it's gone
	resp, err := svc.GetTenant(ctx, "to-delete")
	assert.Nil(t, resp)
	assert.ErrorIs(t, err, seal.ErrTenantNotFound)
}

func TestDeleteTenant_NotFound(t *testing.T) {
	svc := setupServiceWithRegistry(t)
	ctx := context.Background()

	err := svc.DeleteTenant(ctx, "nonexistent-tenant")
	assert.ErrorIs(t, err, seal.ErrTenantNotFound)
}

func TestDeleteTenant_EmptyID(t *testing.T) {
	svc := setupServiceWithRegistry(t)
	ctx := context.Background()

	err := svc.DeleteTenant(ctx, "")
	assert.ErrorIs(t, err, ErrTenantIDRequired)
}

func TestDeleteTenant_NoRegistry(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	err = svc.DeleteTenant(context.Background(), "tenant-1")
	assert.ErrorIs(t, err, ErrBarrierRegistryNotConfigured)
}

// ========================================================================
// TenantBarrierInit
// ========================================================================

func TestTenantBarrierInit_Success(t *testing.T) {
	svc := setupServiceWithRegistry(t)
	ctx := context.Background()

	_, err := svc.CreateTenant(ctx, &transport.CreateTenantRequest{
		ID:   "init-tenant",
		Name: "Init Tenant",
	})
	require.NoError(t, err)

	err = svc.TenantBarrierInit(ctx, &transport.TenantBarrierInitRequest{
		TenantID:  "init-tenant",
		Threshold: 2,
		Shares:    3,
	})
	require.NoError(t, err)
}

func TestTenantBarrierInit_NilRequest(t *testing.T) {
	svc := setupServiceWithRegistry(t)
	ctx := context.Background()

	err := svc.TenantBarrierInit(ctx, nil)
	assert.ErrorIs(t, err, ErrNilRequest)
}

func TestTenantBarrierInit_EmptyTenantID(t *testing.T) {
	svc := setupServiceWithRegistry(t)
	ctx := context.Background()

	err := svc.TenantBarrierInit(ctx, &transport.TenantBarrierInitRequest{
		TenantID: "",
	})
	assert.ErrorIs(t, err, ErrTenantIDRequired)
}

func TestTenantBarrierInit_NoRegistry(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	err = svc.TenantBarrierInit(context.Background(), &transport.TenantBarrierInitRequest{
		TenantID: "tenant-1",
	})
	assert.ErrorIs(t, err, ErrBarrierRegistryNotConfigured)
}

func TestTenantBarrierInit_TenantNotFound(t *testing.T) {
	svc := setupServiceWithRegistry(t)
	ctx := context.Background()

	err := svc.TenantBarrierInit(ctx, &transport.TenantBarrierInitRequest{
		TenantID: "nonexistent",
	})
	assert.ErrorIs(t, err, seal.ErrTenantNotFound)
}

// ========================================================================
// TenantBarrierUnseal
// ========================================================================

func TestTenantBarrierUnseal_Success(t *testing.T) {
	svc := setupServiceWithRegistry(t)
	ctx := context.Background()

	_, err := svc.CreateTenant(ctx, &transport.CreateTenantRequest{
		ID:   "unseal-tenant",
		Name: "Unseal Tenant",
	})
	require.NoError(t, err)

	// System barrier is already unsealed (initialized in setupServiceWithRegistry),
	// so the tenant barrier should report unsealed too.
	err = svc.TenantBarrierUnseal(ctx, &transport.TenantBarrierUnsealRequest{
		TenantID: "unseal-tenant",
	})
	require.NoError(t, err)
}

func TestTenantBarrierUnseal_Sealed(t *testing.T) {
	svc := setupServiceWithRegistry(t)
	ctx := context.Background()

	_, err := svc.CreateTenant(ctx, &transport.CreateTenantRequest{
		ID:   "sealed-tenant",
		Name: "Sealed Tenant",
	})
	require.NoError(t, err)

	// Seal the system barrier so the tenant barrier reports sealed.
	svc.barrier = nil // not needed for this path, the barrier is inside the registry

	// We need access to the actual barrier. Recreate the scenario by creating
	// a separate barrier that we seal.
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	base := storage.NewMemory()
	barrier, err := seal.NewBarrier(
		logger,
		base,
		seal.BarrierConfig{
			RootKeyPath:     "core/seal",
			PreferenceOrder: []seal.StrategyID{seal.StrategySoftware},
		},
		seal.NewSoftwareStrategy(),
	)
	require.NoError(t, err)

	creds := seal.Credentials{Secret: "test-pw"}
	err = barrier.Initialize(ctx, creds)
	require.NoError(t, err)

	registry, err := seal.NewBarrierRegistry(barrier)
	require.NoError(t, err)

	_, err = registry.RegisterTenant("sealed-test")
	require.NoError(t, err)

	svc.SetBarrierRegistry(registry)

	// Now seal the barrier.
	err = barrier.Seal()
	require.NoError(t, err)

	err = svc.TenantBarrierUnseal(ctx, &transport.TenantBarrierUnsealRequest{
		TenantID: "sealed-test",
	})
	assert.ErrorIs(t, err, seal.ErrSealed)
}

func TestTenantBarrierUnseal_NilRequest(t *testing.T) {
	svc := setupServiceWithRegistry(t)
	ctx := context.Background()

	err := svc.TenantBarrierUnseal(ctx, nil)
	assert.ErrorIs(t, err, ErrNilRequest)
}

func TestTenantBarrierUnseal_EmptyTenantID(t *testing.T) {
	svc := setupServiceWithRegistry(t)
	ctx := context.Background()

	err := svc.TenantBarrierUnseal(ctx, &transport.TenantBarrierUnsealRequest{
		TenantID: "",
	})
	assert.ErrorIs(t, err, ErrTenantIDRequired)
}

func TestTenantBarrierUnseal_NoRegistry(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	err = svc.TenantBarrierUnseal(context.Background(), &transport.TenantBarrierUnsealRequest{
		TenantID: "tenant-1",
	})
	assert.ErrorIs(t, err, ErrBarrierRegistryNotConfigured)
}

func TestTenantBarrierUnseal_TenantNotFound(t *testing.T) {
	svc := setupServiceWithRegistry(t)
	ctx := context.Background()

	err := svc.TenantBarrierUnseal(ctx, &transport.TenantBarrierUnsealRequest{
		TenantID: "nonexistent",
	})
	assert.ErrorIs(t, err, seal.ErrTenantNotFound)
}

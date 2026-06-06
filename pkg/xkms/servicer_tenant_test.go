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
			PreferenceOrder: []seal.StrategyID{seal.StrategyPassphrase},
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

	// Phase 2: the tenant admin supplies their OWN passphrase.
	err = svc.TenantBarrierInit(ctx, &transport.TenantBarrierInitRequest{
		TenantID:   "init-tenant",
		Passphrase: "tenant-admin-secret",
	})
	require.NoError(t, err)
}

// TestCreateTenant_LeavesBarrierSealed proves Phase 1 of the §3.6 two-phase
// model: after CreateTenant the tenant barrier is registered but NOT
// initialized — it is sealed and the server holds no secret for it.
func TestCreateTenant_LeavesBarrierSealed(t *testing.T) {
	svc := setupServiceWithRegistry(t)
	ctx := context.Background()

	_, err := svc.CreateTenant(ctx, &transport.CreateTenantRequest{
		ID:   "sealed-shell",
		Name: "Sealed Shell",
	})
	require.NoError(t, err)

	tb, err := svc.barrierRegistry.Tenant("sealed-shell")
	require.NoError(t, err)
	assert.True(t, tb.IsSealed(), "tenant barrier must be sealed after CreateTenant")

	// The barrier is uninitialized: storage operations must fail until Phase 2.
	_, err = tb.Get(ctx, "any-key")
	require.Error(t, err, "uninitialized tenant barrier must reject operations")
}

// TestTenantBarrierInit_EmptyPassphraseRejected proves the §3.6 security
// invariant: with the passphrase strategy an empty passphrase is a hard error.
// The server must NEVER fall back to a server-generated secret.
func TestTenantBarrierInit_EmptyPassphraseRejected(t *testing.T) {
	svc := setupServiceWithRegistry(t)
	ctx := context.Background()

	_, err := svc.CreateTenant(ctx, &transport.CreateTenantRequest{
		ID:   "no-pw-tenant",
		Name: "No Passphrase Tenant",
	})
	require.NoError(t, err)

	err = svc.TenantBarrierInit(ctx, &transport.TenantBarrierInitRequest{
		TenantID:   "no-pw-tenant",
		Passphrase: "",
	})
	assert.ErrorIs(t, err, ErrTenantPassphraseRequired)

	// The barrier must remain sealed — no server-generated init happened.
	tb, err := svc.barrierRegistry.Tenant("no-pw-tenant")
	require.NoError(t, err)
	assert.True(t, tb.IsSealed(), "barrier must stay sealed after rejected init")
}

// TestTenantBarrierInit_SamePassphraseUnseals proves the round trip: a
// tenant-supplied passphrase initializes the barrier and the SAME passphrase
// unseals it after a reseal.
func TestTenantBarrierInit_SamePassphraseUnseals(t *testing.T) {
	svc := setupServiceWithRegistry(t)
	ctx := context.Background()

	_, err := svc.CreateTenant(ctx, &transport.CreateTenantRequest{
		ID:   "roundtrip-tenant",
		Name: "Roundtrip Tenant",
	})
	require.NoError(t, err)

	err = svc.TenantBarrierInit(ctx, &transport.TenantBarrierInitRequest{
		TenantID:   "roundtrip-tenant",
		Passphrase: "shared-secret-123",
	})
	require.NoError(t, err)

	tb, err := svc.barrierRegistry.Tenant("roundtrip-tenant")
	require.NoError(t, err)
	assert.False(t, tb.IsSealed(), "barrier must be unsealed after init")

	require.NoError(t, svc.barrierRegistry.SealTenant("roundtrip-tenant"))
	assert.True(t, tb.IsSealed())

	err = svc.TenantBarrierUnseal(ctx, &transport.TenantBarrierUnsealRequest{
		TenantID: "roundtrip-tenant",
		Key:      []byte("shared-secret-123"),
	})
	require.NoError(t, err)
	assert.False(t, tb.IsSealed())
}

// TestTenantBarrierInit_Idempotent proves repeated init calls with the
// caller's passphrase are idempotent.
func TestTenantBarrierInit_Idempotent(t *testing.T) {
	svc := setupServiceWithRegistry(t)
	ctx := context.Background()

	_, err := svc.CreateTenant(ctx, &transport.CreateTenantRequest{
		ID:   "idem-tenant",
		Name: "Idempotent Tenant",
	})
	require.NoError(t, err)

	req := &transport.TenantBarrierInitRequest{
		TenantID:   "idem-tenant",
		Passphrase: "idem-pw",
	}
	require.NoError(t, svc.TenantBarrierInit(ctx, req))
	require.NoError(t, svc.TenantBarrierInit(ctx, req), "init must be idempotent")
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

	// Phase 2 init leaves the tenant barrier unsealed. Calling unseal on an
	// already-unsealed barrier is a no-op that returns nil.
	err = svc.TenantBarrierInit(ctx, &transport.TenantBarrierInitRequest{
		TenantID:   "unseal-tenant",
		Passphrase: "unseal-pw",
	})
	require.NoError(t, err)

	err = svc.TenantBarrierUnseal(ctx, &transport.TenantBarrierUnsealRequest{
		TenantID: "unseal-tenant",
	})
	require.NoError(t, err)
}

func TestTenantBarrierUnseal_WrongPassphraseFails(t *testing.T) {
	svc := setupServiceWithRegistry(t)
	ctx := context.Background()

	_, err := svc.CreateTenant(ctx, &transport.CreateTenantRequest{
		ID:   "wrong-pw-tenant",
		Name: "Wrong PW Tenant",
	})
	require.NoError(t, err)

	// Phase 2: initialize with the tenant admin's passphrase.
	err = svc.TenantBarrierInit(ctx, &transport.TenantBarrierInitRequest{
		TenantID:   "wrong-pw-tenant",
		Passphrase: "correct-horse",
	})
	require.NoError(t, err)

	// Seal the tenant barrier so it must be re-unsealed.
	require.NoError(t, svc.barrierRegistry.SealTenant("wrong-pw-tenant"))

	// A WRONG passphrase must fail to unseal.
	err = svc.TenantBarrierUnseal(ctx, &transport.TenantBarrierUnsealRequest{
		TenantID: "wrong-pw-tenant",
		Key:      []byte("battery-staple"),
	})
	require.Error(t, err)

	// The barrier must remain sealed after the failed attempt.
	tb, err := svc.barrierRegistry.Tenant("wrong-pw-tenant")
	require.NoError(t, err)
	assert.True(t, tb.IsSealed(), "barrier must stay sealed after wrong passphrase")

	// The SAME passphrase the tenant supplied at init must unseal it.
	err = svc.TenantBarrierUnseal(ctx, &transport.TenantBarrierUnsealRequest{
		TenantID: "wrong-pw-tenant",
		Key:      []byte("correct-horse"),
	})
	require.NoError(t, err)
	assert.False(t, tb.IsSealed(), "barrier must be unsealed by the correct passphrase")
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

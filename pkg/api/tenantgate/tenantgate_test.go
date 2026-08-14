// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package tenantgate

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testRegistry creates an initialized and unsealed BarrierRegistry backed by
// in-memory storage.
func testRegistry(t *testing.T) *seal.BarrierRegistry {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
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

	require.NoError(t, barrier.Initialize(context.Background(), seal.Credentials{Secret: []byte("test-password")}))

	registry, err := seal.NewBarrierRegistry(barrier)
	require.NoError(t, err)
	return registry
}

// testRegisteredTenant registers and initializes a tenant, returning its
// unsealed TenantBarrier.
func testRegisteredTenant(t *testing.T, registry *seal.BarrierRegistry, tenantID string) *seal.TenantBarrier {
	t.Helper()
	tb, err := registry.RegisterTenant(tenantID)
	require.NoError(t, err)

	require.NoError(t, registry.InitializeTenant(context.Background(), tenantID, seal.Credentials{Secret: []byte("tenant-password")}))
	require.False(t, tb.IsSealed(), "tenant barrier should be unsealed after initialization")

	return tb
}

func TestAccess_NilIdentity(t *testing.T) {
	tb, err := Access(nil, testRegistry(t))
	require.NoError(t, err)
	assert.Nil(t, tb)
}

func TestAccess_EmptyTenantID(t *testing.T) {
	identity := &auth.Identity{Subject: "system-admin", TenantID: ""}
	tb, err := Access(identity, testRegistry(t))
	require.NoError(t, err)
	assert.Nil(t, tb)
}

// TestAccess_SystemTenantID is the source-of-truth regression test for the
// reported bug: an identity rooted in the reserved "system" tenant (e.g. a
// WebAuthn-registered user, see pkg/server.webAuthnSystemTenant) must pass
// exactly like an empty-TenantID identity.
func TestAccess_SystemTenantID(t *testing.T) {
	identity := &auth.Identity{Subject: "webauthn-user", TenantID: "system"}
	tb, err := Access(identity, testRegistry(t))
	require.NoError(t, err)
	assert.Nil(t, tb)
}

func TestAccess_SORolePassesThrough(t *testing.T) {
	identity := &auth.Identity{Subject: "so-admin", TenantID: "nonexistent-tenant", Roles: []string{"so"}}
	tb, err := Access(identity, testRegistry(t))
	require.NoError(t, err)
	assert.Nil(t, tb)
}

func TestAccess_NoRegistry(t *testing.T) {
	identity := &auth.Identity{Subject: "tenant-user", TenantID: "some-tenant"}
	tb, err := Access(identity, nil)
	require.NoError(t, err)
	assert.Nil(t, tb)
}

func TestAccess_TenantNotFound(t *testing.T) {
	identity := &auth.Identity{Subject: "tenant-user", TenantID: "nonexistent-tenant", Roles: []string{"user"}}
	tb, err := Access(identity, testRegistry(t))
	require.Nil(t, tb)
	require.Error(t, err)

	var notFound *ErrTenantNotFound
	require.ErrorAs(t, err, &notFound)
	assert.Equal(t, "nonexistent-tenant", notFound.TenantID)
	assert.NotEmpty(t, notFound.Error())
	require.Error(t, errors.Unwrap(err))
}

func TestAccess_TenantSealed(t *testing.T) {
	registry := testRegistry(t)
	_, err := registry.RegisterTenant("sealed-tenant")
	require.NoError(t, err)

	identity := &auth.Identity{Subject: "tenant-user", TenantID: "sealed-tenant", Roles: []string{"operator"}}
	tb, err := Access(identity, registry)
	require.Nil(t, tb)
	require.Error(t, err)

	var sealed *ErrTenantSealed
	require.ErrorAs(t, err, &sealed)
	assert.Equal(t, "sealed-tenant", sealed.TenantID)
	assert.NotEmpty(t, sealed.Error())
}

func TestAccess_Success(t *testing.T) {
	registry := testRegistry(t)
	testRegisteredTenant(t, registry, "active-tenant")

	identity := &auth.Identity{Subject: "tenant-user", TenantID: "active-tenant", Roles: []string{"operator"}}
	tb, err := Access(identity, registry)
	require.NoError(t, err)
	require.NotNil(t, tb)
	assert.Equal(t, "active-tenant", tb.TenantID())
	assert.False(t, tb.IsSealed())
}

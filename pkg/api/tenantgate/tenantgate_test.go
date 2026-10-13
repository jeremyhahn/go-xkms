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

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
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

	creds := seal.MustCredentials(t.Context(), []byte("test-password"))
	defer creds.Secret.Destroy()
	require.NoError(t, barrier.Initialize(context.Background(), creds))

	registry, err := seal.NewBarrierRegistry(barrier)
	require.NoError(t, err)
	return registry
}

// testRegisteredTenant registers and initializes a tenant, returning its
// unsealed TenantBarrier.
func testRegisteredTenant(t *testing.T, registry *seal.BarrierRegistry, tenantID string) *seal.TenantBarrier {
	t.Helper()
	tb, err := registry.RegisterTenantDefault(tenantID)
	require.NoError(t, err)

	tenantCreds := seal.MustCredentials(t.Context(), []byte("tenant-password"))
	defer tenantCreds.Secret.Destroy()
	require.NoError(t, registry.InitializeTenant(context.Background(), tenantID, tenantCreds))
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

// seededGateNode returns a first-boot-seeded qrdb node on which "tenant-a"
// has been provisioned, so both the system tenant and tenant-a carry their
// built-in roles under real identifiers.
func seededGateNode(t *testing.T) *testutil.FirstBootNode {
	t.Helper()
	n, err := testutil.NewFirstBootNode(t)
	require.NoError(t, err)
	require.NoError(t, n.ProvisionTenant("tenant-a"))
	return n
}

// seededRoleID resolves roleName in tenantID on n.
func seededRoleID(t *testing.T, n *testutil.FirstBootNode, tenantID, roleName string) string {
	t.Helper()
	id, err := n.RoleID(tenantID, roleName)
	require.NoError(t, err)
	return id
}

// TestAccess_SystemTenantOfficersPass proves the system tenant's Security
// Officer and Admin -- identified by the role IDs they actually carry -- have
// no tenant barrier to gate, whatever the registry holds.
func TestAccess_SystemTenantOfficersPass(t *testing.T) {
	n := seededGateNode(t)

	for _, roleName := range []string{qrdbsdk.RoleNameSO, qrdbsdk.RoleNameAdmin} {
		identity := &auth.Identity{
			Subject:  "officer",
			TenantID: qrdbsdk.SystemTenantID,
			Roles:    []string{seededRoleID(t, n, qrdbsdk.SystemTenantID, roleName)},
		}
		tb, err := Access(identity, testRegistry(t))
		require.NoError(t, err, roleName)
		assert.Nil(t, tb)
	}
}

// TestAccess_TenantLocalOfficerIsScoped proves a tenant-local Security Officer
// or Admin gets no exemption: it is gated on its own tenant's barrier like
// every other tenant identity -- refused while that tenant is unregistered or
// sealed, and handed the tenant barrier once it is unsealed.
func TestAccess_TenantLocalOfficerIsScoped(t *testing.T) {
	n := seededGateNode(t)

	for _, roleName := range []string{qrdbsdk.RoleNameSO, qrdbsdk.RoleNameAdmin} {
		identity := &auth.Identity{
			Subject:  "tenant-officer",
			TenantID: "tenant-a",
			Roles:    []string{seededRoleID(t, n, "tenant-a", roleName)},
		}

		registry := testRegistry(t)
		_, err := Access(identity, registry)
		var notFound *ErrTenantNotFound
		require.ErrorAs(t, err, &notFound, roleName)

		_, err = registry.RegisterTenantDefault("tenant-a")
		require.NoError(t, err)
		_, err = Access(identity, registry)
		var sealed *ErrTenantSealed
		require.ErrorAs(t, err, &sealed, roleName)

		unsealed := testRegistry(t)
		testRegisteredTenant(t, unsealed, "tenant-a")
		tb, err := Access(identity, unsealed)
		require.NoError(t, err, roleName)
		require.NotNil(t, tb)
		assert.Equal(t, "tenant-a", tb.TenantID())
	}
}

// TestAccess_SORoleNameConfersNothing is the #1074 regression: an identity
// whose Roles spell "so" -- the shape of an unverified token claim -- used to
// bypass the tenant-registered and tenant-sealed checks. It is now gated like
// any other tenant identity.
func TestAccess_SORoleNameConfersNothing(t *testing.T) {
	identity := &auth.Identity{Subject: "so-admin", TenantID: "nonexistent-tenant", Roles: []string{qrdbsdk.RoleNameSO}}
	tb, err := Access(identity, testRegistry(t))
	assert.Nil(t, tb)
	var notFound *ErrTenantNotFound
	require.ErrorAs(t, err, &notFound)

	registry := testRegistry(t)
	_, err = registry.RegisterTenantDefault("sealed-tenant")
	require.NoError(t, err)
	identity.TenantID = "sealed-tenant"
	_, err = Access(identity, registry)
	var sealed *ErrTenantSealed
	require.ErrorAs(t, err, &sealed)
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
	assert.Equal(t, "tenantgate: tenant not found: nonexistent-tenant", notFound.Error())
	// The registry lookup failure stays reachable for logging and
	// errors.Is/As, but never enters the client-facing text (go-xkms#1118).
	cause := errors.Unwrap(err)
	require.Error(t, cause)
	assert.NotContains(t, notFound.Error(), cause.Error())
}

func TestAccess_TenantSealed(t *testing.T) {
	registry := testRegistry(t)
	_, err := registry.RegisterTenantDefault("sealed-tenant")
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

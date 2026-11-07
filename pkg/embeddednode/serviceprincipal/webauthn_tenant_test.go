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

package serviceprincipal

import (
	"context"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbnode "github.com/jeremyhahn/go-qrdb/sdk/go/node"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/webauthn"
)

// tenantServiceBinder returns a CallContext that binds an identity of tenant
// holding the principal's grant: what node.DelegatedContext yields for a
// delegation the tenant issued to the principal. Unlike node.ServiceContext,
// it adds no tenant to the context, so the store must scope it.
func tenantServiceBinder(t *testing.T, node *qrdbnode.Node, tenant string) func(context.Context) (context.Context, error) {
	t.Helper()
	_, err := node.Services().Tenant.CreateTenant(context.Background(), tenant, tenant,
		qrdbsdk.TenantIsolationPrefix)
	require.NoError(t, err)
	role, err := node.Services().Role.CreateRole(qrdbsdk.ContextWithTenant(context.Background(), tenant),
		&qrdbsdk.CreateRoleRequest{Name: "webauthn-relying-party", TenantID: tenant, Permissions: Grant()})
	require.NoError(t, err)
	identity := &qrdbsdk.Identity{Subject: "webauthn-rp", TenantID: tenant, Roles: []string{role.ID}}
	return func(ctx context.Context) (context.Context, error) {
		return qrdbsdk.WithIdentity(ctx, identity), nil
	}
}

// newTenantUserStore returns a WebAuthn user store for tenant whose calls
// run on bind's context.
func newTenantUserStore(t *testing.T, node *qrdbnode.Node, tenant string, bind func(context.Context) (context.Context, error)) webauthn.UserStore {
	t.Helper()
	kv := qrdbsdk.NewMemoryKVStore()
	users, _, err := webauthn.NewQRDBUserStoreAdapter(webauthn.QRDBUserStoreOptions{
		Users:       node.Client().Users(),
		DAOFactory:  qrdbsdk.NewDAOFactory(func(uint64) qrdbsdk.KVStore { return kv }),
		TenantID:    tenant,
		KV:          node.Client().KV(),
		CallContext: bind,
	})
	require.NoError(t, err)
	return users
}

// TestWebAuthnTenantStore_RegistersInConfiguredTenant proves a store for a
// non-system tenant, bound to an identity of that tenant, registers and
// finds a user by email from an anonymous ceremony's context, and that the
// user lands in that tenant and not the system tenant (Codex 9054).
func TestWebAuthnTenantStore_RegistersInConfiguredTenant(t *testing.T) {
	node := newNode(t, Option())
	users := newTenantUserStore(t, node, "tenant-a", tenantServiceBinder(t, node, "tenant-a"))

	created, err := users.Create(context.Background(), "alice@example.com", "Alice")
	require.NoError(t, err)
	found, err := users.GetByEmail(context.Background(), "alice@example.com")
	require.NoError(t, err)
	require.Equal(t, created.WebAuthnID(), found.WebAuthnID())

	svcCtx, err := node.ServiceContext(context.Background())
	require.NoError(t, err)
	_, err = node.Client().Users().GetUserByEmail(svcCtx, qrdbsdk.SystemTenantID, "alice@example.com")
	require.Error(t, err, "the user must not land in the system tenant")
	userID, err := webauthn.UserIDFromHandle(created.WebAuthnID())
	require.NoError(t, err)
	_, err = node.Client().Users().GetUser(svcCtx, userID)
	require.Error(t, err, "the system tenant must not see the tenant's user")
}

// TestWebAuthnTenantStore_CannotReadAnotherTenantsUser proves a ceremony
// for tenant A finds no user of tenant B, by email or by handle.
func TestWebAuthnTenantStore_CannotReadAnotherTenantsUser(t *testing.T) {
	node := newNode(t, Option())
	usersA := newTenantUserStore(t, node, "tenant-a", tenantServiceBinder(t, node, "tenant-a"))
	usersB := newTenantUserStore(t, node, "tenant-b", tenantServiceBinder(t, node, "tenant-b"))

	bob, err := usersB.Create(context.Background(), "bob@example.com", "Bob")
	require.NoError(t, err)

	_, err = usersA.GetByEmail(context.Background(), "bob@example.com")
	require.ErrorIs(t, err, webauthn.ErrUserNotFound)
	_, err = usersA.GetByID(context.Background(), bob.WebAuthnID())
	require.ErrorIs(t, err, webauthn.ErrUserNotFound)
}

// TestWebAuthnTenantStore_SystemPrincipalIsRefusedInTenant proves the
// store's tenant scoping grants nothing: the service principal lives in the
// system tenant, so a tenant store bound to it is refused, never served
// from the system tenant.
func TestWebAuthnTenantStore_SystemPrincipalIsRefusedInTenant(t *testing.T) {
	node := newNode(t, Option())
	_, err := node.Services().Tenant.CreateTenant(context.Background(), "tenant-a", "tenant-a",
		qrdbsdk.TenantIsolationPrefix)
	require.NoError(t, err)
	users := newTenantUserStore(t, node, "tenant-a", node.ServiceContext)

	_, err = users.Create(context.Background(), "alice@example.com", "Alice")
	var denied *qrdbsdk.PermissionDeniedError
	require.ErrorAs(t, err, &denied)
}

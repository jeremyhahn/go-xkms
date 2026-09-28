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

package auth

import (
	"context"
	"errors"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/testutil"
)

// seededRoles returns the role client of a first-boot-seeded qrdb node and a
// function resolving a built-in role name to its persisted identifier.
func seededRoles(t *testing.T) (qrdbtransport.RoleClient, func(string) string) {
	t.Helper()
	n, err := testutil.NewFirstBootNode(t)
	require.NoError(t, err)
	return n.Client().Roles(), func(name string) string {
		id, err := n.RoleID(qrdbsdk.SystemTenantID, name)
		require.NoError(t, err)
		return id
	}
}

// TestHoldsSystemRole_MatchesPersistedRoleID proves membership is decided by
// the identifier qrdb persisted the role under: the Admin ID holds Admin, and
// holds nothing else.
func TestHoldsSystemRole_MatchesPersistedRoleID(t *testing.T) {
	roles, roleID := seededRoles(t)
	ctx := context.Background()
	admin := &Identity{Subject: "admin", TenantID: qrdbsdk.SystemTenantID, Roles: []string{roleID(qrdbsdk.RoleNameUser), roleID(qrdbsdk.RoleNameAdmin)}}

	held, err := HoldsSystemRole(ctx, roles, admin, qrdbsdk.RoleNameAdmin)
	require.NoError(t, err)
	assert.True(t, held, "the Admin role ID must hold Admin")

	held, err = HoldsSystemRole(ctx, roles, admin, qrdbsdk.RoleNameSO)
	require.NoError(t, err)
	assert.False(t, held, "the Admin role ID must not hold SO")

	// An empty TenantID is the system tenant, as everywhere else in xkms.
	unscoped := &Identity{Subject: "admin", Roles: []string{roleID(qrdbsdk.RoleNameAdmin)}}
	held, err = HoldsSystemRole(ctx, roles, unscoped, qrdbsdk.RoleNameAdmin)
	require.NoError(t, err)
	assert.True(t, held)
}

// TestHoldsSystemRole_NonMemberRefused proves an identity holding a lesser
// role, or none, is not a member.
func TestHoldsSystemRole_NonMemberRefused(t *testing.T) {
	roles, roleID := seededRoles(t)
	ctx := context.Background()

	operator := &Identity{Subject: "op", TenantID: qrdbsdk.SystemTenantID, Roles: []string{roleID(qrdbsdk.RoleNameOperator)}}
	held, err := HoldsSystemRole(ctx, roles, operator, qrdbsdk.RoleNameAdmin)
	require.NoError(t, err)
	assert.False(t, held)

	for _, id := range []*Identity{nil, {Subject: "nobody", TenantID: qrdbsdk.SystemTenantID}} {
		held, err = HoldsSystemRole(ctx, roles, id, qrdbsdk.RoleNameAdmin)
		require.NoError(t, err)
		assert.False(t, held)
	}
}

// TestHoldsSystemRole_RoleNameConfersNothing is the #1074 regression: an
// identity whose Roles spell the role NAME — the shape an unverified token
// claim produces — is not a member, while the same identity carrying the
// role's identifier is.
func TestHoldsSystemRole_RoleNameConfersNothing(t *testing.T) {
	roles, _ := seededRoles(t)
	ctx := context.Background()

	for _, name := range []string{qrdbsdk.RoleNameAdmin, qrdbsdk.RoleNameSO} {
		named := &Identity{Subject: "claims", TenantID: qrdbsdk.SystemTenantID, Roles: []string{name}}
		held, err := HoldsSystemRole(ctx, roles, named, name)
		require.NoError(t, err)
		assert.False(t, held, "a role name on the identity must not confer %q", name)
	}
}

// TestHoldsSystemRole_TenantScoped proves the role is resolved in the
// identity's own tenant: a tenant's Admin ID makes that tenant's identity its
// Admin, while the system tenant's Admin ID does not.
func TestHoldsSystemRole_TenantScoped(t *testing.T) {
	n, err := testutil.NewFirstBootNode(t)
	require.NoError(t, err)
	require.NoError(t, n.ProvisionTenant("tenant-a"))
	tenantAdminID, err := n.RoleID("tenant-a", qrdbsdk.RoleNameAdmin)
	require.NoError(t, err)
	systemAdminID, err := n.RoleID(qrdbsdk.SystemTenantID, qrdbsdk.RoleNameAdmin)
	require.NoError(t, err)
	ctx := context.Background()

	tenantAdmin := &Identity{Subject: "admin", TenantID: "tenant-a", Roles: []string{tenantAdminID}}
	held, err := HoldsSystemRole(ctx, n.Client().Roles(), tenantAdmin, qrdbsdk.RoleNameAdmin)
	require.NoError(t, err)
	assert.True(t, held)

	borrowed := &Identity{Subject: "admin", TenantID: "tenant-a", Roles: []string{systemAdminID}}
	held, err = HoldsSystemRole(ctx, n.Client().Roles(), borrowed, qrdbsdk.RoleNameAdmin)
	require.NoError(t, err)
	assert.False(t, held, "another tenant's Admin ID must not hold this tenant's Admin")
}

// TestHoldsSystemRole_NilRoleClient proves a missing role store fails closed
// with a typed error instead of answering "not a member".
func TestHoldsSystemRole_NilRoleClient(t *testing.T) {
	held, err := HoldsSystemRole(context.Background(), nil, &Identity{Subject: "a", Roles: []string{"x"}}, qrdbsdk.RoleNameAdmin)
	require.ErrorIs(t, err, ErrRoleClientRequired)
	assert.False(t, held)
}

// failingRoleClient answers every name lookup with a fixed store failure.
// Every other RoleClient method is unreachable from HoldsSystemRole and
// panics through the nil embedded interface if ever called.
type failingRoleClient struct {
	qrdbtransport.RoleClient
	err  error
	role *qrdbtransport.Role
}

func (f failingRoleClient) GetRoleByName(context.Context, *qrdbtransport.GetRoleByNameRequest) (*qrdbtransport.Role, error) {
	return f.role, f.err
}

// errRoleStoreDown stands in for a role store outage.
var errRoleStoreDown = errors.New("role store unavailable")

// TestHoldsSystemRole_StoreFailure proves a role store failure, and a store
// that answers neither a role nor an error, surface as *RoleResolutionError
// rather than as non-membership.
func TestHoldsSystemRole_StoreFailure(t *testing.T) {
	id := &Identity{Subject: "a", TenantID: "tenant-a", Roles: []string{"some-id"}}

	held, err := HoldsSystemRole(context.Background(), failingRoleClient{err: errRoleStoreDown}, id, qrdbsdk.RoleNameAdmin)
	assert.False(t, held)
	var resErr *RoleResolutionError
	require.ErrorAs(t, err, &resErr)
	assert.Equal(t, "tenant-a", resErr.TenantID)
	assert.Equal(t, qrdbsdk.RoleNameAdmin, resErr.Role)
	assert.ErrorIs(t, err, errRoleStoreDown)
	assert.Contains(t, err.Error(), "tenant-a")

	held, err = HoldsSystemRole(context.Background(), failingRoleClient{}, id, qrdbsdk.RoleNameAdmin)
	assert.False(t, held)
	require.ErrorAs(t, err, &resErr)
}

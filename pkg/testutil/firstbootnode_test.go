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

package testutil

import (
	"context"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFirstBootNode_SeedsBuiltInRolesUnderPersistedIDs proves first-boot ran:
// every built-in role resolves, and RoleID answers with the identifier the
// role store holds, which RBAC then honours.
func TestFirstBootNode_SeedsBuiltInRolesUnderPersistedIDs(t *testing.T) {
	n, err := NewFirstBootNode(t)
	require.NoError(t, err)

	for _, name := range []string{qrdbsdk.RoleNameSO, qrdbsdk.RoleNameAdmin, qrdbsdk.RoleNameOperator, qrdbsdk.RoleNameUser} {
		id, err := n.RoleID(qrdbsdk.SystemTenantID, name)
		require.NoError(t, err, name)
		assert.NotEqual(t, name, id, "a role identifier is not the role name")

		r, err := n.Client().Roles().GetRole(qrdbsdk.ContextWithTenant(context.Background(), qrdbsdk.SystemTenantID), id)
		require.NoError(t, err, name)
		assert.Equal(t, name, r.Name)
	}

	adminID, err := n.RoleID(qrdbsdk.SystemTenantID, qrdbsdk.RoleNameAdmin)
	require.NoError(t, err)
	admin := &qrdbtransport.Identity{Subject: "admin", TenantID: qrdbsdk.SystemTenantID, Roles: []string{adminID}}
	require.NoError(t, n.Client().RBAC().Authorize(context.Background(), admin, "certs", "generate"),
		"the seeded Admin role must carry its built-in grants")
}

// TestFirstBootNode_RoleIDUnknownRole proves an unseeded role name is an
// error, not an empty identifier a test could silently grant.
func TestFirstBootNode_RoleIDUnknownRole(t *testing.T) {
	n, err := NewFirstBootNode(t)
	require.NoError(t, err)

	id, err := n.RoleID(qrdbsdk.SystemTenantID, "no-such-role")
	require.Error(t, err)
	var notFound *qrdbsdk.RoleNotFoundError
	assert.ErrorAs(t, err, &notFound)
	assert.Empty(t, id)
}

// TestFirstBootNode_ProvisionTenantSeedsTenantRoles proves a provisioned
// tenant carries its own built-in roles under identifiers distinct from the
// system tenant's, so a test can hold a tenant-local grant.
func TestFirstBootNode_ProvisionTenantSeedsTenantRoles(t *testing.T) {
	n, err := NewFirstBootNode(t)
	require.NoError(t, err)
	require.NoError(t, n.ProvisionTenant("tenant-a"))

	tenantAdmin, err := n.RoleID("tenant-a", qrdbsdk.RoleNameAdmin)
	require.NoError(t, err)
	systemAdmin, err := n.RoleID(qrdbsdk.SystemTenantID, qrdbsdk.RoleNameAdmin)
	require.NoError(t, err)
	assert.NotEqual(t, systemAdmin, tenantAdmin)
}

// TestFirstBootNode_ProvisionTenantRejectsEmptyID proves provisioning errors
// surface to the test rather than leaving an unseeded tenant behind.
func TestFirstBootNode_ProvisionTenantRejectsEmptyID(t *testing.T) {
	n, err := NewFirstBootNode(t)
	require.NoError(t, err)
	require.Error(t, n.ProvisionTenant(""))
}

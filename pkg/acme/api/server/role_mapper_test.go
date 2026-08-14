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

//go:build !integration

package server

import (
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDefaultRoleMapping verifies the shipped defaults: root and the root group
// get admin, wheel/admin groups get operator, and nothing else is mapped.
func TestDefaultRoleMapping(t *testing.T) {
	rm := DefaultRoleMapping()
	require.NotNil(t, rm)

	assert.Equal(t, []uint32{0}, rm.AdminUIDs)
	assert.Equal(t, []uint32{0}, rm.AdminGIDs)
	assert.Equal(t, []uint32{10, 80}, rm.OperatorGIDs)
	assert.Empty(t, rm.AuditorUIDs)
	assert.Empty(t, rm.AuditorGIDs)
}

// TestRoleMappingRoles_UsesCanonicalNames verifies the mapper emits go-qrdb's
// canonical role names, not a local vocabulary.
func TestRoleMappingRoles_UsesCanonicalNames(t *testing.T) {
	assert.Equal(t, qrdbsdk.RoleNameAdmin, RoleAdmin)
	assert.Equal(t, qrdbsdk.RoleNameOperator, RoleOperator)
	assert.Equal(t, qrdbsdk.RoleNameAuditor, RoleAuditor)
}

// TestRoleMappingRoles_Matching verifies each configured UID/GID resolves to the
// expected canonical role.
func TestRoleMappingRoles_Matching(t *testing.T) {
	rm := &RoleMapping{
		AdminUIDs:    []uint32{0, 1000},
		AdminGIDs:    []uint32{0},
		OperatorUIDs: []uint32{1001},
		OperatorGIDs: []uint32{10},
		AuditorUIDs:  []uint32{1002},
		AuditorGIDs:  []uint32{20},
	}

	tests := []struct {
		name  string
		creds *PeerCredentials
		want  []string
	}{
		{"admin uid", &PeerCredentials{UID: 0, GID: 999}, []string{RoleAdmin}},
		{"admin uid alt", &PeerCredentials{UID: 1000, GID: 999}, []string{RoleAdmin}},
		{"admin gid", &PeerCredentials{UID: 5000, GID: 0}, []string{RoleAdmin}},
		{"operator uid", &PeerCredentials{UID: 1001, GID: 999}, []string{RoleOperator}},
		{"operator gid", &PeerCredentials{UID: 5000, GID: 10}, []string{RoleOperator}},
		{"auditor uid", &PeerCredentials{UID: 1002, GID: 999}, []string{RoleAuditor}},
		{"auditor gid", &PeerCredentials{UID: 5000, GID: 20}, []string{RoleAuditor}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, rm.Roles(tc.creds))
		})
	}
}

// TestRoleMappingRoles_Priority verifies the mapper checks admin before
// operator before auditor, and prefers a UID match over a GID match.
func TestRoleMappingRoles_Priority(t *testing.T) {
	rm := &RoleMapping{
		AdminGIDs:    []uint32{100},
		OperatorGIDs: []uint32{100},
		AuditorGIDs:  []uint32{100},
	}
	assert.Equal(t, []string{RoleAdmin}, rm.Roles(&PeerCredentials{UID: 5000, GID: 100}))

	uidWins := &RoleMapping{
		AdminUIDs:    []uint32{1000},
		OperatorGIDs: []uint32{1000},
	}
	assert.Equal(t, []string{RoleAdmin}, uidWins.Roles(&PeerCredentials{UID: 1000, GID: 1000}))
}

// TestRoleMappingRoles_NoImplicitDefault is the fail-closed assertion: a peer
// that matches no configured entry receives no roles. The previous mapper
// returned "viewer" for every unmatched local connection, handing the whole
// read surface of the ACME admin API to any local user.
func TestRoleMappingRoles_NoImplicitDefault(t *testing.T) {
	rm := DefaultRoleMapping()

	assert.Nil(t, rm.Roles(&PeerCredentials{UID: 4242, GID: 4242}))
	assert.Nil(t, (&RoleMapping{}).Roles(&PeerCredentials{UID: 0, GID: 0}))
}

// TestRoleMappingRoles_NilInputs verifies the error paths: nil credentials and a
// nil mapping both yield no roles rather than panicking or defaulting.
func TestRoleMappingRoles_NilInputs(t *testing.T) {
	assert.Nil(t, DefaultRoleMapping().Roles(nil))

	var rm *RoleMapping
	assert.Nil(t, rm.Roles(&PeerCredentials{UID: 0, GID: 0}))
	assert.Nil(t, rm.Roles(nil))
}

// TestRoleMappingIdentity_BuildsAttributableIdentity verifies the identity
// carries the kernel-reported peer credentials so denials are attributable.
func TestRoleMappingIdentity_BuildsAttributableIdentity(t *testing.T) {
	rm := DefaultRoleMapping()
	rm.TenantID = "acme-tenant"

	id := rm.Identity(&PeerCredentials{PID: 4321, UID: 0, GID: 0})
	require.NotNil(t, id)

	assert.Equal(t, "uid:0", id.Subject)
	assert.Equal(t, "acme-tenant", id.TenantID)
	assert.Equal(t, []string{RoleAdmin}, id.Roles)
	assert.Equal(t, "so_peercred", id.Metadata["auth_method"])
	assert.Equal(t, "0", id.Metadata["uid"])
	assert.Equal(t, "0", id.Metadata["gid"])
	assert.Equal(t, "4321", id.Metadata["pid"])
}

// TestRoleMappingIdentity_UnmappedPeerHasNoRoles verifies an unmapped peer gets
// an identity with no grants, which the authorizer then denies.
func TestRoleMappingIdentity_UnmappedPeerHasNoRoles(t *testing.T) {
	id := DefaultRoleMapping().Identity(&PeerCredentials{PID: 1, UID: 4242, GID: 4242})
	require.NotNil(t, id)
	assert.Empty(t, id.Roles)
}

// TestRoleMappingIdentity_NilCredentials verifies the error path: no peer
// credentials means no identity, and the caller must deny.
func TestRoleMappingIdentity_NilCredentials(t *testing.T) {
	assert.Nil(t, DefaultRoleMapping().Identity(nil))

	var rm *RoleMapping
	assert.Nil(t, rm.Identity(nil))

	// A nil mapping with real credentials still yields an attributable
	// identity that holds no grants.
	id := rm.Identity(&PeerCredentials{PID: 7, UID: 0, GID: 0})
	require.NotNil(t, id)
	assert.Empty(t, id.Roles)
	assert.Equal(t, "uid:0", id.Subject)
}

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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultRoleMapping(t *testing.T) {
	rm := DefaultRoleMapping()

	require.NotNil(t, rm, "DefaultRoleMapping should not return nil")
	assert.Equal(t, []uint32{0}, rm.AdminUIDs, "AdminUIDs should contain root UID 0")
	assert.Equal(t, []uint32{0}, rm.AdminGIDs, "AdminGIDs should contain root GID 0")
	assert.Equal(t, []uint32{10, 80}, rm.OperatorGIDs, "OperatorGIDs should contain wheel (10) and admin (80)")
	assert.Nil(t, rm.OperatorUIDs, "OperatorUIDs should be nil by default")
	assert.Nil(t, rm.ViewerUIDs, "ViewerUIDs should be nil by default")
	assert.Nil(t, rm.ViewerGIDs, "ViewerGIDs should be nil by default")
}

func TestRoleMappingGetRole_NilCredentials(t *testing.T) {
	rm := DefaultRoleMapping()
	role := rm.GetRole(nil)
	assert.Equal(t, RoleNone, role, "GetRole should return RoleNone for nil credentials")
}

func TestRoleMappingGetRole_AdminUID(t *testing.T) {
	rm := DefaultRoleMapping()

	// Root user (UID 0) should get admin role
	creds := &PeerCredentials{
		PID: 1234,
		UID: 0,
		GID: 1000, // Non-admin group
	}
	role := rm.GetRole(creds)
	assert.Equal(t, RoleAdmin, role, "UID 0 (root) should receive RoleAdmin")
}

func TestRoleMappingGetRole_AdminGID(t *testing.T) {
	rm := DefaultRoleMapping()

	// Non-root user but in root group (GID 0) should get admin role
	creds := &PeerCredentials{
		PID: 1234,
		UID: 1000, // Non-root user
		GID: 0,    // Root group
	}
	role := rm.GetRole(creds)
	assert.Equal(t, RoleAdmin, role, "GID 0 (root group) should receive RoleAdmin")
}

func TestRoleMappingGetRole_OperatorUID(t *testing.T) {
	rm := &RoleMapping{
		OperatorUIDs: []uint32{1001, 1002},
	}

	creds := &PeerCredentials{
		PID: 1234,
		UID: 1001,
		GID: 1000,
	}
	role := rm.GetRole(creds)
	assert.Equal(t, RoleOperator, role, "UID in OperatorUIDs should receive RoleOperator")

	creds.UID = 1002
	role = rm.GetRole(creds)
	assert.Equal(t, RoleOperator, role, "Second UID in OperatorUIDs should also receive RoleOperator")
}

func TestRoleMappingGetRole_OperatorGID(t *testing.T) {
	rm := DefaultRoleMapping()

	// User in wheel group (GID 10) should get operator role
	creds := &PeerCredentials{
		PID: 1234,
		UID: 1000,
		GID: 10, // wheel group on Linux
	}
	role := rm.GetRole(creds)
	assert.Equal(t, RoleOperator, role, "GID 10 (wheel) should receive RoleOperator")

	// User in admin group (GID 80) should also get operator role
	creds.GID = 80 // admin group on macOS
	role = rm.GetRole(creds)
	assert.Equal(t, RoleOperator, role, "GID 80 (admin) should receive RoleOperator")
}

func TestRoleMappingGetRole_ViewerUID(t *testing.T) {
	rm := &RoleMapping{
		ViewerUIDs: []uint32{2001, 2002},
	}

	creds := &PeerCredentials{
		PID: 1234,
		UID: 2001,
		GID: 1000,
	}
	role := rm.GetRole(creds)
	assert.Equal(t, RoleViewer, role, "UID in ViewerUIDs should receive RoleViewer")
}

func TestRoleMappingGetRole_ViewerGID(t *testing.T) {
	rm := &RoleMapping{
		ViewerGIDs: []uint32{3001, 3002},
	}

	creds := &PeerCredentials{
		PID: 1234,
		UID: 1000,
		GID: 3001,
	}
	role := rm.GetRole(creds)
	assert.Equal(t, RoleViewer, role, "GID in ViewerGIDs should receive RoleViewer")
}

func TestRoleMappingGetRole_DefaultViewer(t *testing.T) {
	rm := DefaultRoleMapping()

	// Regular user not matching any specific mapping should get viewer role
	creds := &PeerCredentials{
		PID: 1234,
		UID: 1000,
		GID: 1000,
	}
	role := rm.GetRole(creds)
	assert.Equal(t, RoleViewer, role, "Unmatched authenticated user should receive RoleViewer")
}

func TestRoleMappingGetRole_CustomMapping(t *testing.T) {
	rm := &RoleMapping{
		AdminUIDs:    []uint32{500, 501},
		AdminGIDs:    []uint32{500},
		OperatorUIDs: []uint32{600, 601, 602},
		OperatorGIDs: []uint32{600},
		ViewerUIDs:   []uint32{700},
		ViewerGIDs:   []uint32{700},
	}

	tests := []struct {
		name     string
		uid      uint32
		gid      uint32
		expected Role
	}{
		{"custom admin UID 500", 500, 1000, RoleAdmin},
		{"custom admin UID 501", 501, 1000, RoleAdmin},
		{"custom admin GID 500", 1000, 500, RoleAdmin},
		{"custom operator UID 600", 600, 1000, RoleOperator},
		{"custom operator UID 601", 601, 1000, RoleOperator},
		{"custom operator UID 602", 602, 1000, RoleOperator},
		{"custom operator GID 600", 1000, 600, RoleOperator},
		{"custom viewer UID 700", 700, 1000, RoleViewer},
		{"custom viewer GID 700", 1000, 700, RoleViewer},
		{"default to viewer", 9999, 9999, RoleViewer},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			creds := &PeerCredentials{
				PID: 1234,
				UID: tt.uid,
				GID: tt.gid,
			}
			role := rm.GetRole(creds)
			assert.Equal(t, tt.expected, role)
		})
	}
}

func TestRoleMappingGetRole_PriorityOrder(t *testing.T) {
	// When a user matches multiple roles, higher privilege should win
	rm := &RoleMapping{
		AdminUIDs:    []uint32{100},
		OperatorUIDs: []uint32{100}, // Same UID in both admin and operator
		ViewerUIDs:   []uint32{100}, // Same UID in all three
	}

	creds := &PeerCredentials{
		PID: 1234,
		UID: 100,
		GID: 1000,
	}
	role := rm.GetRole(creds)
	assert.Equal(t, RoleAdmin, role, "Admin should take priority when UID matches multiple roles")

	// Test GID priority
	rm2 := &RoleMapping{
		AdminGIDs:    []uint32{200},
		OperatorGIDs: []uint32{200},
	}
	creds.UID = 1000
	creds.GID = 200
	role = rm2.GetRole(creds)
	assert.Equal(t, RoleAdmin, role, "Admin GID should take priority over operator GID")
}

func TestRoleMappingGetRole_UIDOverGID(t *testing.T) {
	// UID matching should take priority over GID matching at each level
	rm := &RoleMapping{
		AdminUIDs:    []uint32{100},
		OperatorGIDs: []uint32{200}, // Different GID
	}

	// User with admin UID but operator GID should be admin
	creds := &PeerCredentials{
		PID: 1234,
		UID: 100,
		GID: 200,
	}
	role := rm.GetRole(creds)
	assert.Equal(t, RoleAdmin, role, "Admin UID should take priority over operator GID")
}

func TestCanPerform(t *testing.T) {
	tests := []struct {
		name         string
		userRole     Role
		requiredRole Role
		expected     bool
	}{
		// Admin can do everything
		{"admin can perform admin", RoleAdmin, RoleAdmin, true},
		{"admin can perform operator", RoleAdmin, RoleOperator, true},
		{"admin can perform viewer", RoleAdmin, RoleViewer, true},
		{"admin can perform none", RoleAdmin, RoleNone, true},

		// Operator can do operator and below
		{"operator cannot perform admin", RoleOperator, RoleAdmin, false},
		{"operator can perform operator", RoleOperator, RoleOperator, true},
		{"operator can perform viewer", RoleOperator, RoleViewer, true},
		{"operator can perform none", RoleOperator, RoleNone, true},

		// Viewer can only do viewer and below
		{"viewer cannot perform admin", RoleViewer, RoleAdmin, false},
		{"viewer cannot perform operator", RoleViewer, RoleOperator, false},
		{"viewer can perform viewer", RoleViewer, RoleViewer, true},
		{"viewer can perform none", RoleViewer, RoleNone, true},

		// None can only do none (no auth required)
		{"none cannot perform admin", RoleNone, RoleAdmin, false},
		{"none cannot perform operator", RoleNone, RoleOperator, false},
		{"none cannot perform viewer", RoleNone, RoleViewer, false},
		{"none can perform none", RoleNone, RoleNone, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CanPerform(tt.userRole, tt.requiredRole)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestCanPerform_AllCombinations(t *testing.T) {
	// Complete matrix test for role hierarchy
	roles := []Role{RoleAdmin, RoleOperator, RoleViewer, RoleNone}

	// Expected results matrix: rows = user role, cols = required role
	// Order: Admin, Operator, Viewer, None
	expected := [][]bool{
		{true, true, true, true},    // Admin user
		{false, true, true, true},   // Operator user
		{false, false, true, true},  // Viewer user
		{false, false, false, true}, // None user
	}

	for i, userRole := range roles {
		for j, requiredRole := range roles {
			t.Run(string(userRole)+"_requires_"+string(requiredRole), func(t *testing.T) {
				result := CanPerform(userRole, requiredRole)
				assert.Equal(t, expected[i][j], result,
					"user=%s, required=%s", userRole, requiredRole)
			})
		}
	}
}

func TestCanPerform_UnknownRole(t *testing.T) {
	// Unknown required role should default to false
	unknownRole := Role("unknown")
	assert.False(t, CanPerform(RoleAdmin, unknownRole), "Unknown required role should return false")
	assert.False(t, CanPerform(unknownRole, RoleViewer), "Unknown user role should return false for viewer requirement")
}

func TestRole_String(t *testing.T) {
	// Verify role constants are as expected
	assert.Equal(t, "admin", string(RoleAdmin))
	assert.Equal(t, "operator", string(RoleOperator))
	assert.Equal(t, "viewer", string(RoleViewer))
	assert.Equal(t, "none", string(RoleNone))
}

func TestRoleMapping_EmptyMapping(t *testing.T) {
	// Empty mapping should default all authenticated users to viewer
	rm := &RoleMapping{}

	creds := &PeerCredentials{
		PID: 1234,
		UID: 0, // Even root
		GID: 0, // Even root group
	}
	role := rm.GetRole(creds)
	assert.Equal(t, RoleViewer, role, "Empty mapping should default to viewer for all authenticated users")
}

func TestRoleMapping_MultipleAdminUIDs(t *testing.T) {
	rm := &RoleMapping{
		AdminUIDs: []uint32{0, 1000, 2000},
	}

	for _, uid := range []uint32{0, 1000, 2000} {
		creds := &PeerCredentials{
			PID: 1234,
			UID: uid,
			GID: 1000,
		}
		role := rm.GetRole(creds)
		assert.Equal(t, RoleAdmin, role, "UID %d should receive RoleAdmin", uid)
	}
}

func TestRoleMapping_MultipleOperatorGIDs(t *testing.T) {
	rm := &RoleMapping{
		OperatorGIDs: []uint32{10, 27, 80, 100},
	}

	for _, gid := range []uint32{10, 27, 80, 100} {
		creds := &PeerCredentials{
			PID: 1234,
			UID: 1000,
			GID: gid,
		}
		role := rm.GetRole(creds)
		assert.Equal(t, RoleOperator, role, "GID %d should receive RoleOperator", gid)
	}
}

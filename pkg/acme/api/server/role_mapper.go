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

package server

// Role represents an authorization role for gRPC Unix socket authentication.
type Role string

const (
	// RoleAdmin has full access to all operations
	RoleAdmin Role = "admin"
	// RoleOperator has access to operational tasks but not administrative ones
	RoleOperator Role = "operator"
	// RoleViewer has read-only access
	RoleViewer Role = "viewer"
	// RoleNone indicates no authenticated role (unauthenticated or unauthorized)
	RoleNone Role = "none"
)

// RoleMapping defines how Unix UIDs and GIDs map to authorization roles.
// This enables fine-grained access control based on the calling process's
// identity as reported by the kernel via SO_PEERCRED.
type RoleMapping struct {
	// AdminUIDs are user IDs that receive admin role (e.g., root = 0)
	AdminUIDs []uint32
	// AdminGIDs are group IDs that receive admin role
	AdminGIDs []uint32
	// OperatorUIDs are user IDs that receive operator role
	OperatorUIDs []uint32
	// OperatorGIDs are group IDs that receive operator role (e.g., wheel, admin)
	OperatorGIDs []uint32
	// ViewerUIDs are user IDs that receive viewer role
	ViewerUIDs []uint32
	// ViewerGIDs are group IDs that receive viewer role
	ViewerGIDs []uint32
}

// DefaultRoleMapping returns sensible default role mappings:
//   - root (UID 0) -> admin
//   - root group (GID 0) -> admin
//   - wheel group (GID 10 on Linux) -> operator
//   - admin group (GID 80 on macOS) -> operator
//   - All other authenticated connections -> viewer
func DefaultRoleMapping() *RoleMapping {
	return &RoleMapping{
		AdminUIDs:    []uint32{0},      // root
		AdminGIDs:    []uint32{0},      // root group
		OperatorGIDs: []uint32{10, 80}, // wheel (Linux), admin (macOS)
	}
}

// GetRole determines the role for the given peer credentials.
// Roles are checked in order of privilege: admin -> operator -> viewer.
// Returns RoleViewer for authenticated connections that don't match any specific mapping.
// Returns RoleNone if credentials are nil.
func (rm *RoleMapping) GetRole(creds *PeerCredentials) Role {
	if creds == nil {
		return RoleNone
	}

	// Check admin UIDs first (highest privilege)
	for _, uid := range rm.AdminUIDs {
		if creds.UID == uid {
			return RoleAdmin
		}
	}

	// Check admin GIDs
	for _, gid := range rm.AdminGIDs {
		if creds.GID == gid {
			return RoleAdmin
		}
	}

	// Check operator UIDs
	for _, uid := range rm.OperatorUIDs {
		if creds.UID == uid {
			return RoleOperator
		}
	}

	// Check operator GIDs
	for _, gid := range rm.OperatorGIDs {
		if creds.GID == gid {
			return RoleOperator
		}
	}

	// Check viewer UIDs
	for _, uid := range rm.ViewerUIDs {
		if creds.UID == uid {
			return RoleViewer
		}
	}

	// Check viewer GIDs
	for _, gid := range rm.ViewerGIDs {
		if creds.GID == gid {
			return RoleViewer
		}
	}

	// Default to viewer for authenticated connections (Unix sockets are inherently local)
	return RoleViewer
}

// CanPerform checks if the given role can perform an action requiring the specified role.
// Roles are hierarchical: admin > operator > viewer.
func CanPerform(userRole, requiredRole Role) bool {
	switch requiredRole {
	case RoleAdmin:
		return userRole == RoleAdmin
	case RoleOperator:
		return userRole == RoleAdmin || userRole == RoleOperator
	case RoleViewer:
		return userRole == RoleAdmin || userRole == RoleOperator || userRole == RoleViewer
	case RoleNone:
		// RoleNone as required means no authentication needed
		return true
	default:
		return false
	}
}

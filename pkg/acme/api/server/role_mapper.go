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

import (
	"fmt"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
)

// Canonical go-qrdb role names assignable from Unix peer credentials. They are
// the same six FIPS 140-3 / PCI-DSS v4 system roles the rest of the stack uses;
// this package defines no role vocabulary of its own. Any role name qrdb knows
// may be configured in a RoleMapping — these constants simply name the ones a
// default deployment assigns.
const (
	// RoleAdmin manages key lifecycle and tenant configuration.
	RoleAdmin = qrdbsdk.RoleNameAdmin
	// RoleOperator performs routine operational tasks.
	RoleOperator = qrdbsdk.RoleNameOperator
	// RoleAuditor has read-only access to system state and the audit trail.
	RoleAuditor = qrdbsdk.RoleNameAuditor
)

// RoleMapping defines how Unix UIDs and GIDs map to canonical qrdb role names.
// SO_PEERCRED gives the kernel-verified identity of the calling process; this
// mapping turns that identity into the role grants the qrdb RBAC engine then
// evaluates. It performs no authorization itself.
//
// There is deliberately no implicit default role. A peer that matches no entry
// yields an identity with no roles, and every privileged method is denied. The
// previous "all other authenticated connections -> viewer" fallback handed the
// entire read surface of the ACME admin API to any local user who could open
// the socket.
type RoleMapping struct {
	// AdminUIDs are user IDs that receive the admin role (e.g. root = 0)
	AdminUIDs []uint32
	// AdminGIDs are group IDs that receive the admin role
	AdminGIDs []uint32
	// OperatorUIDs are user IDs that receive the operator role
	OperatorUIDs []uint32
	// OperatorGIDs are group IDs that receive the operator role (e.g. wheel, admin)
	OperatorGIDs []uint32
	// AuditorUIDs are user IDs that receive the read-only auditor role
	AuditorUIDs []uint32
	// AuditorGIDs are group IDs that receive the read-only auditor role
	AuditorGIDs []uint32

	// TenantID scopes the identities this mapping produces. An empty value is
	// normalized by the Authorizer to the reserved system tenant, which is the
	// correct scope for a local administrative socket.
	TenantID string
}

// DefaultRoleMapping returns sensible default role mappings:
//   - root (UID 0) -> admin
//   - root group (GID 0) -> admin
//   - wheel group (GID 10 on Linux) -> operator
//   - admin group (GID 80 on macOS) -> operator
//   - every other peer -> no roles (denied)
func DefaultRoleMapping() *RoleMapping {
	return &RoleMapping{
		AdminUIDs:    []uint32{0},      // root
		AdminGIDs:    []uint32{0},      // root group
		OperatorGIDs: []uint32{10, 80}, // wheel (Linux), admin (macOS)
	}
}

// Roles returns the canonical qrdb role names for the given peer credentials,
// checked in order of privilege: admin -> operator -> auditor. It returns nil
// for nil credentials and for a peer that matches no configured entry, so the
// resulting identity holds no grants and fails closed at the authorizer.
func (rm *RoleMapping) Roles(creds *PeerCredentials) []string {
	if rm == nil || creds == nil {
		return nil
	}

	for _, role := range []struct {
		name string
		uids []uint32
		gids []uint32
	}{
		{RoleAdmin, rm.AdminUIDs, rm.AdminGIDs},
		{RoleOperator, rm.OperatorUIDs, rm.OperatorGIDs},
		{RoleAuditor, rm.AuditorUIDs, rm.AuditorGIDs},
	} {
		for _, uid := range role.uids {
			if creds.UID == uid {
				return []string{role.name}
			}
		}
		for _, gid := range role.gids {
			if creds.GID == gid {
				return []string{role.name}
			}
		}
	}

	return nil
}

// Identity builds the canonical auth.Identity for the given peer credentials.
// The subject records the kernel-reported UID/PID so denials are attributable.
// It returns nil for nil credentials — the caller must then deny.
func (rm *RoleMapping) Identity(creds *PeerCredentials) *auth.Identity {
	if creds == nil {
		return nil
	}

	tenantID := ""
	if rm != nil {
		tenantID = rm.TenantID
	}

	return &auth.Identity{
		Subject:  fmt.Sprintf("uid:%d", creds.UID),
		TenantID: tenantID,
		Roles:    rm.Roles(creds),
		Metadata: map[string]string{
			"auth_method": "so_peercred",
			"uid":         fmt.Sprintf("%d", creds.UID),
			"gid":         fmt.Sprintf("%d", creds.GID),
			"pid":         fmt.Sprintf("%d", creds.PID),
		},
	}
}

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

package main

// Role names the access-control role the CLI assigns when registering users
// and admins. Identity itself lives in the embedded qrdb node; these constants
// mirror qrdb's canonical role names so the strings the CLI sends to the SDK
// match what the server understands.
type Role string

const (
	// RoleSO is the Security Officer role per FIPS 140-2/3 separation of duties.
	RoleSO Role = "so"
	// RoleAdmin has full access to manage the xkms and other users.
	RoleAdmin Role = "admin"
	// RoleOperator can manage keys and certificates but not users.
	RoleOperator Role = "operator"
	// RoleUser can use keys for cryptographic operations but not manage them.
	RoleUser Role = "user"
	// RoleAuditor can only view audit logs and key metadata.
	RoleAuditor Role = "auditor"
	// RoleCustodian participates in key ceremonies and manages key shares.
	RoleCustodian Role = "custodian"
)

// IsValidRole reports whether r is one of the canonical qrdb role names the
// CLI is allowed to assign.
func IsValidRole(r Role) bool {
	switch r {
	case RoleSO, RoleAdmin, RoleOperator, RoleUser, RoleAuditor, RoleCustodian:
		return true
	default:
		return false
	}
}

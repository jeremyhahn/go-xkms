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
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
)

// TestActionReadCross_MatchesQRDBAuditReadCross pins the restated
// audit:read:cross string to go-qrdb's registry. The SDK does not re-export
// permission.AuditReadCross, so a rename upstream would otherwise leave
// QueryAudit asking about a permission nobody holds, silently clamping every
// platform auditor to the system tenant.
func TestActionReadCross_MatchesQRDBAuditReadCross(t *testing.T) {
	perm := qrdbsdk.Permission(ResourceAudit + ":" + ActionReadCross)

	assert.True(t, qrdbsdk.IsPermissionRegistered(perm), "%s must be registered by qrdb", perm)
	assert.True(t, qrdbsdk.HasPermissionRoleGrant(qrdbsdk.PermissionRoleAdmin, perm), "qrdb's Admin role grants %s", perm)
}

// TestActionReadCross_NotHeldByAuditor records qrdb's grant table: the
// built-in Auditor role reads audit self-scope only, so a system-tenant
// Auditor is confined to the system tenant's events.
func TestActionReadCross_NotHeldByAuditor(t *testing.T) {
	perm := qrdbsdk.Permission(ResourceAudit + ":" + ActionReadCross)

	assert.False(t, qrdbsdk.HasPermissionRoleGrant(qrdbsdk.PermissionRoleAuditor, perm))
	assert.True(t, qrdbsdk.HasPermissionRoleGrant(qrdbsdk.PermissionRoleAuditor, qrdbsdk.Permission(ResourceAudit+":"+ActionRead)))
}

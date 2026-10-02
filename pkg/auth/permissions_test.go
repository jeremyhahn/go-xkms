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

// TestAudit_NoCrossTenantRead pins go-qrdb's audit contract that QueryAudit
// relies on: there is no cross-tenant audit permission (go-qrdb v0.28 removed
// audit:read:cross), so every caller, the system tenant included, reads only
// its own tenant's events. Should a cross-tenant read reappear upstream this
// fails, and the service's own-tenant confinement must be revisited.
func TestAudit_NoCrossTenantRead(t *testing.T) {
	assert.False(t, qrdbsdk.IsPermissionRegistered(qrdbsdk.Permission(ResourceAudit+":read:cross")))
	assert.True(t, qrdbsdk.IsPermissionRegistered(qrdbsdk.Permission(ResourceAudit+":"+ActionRead)))
	assert.True(t, qrdbsdk.HasPermissionRoleGrant(qrdbsdk.PermissionRoleAuditor, qrdbsdk.Permission(ResourceAudit+":"+ActionRead)))
}

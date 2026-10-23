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

package xkms

import (
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pkgxkms "github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// TestTrustWritePermissions_GrantedByServiceModule proves a consumer can
// gate the trust write verbs with the re-exported names alone: mounting the
// service module registers both, and Admin holds them.
func TestTrustWritePermissions_GrantedByServiceModule(t *testing.T) {
	_, err := NewServiceModule(func() *pkgxkms.XKMSService { return nil })
	require.NoError(t, err)

	for _, action := range []string{PermissionActionPublishDANE, PermissionActionAutoImportAIA} {
		perm := qrdbsdk.Permission(PermissionResourceTrust + ":" + action)
		assert.True(t, qrdbsdk.HasPermissionRoleGrant(qrdbsdk.PermissionRoleAdmin, perm), "Admin must hold %s", perm)
		assert.False(t, qrdbsdk.HasPermissionRoleGrant(qrdbsdk.PermissionRoleUser, perm), "User must not hold %s", perm)
	}
}

// TestTrustWritePermissions_UnknownActionNotGranted is the negative case: a
// trust action go-xkms does not declare is held by no role.
func TestTrustWritePermissions_UnknownActionNotGranted(t *testing.T) {
	_, err := NewServiceModule(func() *pkgxkms.XKMSService { return nil })
	require.NoError(t, err)

	perm := qrdbsdk.Permission(PermissionResourceTrust + ":publish")
	assert.False(t, qrdbsdk.HasPermissionRoleGrant(qrdbsdk.PermissionRoleAdmin, perm))
}

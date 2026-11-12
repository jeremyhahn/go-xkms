// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

package scope_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/scope"
)

// TestAuthorize_OwnTenant checks the tenant step of Authorize is go-qrdb's
// OwnTenant rule: a cross-tenant refusal is both scope's *CrossTenantError
// (ErrRefused) and go-qrdb's *CrossTenantDeniedError.
func TestAuthorize_OwnTenant(t *testing.T) {
	alice := scope.Principal{TenantID: "a", Subject: "alice", Authenticated: true}

	err := alice.Authorize(scope.Target{TenantID: "b", Scope: scope.Tenant})
	require.Error(t, err)
	assert.ErrorIs(t, err, scope.ErrRefused)

	var cross *scope.CrossTenantError
	require.ErrorAs(t, err, &cross)
	assert.Equal(t, "a", cross.CallerTenantID)
	assert.Equal(t, "b", cross.TargetTenantID)

	var denied *qrdbsdk.CrossTenantDeniedError
	require.ErrorAs(t, err, &denied)
	assert.Equal(t, "a", denied.IdentityTenantID)
	assert.Equal(t, "b", denied.RequestedTenantID)
}

// TestAuthorize_OwnTenant_SystemSpellings checks the system tenant written as
// "" and as SystemTenant is one tenant on either side of the check.
func TestAuthorize_OwnTenant_SystemSpellings(t *testing.T) {
	for _, caller := range []string{"", scope.SystemTenant} {
		for _, target := range []string{"", scope.SystemTenant} {
			p := scope.Principal{TenantID: caller, Subject: "root", Authenticated: true}
			assert.NoError(t, p.Authorize(scope.Target{TenantID: target, Scope: scope.Tenant}),
				"caller %q target %q", caller, target)
		}
	}
}

// TestAuthorize_OwnTenant_NoPlatformException checks a system-tenant
// principal addressing another tenant is refused, and a tenant principal
// addressing the system tenant (written either way) is refused too.
func TestAuthorize_OwnTenant_NoPlatformException(t *testing.T) {
	for _, sys := range []string{"", scope.SystemTenant} {
		root := scope.Principal{TenantID: sys, Subject: "root", Authenticated: true, ServiceAccess: true}
		for _, sc := range []scope.Scope{scope.Tenant, scope.User, scope.Service} {
			err := root.Authorize(scope.Target{TenantID: "a", Scope: sc, Owner: "root"})
			var denied *qrdbsdk.CrossTenantDeniedError
			require.ErrorAs(t, err, &denied, "system %q scope %s", sys, sc)
			assert.Equal(t, qrdbsdk.SystemTenantID, denied.IdentityTenantID)
			assert.Equal(t, "a", denied.RequestedTenantID)
			assert.ErrorIs(t, err, scope.ErrRefused)
		}

		alice := scope.Principal{TenantID: "a", Subject: "alice", Authenticated: true}
		err := alice.Authorize(scope.Target{TenantID: sys, Scope: scope.Tenant})
		var denied *qrdbsdk.CrossTenantDeniedError
		require.ErrorAs(t, err, &denied, "tenant to system %q", sys)
		assert.Equal(t, qrdbsdk.SystemTenantID, denied.RequestedTenantID)
	}
}

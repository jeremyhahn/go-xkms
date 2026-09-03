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

package xkms

import (
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================
// ScopeBackendToTenant
//
// The tenant-scoped view a transport needs when it already holds a Backend --
// its default keystore, say -- rather than a name to resolve.
// ============================================================

func TestScopeBackendToTenant_RealTenantIsScoped(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	base, err := svc.LookupBackend("software")
	require.NoError(t, err)

	got, err := ScopeBackendToTenant(base, "acme")
	require.NoError(t, err)

	tsb, ok := got.(*TenantScopedBackend)
	require.True(t, ok, "expected *TenantScopedBackend, got %T", got)
	assert.Equal(t, "acme", tsb.tenantID)
	assert.Equal(t, base, tsb.base)
}

// TestScopeBackendToTenant_SystemScopeIsNotATenant covers the platform scope:
// "" and the system tenant are the same scope, and both must return the base
// backend unchanged so the control plane keeps the view internal pipelines use.
func TestScopeBackendToTenant_SystemScopeIsNotATenant(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	base, err := svc.LookupBackend("software")
	require.NoError(t, err)

	for _, tenantID := range []string{"", qrdbsdk.SystemTenantID} {
		got, err := ScopeBackendToTenant(base, tenantID)
		require.NoError(t, err)
		assert.Equal(t, base, got, "tenant %q must not be scoped", tenantID)
	}
}

// TestScopeBackendToTenant_InvalidTenantIDRefused proves the function fails
// closed: a tenant ID that could escape its namespace is an error, never a
// silent fall back to the unscoped backend.
func TestScopeBackendToTenant_InvalidTenantIDRefused(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	base, err := svc.LookupBackend("software")
	require.NoError(t, err)

	for _, tenantID := range []string{"../etc", "tenant/evil", `tenant\evil`} {
		got, err := ScopeBackendToTenant(base, tenantID)
		require.Error(t, err, "tenant %q must be refused", tenantID)
		assert.ErrorIs(t, err, ErrTenantIDRequired)
		assert.Nil(t, got)
	}
}

// ============================================================
// XKMSService.LookupTenantBackend
// ============================================================

func TestLookupTenantBackend_RealTenantIsScoped(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	got, err := svc.LookupTenantBackend("software", "acme")
	require.NoError(t, err)

	tsb, ok := got.(*TenantScopedBackend)
	require.True(t, ok, "expected *TenantScopedBackend, got %T", got)
	assert.Equal(t, "acme", tsb.tenantID)
}

func TestLookupTenantBackend_SystemScopeIsUnscoped(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	base, err := svc.LookupBackend("software")
	require.NoError(t, err)

	got, err := svc.LookupTenantBackend("software", "")
	require.NoError(t, err)
	assert.Equal(t, base, got)
}

func TestLookupTenantBackend_UnknownBackendRefused(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	got, err := svc.LookupTenantBackend("nonexistent", "acme")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrBackendNotFound)
	assert.Nil(t, got)
}

func TestLookupTenantBackend_InvalidTenantIDRefused(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	got, err := svc.LookupTenantBackend("software", "tenant/evil")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTenantIDRequired)
	assert.Nil(t, got)
}

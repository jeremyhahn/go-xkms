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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================
// resolveTenantBackend tests
// ============================================================

// TestResolveTenantBackend_EmptyTenantID verifies that an empty tenantID returns
// the base backend unchanged (backward-compatible path).
func TestResolveTenantBackend_EmptyTenantID(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	base, err := svc.resolveBackend("software")
	require.NoError(t, err)

	got, err := svc.resolveTenantBackend("software", "")
	require.NoError(t, err)
	require.NotNil(t, got)

	// No wrapping should occur; the returned backend should be the same object.
	assert.Equal(t, base, got)
}

// TestResolveTenantBackend_NonEmptyTenantID verifies that a valid tenantID returns
// a TenantScopedBackend wrapping the base backend.
func TestResolveTenantBackend_NonEmptyTenantID(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	got, err := svc.resolveTenantBackend("software", "acme")
	require.NoError(t, err)
	require.NotNil(t, got)

	tsb, ok := got.(*TenantScopedBackend)
	require.True(t, ok, "expected *TenantScopedBackend, got %T", got)
	assert.Equal(t, "acme", tsb.tenantID)
}

// TestResolveTenantBackend_InvalidTenantID_DotDot verifies that a tenantID
// containing ".." is rejected.
func TestResolveTenantBackend_InvalidTenantID_DotDot(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.resolveTenantBackend("software", "../etc")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTenantIDRequired)
}

// TestResolveTenantBackend_InvalidTenantID_Slash verifies that a tenantID
// containing "/" is rejected.
func TestResolveTenantBackend_InvalidTenantID_Slash(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.resolveTenantBackend("software", "tenant/evil")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTenantIDRequired)
}

// TestResolveTenantBackend_InvalidTenantID_Backslash verifies that a tenantID
// containing "\" is rejected.
func TestResolveTenantBackend_InvalidTenantID_Backslash(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.resolveTenantBackend("software", `tenant\evil`)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTenantIDRequired)
}

// TestResolveTenantBackend_InvalidBackend verifies that an unknown backend name
// propagates the backend-not-found error regardless of the tenantID.
func TestResolveTenantBackend_InvalidBackend(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.resolveTenantBackend("nonexistent", "acme")
	require.Error(t, err)
}

// TestResolveTenantBackend_EmptyTenantID_EmptyBackend verifies that both
// empty tenant and empty backend name falls back to the default backend.
func TestResolveTenantBackend_EmptyTenantID_EmptyBackend(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	got, err := svc.resolveTenantBackend("", "")
	require.NoError(t, err)
	assert.NotNil(t, got)
}

// TestResolveTenantBackend_ValidTenantID_EmptyBackend verifies that an empty
// backend name resolves to the default backend and wraps it with tenant scope.
func TestResolveTenantBackend_ValidTenantID_EmptyBackend(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	got, err := svc.resolveTenantBackend("", "tenant-x")
	require.NoError(t, err)
	require.NotNil(t, got)

	tsb, ok := got.(*TenantScopedBackend)
	require.True(t, ok, "expected *TenantScopedBackend, got %T", got)
	assert.Equal(t, "tenant-x", tsb.tenantID)
}

// ============================================================
// resolveTenantBackendWithName tests
// ============================================================

func TestResolveTenantBackendWithName_EmptyTenantID(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	b, name, err := svc.resolveTenantBackendWithName("software", "")
	require.NoError(t, err)
	assert.NotNil(t, b)
	assert.Equal(t, "software", name)
	// Should NOT be wrapped in TenantScopedBackend.
	_, ok := b.(*TenantScopedBackend)
	assert.False(t, ok)
}

func TestResolveTenantBackendWithName_NonEmptyTenantID(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	b, name, err := svc.resolveTenantBackendWithName("software", "acme")
	require.NoError(t, err)
	assert.Equal(t, "software", name)

	tsb, ok := b.(*TenantScopedBackend)
	require.True(t, ok)
	assert.Equal(t, "acme", tsb.tenantID)
}

func TestResolveTenantBackendWithName_InvalidTenantID(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, _, err = svc.resolveTenantBackendWithName("software", "bad/id")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTenantIDRequired)
}

func TestResolveTenantBackendWithName_EmptyBackend_DefaultResolved(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, name, err := svc.resolveTenantBackendWithName("", "")
	require.NoError(t, err)
	assert.Equal(t, "software", name)
}

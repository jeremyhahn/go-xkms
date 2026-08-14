//go:build codec_json

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

package admin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
)

// TestPermissionGate_AllowsHeldGrant verifies the gate admits a caller whose
// qrdb role carries the requested resource:action.
func TestPermissionGate_AllowsHeldGrant(t *testing.T) {
	gate, client := newQRDBGate()
	ctx := auth.WithIdentity(context.Background(),
		identityWithRoles("tenant-a", qrdbsdk.RoleNameAdmin))

	require.NoError(t, gate.Authorize(ctx, auth.ResourceACMEEAB, auth.ActionCreate))
	assert.Equal(t, []string{"acme_eab:create"}, client.requests())
}

// TestPermissionGate_DeniesMissingGrant verifies the gate rejects a caller
// whose qrdb role does not carry the requested resource:action. The auditor
// role reaches the ACME read surface but never the mutating one.
func TestPermissionGate_DeniesMissingGrant(t *testing.T) {
	gate, client := newQRDBGate()
	ctx := auth.WithIdentity(context.Background(),
		identityWithRoles("tenant-a", qrdbsdk.RoleNameAuditor))

	require.NoError(t, gate.Authorize(ctx, auth.ResourceACMEEAB, auth.ActionList))

	client.reset()
	err := gate.Authorize(ctx, auth.ResourceACMEEAB, auth.ActionCreate)
	require.Error(t, err)
	assert.Equal(t, []string{"acme_eab:create"}, client.requests())
}

// TestPermissionGate_DeniesWithoutIdentity verifies an unauthenticated request
// is rejected with ErrUnauthenticated and never reaches the RBAC engine.
func TestPermissionGate_DeniesWithoutIdentity(t *testing.T) {
	gate, client := newQRDBGate()

	err := gate.Authorize(context.Background(), auth.ResourceCerts, auth.ActionList)
	require.ErrorIs(t, err, auth.ErrUnauthenticated)
	assert.Empty(t, client.requests(), "no identity must short-circuit before the RBAC call")
}

// TestPermissionGate_NilGateDenies verifies an unwired gate fails closed. A
// composition that forgets to build the gate must deny, never serve.
func TestPermissionGate_NilGateDenies(t *testing.T) {
	var gate *PermissionGate

	err := gate.Authorize(context.Background(), auth.ResourceCerts, auth.ActionList)
	require.ErrorIs(t, err, ErrGateNotConfigured)
	assert.False(t, gate.Enforcing())
}

// TestPermissionGate_NilGateWrapDenies verifies the route decorator on an
// unwired gate answers 403 and never invokes the handler.
func TestPermissionGate_NilGateWrapDenies(t *testing.T) {
	var gate *PermissionGate
	served := false

	h := gate.Wrap(auth.ResourceCerts, auth.ActionList, func(w http.ResponseWriter, r *http.Request) {
		served = true
	})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/admin/certificates", nil))

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.False(t, served, "handler must not run when the gate is unwired")
}

// TestPermissionGate_DisabledAuthorizerAllowsAuthenticated verifies the
// documented stack-wide "RBAC disabled => allow all" behavior: with no RBAC
// client the gate admits an authenticated caller. Authentication is still
// mandatory (see TestPermissionGate_DisabledAuthorizerStillNeedsIdentity).
func TestPermissionGate_DisabledAuthorizerAllowsAuthenticated(t *testing.T) {
	gate := NewPermissionGate(auth.NewAuthorizer(nil), discardLogger())
	ctx := auth.WithIdentity(context.Background(), identityWithRoles("tenant-a"))

	assert.False(t, gate.Enforcing())
	require.NoError(t, gate.Authorize(ctx, auth.ResourceCerts, auth.ActionRevoke))
}

// TestPermissionGate_DisabledAuthorizerStillNeedsIdentity verifies that
// disabling RBAC does not disable authentication.
func TestPermissionGate_DisabledAuthorizerStillNeedsIdentity(t *testing.T) {
	gate := NewPermissionGate(auth.NewAuthorizer(nil), discardLogger())

	err := gate.Authorize(context.Background(), auth.ResourceCerts, auth.ActionRevoke)
	require.ErrorIs(t, err, auth.ErrUnauthenticated)
}

// TestPermissionGate_WrapStatusCodes verifies the decorator maps an
// authorization outcome onto the right HTTP status: 200 on allow, 403 on a
// missing grant, 401 when the request carries no identity.
func TestPermissionGate_WrapStatusCodes(t *testing.T) {
	gate, _ := newQRDBGate()

	tests := []struct {
		name     string
		identity *auth.Identity
		wantCode int
		wantRun  bool
	}{
		{"granted", identityWithRoles("tenant-a", qrdbsdk.RoleNameAdmin), http.StatusOK, true},
		{"denied", identityWithRoles("tenant-a", qrdbsdk.RoleNameUser), http.StatusForbidden, false},
		{"unauthenticated", nil, http.StatusUnauthorized, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			served := false
			h := gate.Wrap(auth.ResourceACMEEAB, auth.ActionCreate, func(w http.ResponseWriter, r *http.Request) {
				served = true
				w.WriteHeader(http.StatusOK)
			})

			req := httptest.NewRequest(http.MethodPost, "/api/v1/tenants/t/eab", nil)
			if tc.identity != nil {
				req = req.WithContext(auth.WithIdentity(req.Context(), tc.identity))
			}

			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			assert.Equal(t, tc.wantCode, rec.Code)
			assert.Equal(t, tc.wantRun, served)
		})
	}
}

// TestPermissionGate_Enforcing verifies Enforcing reports the true state of the
// backing authorizer.
func TestPermissionGate_Enforcing(t *testing.T) {
	enforcing, _ := newQRDBGate()
	assert.True(t, enforcing.Enforcing())

	assert.False(t, NewPermissionGate(auth.NewAuthorizer(nil), discardLogger()).Enforcing())
	assert.False(t, NewPermissionGate(nil, discardLogger()).Enforcing())

	var nilGate *PermissionGate
	assert.False(t, nilGate.Enforcing())
}

// TestPermissionGate_NilLoggerIsReplaced verifies the constructor never leaves a
// nil logger behind, so a denial is always recorded.
func TestPermissionGate_NilLoggerIsReplaced(t *testing.T) {
	gate := NewPermissionGate(auth.NewAuthorizer(&qrdbRoleRBAC{}), nil)
	require.NotNil(t, gate.logger)

	err := gate.Authorize(context.Background(), auth.ResourceCerts, auth.ActionList)
	require.ErrorIs(t, err, auth.ErrUnauthenticated)
}

// TestRequireTenantScope_SystemTenantReachesEveryTenant verifies qrdb's
// system-tenant rule: an identity rooted in the system tenant is
// platform-scoped. This replaces the deleted "super-admin can access any
// tenant" check.
func TestRequireTenantScope_SystemTenantReachesEveryTenant(t *testing.T) {
	for _, tenant := range []string{"", qrdbsdk.SystemTenantID} {
		ctx := auth.WithIdentity(context.Background(),
			identityWithRoles(tenant, qrdbsdk.RoleNameAdmin))
		require.NoError(t, RequireTenantScope(ctx, "some-other-tenant"))
	}
}

// TestRequireTenantScope_TenantLocalIsConfined verifies a tenant-scoped
// identity reaches its own tenant and no other.
func TestRequireTenantScope_TenantLocalIsConfined(t *testing.T) {
	ctx := auth.WithIdentity(context.Background(),
		identityWithRoles("tenant-a", qrdbsdk.RoleNameAdmin))

	require.NoError(t, RequireTenantScope(ctx, "tenant-a"))
	require.ErrorIs(t, RequireTenantScope(ctx, "tenant-b"), ErrForbidden)
}

// TestRequireTenantScope_NoIdentity verifies the error path: no identity means
// unauthenticated, not "allowed".
func TestRequireTenantScope_NoIdentity(t *testing.T) {
	require.ErrorIs(t, RequireTenantScope(context.Background(), "tenant-a"), auth.ErrUnauthenticated)
}

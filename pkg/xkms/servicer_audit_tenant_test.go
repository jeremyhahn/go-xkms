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
	"context"
	"errors"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
)

// errGrantMissing is the fake RBAC client's denial.
var errGrantMissing = errors.New("fake rbac: permission denied")

// grantTableRBAC decides from qrdb's own built-in role grant table, reached
// through the SDK, and applies qrdb's ScopeCross rule for audit:read:cross (a
// tenant identity never holds it). The test therefore exercises the real
// grants — system Admin holds it, Auditor does not — rather than a fixture's.
type grantTableRBAC struct {
	err   error
	calls int
}

func (g *grantTableRBAC) Authorize(_ context.Context, id *qrdbtransport.Identity, resource, action string) error {
	g.calls++
	if g.err != nil {
		return g.err
	}
	perm := qrdbsdk.Permission(resource + ":" + action)
	if action == auth.ActionReadCross && !qrdbsdk.IsSystemTenant(id.TenantID) {
		return errGrantMissing
	}
	for _, role := range id.Roles {
		if qrdbsdk.HasPermissionRoleGrant(role, perm) {
			return nil
		}
	}
	return errGrantMissing
}

func (g *grantTableRBAC) ListPermissions(_ context.Context, _ *qrdbtransport.Identity) ([]qrdbtransport.PermissionInfo, error) {
	return nil, errGrantMissing
}

func auditServiceWithRBAC(t *testing.T, rbac qrdbtransport.RBACClient) (*XKMSService, *stubAuditClient) {
	t.Helper()
	stub := &stubAuditClient{page: &qrdbtransport.AuditPage{}}
	svc := auditService(t, stub)
	svc.SetAuthorizer(auth.NewAuthorizer(rbac))
	return svc, stub
}

func identityCtx(tenantID string, roles ...string) context.Context {
	return auth.WithIdentity(context.Background(), &auth.Identity{Subject: "caller", TenantID: tenantID, Roles: roles})
}

// TestQueryAudit_TenantCallerIsClampedToItsOwnTenant is the #1115 exploit: a
// tenant Admin asking for every tenant (empty filter) or another tenant gets
// only its own tenant's events.
func TestQueryAudit_TenantCallerIsClampedToItsOwnTenant(t *testing.T) {
	for _, requested := range []string{"", "tenant-b", qrdbsdk.SystemTenantID, "tenant-a"} {
		t.Run("requested="+requested, func(t *testing.T) {
			rbac := &grantTableRBAC{}
			svc, stub := auditServiceWithRBAC(t, rbac)

			_, err := svc.QueryAudit(identityCtx("tenant-a", qrdbsdk.PermissionRoleAdmin), &transport.AuditFilter{TenantID: requested})

			require.NoError(t, err)
			assert.Equal(t, "tenant-a", stub.gotFilter.TenantID)
			assert.Zero(t, rbac.calls, "a tenant caller's scope is fixed; the cross grant is never consulted")
		})
	}
}

// TestQueryAudit_SystemCallerWithReadCrossSeesEveryTenant proves the platform
// Admin, which qrdb grants audit:read:cross, reads the filter as given.
func TestQueryAudit_SystemCallerWithReadCrossSeesEveryTenant(t *testing.T) {
	for _, requested := range []string{"", "tenant-b"} {
		t.Run("requested="+requested, func(t *testing.T) {
			svc, stub := auditServiceWithRBAC(t, &grantTableRBAC{})

			_, err := svc.QueryAudit(identityCtx(qrdbsdk.SystemTenantID, qrdbsdk.PermissionRoleAdmin), &transport.AuditFilter{TenantID: requested})

			require.NoError(t, err)
			assert.Equal(t, requested, stub.gotFilter.TenantID)
		})
	}
}

// TestQueryAudit_SystemCallerWithoutReadCrossIsClampedToSystem proves qrdb's
// grant semantics: the built-in Auditor holds audit:read but not
// audit:read:cross, so even in the system tenant it reads the system tenant's
// events only — never "" (the match-everything filter).
func TestQueryAudit_SystemCallerWithoutReadCrossIsClampedToSystem(t *testing.T) {
	for _, requested := range []string{"", "tenant-b"} {
		t.Run("requested="+requested, func(t *testing.T) {
			svc, stub := auditServiceWithRBAC(t, &grantTableRBAC{})

			_, err := svc.QueryAudit(identityCtx(qrdbsdk.SystemTenantID, qrdbsdk.PermissionRoleAuditor), &transport.AuditFilter{TenantID: requested})

			require.NoError(t, err)
			assert.Equal(t, qrdbsdk.SystemTenantID, stub.gotFilter.TenantID)
		})
	}
}

// TestQueryAudit_AuthorizerFailureNarrowsTheView proves an Authorizer error is
// resolved to the smaller view, never the larger.
func TestQueryAudit_AuthorizerFailureNarrowsTheView(t *testing.T) {
	svc, stub := auditServiceWithRBAC(t, &grantTableRBAC{err: errors.New("rbac unavailable")})

	_, err := svc.QueryAudit(identityCtx(qrdbsdk.SystemTenantID, qrdbsdk.PermissionRoleAdmin), &transport.AuditFilter{})

	require.NoError(t, err)
	assert.Equal(t, qrdbsdk.SystemTenantID, stub.gotFilter.TenantID)
}

// TestQueryAudit_NoIdentityWithRBACEnabledIsClampedToSystem proves a query
// that reaches the service without an identity cannot read across tenants
// when RBAC is on.
func TestQueryAudit_NoIdentityWithRBACEnabledIsClampedToSystem(t *testing.T) {
	svc, stub := auditServiceWithRBAC(t, &grantTableRBAC{})

	_, err := svc.QueryAudit(context.Background(), &transport.AuditFilter{TenantID: "tenant-b"})

	require.NoError(t, err)
	assert.Equal(t, qrdbsdk.SystemTenantID, stub.gotFilter.TenantID)
}

// TestQueryAudit_RBACDisabledStillClampsTenantCallers proves the clamp does not
// depend on RBAC: with authorization off the platform scope reads as asked, as
// every transport does, but a tenant identity is still confined.
func TestQueryAudit_RBACDisabledStillClampsTenantCallers(t *testing.T) {
	svc, stub := auditServiceWithRBAC(t, nil)

	_, err := svc.QueryAudit(identityCtx("tenant-a"), &transport.AuditFilter{})
	require.NoError(t, err)
	assert.Equal(t, "tenant-a", stub.gotFilter.TenantID)

	_, err = svc.QueryAudit(identityCtx(qrdbsdk.SystemTenantID), &transport.AuditFilter{TenantID: "tenant-b"})
	require.NoError(t, err)
	assert.Equal(t, "tenant-b", stub.gotFilter.TenantID)
}

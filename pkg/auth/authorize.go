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

package auth

import (
	"context"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
)

// Authorizer is the single authorization seam for the xkms API surface
// (REST, gRPC, QUIC). It delegates every decision to the hosted go-qrdb
// node's RBAC service — the canonical RBAC engine for the stack — so xkms
// carries no parallel role/permission model.
//
// A nil Authorizer, or one constructed with a nil RBAC client, treats
// authorization as disabled and allows every request. This preserves the
// historical "RBAC disabled => allow all" behavior for deployments that do
// not enable authorization, while an enabled Authorizer enforces the qrdb
// role grants for the identity carried on the request context.
type Authorizer struct {
	rbac qrdbtransport.RBACClient
}

// Authorizer satisfies go-qrdb's authorization contract, qrdbsdk.Authorizer.
// Every xkms surface enforces the permission a method declares through it.
var _ qrdbsdk.Authorizer = (*Authorizer)(nil)

// NewAuthorizer returns an Authorizer backed by the given qrdb RBAC client.
// Pass nil to disable authorization (allow all) — used when RBAC is not
// enabled or no qrdb node is hosted.
func NewAuthorizer(rbac qrdbtransport.RBACClient) *Authorizer {
	return &Authorizer{rbac: rbac}
}

// Enabled reports whether authorization is actively enforced. It is false
// for a nil Authorizer or one without a backing RBAC client.
func (a *Authorizer) Enabled() bool {
	return a != nil && a.rbac != nil
}

// Authorize reports whether identity may perform action on resource. It
// returns nil when the request is allowed, ErrUnauthenticated when no
// identity is present, or the qrdb authorizer's PermissionDeniedError when
// the grant is missing or the tenant scope gate rejects the request.
//
// The identity's tenant is bound as the request's target tenant so qrdb's
// system-tenant rule resolves a self-scope permission against the identity's
// own tenant: a tenant-scoped identity is confined to its tenant, while a
// system-tenant identity is admitted across tenants. An empty tenant is
// normalized to the system tenant (xkms treats an unset tenant as the
// structurally privileged platform scope, matching IsCrossTenant).
func (a *Authorizer) Authorize(ctx context.Context, identity *Identity, resource, action string) error {
	if !a.Enabled() {
		return nil
	}
	if identity == nil {
		return ErrUnauthenticated
	}

	authzCtx, qid := bindIdentity(ctx, identity)
	return a.rbac.Authorize(authzCtx, qid, resource, action)
}

// ListPermissions returns the "resource:action" name of every permission
// identity can exercise in its own tenant, as qrdb resolves them from its
// roles. qrdb surfaces every granted permission whatever its scope, so the
// ones the identity's tenant cannot exercise are dropped: cross-tenant
// permissions outside the system tenant, and tenant-only permissions inside
// it.
//
// When authorization is not enforced every registered permission is
// returned, because Authorize then admits every request.
func (a *Authorizer) ListPermissions(ctx context.Context, identity *Identity) ([]string, error) {
	if !a.Enabled() {
		all := qrdbsdk.AllPermissions()
		names := make([]string, 0, len(all))
		for _, p := range all {
			names = append(names, p.String())
		}
		return names, nil
	}
	if identity == nil {
		return nil, ErrUnauthenticated
	}

	authzCtx, qid := bindIdentity(ctx, identity)
	perms, err := a.rbac.ListPermissions(authzCtx, qid)
	if err != nil {
		return nil, &PermissionListError{Err: err}
	}

	system := qid.TenantID == qrdbsdk.SystemTenantID
	names := make([]string, 0, len(perms))
	for _, p := range perms {
		if p.Scope == qrdbtransport.PermissionScopeCross && !system {
			continue
		}
		if p.Scope == qrdbtransport.PermissionScopeTenantOnly && system {
			continue
		}
		names = append(names, p.Name)
	}
	return names, nil
}

// bindIdentity projects identity onto the qrdb identity and binds its tenant
// as the request's target tenant. An empty tenant is normalized to the system
// tenant.
func bindIdentity(ctx context.Context, identity *Identity) (context.Context, *qrdbtransport.Identity) {
	tenantID := identity.TenantID
	if tenantID == "" {
		tenantID = qrdbsdk.SystemTenantID
	}

	qid := &qrdbtransport.Identity{
		Subject:  identity.Subject,
		TenantID: tenantID,
		Roles:    identity.Roles,
		Metadata: identity.Metadata,
	}
	return qrdbsdk.ContextWithTenant(ctx, tenantID), qid
}

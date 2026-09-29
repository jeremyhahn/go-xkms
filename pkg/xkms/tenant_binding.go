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

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
)

// TenantBindingError reports that a tenant-scoped caller addressed a tenant
// it is not bound to. It is the single refusal of the tenant binding
// (bindTenantTarget, requirePlatformScope) and deliberately looks exactly like
// a missing tenant: it unwraps to qrdbsdk.ErrTenantMissing -- the error the
// composed go-qrdb TenantService returns, unwrapped, for every operation on an
// unknown tenant -- and renders the same message, so every transport answers
// its not-found status (REST 404, gRPC NotFound, MCP JSONRPCCodeNotFound) with
// the same body, and a probe for another tenant's ID cannot tell a foreign
// tenant from a nonexistent one. The fields carry the detail for server-side
// diagnostics (errors.As) and are never rendered.
type TenantBindingError struct {
	// Op names the refused service operation.
	Op string
	// CallerTenantID is the tenant the caller's identity is bound to.
	CallerTenantID string
	// TargetTenantID is the tenant the request addressed ("" is the
	// system scope).
	TargetTenantID string
}

// Error returns qrdbsdk.ErrTenantMissing's message verbatim, so the refusal
// is indistinguishable on the wire from a genuinely absent tenant.
func (e *TenantBindingError) Error() string {
	return qrdbsdk.ErrTenantMissing.Error()
}

// Unwrap returns qrdbsdk.ErrTenantMissing, the sentinel every transport maps
// to its not-found answer.
func (e *TenantBindingError) Unwrap() error {
	return qrdbsdk.ErrTenantMissing
}

// bindTenantTarget enforces the tenant binding for an operation that
// addresses target, a tenant ID the caller supplied in the request. The
// transports' RBAC gate cannot do this: auth.Authorizer.Authorize binds the
// caller's OWN tenant as the request's target tenant, so a self-scoped grant
// such as tenants:* or tenant_barrier:* admits a tenant-scoped caller no
// matter which tenant the request names.
//
// A cross-tenant identity (auth.IsCrossTenant: no identity, an empty tenant,
// or the reserved system tenant) may address any tenant. A tenant-scoped
// identity may address only its own tenant; an empty target is the system
// scope and is refused like any other foreign tenant.
func bindTenantTarget(ctx context.Context, op, target string) error {
	identity := auth.GetIdentity(ctx)
	if auth.IsCrossTenant(identity) || identity.TenantID == target {
		return nil
	}
	return &TenantBindingError{Op: op, CallerTenantID: identity.TenantID, TargetTenantID: target}
}

// requirePlatformScope admits only a cross-tenant identity to an operation on
// target. Plan management (entitlements and quotas) decides what a tenant is
// allowed to consume, so a tenant-scoped caller may not change even its own
// tenant's plan; the refusal is the same TenantBindingError the binding
// raises, so it adds nothing a probe could enumerate.
func requirePlatformScope(ctx context.Context, op, target string) error {
	identity := auth.GetIdentity(ctx)
	if auth.IsCrossTenant(identity) {
		return nil
	}
	return &TenantBindingError{Op: op, CallerTenantID: identity.TenantID, TargetTenantID: target}
}

// visibleToCaller reports whether a tenant-list entry for tenantID may be
// shown to the caller: every tenant for a cross-tenant identity, only its own
// tenant for a tenant-scoped one.
func visibleToCaller(identity *auth.Identity, tenantID string) bool {
	return auth.IsCrossTenant(identity) || identity.TenantID == tenantID
}

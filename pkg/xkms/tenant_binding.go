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
	"github.com/jeremyhahn/go-xkms/pkg/scope"
)

// TenantBindingError reports that a caller addressed a tenant it is not bound
// to. It is the single refusal of the tenant binding (bindTenantTarget,
// bindTenantRecord, requireSystemTenant) and deliberately looks exactly like
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

// callerTenant returns the scope name of the tenant the caller on ctx is bound
// to. A context with no identity is an in-process caller holding the service
// directly; like go-qrdb (qrdbsdk.IdentityIsSystemTenant) it is the system
// tenant, and like every other system-tenant caller it is confined to that
// tenant.
func callerTenant(ctx context.Context) string {
	identity := auth.GetIdentity(ctx)
	if identity == nil {
		return scope.SystemTenant
	}
	return scope.TenantName(identity.TenantID)
}

// refuseTenant returns the binding refusal of op on target for the caller on
// ctx.
func refuseTenant(ctx context.Context, op, target string) error {
	refusal := &TenantBindingError{Op: op, TargetTenantID: target}
	if identity := auth.GetIdentity(ctx); identity != nil {
		refusal.CallerTenantID = identity.TenantID
	}
	return refusal
}

// bindTenantTarget enforces the tenant binding for an operation that
// addresses target, a tenant ID the caller supplied in the request ("" is the
// system tenant). The transports' RBAC gate cannot do this:
// auth.Authorizer.Authorize binds the caller's OWN tenant as the request's
// target tenant, so a self-scoped grant such as tenants:* or tenant_barrier:*
// admits a caller no matter which tenant the request names.
//
// Every caller may address only its own tenant. The system tenant is no
// exception: as in go-qrdb, it does not reach another tenant's objects.
func bindTenantTarget(ctx context.Context, op, target string) error {
	if callerTenant(ctx) == scope.TenantName(target) {
		return nil
	}
	return refuseTenant(ctx, op, target)
}

// bindTenantRecord admits an operation on target's tenant-registry record --
// reading or deleting the tenant itself. The registry is the system tenant's,
// so a system caller may address any tenant's record; any other caller only
// its own.
func bindTenantRecord(ctx context.Context, op, target string) error {
	if scope.IsSystem(callerTenant(ctx)) {
		return nil
	}
	return bindTenantTarget(ctx, op, target)
}

// requireSystemTenant admits only a system-tenant caller to an operation on
// target. It guards two kinds of operation:
//
//   - plan management (entitlements and quotas) and the tenant TPM mode,
//     which decide what a tenant is allowed to consume, so a tenant's own
//     caller may not change even its own tenant's plan (go-xkms#1113);
//   - platform-global state that belongs to no tenant -- the sealed platform
//     store and credential submission (go-xkms#1226), the system barrier, the
//     token PINs, the server's PIV card and the PCR policies (go-xkms#1227).
//     These pass an empty target, the system tenant.
//
// The refusal is the same TenantBindingError the binding raises, so it adds
// nothing a probe could enumerate.
func requireSystemTenant(ctx context.Context, op, target string) error {
	if scope.IsSystem(callerTenant(ctx)) {
		return nil
	}
	return refuseTenant(ctx, op, target)
}

// visibleToCaller reports whether a tenant-list entry for tenantID may be
// shown to the caller on ctx: every tenant of the registry for a system-tenant
// caller, only its own tenant for any other.
func visibleToCaller(ctx context.Context, tenantID string) bool {
	return bindTenantRecord(ctx, "list tenants", tenantID) == nil
}

// targetTenant resolves the tenant an operation that addresses a tenant acts
// on -- TPM policy management, RotateScopeKeys. Every caller acts on its own
// tenant ("" for the system tenant): requested may be empty or name that
// tenant, and naming another is refused with *TenantBindingError.
func targetTenant(ctx context.Context, op, requested string) (string, error) {
	if requested != "" {
		if err := bindTenantTarget(ctx, op, requested); err != nil {
			return "", err
		}
	}
	tenant := callerTenant(ctx)
	if scope.IsSystem(tenant) {
		return "", nil
	}
	return tenant, nil
}

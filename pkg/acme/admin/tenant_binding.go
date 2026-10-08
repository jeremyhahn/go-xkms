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

package admin

import (
	"context"
	"errors"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	db "github.com/jeremyhahn/go-qrdb/sdk/go/transport"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
)

// TenantBindingError reports that a tenant-scoped caller addressed a tenant
// it is not bound to. It is the single refusal of the ACME admin tenant
// binding (bindTenantTarget) and deliberately looks exactly like a missing
// tenant: it unwraps to ErrTenantNotFound -- the error every tenant operation
// returns for an unknown tenant -- and renders the same message, so every
// transport answers its not-found status with the same body and a probe for
// another tenant's ID cannot tell a foreign tenant from a nonexistent one.
// This is the go-xkms#1112 convention pkg/xkms's TenantBindingError follows.
// The fields carry the detail for server-side diagnostics (errors.As) and are
// never rendered.
type TenantBindingError struct {
	// Op names the refused service operation.
	Op string
	// CallerTenantID is the tenant the caller's identity is bound to.
	CallerTenantID string
	// TargetTenantID is the tenant the request addressed.
	TargetTenantID string
}

// Error returns ErrTenantNotFound's message verbatim, so the refusal is
// indistinguishable on the wire from a genuinely absent tenant.
func (e *TenantBindingError) Error() string {
	return ErrTenantNotFound.Error()
}

// Unwrap returns ErrTenantNotFound, the sentinel every transport maps to its
// not-found answer.
func (e *TenantBindingError) Unwrap() error {
	return ErrTenantNotFound
}

// PlatformScopeError reports that a tenant-scoped caller attempted an
// operation reserved to the platform (a cross-tenant identity): creating a
// tenant, or reading the audit trail, which carries no tenant attribution to
// confine it by. No tenant ID is being probed, so the refusal need not pose
// as a missing resource; it unwraps to ErrForbidden and every transport
// answers it exactly as it answers a caller that lacks the permission.
type PlatformScopeError struct {
	// Op names the refused operation.
	Op string
	// CallerTenantID is the tenant the caller's identity is bound to.
	CallerTenantID string
}

// Error returns ErrForbidden's message verbatim.
func (e *PlatformScopeError) Error() string {
	return ErrForbidden.Error()
}

// Unwrap returns ErrForbidden.
func (e *PlatformScopeError) Unwrap() error {
	return ErrForbidden
}

// callerTenant reports the tenant a tenant-scoped caller is confined to, and
// whether the caller is confined at all. A cross-tenant identity
// (auth.IsCrossTenant: no identity, an empty tenant, or the reserved system
// tenant) is not confined. No identity means an in-process caller that did
// not come through a transport: every admin transport authenticates before
// it reaches the service and publishes the identity it resolved.
func callerTenant(ctx context.Context) (string, bool) {
	identity := auth.GetIdentity(ctx)
	if auth.IsCrossTenant(identity) {
		return "", false
	}
	return identity.TenantID, true
}

// bindTenantTarget enforces the tenant binding for an operation that
// addresses target, a tenant ID the caller supplied in the request. The
// permission gate cannot do this: auth.Authorizer.Authorize binds the
// caller's OWN tenant as the request's target tenant, so a self-scoped grant
// such as tenants:delete or users:update admits a tenant-scoped caller no
// matter which tenant the request names.
//
// A cross-tenant caller may address any tenant; a tenant-scoped caller only
// its own. The refusal is a *TenantBindingError, which reads as not-found.
func bindTenantTarget(ctx context.Context, op, target string) error {
	caller, confined := callerTenant(ctx)
	if !confined || caller == target {
		return nil
	}
	return &TenantBindingError{Op: op, CallerTenantID: caller, TargetTenantID: target}
}

// bindTenantIAM enforces the tenant binding for a user or role operation on
// target and returns ctx scoped to target. qrdb resolves a user or role
// within the context's tenant, so a cross-tenant caller's IAM call is scoped
// to the tenant the request addressed once the binding has admitted it.
func bindTenantIAM(ctx context.Context, op, target string) (context.Context, error) {
	if err := bindTenantTarget(ctx, op, target); err != nil {
		return nil, err
	}
	return qrdbsdk.ContextWithTenant(ctx, target), nil
}

// requirePlatformScope admits only a cross-tenant caller to op. The refusal
// is a *PlatformScopeError, which reads as a missing permission.
func requirePlatformScope(ctx context.Context, op string) error {
	caller, confined := callerTenant(ctx)
	if !confined {
		return nil
	}
	return &PlatformScopeError{Op: op, CallerTenantID: caller}
}

// sameTenant reports whether two tenant IDs name the same tenant, folding the
// empty ID onto the system tenant the way qrdb does.
func sameTenant(a, b string) bool {
	return qrdbsdk.NormalizeTenantID(a) == qrdbsdk.NormalizeTenantID(b)
}

// isRoleNotFound reports whether err is qrdb's answer for a role that does
// not exist. The embedded transport returns the role service's error
// (qrdbsdk.RoleNotFoundError); the wire transports return the transport's.
func isRoleNotFound(err error) bool {
	var embedded *qrdbsdk.RoleNotFoundError
	var wire *db.RoleNotFoundError
	return errors.As(err, &embedded) || errors.As(err, &wire)
}

// isUserNotFound reports whether err is qrdb's answer for a user that does
// not exist; every qrdb transport returns the one UserNotFoundError type.
func isUserNotFound(err error) bool {
	var notFound *db.UserNotFoundError
	return errors.As(err, &notFound)
}

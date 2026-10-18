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

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/scope"
)

// TenantBindingError reports that a caller addressed a tenant it is not bound
// to. It is the single refusal of the tenant binding (ownTenant,
// admitTenantRecord, the system-tenant checks) and deliberately looks exactly like
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

// refuseTenant returns the binding refusal of op on target for the caller on
// ctx.
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

func refuseTenant(ctx context.Context, op, target string) error {
	refusal := &TenantBindingError{Op: op, TargetTenantID: target}
	if identity := auth.GetIdentity(ctx); identity != nil {
		refusal.CallerTenantID = identity.TenantID
	}
	return refusal
}

// tenantRefusal maps auth's tenant refusal, a *qrdbsdk.CrossTenantDeniedError,
// onto the binding's not-found refusal of op on target. Any other error is
// returned as it is.
func tenantRefusal(ctx context.Context, op, target string, err error) error {
	var denied *qrdbsdk.CrossTenantDeniedError
	if errors.As(err, &denied) {
		return refuseTenant(ctx, op, target)
	}
	return err
}

// ownTenant resolves the tenant op acts on through auth.OwnTenant -- the
// caller's own, which requested may name or leave empty -- and returns it in
// the store's form, "" for the system tenant. The transports' RBAC gate cannot
// do this: auth.Authorizer.Authorize binds the caller's OWN tenant as the
// request's target tenant, so a self-scoped grant admits a caller no matter
// which tenant the request names. Naming another tenant is refused to every
// caller, the system tenant's included, with *TenantBindingError; a caller
// whose "" names the system tenant passes qrdbsdk.NormalizeTenantID(target).
func ownTenant(ctx context.Context, op, requested string) (string, error) {
	tenant, err := auth.OwnTenant(ctx, op, requested)
	if err != nil {
		return "", tenantRefusal(ctx, op, requested, err)
	}
	if qrdbsdk.IsSystemTenant(tenant) {
		return "", nil
	}
	return tenant, nil
}

// admitTenantRecord admits op on target's tenant-registry record -- reading,
// listing or deleting the tenant itself -- through auth.AdmitTenant. The
// registry is the system tenant's, so a system caller may address any
// tenant's record; any other caller only its own.
func admitTenantRecord(ctx context.Context, op, target string) error {
	if err := auth.AdmitTenant(ctx, op, target); err != nil {
		return tenantRefusal(ctx, op, target, err)
	}
	return nil
}

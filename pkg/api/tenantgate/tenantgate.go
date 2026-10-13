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

// Package tenantgate is the single, transport-neutral implementation of
// per-request tenant scoping. Every transport that carries an authenticated
// identity — REST, gRPC (network and Unix domain socket), QUIC, and MCP —
// calls Access with the same two inputs (the caller's identity and the
// process's *seal.BarrierRegistry) and gets back the same decision:
//
//   - a caller with no identity, or one in the system tenant (an empty
//     TenantID or the reserved system tenant ID), passes with no tenant
//     barrier
//   - no registry configured means tenant enforcement is disabled for this
//     deployment; every caller passes
//   - the caller's tenant is not registered: ErrTenantNotFound
//   - the caller's tenant barrier is sealed: ErrTenantSealed
//   - otherwise the caller's *seal.TenantBarrier is returned for the
//     transport to inject into the request context
//
// # Placement
//
// This logic used to be hand-mirrored in pkg/api/rest/middleware_tenant.go
// and pkg/api/grpc/interceptor_tenant.go, and was entirely absent from QUIC,
// MCP, and the Unix domain socket gRPC listener. It cannot live in pkg/auth
// (which owns the identity): pkg/auth would have to import
// pkg/seal for *seal.BarrierRegistry / *seal.TenantBarrier, but pkg/seal
// already imports pkg/audit, and pkg/audit imports pkg/auth — auth -> seal
// would close that cycle. pkg/api/tenantgate sits above both, mirroring how
// pkg/api/initgate is the transport-neutral seam for the init-ceremony
// public-method table. Every pkg/api/* transport may import it; pkg/auth and
// pkg/seal never import it back.
//
// # The gate selects a barrier; it grants no reach
//
// Passing the gate without a tenant barrier is not cross-tenant power. The
// system tenant's data sits behind the system barrier, which every transport
// already gates, so a system-tenant caller has no tenant barrier to check; a
// caller with no identity has no tenant at all, and the object layer
// (pkg/scope, the service-layer tenant binding) refuses it. Every caller, the
// system tenant's included, is confined to its own tenant there (#1406).
//
// Which tenant a caller belongs to is decided by its identity alone (scope.
// IsSystem). There is deliberately no role-based exemption. One existed -- a Security Officer bypass that compared
// the identity's roles against the NAME "so" -- and it never matched a real
// grant, because identities carry role IDENTIFIERS; it only matched an
// identity whose roles came from an unverified token claim spelling "so",
// which it then let past the tenant-registered and tenant-sealed checks
// (go-xkms#1074). A tenant-local officer is gated on its tenant's barrier
// exactly like any other member of the tenant.
//
// Each transport maps the returned error onto its own wire shape (REST 403 /
// 503, gRPC PermissionDenied / Unavailable, QUIC 403 / 503, MCP JSON-RPC
// -32003 / -32004) and logs with its own structured logger; Access itself
// performs no logging and no I/O beyond the registry lookup.
package tenantgate

import (
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/scope"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
)

// ErrTenantNotFound reports that the caller's tenant carries no registered
// barrier in the BarrierRegistry. Err carries the underlying registry lookup
// failure for logging; it is never nil.
type ErrTenantNotFound struct {
	TenantID string
	Err      error
}

// Error implements the error interface. It names only the caller's own
// tenant: Err, the registry lookup failure, is server-side detail for
// logging and errors.Is/As (Unwrap), never for a client-facing message --
// the MCP transport reports this error's text to the caller as-is
// (go-xkms#1118).
func (e *ErrTenantNotFound) Error() string {
	return "tenantgate: tenant not found: " + e.TenantID
}

// Unwrap exposes the underlying registry lookup error for errors.Is/As.
func (e *ErrTenantNotFound) Unwrap() error {
	return e.Err
}

// ErrTenantSealed reports that the caller's tenant barrier exists but is
// currently sealed, so no request scoped to it can proceed.
type ErrTenantSealed struct {
	TenantID string
}

// Error implements the error interface.
func (e *ErrTenantSealed) Error() string {
	return "tenantgate: tenant barrier is sealed: " + e.TenantID
}

// Access resolves the tenant-scoped barrier, if any, that a request from
// identity should be gated against. registry may be nil (tenant enforcement
// disabled); identity may be nil (unauthenticated / bootstrap caller).
//
// A nil *seal.TenantBarrier with a nil error means the caller passes without
// tenant barrier to gate — either because the caller has no identity or is in
// the system tenant (empty TenantID or the reserved system tenant ID), or no
// registry is configured. The caller must not assume a non-nil barrier: a nil
// barrier and nil error is the common "no tenant barrier" case, not a failure,
// and it grants no access to any tenant's objects.
func Access(identity *auth.Identity, registry *seal.BarrierRegistry) (*seal.TenantBarrier, error) {
	if identity == nil || scope.IsSystem(identity.TenantID) {
		return nil, nil
	}

	if registry == nil {
		return nil, nil
	}

	tb, err := registry.Tenant(identity.TenantID)
	if err != nil {
		return nil, &ErrTenantNotFound{TenantID: identity.TenantID, Err: err}
	}

	if tb.IsSealed() {
		return nil, &ErrTenantSealed{TenantID: identity.TenantID}
	}

	return tb, nil
}

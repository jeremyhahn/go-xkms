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
//   - a cross-tenant-scoped caller (auth.IsCrossTenant: nil identity, empty
//     TenantID, or the reserved system tenant) passes with no barrier
//   - the Security Officer role passes with cross-tenant access regardless
//     of TenantID, per the FIPS 140-2/3 separation-of-duties model
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
// (which already owns auth.IsCrossTenant): pkg/auth would have to import
// pkg/seal for *seal.BarrierRegistry / *seal.TenantBarrier, but pkg/seal
// already imports pkg/audit, and pkg/audit imports pkg/auth — auth -> seal
// would close that cycle. pkg/api/tenantgate sits above both, mirroring how
// pkg/api/initgate is the transport-neutral seam for the init-ceremony
// public-method table. Every pkg/api/* transport may import it; pkg/auth and
// pkg/seal never import it back.
//
// Each transport maps the returned error onto its own wire shape (REST 403 /
// 503, gRPC PermissionDenied / Unavailable, QUIC 403 / 503, MCP JSON-RPC
// -32003 / -32004) and logs with its own structured logger; Access itself
// performs no logging and no I/O beyond the registry lookup.
package tenantgate

import (
	"github.com/jeremyhahn/go-xkms/pkg/auth"
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
// tenant scoping applied — either because the caller is cross-tenant scoped
// (system tenant, empty TenantID, or a nil identity), holds the "so" role, or
// no registry is configured. The caller must not assume a non-nil barrier: a
// nil barrier and nil error is the common "no enforcement needed" case, not a
// failure.
func Access(identity *auth.Identity, registry *seal.BarrierRegistry) (*seal.TenantBarrier, error) {
	if auth.IsCrossTenant(identity) {
		return nil, nil
	}

	// Security Officer role gets cross-tenant access per the FIPS 140-2/3
	// separation-of-duties model, regardless of the identity's own TenantID.
	if identity.HasRole("so") {
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

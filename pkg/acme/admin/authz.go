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
	"errors"
	"log/slog"
	"net/http"

	"github.com/gorilla/mux"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
)

// Authorization sentinels for the ACME admin surface. They mirror the REST
// and MCP transports' sentinels so a denial means the same thing everywhere.
var (
	// ErrGateNotConfigured is returned when a privileged ACME admin route is
	// reached without a PermissionGate. The ACME admin surface has no
	// "authorization is optional" mode: an unwired gate is a composition bug,
	// and the request is denied rather than served.
	ErrGateNotConfigured = errors.New("admin: authorization gate is not configured")

	// ErrOperationUnmapped is returned when a dispatchable ACME admin
	// operation carries no entry in its transport's permission table. The
	// gate fails closed so an operation added without a permission mapping is
	// denied rather than silently exposed.
	ErrOperationUnmapped = errors.New("admin: operation has no permission mapping")
)

// Problem detail URIs for authorization failures on the ACME admin surface.
const (
	problemUnauthorized = "urn:trusted-ca:error:unauthorized"
	problemForbidden    = "urn:trusted-ca:error:forbidden"
)

// PermissionGate is the single authorization seam for the ACME admin surface.
// Every decision is delegated to the hosted go-qrdb node's RBAC service via the
// xkms auth.Authorizer — the same seam the REST, gRPC, QUIC, and MCP transports
// use — so the ACME admin API carries no role or permission model of its own.
// A grant means exactly the same thing here as it does on the main transports.
//
// When the Authorizer is not Enabled (RBAC disabled, or no qrdb identity plane
// is hosted) it allows every authenticated caller, matching the documented
// stack-wide "RBAC disabled => allow all" behavior of pkg/api/rest and
// pkg/api/quic. Authentication is mandatory either way: the gate refuses a
// request that carries no identity.
type PermissionGate struct {
	authorizer *auth.Authorizer
	logger     *slog.Logger
}

// NewPermissionGate returns a gate backed by the given qrdb-backed authorizer.
// A nil logger is replaced with the default logger so the gate always records
// its denials.
func NewPermissionGate(authorizer *auth.Authorizer, logger *slog.Logger) *PermissionGate {
	if logger == nil {
		logger = slog.Default()
	}
	return &PermissionGate{authorizer: authorizer, logger: logger}
}

// Enforcing reports whether the gate actively evaluates qrdb grants. It is
// false for a nil gate or one whose authorizer has no RBAC client.
func (g *PermissionGate) Enforcing() bool {
	return g != nil && g.authorizer.Enabled()
}

// Authorize evaluates resource:action for the identity on ctx. It returns nil
// when the request is allowed, auth.ErrUnauthenticated when no identity is
// present, ErrGateNotConfigured for an unwired gate, and the qrdb authorizer's
// denial otherwise. Every path other than an explicit allow is a denial.
//
// extra carries the caller's transport-specific context for the log line — the
// gRPC full method, the HTTP method and path, or the MCP JSON-RPC method name —
// so a denial can be traced to the request that caused it. The gate is the one
// seam every admin transport (REST via Wrap, gRPC, MCP) calls to reach the
// authorizer, so it is also the one place that logs a denial: callers pass
// their transport's identifying attributes here instead of logging the same
// denial a second time themselves. extra is never included in the client-facing
// error; only the shape callers already return (401/403, PermissionDenied,
// JSON-RPC "Forbidden") reaches the caller.
func (g *PermissionGate) Authorize(ctx context.Context, resource, action string, extra ...slog.Attr) error {
	if g == nil {
		return ErrGateNotConfigured
	}

	identity := auth.GetIdentity(ctx)
	if identity == nil {
		args := append([]any{
			slog.String("resource", resource),
			slog.String("action", action),
		}, attrsToArgs(extra)...)
		g.logger.WarnContext(ctx, "ACME admin authorization failed: no identity on request", args...)
		return auth.ErrUnauthenticated
	}

	if err := g.authorizer.Authorize(ctx, identity, resource, action); err != nil {
		args := append([]any{
			slog.String("subject", identity.Subject),
			slog.String("tenant", identity.TenantID),
			slog.String("resource", resource),
			slog.String("action", action),
			slog.String("error", err.Error()),
		}, attrsToArgs(extra)...)
		g.logger.WarnContext(ctx, "ACME admin authorization denied", args...)
		return err
	}

	g.logger.DebugContext(ctx, "ACME admin authorization granted",
		slog.String("subject", identity.Subject),
		slog.String("resource", resource),
		slog.String("action", action))
	return nil
}

// attrsToArgs widens extra to []any so it can be spread into a slog call
// alongside key-value pairs built with slog.String. slog treats each Attr
// element as-is rather than as a key awaiting a value.
func attrsToArgs(extra []slog.Attr) []any {
	args := make([]any, len(extra))
	for i, a := range extra {
		args[i] = a
	}
	return args
}

// Wrap returns an http.Handler that serves next only when the caller holds
// resource:action. It is the route decorator every privileged ACME admin route
// is registered with, so each route declares the exact qrdb grant it requires
// at its registration site.
func (g *PermissionGate) Wrap(resource, action string, next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		g.serve(w, r, resource, action, writePermissionDenied, next)
	})
}

// serve authorizes r for resource:action and runs next on a grant. A caller
// with no identity is answered 401; any other refusal is answered by deny.
func (g *PermissionGate) serve(w http.ResponseWriter, r *http.Request, resource, action string, deny func(http.ResponseWriter), next http.HandlerFunc) {
	err := g.Authorize(r.Context(), resource, action,
		slog.String("method", r.Method),
		slog.String("path", r.URL.Path))
	switch {
	case err == nil:
		next.ServeHTTP(w, r)
	case errors.Is(err, auth.ErrUnauthenticated):
		writeProblem(w, http.StatusUnauthorized, problemUnauthorized, "Authentication required")
	default:
		deny(w)
	}
}

// WrapPermission is Wrap for a grant named by one qrdb permission constant,
// such as the three-part qrdbsdk.PermissionTenantsListCross, split into its
// resource and action the way qrdb splits it.
func (g *PermissionGate) WrapPermission(p qrdbsdk.Permission, next http.HandlerFunc) http.Handler {
	return g.Wrap(qrdbsdk.PermissionResource(p), qrdbsdk.PermissionAction(p), next)
}

// WrapTenant gates a route that names its target tenant in the {id} path
// variable by the reach of the call. On the caller's own tenant it needs the
// self-scoped resource:action grant; on any other tenant, the cross-scope
// grant, which only a system-tenant caller holds (go-xkms#1557). A
// tenant-scoped caller can hold no cross-scope grant, so its refusal reads
// exactly as a missing tenant does: it cannot tell a foreign tenant from one
// that does not exist (go-xkms#1225).
func (g *PermissionGate) WrapTenant(resource, action string, cross qrdbsdk.Permission, next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identity := auth.GetIdentity(r.Context())
		if identity != nil && identity.TenantID == mux.Vars(r)["id"] {
			g.serve(w, r, resource, action, writePermissionDenied, next)
			return
		}
		deny := writePermissionDenied
		if identity != nil && !auth.IsCrossTenant(identity) {
			deny = writeTenantNotFound
		}
		g.serve(w, r, qrdbsdk.PermissionResource(cross), qrdbsdk.PermissionAction(cross), deny, next)
	})
}

// writePermissionDenied writes the single response for a caller that may not
// perform an operation: the gate's denial, and the system-tenant refusal of
// ListAuditLogs that must read exactly like it.
func writePermissionDenied(w http.ResponseWriter) {
	writeProblem(w, http.StatusForbidden, problemForbidden, "Access denied: insufficient permissions")
}

// RequireTenantScope reports whether the identity on ctx may act on
// targetTenantID. It applies qrdb's canonical system-tenant rule through the
// tenant binding (admitTenant): an identity rooted in the reserved system
// tenant is platform-scoped and reaches every tenant, anything else is
// confined to its own tenant and refused with a *TenantBindingError, which
// reads as a missing tenant. A request that carries no identity is
// auth.ErrUnauthenticated.
func RequireTenantScope(ctx context.Context, targetTenantID string) error {
	if auth.GetIdentity(ctx) == nil {
		return auth.ErrUnauthenticated
	}
	return admitTenant(ctx, "require tenant scope", targetTenantID)
}

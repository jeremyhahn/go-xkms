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
		err := g.Authorize(r.Context(), resource, action,
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path))
		switch {
		case err == nil:
			next.ServeHTTP(w, r)
		case errors.Is(err, auth.ErrUnauthenticated):
			writeProblem(w, http.StatusUnauthorized, problemUnauthorized, "Authentication required")
		default:
			writePermissionDenied(w)
		}
	})
}

// writePermissionDenied writes the single response for a caller that may not
// perform an operation: the gate's denial, and the platform-scope refusal
// (PlatformScopeError) that must read exactly like it.
func writePermissionDenied(w http.ResponseWriter) {
	writeProblem(w, http.StatusForbidden, problemForbidden, "Access denied: insufficient permissions")
}

// RequireTenantScope reports whether the identity on ctx may act on
// targetTenantID. It applies qrdb's canonical system-tenant rule through the
// tenant binding (bindTenantTarget): an identity rooted in the reserved system
// tenant is platform-scoped and reaches every tenant, anything else is
// confined to its own tenant and refused with a *TenantBindingError, which
// reads as a missing tenant. A request that carries no identity is
// auth.ErrUnauthenticated.
func RequireTenantScope(ctx context.Context, targetTenantID string) error {
	if auth.GetIdentity(ctx) == nil {
		return auth.ErrUnauthenticated
	}
	return bindTenantTarget(ctx, "require tenant scope", targetTenantID)
}

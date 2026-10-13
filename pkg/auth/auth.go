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

// Package auth provides xkms authentication adapters and identity helpers.
//
// Identity itself is qrdb-shaped: xkms aliases qrdb's auth.Identity so the
// platform identity model lives in qrdb (Subject, TenantID, Roles, Metadata)
// and downstream xkms code never re-models it. Authorization is the Authorizer
// in authorize.go, which delegates every resource:action decision to the hosted
// qrdb node's RBAC service; permissions.go holds the resource and action
// identifiers the transports pass in. Beyond that, this package owns only
// authentication and the request-scoped tenant barrier.
package auth

import (
	"context"
	"crypto/tls"
	"net/http"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"google.golang.org/grpc/metadata"
)

// Identity is the qrdb-shaped authenticated principal. It is intentionally
// a type alias so identity values flow between xkms and qrdb without a
// translation step. The fields are documented on qrdbsdk.Identity:
//
//   - Subject  — principal id (CN, JWT sub, ...)
//   - TenantID — owning tenant; never empty for a well-formed identity
//   - Roles    — assigned role names
//   - Metadata — additional auth attributes (auth_method, cert_serial, ...)
type Identity = qrdbsdk.Identity

// Authenticator is the xkms authentication adapter interface. It is
// transport-aware (HTTP and gRPC) and is therefore distinct from
// qrdb's single-method Authenticator; xkms's adapters wrap protocol
// state to extract credentials.
type Authenticator interface {
	// AuthenticateHTTP authenticates an HTTP request and returns an identity.
	// Returns an error if authentication fails.
	AuthenticateHTTP(r *http.Request) (*Identity, error)

	// AuthenticateGRPC authenticates a gRPC request using metadata.
	// Returns an error if authentication fails.
	AuthenticateGRPC(ctx context.Context, md metadata.MD) (*Identity, error)

	// Name returns the authenticator name for logging/debugging.
	Name() string
}

// ContextKey is the type for context keys used by the auth package.
type ContextKey string

const (
	// IdentityContextKey is the context key for storing authenticated identity.
	// It is retained as a stable export for callers that put non-Identity
	// values under the same context key in tests; production code should use
	// WithIdentity / GetIdentity.
	IdentityContextKey ContextKey = "auth.identity"

	// TenantBarrierContextKey is the context key for storing the tenant barrier.
	TenantBarrierContextKey ContextKey = "auth.tenant_barrier"
)

// WithIdentity stores an Identity in the context. It delegates to qrdb's
// auth.WithIdentity so xkms and qrdb share the same context-key implementation.
func WithIdentity(ctx context.Context, id *Identity) context.Context {
	return qrdbsdk.WithIdentity(ctx, id)
}

// WithTLSState stores the mTLS connection state on the context. It delegates
// to qrdb's auth.WithTLSState so xkms and qrdb share one carrier for the
// verified peer certificate. Transports that terminate TLS on a raw socket
// (MCP) must install it; HTTP-shaped transports read *http.Request.TLS.
func WithTLSState(ctx context.Context, state *tls.ConnectionState) context.Context {
	return qrdbsdk.WithTLSState(ctx, state)
}

// TLSStateFromContext retrieves the mTLS connection state stored by
// WithTLSState. It returns nil when the context carries none, so callers that
// bind an operation to the caller's certificate fail closed.
func TLSStateFromContext(ctx context.Context) *tls.ConnectionState {
	return qrdbsdk.TLSStateFromContext(ctx)
}

// GetIdentity retrieves the Identity stored in the context. Returns nil
// when no identity is present.
func GetIdentity(ctx context.Context) *Identity {
	return qrdbsdk.IdentityFromContext(ctx)
}

// IsCrossTenant reports whether the identity has cross-tenant scope under
// the system-tenant rule: an identity rooted in the reserved system tenant
// is treated as platform-scoped, anything else is bound to its own tenant.
// A nil identity is treated as system-scoped (no auth context => platform
// boot / internal pipeline).
//
// It grants administration of the tenant model only (tenants and their IAM,
// pkg/acme/admin). It never lifts a caller over another tenant's objects:
// pkg/scope and the service-layer tenant binding confine every caller, the
// system tenant's included, to its own tenant (#1406).
//
// The rule belongs to go-qrdb, which owns the tenant model, so this delegates
// to the predicate exported by its SDK rather than restating it. Re-deriving
// the comparison here is what let it drift once already: enforcement sites
// hand-rolled `TenantID == ""` and silently rejected identities in the
// reserved "system" tenant, which the rule says ARE platform-scoped.
func IsCrossTenant(id *Identity) bool {
	return qrdbsdk.IdentityIsSystemTenant(id)
}

// FirstRole returns the first role on the identity, or "" if the identity
// has none. It is the canonical helper for call sites that need a single
// role string for audit / authorization-request building.
func FirstRole(id *Identity) string {
	if id == nil || len(id.Roles) == 0 {
		return ""
	}
	return id.Roles[0]
}

// GetTenantBarrier extracts the tenant barrier from a context.
func GetTenantBarrier(ctx context.Context) interface{} {
	return ctx.Value(TenantBarrierContextKey)
}

// WithTenantBarrier adds a tenant barrier to a context.
func WithTenantBarrier(ctx context.Context, barrier interface{}) context.Context {
	return context.WithValue(ctx, TenantBarrierContextKey, barrier)
}

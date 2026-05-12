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
// and downstream xkms code never re-models it. Authorization that depends on
// xkms-domain permissions (keys, certs, secrets, ...) is handled by
// pkg/keyrbac and pkg/keyauthz; this package owns only authentication and
// the request-scoped tenant barrier.
package auth

import (
	"context"
	"net/http"

	qrdbauth "github.com/jeremyhahn/go-qrdb/pkg/auth"
	"github.com/jeremyhahn/go-qrdb/pkg/tenant"
	"google.golang.org/grpc/metadata"
)

// Identity is the qrdb-shaped authenticated principal. It is intentionally
// a type alias so identity values flow between xkms and qrdb without a
// translation step. The fields are documented on qrdbauth.Identity:
//
//   - Subject  — principal id (CN, JWT sub, ...)
//   - TenantID — owning tenant; never empty for a well-formed identity
//   - Roles    — assigned role names
//   - Metadata — additional auth attributes (auth_method, cert_serial, ...)
type Identity = qrdbauth.Identity

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
	return qrdbauth.WithIdentity(ctx, id)
}

// GetIdentity retrieves the Identity stored in the context. Returns nil
// when no identity is present.
func GetIdentity(ctx context.Context) *Identity {
	return qrdbauth.IdentityFromContext(ctx)
}

// IsCrossTenant reports whether the identity has cross-tenant scope under
// the system-tenant rule: an identity rooted in the reserved system tenant
// is treated as platform-scoped, anything else is bound to its own tenant.
// A nil identity is treated as system-scoped (no auth context => platform
// boot / internal pipeline).
func IsCrossTenant(id *Identity) bool {
	if id == nil {
		return true
	}
	return id.TenantID == tenant.SystemTenantID || id.TenantID == ""
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

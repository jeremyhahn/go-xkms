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

package auth

import (
	"context"
	"net/http"

	"google.golang.org/grpc/metadata"
)

// Identity represents an authenticated user or service
type Identity struct {
	// Subject is the unique identifier for the authenticated entity (user ID, service name, etc.)
	Subject string

	// TenantID is the tenant scope for this identity. An empty value indicates system-level access.
	TenantID string

	// Claims contains additional authenticated information (roles, permissions, etc.)
	Claims map[string]interface{}

	// Attributes contains metadata about the authentication (auth method, timestamp, etc.)
	Attributes map[string]string
}

// IsCrossTenant returns true if this identity has no tenant scope (system-level).
func (i *Identity) IsCrossTenant() bool {
	return i == nil || i.TenantID == ""
}

// Authenticator is the interface for authentication adapters
// Applications implement this interface to integrate their authentication system
type Authenticator interface {
	// AuthenticateHTTP authenticates an HTTP request and returns an identity
	// Returns nil identity if authentication fails
	AuthenticateHTTP(r *http.Request) (*Identity, error)

	// AuthenticateGRPC authenticates a gRPC request using metadata
	// Returns nil identity if authentication fails
	AuthenticateGRPC(ctx context.Context, md metadata.MD) (*Identity, error)

	// Name returns the authenticator name for logging/debugging
	Name() string
}

// ContextKey is the type for context keys used by the auth package
type ContextKey string

const (
	// IdentityContextKey is the context key for storing authenticated identity
	IdentityContextKey ContextKey = "auth.identity"

	// TenantBarrierContextKey is the context key for storing the tenant barrier
	TenantBarrierContextKey ContextKey = "auth.tenant_barrier"
)

// GetIdentity extracts the identity from a context
func GetIdentity(ctx context.Context) *Identity {
	if identity, ok := ctx.Value(IdentityContextKey).(*Identity); ok {
		return identity
	}
	return nil
}

// WithIdentity adds an identity to a context
func WithIdentity(ctx context.Context, identity *Identity) context.Context {
	return context.WithValue(ctx, IdentityContextKey, identity)
}

// GetTenantBarrier extracts the tenant barrier from a context.
func GetTenantBarrier(ctx context.Context) interface{} {
	return ctx.Value(TenantBarrierContextKey)
}

// WithTenantBarrier adds a tenant barrier to a context.
func WithTenantBarrier(ctx context.Context, barrier interface{}) context.Context {
	return context.WithValue(ctx, TenantBarrierContextKey, barrier)
}

// HasRole checks if the identity has a specific role
func (i *Identity) HasRole(role string) bool {
	if i == nil || i.Claims == nil {
		return false
	}

	roles, ok := i.Claims["roles"]
	if !ok {
		return false
	}

	switch r := roles.(type) {
	case []string:
		for _, v := range r {
			if v == role {
				return true
			}
		}
	case []interface{}:
		for _, v := range r {
			if str, ok := v.(string); ok && str == role {
				return true
			}
		}
	case string:
		return r == role
	}

	return false
}

// HasPermission checks if the identity has a specific permission
func (i *Identity) HasPermission(permission string) bool {
	if i == nil || i.Claims == nil {
		return false
	}

	perms, ok := i.Claims["permissions"]
	if !ok {
		return false
	}

	switch p := perms.(type) {
	case []string:
		for _, v := range p {
			if v == permission {
				return true
			}
		}
	case []interface{}:
		for _, v := range p {
			if str, ok := v.(string); ok && str == permission {
				return true
			}
		}
	case string:
		return p == permission
	}

	return false
}

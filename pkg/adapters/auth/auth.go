// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
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

	// Claims contains additional authenticated information (roles, permissions, etc.)
	Claims map[string]interface{}

	// Attributes contains metadata about the authentication (auth method, timestamp, etc.)
	Attributes map[string]string
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

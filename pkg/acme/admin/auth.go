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
	"net/http"
	"strings"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	acmeauth "github.com/jeremyhahn/go-xkms/pkg/acme/auth"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
)

// AuthHandler is the interface for authentication middleware.
// Both token-based and mTLS authentication implement this interface.
//
// Every implementation must publish two things on the request context: the
// AuthenticatedUser record (for tenant scoping and audit attribution) and the
// canonical auth.Identity (for the qrdb-backed PermissionGate). Publishing only
// the former would leave every privileged route unauthorizable and therefore
// denied.
type AuthHandler interface {
	// Authenticate wraps an http.Handler with authentication.
	Authenticate(next http.Handler) http.Handler
}

// contextKey is a custom type for context keys to avoid collisions.
type contextKey string

const (
	// ContextKeyUser is the context key for the authenticated user.
	ContextKeyUser contextKey = "user"

	// ContextKeyTenantID is the context key for the tenant ID.
	ContextKeyTenantID contextKey = "tenant_id"
)

// AuthenticatedUser is the authenticated principal on an ACME admin request.
// It carries attribution and tenant scope only: authorization is decided by the
// qrdb RBAC engine through PermissionGate, never by inspecting these fields.
type AuthenticatedUser struct {
	UserID    string
	Username  string
	Email     string
	TenantID  string
	Roles     []string
	Groups    []string
	SessionID string
	IssuedAt  time.Time
	ExpiresAt time.Time
}

// identity converts the authenticated user into the canonical qrdb-shaped
// identity the Authorizer consumes.
func (u *AuthenticatedUser) identity() *auth.Identity {
	return &auth.Identity{
		Subject:  u.UserID,
		TenantID: u.TenantID,
		Roles:    u.Roles,
		Metadata: map[string]string{
			"auth_method": "acme-admin",
			"username":    u.Username,
			"session_id":  u.SessionID,
		},
	}
}

// withUser publishes the AuthenticatedUser record and the canonical
// auth.Identity on the request context, and binds the user's tenant as the
// context's qrdb tenant. All three are required: handlers read the user for
// tenant scoping and audit attribution, the PermissionGate reads the identity
// to resolve the caller's qrdb role grants, and qrdb's own services read the
// bound tenant to confine every identity-plane call the request makes.
//
// The admin surface binds the tenant itself rather than relying on whatever
// qrdb's middleware bound for the identity-gated module route; without this
// binding every call the admin service makes into qrdb (roles, users) could
// resolve to the system tenant, which qrdb's EffectiveTenant enforcement
// admits everywhere.
// The tenant is normalized first, so a user with no tenant binds the system
// tenant explicitly (qrdbsdk.NormalizeTenantID).
func withUser(ctx context.Context, user *AuthenticatedUser) context.Context {
	ctx = context.WithValue(ctx, ContextKeyUser, user)
	ctx = context.WithValue(ctx, ContextKeyTenantID, user.TenantID)
	ctx = qrdbsdk.ContextWithTenant(ctx, qrdbsdk.NormalizeTenantID(user.TenantID))
	return auth.WithIdentity(ctx, user.identity())
}

// AuthMiddleware provides JWT authentication using QRDB Auth.
type AuthMiddleware struct {
	client acmeauth.Client
}

// NewAuthMiddleware creates a new authentication middleware.
func NewAuthMiddleware(client acmeauth.Client) *AuthMiddleware {
	return &AuthMiddleware{client: client}
}

// Authenticate validates JWT tokens and adds user info to context.
func (am *AuthMiddleware) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := extractBearerToken(r)
		if token == "" {
			writeProblem(w, http.StatusUnauthorized, problemUnauthorized, "Missing or invalid Authorization header")
			return
		}

		claims, err := am.client.ValidateToken(r.Context(), token)
		if err != nil || claims == nil || !claims.Valid {
			writeProblem(w, http.StatusUnauthorized, problemUnauthorized, "Invalid token")
			return
		}

		if !claims.ExpiresAt.IsZero() && time.Now().After(claims.ExpiresAt) {
			writeProblem(w, http.StatusUnauthorized, problemUnauthorized, "Token expired")
			return
		}

		user := &AuthenticatedUser{
			UserID:    claims.UserID,
			Username:  claims.Username,
			Email:     claims.Email,
			TenantID:  claims.TenantID,
			Roles:     claims.Roles,
			Groups:    claims.Groups,
			SessionID: claims.SessionID,
			IssuedAt:  claims.IssuedAt,
			ExpiresAt: claims.ExpiresAt,
		}

		next.ServeHTTP(w, r.WithContext(withUser(r.Context(), user)))
	})
}

// RequireTenant creates a middleware that validates tenant access. Cross-tenant
// reach is decided by qrdb's system-tenant rule (see RequireTenantScope), not by
// a local role name, and a tenant the caller may not reach is answered exactly
// as a missing tenant is.
func RequireTenant(getTenantID func(r *http.Request) string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tenantID := getTenantID(r)
			if tenantID == "" {
				writeProblem(w, http.StatusBadRequest, "urn:trusted-ca:error:bad-request", "Tenant ID is required")
				return
			}

			switch err := RequireTenantScope(r.Context(), tenantID); {
			case err == nil:
				next.ServeHTTP(w, r)
			case errors.Is(err, auth.ErrUnauthenticated):
				writeProblem(w, http.StatusUnauthorized, problemUnauthorized, "Authentication required")
			default:
				writeTenantNotFound(w)
			}
		})
	}
}

// GetUserFromContext extracts the authenticated user from context.
func GetUserFromContext(ctx context.Context) *AuthenticatedUser {
	user, ok := ctx.Value(ContextKeyUser).(*AuthenticatedUser)
	if !ok {
		return nil
	}
	return user
}

// GetTenantIDFromContext extracts the tenant ID from context.
func GetTenantIDFromContext(ctx context.Context) string {
	tenantID, ok := ctx.Value(ContextKeyTenantID).(string)
	if !ok {
		return ""
	}
	return tenantID
}

// extractBearerToken extracts the Bearer token from Authorization header.
func extractBearerToken(r *http.Request) string {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return ""
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
		return ""
	}

	return parts[1]
}

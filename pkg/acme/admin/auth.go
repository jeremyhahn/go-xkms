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
	"crypto/x509"
	"net/http"
	"strings"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/acme/auth"
)

// AuthHandler is the interface for authentication middleware.
// Both token-based and mTLS authentication implement this interface.
type AuthHandler interface {
	// Authenticate wraps an http.Handler with authentication.
	Authenticate(next http.Handler) http.Handler
}

// contextKey is a custom type for context keys to avoid collisions.
type contextKey string

const (
	// ContextKeyUser is the context key for the authenticated user.
	ContextKeyUser contextKey = "user"

	// ContextKeyRole is the context key for the user's role.
	ContextKeyRole contextKey = "role"

	// ContextKeyTenantID is the context key for the tenant ID.
	ContextKeyTenantID contextKey = "tenant_id"
)

// AuthenticatedUser represents the authenticated user from QRDB.
type AuthenticatedUser struct {
	UserID      string
	Username    string
	Email       string
	TenantID    string
	Role        Role
	Roles       []string
	Groups      []string
	Permissions []string
	SessionID   string
	IssuedAt    time.Time
	ExpiresAt   time.Time
}

// AuthMiddleware provides JWT authentication using QRDB Auth.
type AuthMiddleware struct {
	client auth.Client
}

// NewAuthMiddleware creates a new authentication middleware.
func NewAuthMiddleware(client auth.Client) *AuthMiddleware {
	return &AuthMiddleware{client: client}
}

// Authenticate validates JWT tokens and adds user info to context.
func (am *AuthMiddleware) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := extractBearerToken(r)
		if token == "" {
			writeProblem(w, http.StatusUnauthorized, "urn:trusted-ca:error:unauthorized", "Missing or invalid Authorization header")
			return
		}

		claims, err := am.client.ValidateToken(r.Context(), token)
		if err != nil || claims == nil || !claims.Valid {
			writeProblem(w, http.StatusUnauthorized, "urn:trusted-ca:error:unauthorized", "Invalid token")
			return
		}

		if !claims.ExpiresAt.IsZero() && time.Now().After(claims.ExpiresAt) {
			writeProblem(w, http.StatusUnauthorized, "urn:trusted-ca:error:unauthorized", "Token expired")
			return
		}

		// Get highest role from claims
		role := getHighestRole(claims.Roles)

		user := &AuthenticatedUser{
			UserID:      claims.UserID,
			Username:    claims.Username,
			Email:       claims.Email,
			TenantID:    claims.TenantID,
			Role:        role,
			Roles:       claims.Roles,
			Groups:      claims.Groups,
			Permissions: claims.Permissions,
			SessionID:   claims.SessionID,
			IssuedAt:    claims.IssuedAt,
			ExpiresAt:   claims.ExpiresAt,
		}

		ctx := context.WithValue(r.Context(), ContextKeyUser, user)
		ctx = context.WithValue(ctx, ContextKeyRole, role)
		ctx = context.WithValue(ctx, ContextKeyTenantID, claims.TenantID)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequireRole creates a middleware that requires a minimum role level.
func RequireRole(minRole Role) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			role, ok := r.Context().Value(ContextKeyRole).(Role)
			if !ok {
				writeProblem(w, http.StatusUnauthorized, "urn:trusted-ca:error:unauthorized", "Authentication required")
				return
			}

			if role.Level() < minRole.Level() {
				writeProblem(w, http.StatusForbidden, "urn:trusted-ca:error:forbidden", "Insufficient privileges")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireOperation creates a middleware that requires permission for a specific operation.
func RequireOperation(operation string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			role, ok := r.Context().Value(ContextKeyRole).(Role)
			if !ok {
				writeProblem(w, http.StatusUnauthorized, "urn:trusted-ca:error:unauthorized", "Authentication required")
				return
			}

			if !HasPermissionForOperation(role, operation) {
				writeProblem(w, http.StatusForbidden, "urn:trusted-ca:error:forbidden", "Insufficient privileges for operation: "+operation)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireTenant creates a middleware that validates tenant access.
func RequireTenant(getTenantID func(r *http.Request) string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user := GetUserFromContext(r.Context())
			if user == nil {
				writeProblem(w, http.StatusUnauthorized, "urn:trusted-ca:error:unauthorized", "Authentication required")
				return
			}

			tenantID := getTenantID(r)
			if tenantID == "" {
				writeProblem(w, http.StatusBadRequest, "urn:trusted-ca:error:bad-request", "Tenant ID is required")
				return
			}

			// Super-admins can access any tenant
			if user.Role != RoleSuperAdmin && user.TenantID != tenantID {
				writeProblem(w, http.StatusForbidden, "urn:trusted-ca:error:forbidden", "Cannot access tenant")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// HasPermissionForOperation checks if a role can perform a specific operation.
func HasPermissionForOperation(role Role, operation string) bool {
	switch operation {
	case "manage_tenants", "manage_root_ca", "system_config":
		return role.CanManageTenants()
	case "manage_tenant_ca", "create_intermediate_ca", "create_root_ca":
		return role.CanManageTenantCA()
	case "create_eab", "endorse_01":
		return role.CanCreateEAB()
	case "revoke_certificate", "disable_account":
		return role.CanRevokeAccess()
	case "read", "list", "get":
		return role.Level() >= RoleViewer.Level()
	case "write", "create", "update":
		return role.Level() >= RoleOperator.Level()
	default:
		return false
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

// GetRoleFromContext extracts the role from context.
func GetRoleFromContext(ctx context.Context) (Role, bool) {
	role, ok := ctx.Value(ContextKeyRole).(Role)
	return role, ok
}

// GetTenantIDFromContext extracts the tenant ID from context.
func GetTenantIDFromContext(ctx context.Context) string {
	tenantID, ok := ctx.Value(ContextKeyTenantID).(string)
	if !ok {
		return ""
	}
	return tenantID
}

// getHighestRole returns the highest privilege role from a list.
func getHighestRole(roles []string) Role {
	var highestRole Role
	var highestLevel int

	for _, roleName := range roles {
		role := Role(roleName)
		if role.IsValid() && role.Level() > highestLevel {
			highestLevel = role.Level()
			highestRole = role
		}
	}

	return highestRole
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

// MTLSAuthMiddleware provides mTLS-based authentication using client certificates.
// This is the preferred authentication method for passwordless operation.
type MTLSAuthMiddleware struct {
	// roleExtractor extracts roles from the client certificate.
	// If nil, defaults to extracting from certificate OU (Organizational Unit).
	roleExtractor func(cert *x509.Certificate) []string

	// tenantExtractor extracts tenant ID from the client certificate.
	// If nil, defaults to extracting from certificate O (Organization).
	tenantExtractor func(cert *x509.Certificate) string
}

// MTLSAuthConfig configures the mTLS authentication middleware.
type MTLSAuthConfig struct {
	// RoleExtractor extracts roles from the client certificate.
	RoleExtractor func(cert *x509.Certificate) []string

	// TenantExtractor extracts tenant ID from the client certificate.
	TenantExtractor func(cert *x509.Certificate) string
}

// NewMTLSAuthMiddleware creates a new mTLS authentication middleware.
func NewMTLSAuthMiddleware(config *MTLSAuthConfig) *MTLSAuthMiddleware {
	m := &MTLSAuthMiddleware{}
	if config != nil {
		m.roleExtractor = config.RoleExtractor
		m.tenantExtractor = config.TenantExtractor
	}
	return m
}

// Authenticate validates client certificates and adds user info to context.
// The TLS handshake must have already verified the client certificate.
func (m *MTLSAuthMiddleware) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check for verified client certificate
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			writeProblem(w, http.StatusUnauthorized, "urn:trusted-ca:error:unauthorized", "Client certificate required")
			return
		}

		// Get the client certificate (first in chain is the client's cert)
		clientCert := r.TLS.PeerCertificates[0]

		// Verify certificate is not expired
		now := time.Now()
		if now.Before(clientCert.NotBefore) || now.After(clientCert.NotAfter) {
			writeProblem(w, http.StatusUnauthorized, "urn:trusted-ca:error:unauthorized", "Client certificate expired or not yet valid")
			return
		}

		// Extract identity from certificate
		user := m.extractUserFromCertificate(clientCert)

		// Add user to context
		ctx := context.WithValue(r.Context(), ContextKeyUser, user)
		ctx = context.WithValue(ctx, ContextKeyRole, user.Role)
		ctx = context.WithValue(ctx, ContextKeyTenantID, user.TenantID)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// extractUserFromCertificate extracts user information from the client certificate.
func (m *MTLSAuthMiddleware) extractUserFromCertificate(cert *x509.Certificate) *AuthenticatedUser {
	// Extract roles - use custom extractor or default to OU
	var roles []string
	if m.roleExtractor != nil {
		roles = m.roleExtractor(cert)
	} else {
		roles = defaultRoleExtractor(cert)
	}

	// Extract tenant ID - use custom extractor or default to O
	var tenantID string
	if m.tenantExtractor != nil {
		tenantID = m.tenantExtractor(cert)
	} else {
		tenantID = defaultTenantExtractor(cert)
	}

	// Use certificate serial number as session ID
	sessionID := cert.SerialNumber.String()

	// Get highest role
	role := getHighestRole(roles)

	// Use CN as username, or first email SAN if available
	username := cert.Subject.CommonName
	email := ""
	if len(cert.EmailAddresses) > 0 {
		email = cert.EmailAddresses[0]
		if username == "" {
			username = email
		}
	}

	return &AuthenticatedUser{
		UserID:      cert.Subject.CommonName,
		Username:    username,
		Email:       email,
		TenantID:    tenantID,
		Role:        role,
		Roles:       roles,
		Groups:      cert.Subject.OrganizationalUnit,
		Permissions: derivePermissionsFromRole(role),
		SessionID:   sessionID,
		IssuedAt:    cert.NotBefore,
		ExpiresAt:   cert.NotAfter,
	}
}

// defaultRoleExtractor extracts roles from certificate Organizational Unit (OU).
// Standard OUs: "super-admin", "admin", "operator", "viewer"
func defaultRoleExtractor(cert *x509.Certificate) []string {
	roles := make([]string, 0, len(cert.Subject.OrganizationalUnit))
	for _, ou := range cert.Subject.OrganizationalUnit {
		// Check if OU is a valid role
		if Role(ou).IsValid() {
			roles = append(roles, ou)
		}
	}

	// Default to viewer if no valid roles found
	if len(roles) == 0 {
		roles = append(roles, string(RoleViewer))
	}

	return roles
}

// defaultTenantExtractor extracts tenant ID from certificate Organization (O).
func defaultTenantExtractor(cert *x509.Certificate) string {
	if len(cert.Subject.Organization) > 0 {
		return cert.Subject.Organization[0]
	}
	return "default"
}

// derivePermissionsFromRole returns permissions based on role.
func derivePermissionsFromRole(role Role) []string {
	switch role {
	case RoleSuperAdmin:
		return []string{"*"}
	case RoleAdmin:
		return []string{
			"read", "write", "create", "update", "delete",
			"manage_tenant_ca", "create_eab", "revoke_certificate", "disable_account",
		}
	case RoleOperator:
		return []string{
			"read", "write", "create", "update",
			"create_eab", "revoke_certificate",
		}
	case RoleViewer:
		return []string{"read", "list", "get"}
	default:
		return []string{}
	}
}

// DevModeAuthMiddleware provides authentication bypass for development/testing.
// This middleware grants super-admin access to all requests.
// WARNING: Only use this in development environments without TLS.
type DevModeAuthMiddleware struct{}

// NewDevModeAuthMiddleware creates a new development mode auth middleware.
func NewDevModeAuthMiddleware() *DevModeAuthMiddleware {
	return &DevModeAuthMiddleware{}
}

// Authenticate grants super-admin access to all requests (development mode only).
func (m *DevModeAuthMiddleware) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Create a default super-admin user for development
		user := &AuthenticatedUser{
			UserID:      "dev-admin",
			Username:    "dev-admin",
			Email:       "dev@localhost",
			TenantID:    "default",
			Role:        RoleSuperAdmin,
			Roles:       []string{string(RoleSuperAdmin)},
			Groups:      []string{"super-admin"},
			Permissions: []string{"*"},
			SessionID:   "dev-session",
			IssuedAt:    time.Now(),
			ExpiresAt:   time.Now().Add(24 * time.Hour),
		}

		// Add user to context
		ctx := context.WithValue(r.Context(), ContextKeyUser, user)
		ctx = context.WithValue(ctx, ContextKeyRole, user.Role)
		ctx = context.WithValue(ctx, ContextKeyTenantID, user.TenantID)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

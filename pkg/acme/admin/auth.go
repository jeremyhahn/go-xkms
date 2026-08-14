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
	UserID      string
	Username    string
	Email       string
	TenantID    string
	Roles       []string
	Groups      []string
	Permissions []string
	SessionID   string
	IssuedAt    time.Time
	ExpiresAt   time.Time
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

// withUser publishes both the AuthenticatedUser record and the canonical
// auth.Identity on the request context. Both are required: handlers read the
// user for tenant scoping and audit attribution, and the PermissionGate reads
// the identity to resolve the caller's qrdb role grants.
func withUser(ctx context.Context, user *AuthenticatedUser) context.Context {
	ctx = context.WithValue(ctx, ContextKeyUser, user)
	ctx = context.WithValue(ctx, ContextKeyTenantID, user.TenantID)
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
			UserID:      claims.UserID,
			Username:    claims.Username,
			Email:       claims.Email,
			TenantID:    claims.TenantID,
			Roles:       claims.Roles,
			Groups:      claims.Groups,
			Permissions: claims.Permissions,
			SessionID:   claims.SessionID,
			IssuedAt:    claims.IssuedAt,
			ExpiresAt:   claims.ExpiresAt,
		}

		next.ServeHTTP(w, r.WithContext(withUser(r.Context(), user)))
	})
}

// RequireTenant creates a middleware that validates tenant access. Cross-tenant
// reach is decided by qrdb's system-tenant rule (see RequireTenantScope), not by
// a local role name.
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
			case err == auth.ErrUnauthenticated:
				writeProblem(w, http.StatusUnauthorized, problemUnauthorized, "Authentication required")
			default:
				writeProblem(w, http.StatusForbidden, problemForbidden, "Cannot access tenant")
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
			writeProblem(w, http.StatusUnauthorized, problemUnauthorized, "Client certificate required")
			return
		}

		// Get the client certificate (first in chain is the client's cert)
		clientCert := r.TLS.PeerCertificates[0]

		// Verify certificate is not expired
		now := time.Now()
		if now.Before(clientCert.NotBefore) || now.After(clientCert.NotAfter) {
			writeProblem(w, http.StatusUnauthorized, problemUnauthorized, "Client certificate expired or not yet valid")
			return
		}

		user := m.extractUserFromCertificate(clientCert)

		next.ServeHTTP(w, r.WithContext(withUser(r.Context(), user)))
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
		UserID:    cert.Subject.CommonName,
		Username:  username,
		Email:     email,
		TenantID:  tenantID,
		Roles:     roles,
		Groups:    cert.Subject.OrganizationalUnit,
		SessionID: sessionID,
		IssuedAt:  cert.NotBefore,
		ExpiresAt: cert.NotAfter,
	}
}

// defaultRoleExtractor reads role names from the certificate's Organizational
// Unit values and hands them to qrdb verbatim. It deliberately mints no
// fallback role: a certificate that names no role yields an identity with no
// roles, and the qrdb authorizer denies every privileged operation. The
// previous "default to viewer" fallback silently granted the whole read surface
// of the ACME admin API to any client certificate the CA had ever issued.
func defaultRoleExtractor(cert *x509.Certificate) []string {
	if len(cert.Subject.OrganizationalUnit) == 0 {
		return nil
	}
	roles := make([]string, 0, len(cert.Subject.OrganizationalUnit))
	for _, ou := range cert.Subject.OrganizationalUnit {
		if ou == "" {
			continue
		}
		roles = append(roles, ou)
	}
	if len(roles) == 0 {
		return nil
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

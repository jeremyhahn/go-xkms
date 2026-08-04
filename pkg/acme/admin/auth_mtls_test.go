//go:build codec_json

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
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createTestCertificate creates a test x509 certificate with the specified attributes
func createTestCertificate(t *testing.T, cn string, org []string, ou []string, emails []string, validFrom, validTo time.Time) *x509.Certificate {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:         cn,
			Organization:       org,
			OrganizationalUnit: ou,
		},
		EmailAddresses: emails,
		NotBefore:      validFrom,
		NotAfter:       validTo,
		KeyUsage:       x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return cert
}

func TestNewMTLSAuthMiddleware_NilConfig(t *testing.T) {
	middleware := NewMTLSAuthMiddleware(nil)
	require.NotNil(t, middleware)
	assert.Nil(t, middleware.roleExtractor)
	assert.Nil(t, middleware.tenantExtractor)
}

func TestNewMTLSAuthMiddleware_WithConfig(t *testing.T) {
	roleExtractor := func(cert *x509.Certificate) []string {
		return []string{"admin"}
	}
	tenantExtractor := func(cert *x509.Certificate) string {
		return "custom-tenant"
	}

	config := &MTLSAuthConfig{
		RoleExtractor:   roleExtractor,
		TenantExtractor: tenantExtractor,
	}

	middleware := NewMTLSAuthMiddleware(config)
	require.NotNil(t, middleware)
	assert.NotNil(t, middleware.roleExtractor)
	assert.NotNil(t, middleware.tenantExtractor)
}

func TestMTLSAuthMiddleware_Authenticate_NoCertificate(t *testing.T) {
	middleware := NewMTLSAuthMiddleware(nil)

	handler := middleware.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("Handler should not be called without certificate")
	}))

	// Request without TLS
	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestMTLSAuthMiddleware_Authenticate_NoPeerCertificates(t *testing.T) {
	middleware := NewMTLSAuthMiddleware(nil)

	handler := middleware.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("Handler should not be called without peer certificates")
	}))

	// Request with TLS but no peer certificates
	req := httptest.NewRequest("GET", "/test", nil)
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{},
	}
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestMTLSAuthMiddleware_Authenticate_ExpiredCertificate(t *testing.T) {
	middleware := NewMTLSAuthMiddleware(nil)

	handler := middleware.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("Handler should not be called with expired certificate")
	}))

	// Create expired certificate
	cert := createTestCertificate(t,
		"testuser",
		[]string{"test-org"},
		[]string{"admin"},
		[]string{"user@example.com"},
		time.Now().Add(-48*time.Hour), // Started 2 days ago
		time.Now().Add(-24*time.Hour), // Expired 1 day ago
	)

	req := httptest.NewRequest("GET", "/test", nil)
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
	}
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestMTLSAuthMiddleware_Authenticate_NotYetValidCertificate(t *testing.T) {
	middleware := NewMTLSAuthMiddleware(nil)

	handler := middleware.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("Handler should not be called with not yet valid certificate")
	}))

	// Create not yet valid certificate
	cert := createTestCertificate(t,
		"testuser",
		[]string{"test-org"},
		[]string{"admin"},
		[]string{"user@example.com"},
		time.Now().Add(24*time.Hour), // Starts tomorrow
		time.Now().Add(48*time.Hour), // Expires in 2 days
	)

	req := httptest.NewRequest("GET", "/test", nil)
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
	}
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestMTLSAuthMiddleware_Authenticate_ValidCertificate(t *testing.T) {
	middleware := NewMTLSAuthMiddleware(nil)

	var capturedUser *AuthenticatedUser
	handler := middleware.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedUser = GetUserFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	// Create valid certificate with admin role
	cert := createTestCertificate(t,
		"testuser",
		[]string{"test-org"},
		[]string{"admin"},
		[]string{"user@example.com"},
		time.Now().Add(-1*time.Hour), // Started 1 hour ago
		time.Now().Add(24*time.Hour), // Expires in 24 hours
	)

	req := httptest.NewRequest("GET", "/test", nil)
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
	}
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	require.NotNil(t, capturedUser)
	assert.Equal(t, "testuser", capturedUser.UserID)
	assert.Equal(t, "testuser", capturedUser.Username)
	assert.Equal(t, "user@example.com", capturedUser.Email)
	assert.Equal(t, "test-org", capturedUser.TenantID)
	assert.Equal(t, RoleAdmin, capturedUser.Role)
	assert.Contains(t, capturedUser.Roles, "admin")
}

func TestMTLSAuthMiddleware_Authenticate_CustomExtractors(t *testing.T) {
	roleExtractor := func(cert *x509.Certificate) []string {
		return []string{"super-admin"}
	}
	tenantExtractor := func(cert *x509.Certificate) string {
		return "custom-tenant-id"
	}

	config := &MTLSAuthConfig{
		RoleExtractor:   roleExtractor,
		TenantExtractor: tenantExtractor,
	}
	middleware := NewMTLSAuthMiddleware(config)

	var capturedUser *AuthenticatedUser
	handler := middleware.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedUser = GetUserFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	cert := createTestCertificate(t,
		"testuser",
		[]string{"test-org"},
		[]string{"operator"},
		[]string{},
		time.Now().Add(-1*time.Hour),
		time.Now().Add(24*time.Hour),
	)

	req := httptest.NewRequest("GET", "/test", nil)
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
	}
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	require.NotNil(t, capturedUser)
	assert.Equal(t, "custom-tenant-id", capturedUser.TenantID)
	assert.Equal(t, RoleSuperAdmin, capturedUser.Role)
}

func TestMTLSAuthMiddleware_Authenticate_NoEmailUsesCN(t *testing.T) {
	middleware := NewMTLSAuthMiddleware(nil)

	var capturedUser *AuthenticatedUser
	handler := middleware.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedUser = GetUserFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	cert := createTestCertificate(t,
		"cn-username",
		[]string{"test-org"},
		[]string{"viewer"},
		[]string{}, // No email
		time.Now().Add(-1*time.Hour),
		time.Now().Add(24*time.Hour),
	)

	req := httptest.NewRequest("GET", "/test", nil)
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
	}
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	require.NotNil(t, capturedUser)
	assert.Equal(t, "cn-username", capturedUser.Username)
	assert.Empty(t, capturedUser.Email)
}

func TestMTLSAuthMiddleware_Authenticate_EmptyCNUsesEmail(t *testing.T) {
	middleware := NewMTLSAuthMiddleware(nil)

	var capturedUser *AuthenticatedUser
	handler := middleware.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedUser = GetUserFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	cert := createTestCertificate(t,
		"", // Empty CN
		[]string{"test-org"},
		[]string{"viewer"},
		[]string{"email@example.com"},
		time.Now().Add(-1*time.Hour),
		time.Now().Add(24*time.Hour),
	)

	req := httptest.NewRequest("GET", "/test", nil)
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
	}
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	require.NotNil(t, capturedUser)
	assert.Equal(t, "email@example.com", capturedUser.Username)
	assert.Equal(t, "email@example.com", capturedUser.Email)
}

func TestDefaultRoleExtractor(t *testing.T) {
	tests := []struct {
		name          string
		ous           []string
		expectedRoles []string
	}{
		{
			name:          "single valid role",
			ous:           []string{"admin"},
			expectedRoles: []string{"admin"},
		},
		{
			name:          "multiple valid roles",
			ous:           []string{"admin", "operator"},
			expectedRoles: []string{"admin", "operator"},
		},
		{
			name:          "no valid roles defaults to viewer",
			ous:           []string{"invalid-role"},
			expectedRoles: []string{"viewer"},
		},
		{
			name:          "empty OU defaults to viewer",
			ous:           []string{},
			expectedRoles: []string{"viewer"},
		},
		{
			name:          "mixed valid and invalid",
			ous:           []string{"invalid", "super-admin", "unknown"},
			expectedRoles: []string{"super-admin"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := createTestCertificate(t, "test", nil, tt.ous, nil,
				time.Now().Add(-1*time.Hour), time.Now().Add(24*time.Hour))
			roles := defaultRoleExtractor(cert)
			assert.Equal(t, tt.expectedRoles, roles)
		})
	}
}

func TestDefaultTenantExtractor(t *testing.T) {
	tests := []struct {
		name             string
		organizations    []string
		expectedTenantID string
	}{
		{
			name:             "single organization",
			organizations:    []string{"tenant-abc"},
			expectedTenantID: "tenant-abc",
		},
		{
			name:             "multiple organizations uses first",
			organizations:    []string{"first-org", "second-org"},
			expectedTenantID: "first-org",
		},
		{
			name:             "no organization defaults to default",
			organizations:    []string{},
			expectedTenantID: "default",
		},
		{
			name:             "nil organizations",
			organizations:    nil,
			expectedTenantID: "default",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := createTestCertificate(t, "test", tt.organizations, nil, nil,
				time.Now().Add(-1*time.Hour), time.Now().Add(24*time.Hour))
			tenantID := defaultTenantExtractor(cert)
			assert.Equal(t, tt.expectedTenantID, tenantID)
		})
	}
}

func TestDerivePermissionsFromRole(t *testing.T) {
	tests := []struct {
		name                string
		role                Role
		expectedPermissions []string
	}{
		{
			name:                "super-admin has all permissions",
			role:                RoleSuperAdmin,
			expectedPermissions: []string{"*"},
		},
		{
			name: "admin has tenant management permissions",
			role: RoleAdmin,
			expectedPermissions: []string{
				"read", "write", "create", "update", "delete",
				"manage_tenant_ca", "create_eab", "revoke_certificate", "disable_account",
			},
		},
		{
			name: "operator has write and create_eab permissions",
			role: RoleOperator,
			expectedPermissions: []string{
				"read", "write", "create", "update",
				"create_eab", "revoke_certificate",
			},
		},
		{
			name:                "viewer has read-only permissions",
			role:                RoleViewer,
			expectedPermissions: []string{"read", "list", "get"},
		},
		{
			name:                "unknown role has no permissions",
			role:                Role("unknown"),
			expectedPermissions: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			permissions := derivePermissionsFromRole(tt.role)
			assert.Equal(t, tt.expectedPermissions, permissions)
		})
	}
}

func TestNewDevModeAuthMiddleware(t *testing.T) {
	middleware := NewDevModeAuthMiddleware()
	require.NotNil(t, middleware)
}

func TestDevModeAuthMiddleware_Authenticate(t *testing.T) {
	middleware := NewDevModeAuthMiddleware()

	var capturedUser *AuthenticatedUser
	var capturedRole Role
	var capturedTenantID string

	handler := middleware.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedUser = GetUserFromContext(r.Context())
		capturedRole, _ = GetRoleFromContext(r.Context())
		capturedTenantID = GetTenantIDFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	require.NotNil(t, capturedUser)
	assert.Equal(t, "dev-admin", capturedUser.UserID)
	assert.Equal(t, "dev-admin", capturedUser.Username)
	assert.Equal(t, "dev@localhost", capturedUser.Email)
	assert.Equal(t, "default", capturedUser.TenantID)
	assert.Equal(t, RoleSuperAdmin, capturedUser.Role)
	assert.Equal(t, []string{"*"}, capturedUser.Permissions)
	assert.Equal(t, RoleSuperAdmin, capturedRole)
	assert.Equal(t, "default", capturedTenantID)
}

func TestMTLSAuthMiddleware_ContextValues(t *testing.T) {
	middleware := NewMTLSAuthMiddleware(nil)

	var capturedRole Role
	var roleOk bool
	var capturedTenantID string

	handler := middleware.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedRole, roleOk = GetRoleFromContext(r.Context())
		capturedTenantID = GetTenantIDFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	cert := createTestCertificate(t,
		"testuser",
		[]string{"my-tenant"},
		[]string{"operator"},
		[]string{},
		time.Now().Add(-1*time.Hour),
		time.Now().Add(24*time.Hour),
	)

	req := httptest.NewRequest("GET", "/test", nil)
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
	}
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.True(t, roleOk)
	assert.Equal(t, RoleOperator, capturedRole)
	assert.Equal(t, "my-tenant", capturedTenantID)
}

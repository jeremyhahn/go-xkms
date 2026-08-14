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
	"context"
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

	"github.com/jeremyhahn/go-xkms/pkg/auth"
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
	var capturedCtx context.Context
	handler := middleware.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedUser = GetUserFromContext(r.Context())
		capturedCtx = r.Context()
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
	assert.Contains(t, capturedUser.Roles, "admin")

	// The middleware must also publish the canonical identity the qrdb-backed
	// PermissionGate reads; without it every privileged route is denied.
	identity := auth.GetIdentity(capturedCtx)
	require.NotNil(t, identity)
	assert.Equal(t, "testuser", identity.Subject)
	assert.Equal(t, "test-org", identity.TenantID)
	assert.Equal(t, []string{"admin"}, identity.Roles)
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
	assert.Equal(t, []string{"super-admin"}, capturedUser.Roles)
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

// TestDefaultRoleExtractor_MintsNoFallbackRole is the fail-closed assertion for
// mTLS role extraction. The previous extractor defaulted to "viewer" whenever a
// certificate named no recognized role, which handed the entire read surface of
// the ACME admin API to any client certificate the CA had ever issued. Role
// names now pass through verbatim and an unlabelled certificate yields none.
func TestDefaultRoleExtractor_MintsNoFallbackRole(t *testing.T) {
	tests := []struct {
		name string
		ous  []string
		want []string
	}{
		{"single role", []string{"admin"}, []string{"admin"}},
		{"multiple roles", []string{"operator", "auditor"}, []string{"operator", "auditor"}},
		{"unknown name passes through for qrdb to resolve", []string{"tenant-reviewer"}, []string{"tenant-reviewer"}},
		{"no organizational unit yields no roles", nil, nil},
		{"empty organizational unit yields no roles", []string{""}, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := createTestCertificate(t, "test", []string{"org"}, tt.ous, nil,
				time.Now().Add(-1*time.Hour), time.Now().Add(24*time.Hour))
			// x509 does not preserve OU ordering through encode/decode, so
			// compare as a set.
			assert.ElementsMatch(t, tt.want, defaultRoleExtractor(cert))
		})
	}
}

// TestMTLSAuthMiddleware_UnlabelledCertificateGetsNoGrants verifies the
// end-to-end fail-closed path: a certificate naming no role authenticates but
// carries an identity with no roles, so the authorizer denies everything.
func TestMTLSAuthMiddleware_UnlabelledCertificateGetsNoGrants(t *testing.T) {
	middleware := NewMTLSAuthMiddleware(nil)

	var identity *auth.Identity
	handler := middleware.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identity = auth.GetIdentity(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	cert := createTestCertificate(t, "nobody", []string{"org"}, nil, nil,
		time.Now().Add(-1*time.Hour), time.Now().Add(24*time.Hour))

	req := httptest.NewRequest("GET", "/test", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	handler.ServeHTTP(httptest.NewRecorder(), req)

	require.NotNil(t, identity)
	assert.Empty(t, identity.Roles)

	gate, _ := newQRDBGate()
	require.Error(t, gate.Authorize(auth.WithIdentity(context.Background(), identity),
		auth.ResourceCerts, auth.ActionList))
}

func TestMTLSAuthMiddleware_ContextValues(t *testing.T) {
	middleware := NewMTLSAuthMiddleware(nil)

	var capturedRoles []string
	var capturedTenantID string

	handler := middleware.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if id := auth.GetIdentity(r.Context()); id != nil {
			capturedRoles = id.Roles
		}
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
	assert.Equal(t, []string{"operator"}, capturedRoles)
	assert.Equal(t, "my-tenant", capturedTenantID)
}

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
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	xkmsauth "github.com/jeremyhahn/go-xkms/pkg/auth"
)

// fakeMTLSUserStore implements xkmsauth.UserStore directly, so these tests
// exercise MTLSAuthHandler -- the AuthHandler cmd/xkmsd/admin.go actually
// wires onto the ACME admin surface (go-xkms#1240) -- without standing up a
// qrdb transport. The SPKI-thumbprint partitioning that go-xkms#1240 fixed is
// covered at its own layer by pkg/auth's QRDBUserStore tests; what these
// prove is that MTLSAuthHandler.Authenticate publishes whatever tenant the
// resolved user carries, through withUser, onto both the AuthenticatedUser
// record and the qrdb context tenant go-xkms#1225's tenant_binding.go reads.
type fakeMTLSUserStore struct {
	byFingerprint map[string]xkmsauth.MTLSUser
}

func (f *fakeMTLSUserStore) GetByCertFingerprint(_ context.Context, fingerprint string) (xkmsauth.MTLSUser, error) {
	u, ok := f.byFingerprint[fingerprint]
	if !ok {
		return xkmsauth.MTLSUser{}, &qrdbsdk.UserNotFoundError{Lookup: "cert_spki/" + fingerprint}
	}
	return u, nil
}

// TestMTLSAuthHandler_TenantUserAuthenticates proves a tenant user's
// certificate authenticates on the ACME admin plane's mTLS boundary and
// binds its own tenant, both on the AuthenticatedUser record and on the
// qrdb context tenant -- the two facts go-xkms#1225's tenant-scoped routes
// depend on to confine the request to tenant-a.
func TestMTLSAuthHandler_TenantUserAuthenticates(t *testing.T) {
	cert := createTestCertificate(t, "alice", nil, []string{"tenant-a"}, nil,
		time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	thumbprint := qrdbsdk.ComputeSPKIThumbprint(cert)

	store := &fakeMTLSUserStore{byFingerprint: map[string]xkmsauth.MTLSUser{
		thumbprint: {
			Username: "alice",
			TenantID: "tenant-a",
			Enabled:  true,
			Roles:    []string{"role-id-operator"},
		},
	}}
	handler := NewMTLSAuthHandler(xkmsauth.NewMTLSAuthenticator(&xkmsauth.MTLSConfig{UserStore: store}))

	var capturedUser *AuthenticatedUser
	var capturedCtx context.Context
	h := handler.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedUser = GetUserFromContext(r.Context())
		capturedCtx = r.Context()
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/api/v1/tenants/tenant-a/roles", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	require.NotNil(t, capturedUser)
	assert.Equal(t, "alice", capturedUser.Username)
	assert.Equal(t, "tenant-a", capturedUser.TenantID)
	assert.Equal(t, []string{"role-id-operator"}, capturedUser.Roles)

	bound, ok := qrdbsdk.TenantFromContext(capturedCtx)
	require.True(t, ok, "withUser must bind the qrdb context tenant explicitly")
	assert.Equal(t, "tenant-a", bound)

	identity := xkmsauth.GetIdentity(capturedCtx)
	require.NotNil(t, identity)
	assert.Equal(t, "tenant-a", identity.TenantID)
}

// TestMTLSAuthHandler_SystemTenantIdentityAuthenticates proves a
// system-tenant identity -- no OU, no SPIFFE SAN -- keeps authenticating
// exactly as it did before go-xkms#1240's fix.
func TestMTLSAuthHandler_SystemTenantIdentityAuthenticates(t *testing.T) {
	cert := createTestCertificate(t, "root", nil, nil, nil,
		time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	thumbprint := qrdbsdk.ComputeSPKIThumbprint(cert)

	store := &fakeMTLSUserStore{byFingerprint: map[string]xkmsauth.MTLSUser{
		thumbprint: {
			Username: "root",
			TenantID: "",
			Enabled:  true,
			Roles:    []string{"role-id-platform-admin"},
		},
	}}
	handler := NewMTLSAuthHandler(xkmsauth.NewMTLSAuthenticator(&xkmsauth.MTLSConfig{UserStore: store}))

	var capturedCtx context.Context
	h := handler.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedCtx = r.Context()
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/admin/tenants", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	bound, ok := qrdbsdk.TenantFromContext(capturedCtx)
	require.True(t, ok)
	assert.Equal(t, qrdbsdk.SystemTenantID, bound)
}

// TestMTLSAuthHandler_UnknownCertificateIsUnauthorized proves a certificate
// bound to no user is refused with 401, never admitted with a
// certificate-derived identity (go-xkms#1096).
func TestMTLSAuthHandler_UnknownCertificateIsUnauthorized(t *testing.T) {
	cert := createTestCertificate(t, "mallory", nil, []string{"tenant-a"}, nil,
		time.Now().Add(-time.Hour), time.Now().Add(time.Hour))

	store := &fakeMTLSUserStore{byFingerprint: map[string]xkmsauth.MTLSUser{}}
	handler := NewMTLSAuthHandler(xkmsauth.NewMTLSAuthenticator(&xkmsauth.MTLSConfig{UserStore: store}))

	h := handler.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler must not run for a certificate bound to no user")
	}))

	req := httptest.NewRequest("GET", "/admin/tenants", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestMTLSAuthHandler_NoCertificateIsUnauthorized proves a request with no
// client certificate at all is refused, not merely a request with an
// unmatched one.
func TestMTLSAuthHandler_NoCertificateIsUnauthorized(t *testing.T) {
	handler := NewMTLSAuthHandler(xkmsauth.NewMTLSAuthenticator(&xkmsauth.MTLSConfig{
		UserStore: &fakeMTLSUserStore{byFingerprint: map[string]xkmsauth.MTLSUser{}},
	}))

	h := handler.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler must not run without a peer certificate")
	}))

	req := httptest.NewRequest("GET", "/admin/tenants", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestMTLSAuthHandler_NilAuthenticatorIsUnauthorized proves the handler
// fails closed when constructed without an authenticator, rather than
// panicking or admitting the request.
func TestMTLSAuthHandler_NilAuthenticatorIsUnauthorized(t *testing.T) {
	handler := NewMTLSAuthHandler(nil)

	h := handler.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler must not run with no authenticator configured")
	}))

	req := httptest.NewRequest("GET", "/admin/tenants", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

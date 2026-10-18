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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	xkmsauth "github.com/jeremyhahn/go-xkms/pkg/auth"
)

// testTrustDomain is the trust domain the deployment's CA issues under in
// these tests.
const testTrustDomain = "kms.example.com"

// tenantMTLSUserStore implements xkmsauth.UserStore the way qrdb's user
// index answers it: a thumbprint is bound within one tenant, and the lookup
// is made in the tenant bound on the context. A lookup with no tenant bound
// fails, so a test passes only if MTLSAuthHandler bound the certificate's
// tenant before the lookup.
type tenantMTLSUserStore struct {
	byTenant map[string]map[string]xkmsauth.MTLSUser
	lookups  int
}

func (s *tenantMTLSUserStore) bind(tenantID string, cert *x509.Certificate, u xkmsauth.MTLSUser) {
	if s.byTenant == nil {
		s.byTenant = map[string]map[string]xkmsauth.MTLSUser{}
	}
	if s.byTenant[tenantID] == nil {
		s.byTenant[tenantID] = map[string]xkmsauth.MTLSUser{}
	}
	s.byTenant[tenantID][qrdbsdk.ComputeSPKIThumbprint(cert)] = u
}

func (s *tenantMTLSUserStore) GetByCertFingerprint(ctx context.Context, fingerprint string) (xkmsauth.MTLSUser, error) {
	s.lookups++
	tenantID, ok := qrdbsdk.TenantFromContext(ctx)
	if !ok {
		return xkmsauth.MTLSUser{}, qrdbsdk.NewMissingTenantContextError("cert thumbprint lookup")
	}
	u, ok := s.byTenant[tenantID][fingerprint]
	if !ok {
		return xkmsauth.MTLSUser{}, &qrdbsdk.UserNotFoundError{Lookup: "cert_spki/" + fingerprint}
	}
	return u, nil
}

// clientCert issues a self-signed client certificate with the given Subject
// OUs and URI SANs.
func clientCert(t *testing.T, cn string, ous []string, uris ...string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn, OrganizationalUnit: ous},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	for _, raw := range uris {
		u, err := url.Parse(raw)
		require.NoError(t, err)
		template.URIs = append(template.URIs, u)
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

func mtlsRequest(path string, cert *x509.Certificate) *http.Request {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if cert != nil {
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	}
	return req
}

func newTestMTLSAuthHandler(store xkmsauth.UserStore) *MTLSAuthHandler {
	return NewMTLSAuthHandler(xkmsauth.NewMTLSAuthenticator(&xkmsauth.MTLSConfig{UserStore: store}), testTrustDomain)
}

// serve runs req through handler.Authenticate and returns the response code
// and the context the next handler saw (nil when it did not run).
func serve(handler *MTLSAuthHandler, req *http.Request) (int, context.Context) {
	var seen context.Context
	h := handler.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Context()
		w.WriteHeader(http.StatusOK)
	}))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w.Code, seen
}

// TestMTLSAuthHandler_TenantUserAuthenticates proves a tenant user whose
// certificate names its tenant in the deployment's trust domain is looked up
// in that tenant, authenticates, and reaches its own tenant's admin routes:
// the AuthenticatedUser, the qrdb context tenant and the identity all carry
// tenant-a, and go-xkms#1225's binding admits tenant-a's routes.
func TestMTLSAuthHandler_TenantUserAuthenticates(t *testing.T) {
	cert := clientCert(t, "alice", []string{"tenant-a"}, "spiffe://"+testTrustDomain+"/tenant/tenant-a/user/alice")
	store := &tenantMTLSUserStore{}
	store.bind("tenant-a", cert, xkmsauth.MTLSUser{
		Username: "alice", TenantID: "tenant-a", Enabled: true, Roles: []string{"role-id-operator"},
	})

	code, ctx := serve(newTestMTLSAuthHandler(store), mtlsRequest("/api/v1/tenants/tenant-a/roles", cert))

	require.Equal(t, http.StatusOK, code)
	user := GetUserFromContext(ctx)
	require.NotNil(t, user)
	assert.Equal(t, "alice", user.Username)
	assert.Equal(t, "tenant-a", user.TenantID)
	assert.Equal(t, []string{"role-id-operator"}, user.Roles)

	bound, ok := qrdbsdk.TenantFromContext(ctx)
	require.True(t, ok)
	assert.Equal(t, "tenant-a", bound)
	identity := xkmsauth.GetIdentity(ctx)
	require.NotNil(t, identity)
	assert.Equal(t, "tenant-a", identity.TenantID)

	assert.NoError(t, admitTenant(ctx, "list roles", "tenant-a"))
}

// TestMTLSAuthHandler_TenantUserByOU proves the OU fallback of qrdb's rule:
// a certificate with no SPIFFE SAN is read as the tenant its first OU names.
func TestMTLSAuthHandler_TenantUserByOU(t *testing.T) {
	cert := clientCert(t, "bob", []string{"tenant-a"})
	store := &tenantMTLSUserStore{}
	store.bind("tenant-a", cert, xkmsauth.MTLSUser{Username: "bob", TenantID: "tenant-a", Enabled: true})

	code, ctx := serve(newTestMTLSAuthHandler(store), mtlsRequest("/api/v1/tenants/tenant-a/roles", cert))

	require.Equal(t, http.StatusOK, code)
	assert.Equal(t, "tenant-a", GetUserFromContext(ctx).TenantID)
}

// TestMTLSAuthHandler_TenantUserRefusedOnOtherTenantRoutes proves a tenant-a
// certificate gets go-xkms#1225's refusal on tenant-b's routes.
func TestMTLSAuthHandler_TenantUserRefusedOnOtherTenantRoutes(t *testing.T) {
	cert := clientCert(t, "alice", nil, "spiffe://"+testTrustDomain+"/tenant/tenant-a/user/alice")
	store := &tenantMTLSUserStore{}
	store.bind("tenant-a", cert, xkmsauth.MTLSUser{Username: "alice", TenantID: "tenant-a", Enabled: true})

	code, ctx := serve(newTestMTLSAuthHandler(store), mtlsRequest("/api/v1/tenants/tenant-b/roles", cert))
	require.Equal(t, http.StatusOK, code)

	var refusal *TenantBindingError
	require.ErrorAs(t, admitTenant(ctx, "list roles", "tenant-b"), &refusal)
	assert.Equal(t, "tenant-a", refusal.CallerTenantID)
	assert.Equal(t, "tenant-b", refusal.TargetTenantID)
}

// TestMTLSAuthHandler_SystemTenantIdentityAuthenticates proves a
// system-tenant identity -- no OU, no SPIFFE SAN -- is looked up in the
// system tenant and keeps authenticating.
func TestMTLSAuthHandler_SystemTenantIdentityAuthenticates(t *testing.T) {
	cert := clientCert(t, "root", nil)
	store := &tenantMTLSUserStore{}
	store.bind(qrdbsdk.SystemTenantID, cert, xkmsauth.MTLSUser{
		Username: "root", Enabled: true, Roles: []string{"role-id-platform-admin"},
	})

	code, ctx := serve(newTestMTLSAuthHandler(store), mtlsRequest("/admin/tenants", cert))

	require.Equal(t, http.StatusOK, code)
	bound, ok := qrdbsdk.TenantFromContext(ctx)
	require.True(t, ok)
	assert.Equal(t, qrdbsdk.SystemTenantID, bound)
}

// TestMTLSAuthHandler_CertificateNotSearchedInOtherTenants proves the
// thumbprint is looked up in the certificate's tenant only: a certificate
// naming tenant-a whose thumbprint is bound in the system tenant is refused,
// never resolved by falling back to the system tenant.
func TestMTLSAuthHandler_CertificateNotSearchedInOtherTenants(t *testing.T) {
	cert := clientCert(t, "alice", []string{"tenant-a"})
	store := &tenantMTLSUserStore{}
	store.bind(qrdbsdk.SystemTenantID, cert, xkmsauth.MTLSUser{Username: "alice", Enabled: true})
	handler := newTestMTLSAuthHandler(store)

	_, err := handler.authenticate(mtlsRequest("/admin/tenants", cert))
	assert.ErrorIs(t, err, xkmsauth.ErrCertNotBound)

	code, _ := serve(handler, mtlsRequest("/admin/tenants", cert))
	assert.Equal(t, http.StatusUnauthorized, code)
}

// TestMTLSAuthHandler_UnknownCertificateIsUnauthorized proves a certificate
// bound to no user is refused with 401, never admitted with a
// certificate-derived identity (go-xkms#1096).
func TestMTLSAuthHandler_UnknownCertificateIsUnauthorized(t *testing.T) {
	cert := clientCert(t, "mallory", []string{"tenant-a"})
	handler := newTestMTLSAuthHandler(&tenantMTLSUserStore{})

	_, err := handler.authenticate(mtlsRequest("/admin/tenants", cert))
	assert.ErrorIs(t, err, xkmsauth.ErrCertNotBound)

	code, ctx := serve(handler, mtlsRequest("/admin/tenants", cert))
	assert.Equal(t, http.StatusUnauthorized, code)
	assert.Nil(t, ctx, "the next handler must not run")
}

// TestMTLSAuthHandler_NoCertificateIsUnauthorized proves a request with no
// client certificate at all is refused, not merely a request with an
// unmatched one.
func TestMTLSAuthHandler_NoCertificateIsUnauthorized(t *testing.T) {
	handler := newTestMTLSAuthHandler(&tenantMTLSUserStore{})

	_, err := handler.authenticate(mtlsRequest("/admin/tenants", nil))
	assert.ErrorIs(t, err, xkmsauth.ErrNoPeerCertificate)

	code, ctx := serve(handler, mtlsRequest("/admin/tenants", nil))
	assert.Equal(t, http.StatusUnauthorized, code)
	assert.Nil(t, ctx)
}

// TestMTLSAuthHandler_ForeignTrustDomainIsUnauthorized proves a certificate
// whose SPIFFE SAN is from another trust domain is refused with qrdb's typed
// refusal before any lookup -- even though its OU names a tenant where the
// thumbprint is bound -- rather than falling back to the OU or the system
// tenant.
func TestMTLSAuthHandler_ForeignTrustDomainIsUnauthorized(t *testing.T) {
	cert := clientCert(t, "eve", []string{"tenant-a"}, "spiffe://other.example.com/tenant/tenant-a/user/eve")
	store := &tenantMTLSUserStore{}
	store.bind("tenant-a", cert, xkmsauth.MTLSUser{Username: "eve", TenantID: "tenant-a", Enabled: true})
	store.bind(qrdbsdk.SystemTenantID, cert, xkmsauth.MTLSUser{Username: "eve", Enabled: true})
	handler := newTestMTLSAuthHandler(store)

	_, err := handler.authenticate(mtlsRequest("/admin/tenants", cert))
	var refusal *qrdbsdk.ClientCertificateTenantError
	require.ErrorAs(t, err, &refusal)
	assert.ErrorIs(t, err, qrdbsdk.ErrSpiffeTrustDomainMismatch)

	code, ctx := serve(handler, mtlsRequest("/admin/tenants", cert))
	assert.Equal(t, http.StatusUnauthorized, code)
	assert.Nil(t, ctx)
	assert.Zero(t, store.lookups, "a refused certificate must never reach the user store")
}

// TestMTLSAuthHandler_NilAuthenticatorIsUnauthorized proves the handler
// fails closed when constructed without an authenticator, rather than
// panicking or admitting the request.
func TestMTLSAuthHandler_NilAuthenticatorIsUnauthorized(t *testing.T) {
	handler := NewMTLSAuthHandler(nil, testTrustDomain)
	cert := clientCert(t, "root", nil)

	_, err := handler.authenticate(mtlsRequest("/admin/tenants", cert))
	assert.ErrorIs(t, err, ErrAuthenticatorNotConfigured)

	code, ctx := serve(handler, mtlsRequest("/admin/tenants", cert))
	assert.Equal(t, http.StatusUnauthorized, code)
	assert.Nil(t, ctx)
}

// TestMTLSAuthHandler_OUNamingARoleGrantsNoRole proves a certificate's OU is
// its tenant and never a role (SPEC authz-cert-ou-roles): an OU spelling a role
// name grants nothing, and a bound user with no roles stays without any.
func TestMTLSAuthHandler_OUNamingARoleGrantsNoRole(t *testing.T) {
	cert := clientCert(t, "alice", []string{"tenant-a", "Admin"}, "spiffe://"+testTrustDomain+"/tenant/tenant-a/user/alice")
	store := &tenantMTLSUserStore{}
	store.bind("tenant-a", cert, xkmsauth.MTLSUser{Username: "alice", TenantID: "tenant-a", Enabled: true})

	identity, err := newTestMTLSAuthHandler(store).authenticate(mtlsRequest("/admin/status", cert))

	require.NoError(t, err)
	assert.Equal(t, "tenant-a", identity.TenantID)
	assert.Empty(t, identity.Roles)
}

// TestMTLSAuthHandler_RolesComeFromTheBoundUser proves the caller's roles are
// exactly the bound qrdb user's role IDs, while its first OU, with no SPIFFE
// tenant SAN, is the tenant qrdbsdk.TenantFromClientCert names.
func TestMTLSAuthHandler_RolesComeFromTheBoundUser(t *testing.T) {
	cert := clientCert(t, "bob", []string{"Admin", "Operator"})
	store := &tenantMTLSUserStore{}
	store.bind("Admin", cert, xkmsauth.MTLSUser{
		Username: "bob", TenantID: "Admin", Enabled: true, Roles: []string{"role-id-viewer"},
	})

	code, ctx := serve(newTestMTLSAuthHandler(store), mtlsRequest("/admin/status", cert))

	require.Equal(t, http.StatusOK, code)
	user := GetUserFromContext(ctx)
	require.NotNil(t, user)
	assert.Equal(t, "Admin", user.TenantID)
	assert.Equal(t, []string{"role-id-viewer"}, user.Roles)
	assert.Equal(t, []string{"role-id-viewer"}, xkmsauth.GetIdentity(ctx).Roles)
}

// TestMTLSAuthHandler_UserOfAnotherTenantIsRefused proves a store answering
// with a user outside the certificate's tenant is refused with a
// *CertificateTenantMismatchError, never admitted with that user's roles.
func TestMTLSAuthHandler_UserOfAnotherTenantIsRefused(t *testing.T) {
	cert := clientCert(t, "carol", nil, "spiffe://"+testTrustDomain+"/tenant/tenant-a/user/carol")
	store := &tenantMTLSUserStore{}
	store.bind("tenant-a", cert, xkmsauth.MTLSUser{
		Username: "carol", TenantID: "tenant-b", Enabled: true, Roles: []string{"role-id-admin"},
	})
	handler := newTestMTLSAuthHandler(store)

	_, err := handler.authenticate(mtlsRequest("/admin/status", cert))
	var mismatch *CertificateTenantMismatchError
	require.ErrorAs(t, err, &mismatch)
	assert.Equal(t, "tenant-a", mismatch.CertificateTenantID)
	assert.Equal(t, "tenant-b", mismatch.UserTenantID)
	assert.ErrorIs(t, err, xkmsauth.ErrUnauthenticated)

	code, ctx := serve(handler, mtlsRequest("/admin/status", cert))
	assert.Equal(t, http.StatusUnauthorized, code)
	assert.Nil(t, ctx)
}

// grpcPeerContext is a gRPC server context whose TLS peer presented cert.
func grpcPeerContext(cert *x509.Certificate) context.Context {
	return peer.NewContext(context.Background(), &peer.Peer{
		Addr:     &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 12345},
		AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}},
	})
}

// TestMTLSAuthHandler_AuthenticateGRPC proves the gRPC entry point applies the
// same rule as the REST one: the tenant from the certificate, the roles from
// the bound user, never from the OU.
func TestMTLSAuthHandler_AuthenticateGRPC(t *testing.T) {
	cert := clientCert(t, "dave", []string{"tenant-a", "Admin"}, "spiffe://"+testTrustDomain+"/tenant/tenant-a/user/dave")
	store := &tenantMTLSUserStore{}
	store.bind("tenant-a", cert, xkmsauth.MTLSUser{
		Username: "dave", TenantID: "tenant-a", Enabled: true, Roles: []string{"role-id-operator"},
	})

	identity, err := newTestMTLSAuthHandler(store).AuthenticateGRPC(grpcPeerContext(cert), cert, nil)

	require.NoError(t, err)
	assert.Equal(t, "dave", identity.Subject)
	assert.Equal(t, "tenant-a", identity.TenantID)
	assert.Equal(t, []string{"role-id-operator"}, identity.Roles)
}

// TestMTLSAuthHandler_AuthenticateGRPCRefusals proves the gRPC entry point
// refuses an unbound certificate and a nil handler with typed errors.
func TestMTLSAuthHandler_AuthenticateGRPCRefusals(t *testing.T) {
	cert := clientCert(t, "mallory", []string{"Admin"})

	_, err := newTestMTLSAuthHandler(&tenantMTLSUserStore{}).AuthenticateGRPC(grpcPeerContext(cert), cert, nil)
	assert.ErrorIs(t, err, xkmsauth.ErrCertNotBound)

	var nilHandler *MTLSAuthHandler
	_, err = nilHandler.AuthenticateGRPC(grpcPeerContext(cert), cert, nil)
	assert.ErrorIs(t, err, ErrAuthenticatorNotConfigured)
}

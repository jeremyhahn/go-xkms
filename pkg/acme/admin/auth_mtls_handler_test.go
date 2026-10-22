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
	"encoding/asn1"
	"encoding/pem"
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
	"github.com/jeremyhahn/go-xkms/pkg/ca"
	"github.com/jeremyhahn/go-xkms/pkg/spiffe"
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
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	// Each OU is its own RDN, so the first stays first: OUs sharing one RDN
	// are a DER SET, which encoding sorts.
	for _, ou := range ous {
		template.Subject.ExtraNames = append(template.Subject.ExtraNames,
			pkix.AttributeTypeAndValue{Type: asn1.ObjectIdentifier{2, 5, 4, 11}, Value: ou})
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
	cert := clientCert(t, "alice", []string{"tenant-a"}, "spiffe://tenant-a/user/alice")
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

// TestMTLSAuthHandler_CAIssuedCertificateUnderTrustDomainPin proves issuance
// and the go-qrdb verifier agree under a non-empty cluster trust-domain pin
// (go-xkms#1602): a client certificate the CA issues for tenant-a under the
// pin carries spiffe://tenant-a/user/<cn> with tenant-a as OU[0], and the
// admin plane, verifying under the same pin, resolves it to tenant-a. A
// tenant equal to the pin is refused at issuance, before login could.
func TestMTLSAuthHandler_CAIssuedCertificateUnderTrustDomainPin(t *testing.T) {
	issuer := createRootOnlyTestCA(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "alice"},
	}, key)
	require.NoError(t, err)
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	cert, err := issuer.SignCSR(context.Background(), csrPEM, &ca.SignOptions{
		Profile: "client", ValidityDays: 30, TenantID: "tenant-a", SPIFFETrustDomain: testTrustDomain,
	})
	require.NoError(t, err)
	require.Len(t, cert.URIs, 1)
	assert.Equal(t, "spiffe://tenant-a/user/alice", cert.URIs[0].String())

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

	_, err = issuer.SignCSR(context.Background(), csrPEM, &ca.SignOptions{
		Profile: "client", ValidityDays: 30, TenantID: testTrustDomain, SPIFFETrustDomain: testTrustDomain,
	})
	assert.ErrorIs(t, err, spiffe.ErrTenantIsClusterTrustDomain)
}

// TestMTLSAuthHandler_TenantUserRefusedOnOtherTenantRoutes proves a tenant-a
// certificate gets go-xkms#1225's refusal on tenant-b's routes.
func TestMTLSAuthHandler_TenantUserRefusedOnOtherTenantRoutes(t *testing.T) {
	cert := clientCert(t, "alice", []string{"tenant-a"}, "spiffe://tenant-a/user/alice")
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
// system-tenant identity -- OU system and spiffe://system/user/<cn> -- is
// looked up in the system tenant and keeps authenticating.
func TestMTLSAuthHandler_SystemTenantIdentityAuthenticates(t *testing.T) {
	cert := clientCert(t, "root", []string{qrdbsdk.SystemTenantID}, "spiffe://"+qrdbsdk.SystemTenantID+"/user/root")
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
	cert := clientCert(t, "alice", []string{"tenant-a"}, "spiffe://tenant-a/user/alice")
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
	cert := clientCert(t, "mallory", []string{"tenant-a"}, "spiffe://tenant-a/user/mallory")
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

// TestMTLSAuthHandler_CertificateTenantRefusals proves a certificate that
// names no tenant under qrdb's rule -- an OU or a SPIFFE SAN alone, OU and SAN
// naming different tenants, or a tenant that is the cluster trust domain -- is
// refused with qrdb's typed refusal before any lookup, even though the
// thumbprint is bound in every tenant it could name, rather than falling back
// to the OU, the SAN or the system tenant.
func TestMTLSAuthHandler_CertificateTenantRefusals(t *testing.T) {
	cases := []struct {
		name    string
		ous     []string
		sans    []string
		wantErr func(t *testing.T, err error)
	}{
		{
			name: "OU without a SPIFFE SAN",
			ous:  []string{"tenant-a"},
			wantErr: func(t *testing.T, err error) {
				assert.ErrorIs(t, err, qrdbsdk.ErrSpiffeNoTenantID)
			},
		},
		{
			name: "SPIFFE SAN without an OU",
			sans: []string{"spiffe://tenant-a/user/eve"},
			wantErr: func(t *testing.T, err error) {
				assert.ErrorIs(t, err, qrdbsdk.ErrSpiffeTrustDomainMismatch)
			},
		},
		{
			name: "OU and SAN name different tenants",
			ous:  []string{"tenant-a"},
			sans: []string{"spiffe://tenant-b/user/eve"},
			wantErr: func(t *testing.T, err error) {
				var mismatch *qrdbsdk.ClientCertificateTenantNameMismatchError
				assert.ErrorAs(t, err, &mismatch)
			},
		},
		{
			name: "tenant is the cluster trust domain",
			ous:  []string{testTrustDomain},
			sans: []string{"spiffe://" + testTrustDomain + "/user/eve"},
			wantErr: func(t *testing.T, err error) {
				assert.ErrorIs(t, err, qrdbsdk.ErrClientCertificateTenantIsClusterTrustDomain)
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cert := clientCert(t, "eve", tc.ous, tc.sans...)
			store := &tenantMTLSUserStore{}
			for _, tenant := range []string{"tenant-a", "tenant-b", testTrustDomain} {
				store.bind(tenant, cert, xkmsauth.MTLSUser{Username: "eve", TenantID: tenant, Enabled: true})
			}
			store.bind(qrdbsdk.SystemTenantID, cert, xkmsauth.MTLSUser{Username: "eve", Enabled: true})
			handler := newTestMTLSAuthHandler(store)

			_, err := handler.authenticate(mtlsRequest("/admin/tenants", cert))
			var refusal *qrdbsdk.ClientCertificateTenantError
			require.ErrorAs(t, err, &refusal)
			tc.wantErr(t, err)

			code, ctx := serve(handler, mtlsRequest("/admin/tenants", cert))
			assert.Equal(t, http.StatusUnauthorized, code)
			assert.Nil(t, ctx)
			assert.Zero(t, store.lookups, "a refused certificate must never reach the user store")
		})
	}
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
	cert := clientCert(t, "alice", []string{"tenant-a", "Admin"}, "spiffe://tenant-a/user/alice")
	store := &tenantMTLSUserStore{}
	store.bind("tenant-a", cert, xkmsauth.MTLSUser{Username: "alice", TenantID: "tenant-a", Enabled: true})

	identity, err := newTestMTLSAuthHandler(store).authenticate(mtlsRequest("/admin/status", cert))

	require.NoError(t, err)
	assert.Equal(t, "tenant-a", identity.TenantID)
	assert.Empty(t, identity.Roles)
}

// TestMTLSAuthHandler_RolesComeFromTheBoundUser proves the caller's roles are
// exactly the bound qrdb user's role IDs, never the Operator its second OU
// spells, while its first OU and SPIFFE SAN name the tenant.
func TestMTLSAuthHandler_RolesComeFromTheBoundUser(t *testing.T) {
	cert := clientCert(t, "bob", []string{"tenant-b", "Operator"}, "spiffe://tenant-b/user/bob")
	store := &tenantMTLSUserStore{}
	store.bind("tenant-b", cert, xkmsauth.MTLSUser{
		Username: "bob", TenantID: "tenant-b", Enabled: true, Roles: []string{"role-id-viewer"},
	})

	code, ctx := serve(newTestMTLSAuthHandler(store), mtlsRequest("/admin/status", cert))

	require.Equal(t, http.StatusOK, code)
	user := GetUserFromContext(ctx)
	require.NotNil(t, user)
	assert.Equal(t, "tenant-b", user.TenantID)
	assert.Equal(t, []string{"role-id-viewer"}, user.Roles)
	assert.Equal(t, []string{"role-id-viewer"}, xkmsauth.GetIdentity(ctx).Roles)
}

// TestMTLSAuthHandler_UserOfAnotherTenantIsRefused proves a store answering
// with a user outside the certificate's tenant is refused with a
// *CertificateTenantMismatchError, never admitted with that user's roles.
func TestMTLSAuthHandler_UserOfAnotherTenantIsRefused(t *testing.T) {
	cert := clientCert(t, "carol", []string{"tenant-a"}, "spiffe://tenant-a/user/carol")
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
	cert := clientCert(t, "dave", []string{"tenant-a", "Admin"}, "spiffe://tenant-a/user/dave")
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
	cert := clientCert(t, "mallory", []string{"tenant-a"}, "spiffe://tenant-a/user/mallory")

	_, err := newTestMTLSAuthHandler(&tenantMTLSUserStore{}).AuthenticateGRPC(grpcPeerContext(cert), cert, nil)
	assert.ErrorIs(t, err, xkmsauth.ErrCertNotBound)

	var nilHandler *MTLSAuthHandler
	_, err = nilHandler.AuthenticateGRPC(grpcPeerContext(cert), cert, nil)
	assert.ErrorIs(t, err, ErrAuthenticatorNotConfigured)
}

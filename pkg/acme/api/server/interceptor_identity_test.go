// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

//go:build !integration

package server

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
	"net/url"
	"testing"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"

	"github.com/jeremyhahn/go-xkms/pkg/acme/admin"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
)

// certWithSubject builds an unsigned *x509.Certificate carrying only the
// Subject fields peerCertificate's tests compare. It is never parsed from
// DER or verified, which is fine here: peerCertificate only reads struct
// fields, never signatures.
func certWithSubject(commonName string, organizationalUnit ...string) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:         commonName,
			OrganizationalUnit: organizationalUnit,
		},
	}
}

// peerContextWithCert returns a context carrying a gRPC peer whose AuthInfo
// is credentials.TLSInfo with cert as the sole verified peer certificate,
// mirroring how a real TLS handshake publishes the client cert.
func peerContextWithCert(cert *x509.Certificate) context.Context {
	p := &peer.Peer{
		Addr: &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 12345},
		AuthInfo: credentials.TLSInfo{
			State: tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}},
		},
	}
	return peer.NewContext(context.Background(), p)
}

func TestPeerCertificate_NoPeerInContext(t *testing.T) {
	assert.Nil(t, peerCertificate(context.Background()))
}

func TestPeerCertificate_NoTLSInfo(t *testing.T) {
	p := &peer.Peer{Addr: &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 1}, AuthInfo: nil}
	ctx := peer.NewContext(context.Background(), p)
	assert.Nil(t, peerCertificate(ctx))
}

func TestPeerCertificate_NoPeerCertificates(t *testing.T) {
	p := &peer.Peer{
		Addr:     &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 1},
		AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{}},
	}
	ctx := peer.NewContext(context.Background(), p)
	assert.Nil(t, peerCertificate(ctx))
}

func TestPeerCertificate_ReturnsLeafCertificate(t *testing.T) {
	cert := certWithSubject("grpc-peer")
	ctx := peerContextWithCert(cert)
	assert.Same(t, cert, peerCertificate(ctx))
}

// TestUnaryMTLSIdentityInterceptor_ExistingIdentityPassesThrough proves the
// interceptor does not re-authenticate or override an identity a preceding
// interceptor already published (e.g. the Unix peer-credential path).
func TestUnaryMTLSIdentityInterceptor_ExistingIdentityPassesThrough(t *testing.T) {
	interceptor := UnaryMTLSIdentityInterceptor(nil, testLogger())

	existing := &auth.Identity{Subject: "uid:1000"}
	ctx := auth.WithIdentity(context.Background(), existing)

	var ran bool
	_, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/x/Y"}, func(ctx context.Context, req interface{}) (interface{}, error) {
		ran = true
		assert.Same(t, existing, auth.GetIdentity(ctx))
		return "ok", nil
	})

	require.NoError(t, err)
	assert.True(t, ran)
}

// TestUnaryMTLSIdentityInterceptor_NoClientCertificate proves a call with no
// client certificate (plaintext, Unix socket, or TLS with no client auth)
// reaches the handler with no identity attached, leaving the denial to the
// authorization interceptor that runs after it.
func TestUnaryMTLSIdentityInterceptor_NoClientCertificate(t *testing.T) {
	interceptor := UnaryMTLSIdentityInterceptor(nil, testLogger())

	var ran bool
	_, err := interceptor(context.Background(), nil, &grpc.UnaryServerInfo{FullMethod: "/x/Y"}, func(ctx context.Context, req interface{}) (interface{}, error) {
		ran = true
		assert.Nil(t, auth.GetIdentity(ctx))
		return "ok", nil
	})

	require.NoError(t, err)
	assert.True(t, ran)
}

// testTrustDomain is the SPIFFE trust domain the interceptor tests pin.
const testTrustDomain = "kms.example.com"

// tenantUserStore is an auth.UserStore that, like go-qrdb's, resolves a
// certificate's user only within the tenant bound on the context.
type tenantUserStore struct {
	byTenant map[string]map[string]auth.MTLSUser
}

func (s *tenantUserStore) bind(tenantID string, cert *x509.Certificate, u auth.MTLSUser) {
	if s.byTenant == nil {
		s.byTenant = map[string]map[string]auth.MTLSUser{}
	}
	if s.byTenant[tenantID] == nil {
		s.byTenant[tenantID] = map[string]auth.MTLSUser{}
	}
	s.byTenant[tenantID][qrdbsdk.ComputeSPKIThumbprint(cert)] = u
}

func (s *tenantUserStore) GetByCertFingerprint(ctx context.Context, fingerprint string) (auth.MTLSUser, error) {
	tenantID, ok := qrdbsdk.TenantFromContext(ctx)
	if !ok {
		return auth.MTLSUser{}, qrdbsdk.NewMissingTenantContextError("cert thumbprint lookup")
	}
	u, ok := s.byTenant[tenantID][fingerprint]
	if !ok {
		return auth.MTLSUser{}, &qrdbsdk.UserNotFoundError{Lookup: "cert_spki/" + fingerprint}
	}
	return u, nil
}

// signedClientCert issues a self-signed client certificate with a real public
// key, so its SPKI thumbprint can bind it to a user.
func signedClientCert(t *testing.T, commonName string, organizationalUnit []string, uris ...string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: commonName, OrganizationalUnit: organizationalUnit},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
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

func newTestCertAuth(store auth.UserStore) *admin.MTLSAuthHandler {
	return admin.NewMTLSAuthHandler(auth.NewMTLSAuthenticator(&auth.MTLSConfig{UserStore: store}), testTrustDomain)
}

// runInterceptor runs interceptor over ctx and returns the identity and
// tenant the handler saw.
func runInterceptor(t *testing.T, interceptor grpc.UnaryServerInterceptor, ctx context.Context) (*auth.Identity, string) {
	t.Helper()
	var (
		ran      bool
		identity *auth.Identity
		tenantID string
	)
	_, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/x/Y"}, func(ctx context.Context, req interface{}) (interface{}, error) {
		ran = true
		identity = auth.GetIdentity(ctx)
		tenantID, _ = qrdbsdk.TenantFromContext(ctx)
		return "ok", nil
	})
	require.NoError(t, err)
	require.True(t, ran)
	return identity, tenantID
}

// TestUnaryMTLSIdentityInterceptor_RolesComeFromTheBoundUser proves a call
// carrying a client certificate gets the roles of the go-qrdb user the
// certificate binds to, and the tenant qrdbsdk.TenantFromClientCert names,
// bound on the context the handler sees.
func TestUnaryMTLSIdentityInterceptor_RolesComeFromTheBoundUser(t *testing.T) {
	store := &tenantUserStore{}
	cert := signedClientCert(t, "grpc-client", []string{"tenant-a"})
	store.bind("tenant-a", cert, auth.MTLSUser{
		Username: "carol", TenantID: "tenant-a", Enabled: true, Roles: []string{"role-id-operator"},
	})

	identity, tenantID := runInterceptor(t, UnaryMTLSIdentityInterceptor(newTestCertAuth(store), testLogger()), peerContextWithCert(cert))

	require.NotNil(t, identity)
	assert.Equal(t, "carol", identity.Subject)
	assert.Equal(t, []string{"role-id-operator"}, identity.Roles)
	assert.Equal(t, "tenant-a", identity.TenantID)
	assert.Equal(t, "tenant-a", tenantID)
}

// TestUnaryMTLSIdentityInterceptor_OUNamingARoleGrantsNoRole proves an OU that
// names a role grants nothing: the SPIFFE SAN names the tenant, and the
// caller's roles are only those of its bound user, here none.
func TestUnaryMTLSIdentityInterceptor_OUNamingARoleGrantsNoRole(t *testing.T) {
	store := &tenantUserStore{}
	cert := signedClientCert(t, "grpc-client", []string{"tenant-a", "Admin"},
		"spiffe://"+testTrustDomain+"/tenant/tenant-a/user/grpc-client")
	store.bind("tenant-a", cert, auth.MTLSUser{Username: "erin", TenantID: "tenant-a", Enabled: true})

	identity, tenantID := runInterceptor(t, UnaryMTLSIdentityInterceptor(newTestCertAuth(store), testLogger()), peerContextWithCert(cert))

	require.NotNil(t, identity)
	assert.Empty(t, identity.Roles)
	assert.Equal(t, "tenant-a", tenantID)
}

// TestUnaryMTLSIdentityInterceptor_RefusedCertificateGetsNoIdentity proves a
// certificate that binds to no user, or to a user of another tenant, reaches
// the handler with no identity and no tenant, leaving the denial to the
// authorization interceptor.
func TestUnaryMTLSIdentityInterceptor_RefusedCertificateGetsNoIdentity(t *testing.T) {
	store := &tenantUserStore{}
	unbound := signedClientCert(t, "stranger", []string{"tenant-a"})
	crossTenant := signedClientCert(t, "mallory", []string{"tenant-a"})
	store.bind("tenant-a", crossTenant, auth.MTLSUser{Username: "mallory", TenantID: "tenant-b", Enabled: true})
	interceptor := UnaryMTLSIdentityInterceptor(newTestCertAuth(store), testLogger())

	for name, cert := range map[string]*x509.Certificate{"unbound": unbound, "cross-tenant": crossTenant} {
		t.Run(name, func(t *testing.T) {
			identity, tenantID := runInterceptor(t, interceptor, peerContextWithCert(cert))
			assert.Nil(t, identity)
			assert.Empty(t, tenantID)
		})
	}
}

// TestUnaryMTLSIdentityInterceptor_NilCertAuthGetsNoIdentity proves an
// interceptor built without a certificate authenticator (and with a nil
// logger) attaches no identity rather than panicking.
func TestUnaryMTLSIdentityInterceptor_NilCertAuthGetsNoIdentity(t *testing.T) {
	cert := signedClientCert(t, "grpc-client", []string{"Admin"})

	identity, tenantID := runInterceptor(t, UnaryMTLSIdentityInterceptor(nil, nil), peerContextWithCert(cert))

	assert.Nil(t, identity)
	assert.Empty(t, tenantID)
}

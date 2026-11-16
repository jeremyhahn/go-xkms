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

package auth

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
)

// tenantCert builds a client certificate with the given Subject OUs and
// URI SANs, the two fields qrdb's certificate-to-tenant rule reads.
func tenantCert(t *testing.T, ous []string, uris ...string) *x509.Certificate {
	t.Helper()
	cert := &x509.Certificate{
		Subject: pkix.Name{
			CommonName:         "tenant-client",
			OrganizationalUnit: ous,
		},
		SerialNumber: big.NewInt(4242),
		Raw:          []byte("tenant-client-raw"),
	}
	for _, raw := range uris {
		u, err := url.Parse(raw)
		require.NoError(t, err)
		cert.URIs = append(cert.URIs, u)
	}
	return cert
}

// withTenant gives a generated certificate the tenant claim go-qrdb's rule
// accepts: first Subject OU and SPIFFE SAN trust domain both naming tenant.
func withTenant(t *testing.T, cert *x509.Certificate, tenant string) *x509.Certificate {
	t.Helper()
	u, err := url.Parse("spiffe://" + tenant + "/user/" + cert.Subject.CommonName)
	require.NoError(t, err)
	cert.Subject.OrganizationalUnit = []string{tenant}
	cert.URIs = append(cert.URIs, u)
	return cert
}

func tenantRequest(cert *x509.Certificate) *http.Request {
	return &http.Request{
		TLS:        &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}},
		RemoteAddr: "10.0.0.20:443",
	}
}

// TestMTLSAuthenticator_CertificateTenant_QRDBRule covers the
// certificate-only path: the tenant is the one qrdbsdk.TenantFromClientCert
// names, and a certificate it refuses is refused.
func TestMTLSAuthenticator_CertificateTenant_QRDBRule(t *testing.T) {
	tests := []struct {
		name        string
		trustDomain string
		ous         []string
		uris        []string
		wantTenant  string
		wantRefused bool
	}{
		{name: "OU and SPIFFE SAN agree", ous: []string{"acme"}, uris: []string{"spiffe://acme/user/alice"}, wantTenant: "acme"},
		{name: "OU and SPIFFE SAN agree under the cluster trust domain", trustDomain: "cluster.local", ous: []string{"acme"}, uris: []string{"spiffe://acme/user/alice"}, wantTenant: "acme"},
		{name: "SPIFFE SAN names a different tenant from the OU", ous: []string{"acme"}, uris: []string{"spiffe://other/user/alice"}, wantRefused: true},
		{name: "OU without a SPIFFE SAN", ous: []string{"acme", "second"}, wantRefused: true},
		{name: "tenant is the cluster trust domain", trustDomain: "cluster.local", ous: []string{"cluster.local"}, uris: []string{"spiffe://cluster.local/svc/node"}, wantRefused: true},
		{name: "SANs under two trust domains", ous: []string{"acme"}, uris: []string{"spiffe://acme/user/alice", "spiffe://other/user/alice"}, wantRefused: true},
		{name: "certificate with no OU names no tenant", wantRefused: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := NewMTLSAuthenticator(&MTLSConfig{TrustDomain: tt.trustDomain})
			identity, err := a.AuthenticateHTTP(tenantRequest(tenantCert(t, tt.ous, tt.uris...)))
			if tt.wantRefused {
				require.Error(t, err)
				assert.Nil(t, identity)
				assert.True(t, errors.Is(err, qrdbsdk.ErrInvalidClientCertificate), "error %v must match qrdbsdk.ErrInvalidClientCertificate", err)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, identity)
			assert.Equal(t, "tenant-client", identity.Subject)
			assert.Equal(t, tt.wantTenant, identity.TenantID)
		})
	}
}

// TestMTLSAuthenticator_CertIdentity_DelegatesToQRDB pins the certificate-only
// path to go-qrdb's rule with no go-xkms rule on top: for each certificate
// shape, certIdentity refuses exactly when qrdbsdk.TenantFromClientCert
// refuses, and otherwise carries the tenant it names (normalized, as
// go-qrdb's doc binds it).
func TestMTLSAuthenticator_CertIdentity_DelegatesToQRDB(t *testing.T) {
	shapes := []struct {
		name string
		ous  []string
		uris []string
	}{
		{name: "SPIFFE SAN only", uris: []string{"spiffe://acme/user/alice"}},
		{name: "OU only", ous: []string{"acme"}},
		{name: "SAN and OU agree", ous: []string{"acme"}, uris: []string{"spiffe://acme/user/alice"}},
		{name: "SAN and OU disagree", ous: []string{"acme"}, uris: []string{"spiffe://other/user/alice"}},
		{name: "neither", uris: nil},
	}
	for _, trustDomain := range []string{"", "cluster.local"} {
		for _, s := range shapes {
			t.Run(s.name+"/trust-domain="+trustDomain, func(t *testing.T) {
				cert := tenantCert(t, s.ous, s.uris...)
				wantTenant, wantErr := qrdbsdk.TenantFromClientCert(cert, trustDomain)

				a := NewMTLSAuthenticator(&MTLSConfig{TrustDomain: trustDomain})
				identity, err := a.certIdentity(cert)
				if wantErr != nil {
					require.Error(t, err)
					assert.Nil(t, identity)
					assert.Equal(t, wantErr.Error(), err.Error())
					assert.True(t, errors.Is(err, qrdbsdk.ErrInvalidClientCertificate))
					return
				}
				require.NoError(t, err)
				require.NotNil(t, identity)
				assert.Equal(t, qrdbsdk.NormalizeTenantID(wantTenant), identity.TenantID)
			})
		}
	}
}

// TestMTLSAuthenticator_BoundUserTenant_QRDBRule covers the bound-user path:
// a certificate that names a tenant resolves only to a user of that tenant.
func TestMTLSAuthenticator_BoundUserTenant_QRDBRule(t *testing.T) {
	tests := []struct {
		name         string
		userTenant   string
		ous          []string
		uris         []string
		wantTenant   string
		wantMismatch bool
		wantInvalid  bool
	}{
		{name: "user in the certificate's tenant", userTenant: "acme", ous: []string{"acme"}, uris: []string{"spiffe://acme/user/alice"}, wantTenant: "acme"},
		{name: "user in another tenant", userTenant: "other", ous: []string{"acme"}, uris: []string{"spiffe://acme/user/alice"}, wantMismatch: true},
		{name: "certificate the rule refuses", userTenant: "acme", ous: []string{"acme"}, wantInvalid: true},
		{name: "certificate claims no tenant", userTenant: "acme", wantTenant: "acme"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := &mockUserStore{user: MTLSUser{Username: "alice", TenantID: tt.userTenant, Enabled: true}}
			a := NewMTLSAuthenticator(&MTLSConfig{UserStore: store})
			identity, err := a.AuthenticateHTTP(tenantRequest(tenantCert(t, tt.ous, tt.uris...)))
			switch {
			case tt.wantMismatch:
				require.Error(t, err)
				assert.Nil(t, identity)
				var mismatch *CertificateTenantMismatchError
				require.True(t, errors.As(err, &mismatch), "error %v must be a *CertificateTenantMismatchError", err)
				assert.Equal(t, "acme", mismatch.CertificateTenantID)
				assert.Equal(t, tt.userTenant, mismatch.UserTenantID)
				assert.True(t, errors.Is(err, ErrUnauthenticated))
			case tt.wantInvalid:
				require.Error(t, err)
				assert.Nil(t, identity)
				assert.True(t, errors.Is(err, qrdbsdk.ErrInvalidClientCertificate), "error %v must match qrdbsdk.ErrInvalidClientCertificate", err)
			default:
				require.NoError(t, err)
				require.NotNil(t, identity)
				assert.Equal(t, "alice", identity.Subject)
				assert.Equal(t, tt.wantTenant, identity.TenantID)
			}
		})
	}
}

// TestMTLSAuthenticator_BoundUser_AsOnMain proves the row leaves bound-user
// mTLS authentication as on main: the user the certificate's SPKI
// fingerprint is bound to authenticates with its own subject, tenant and
// roles over HTTP and gRPC, whatever tenant the certificate's OU names and
// with no SPIFFE SAN. The tenant rule of this row is certificate-only
// (certIdentity, docs/SPEC.md).
func TestMTLSAuthenticator_BoundUser_AsOnMain(t *testing.T) {
	tests := []struct {
		name string
		ous  []string
	}{
		{name: "certificate OU names the user's tenant", ous: []string{"acme"}},
		{name: "certificate OU names another tenant", ous: []string{"other"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := &mockUserStore{user: MTLSUser{Username: "alice", TenantID: "acme", Roles: []string{"operator"}, Enabled: true}}
			a := NewMTLSAuthenticator(&MTLSConfig{UserStore: store})
			cert := tenantCert(t, tt.ous)

			httpIdentity, httpErr := a.AuthenticateHTTP(tenantRequest(cert))
			grpcCtx := peer.NewContext(context.Background(), &peer.Peer{
				Addr: &net.TCPAddr{IP: net.ParseIP("10.0.0.4"), Port: 9090},
				AuthInfo: credentials.TLSInfo{
					State: tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}},
				},
			})
			grpcIdentity, grpcErr := a.AuthenticateGRPC(grpcCtx, metadata.MD{})

			for transport, got := range map[string]struct {
				identity *Identity
				err      error
			}{
				"http": {httpIdentity, httpErr},
				"grpc": {grpcIdentity, grpcErr},
			} {
				require.NoError(t, got.err, transport)
				require.NotNil(t, got.identity, transport)
				assert.Equal(t, "alice", got.identity.Subject, transport)
				assert.Equal(t, "acme", got.identity.TenantID, transport)
				assert.Equal(t, []string{"operator"}, got.identity.Roles, transport)
			}
			assert.NotEmpty(t, store.queriedFingerprint)
		})
	}
}

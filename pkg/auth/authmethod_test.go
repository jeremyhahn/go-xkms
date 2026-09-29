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
	"errors"
	"net"
	"net/http"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
)

// TestCheckAuthMethod_Permits pins the cases go-qrdb's checkAuthMethod lets
// through: an empty or nil policy states no restriction, and a policy naming
// the method (after qrdb's own normalization of the method name) admits it.
func TestCheckAuthMethod_Permits(t *testing.T) {
	tests := []struct {
		name   string
		policy []string
		method string
	}{
		{name: "nil policy states no restriction", policy: nil, method: qrdbsdk.MethodMTLS},
		{name: "empty policy states no restriction", policy: []string{}, method: qrdbsdk.MethodMTLS},
		{name: "empty policy admits even a blank method", policy: nil, method: ""},
		{name: "policy naming mtls", policy: []string{"mtls"}, method: qrdbsdk.MethodMTLS},
		{name: "mtls among several", policy: []string{"webauthn", "mtls"}, method: qrdbsdk.MethodMTLS},
		{name: "method name is normalized", policy: []string{"mtls"}, method: "  MTLS "},
		{name: "policy naming webauthn admits the relying party", policy: []string{"piv", "webauthn"}, method: MethodWebAuthn},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.NoError(t, CheckAuthMethod("alice", "tenant-a", tt.policy, tt.method))
		})
	}
}

// TestCheckAuthMethod_Refuses pins the fail-closed cases: a non-empty policy
// that does not name the method, and an observed method whose name does not
// survive normalization, are both refused with the typed error naming the
// method and the permitted set.
func TestCheckAuthMethod_Refuses(t *testing.T) {
	tests := []struct {
		name       string
		policy     []string
		method     string
		wantMethod string
	}{
		{name: "fido2-only refuses mtls", policy: []string{"fido2"}, method: qrdbsdk.MethodMTLS, wantMethod: "mtls"},
		{name: "mtls-only refuses webauthn", policy: []string{"mtls"}, method: MethodWebAuthn, wantMethod: "webauthn"},
		{name: "refused method is reported normalized", policy: []string{"webauthn"}, method: "MTLS", wantMethod: "mtls"},
		{name: "blank method matches nothing", policy: []string{"mtls"}, method: "", wantMethod: ""},
		{name: "whitespace method matches nothing", policy: []string{"mtls"}, method: "   ", wantMethod: "   "},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CheckAuthMethod("alice", "tenant-a", tt.policy, tt.method)

			var refused *AuthMethodNotPermittedError
			require.True(t, errors.As(err, &refused), "want *AuthMethodNotPermittedError, got %v", err)
			assert.Equal(t, "alice", refused.Username)
			assert.Equal(t, "tenant-a", refused.TenantID)
			assert.Equal(t, tt.wantMethod, refused.Method)
			assert.Equal(t, tt.policy, refused.Permitted)
		})
	}
}

func TestAuthMethodNotPermittedError_Error(t *testing.T) {
	err := &AuthMethodNotPermittedError{
		Username:  "alice",
		TenantID:  "tenant-a",
		Method:    "mtls",
		Permitted: []string{"fido2", "webauthn"},
	}
	assert.Equal(t,
		"auth: authentication method mtls is not permitted for alice in tenant tenant-a (permitted: fido2, webauthn)",
		err.Error())
}

// newPolicyAuthenticator wires the production QRDBUserStore, over the
// in-memory qrdb user client, into an MTLSAuthenticator with a single active
// user bound to a fresh client certificate's SPKI thumbprint.
func newPolicyAuthenticator(t *testing.T, policy []string) (*MTLSAuthenticator, *x509.Certificate) {
	t.Helper()
	ca, err := testutil.GenerateTestCA()
	require.NoError(t, err)
	clientCert, err := testutil.GenerateTestClientCert(ca, "policy-client")
	require.NoError(t, err)

	users := newFakeQRDBUserClient()
	users.byThumbprint[qrdbsdk.ComputeSPKIThumbprint(clientCert.Cert)] = &qrdbtransport.User{
		Username:    "alice",
		TenantID:    "tenant-a",
		RoleIDs:     []string{"role-1"},
		Lifecycle:   string(qrdbsdk.LifecycleActive),
		AuthMethods: policy,
	}

	authn := NewMTLSAuthenticator(&MTLSConfig{UserStore: NewQRDBUserStore(users)})
	return authn, clientCert.Cert
}

func policyHTTPRequest(cert *x509.Certificate) *http.Request {
	return &http.Request{
		TLS:        &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}},
		RemoteAddr: "10.0.0.9:443",
	}
}

// TestMTLSAuthenticator_AuthMethodPolicy_RefusesHTTP proves a FIDO2-only
// account presenting its bound certificate is refused, and is NOT admitted
// through the certificate-field fallback that serves unknown certificates.
func TestMTLSAuthenticator_AuthMethodPolicy_RefusesHTTP(t *testing.T) {
	authn, cert := newPolicyAuthenticator(t, []string{"fido2"})

	identity, err := authn.AuthenticateHTTP(policyHTTPRequest(cert))
	assert.Nil(t, identity)
	var refused *AuthMethodNotPermittedError
	require.True(t, errors.As(err, &refused), "want *AuthMethodNotPermittedError, got %v", err)
	assert.Equal(t, qrdbsdk.MethodMTLS, refused.Method)
	assert.Equal(t, []string{"fido2"}, refused.Permitted)
}

func TestMTLSAuthenticator_AuthMethodPolicy_RefusesGRPC(t *testing.T) {
	authn, cert := newPolicyAuthenticator(t, []string{"webauthn"})
	p := &peer.Peer{
		Addr: &net.TCPAddr{IP: net.ParseIP("10.0.0.9"), Port: 9090},
		AuthInfo: credentials.TLSInfo{
			State: tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}},
		},
	}

	identity, err := authn.AuthenticateGRPC(peer.NewContext(context.Background(), p), metadata.MD{})
	assert.Nil(t, identity)
	var refused *AuthMethodNotPermittedError
	require.True(t, errors.As(err, &refused), "want *AuthMethodNotPermittedError, got %v", err)
}

// TestMTLSAuthenticator_AuthMethodPolicy_Admits proves an account whose policy
// names mTLS, and an account with no policy at all, both authenticate exactly
// as before.
func TestMTLSAuthenticator_AuthMethodPolicy_Admits(t *testing.T) {
	for name, policy := range map[string][]string{
		"policy names mtls": {"webauthn", "mtls"},
		"empty policy":      nil,
	} {
		t.Run(name, func(t *testing.T) {
			authn, cert := newPolicyAuthenticator(t, policy)

			identity, err := authn.AuthenticateHTTP(policyHTTPRequest(cert))
			require.NoError(t, err)
			assert.Equal(t, "alice", identity.Subject)
			assert.Equal(t, "tenant-a", identity.TenantID)
			assert.Equal(t, []string{"role-1"}, identity.Roles)
			assert.Equal(t, qrdbsdk.MethodMTLS, identity.Metadata["auth_method"])
		})
	}
}

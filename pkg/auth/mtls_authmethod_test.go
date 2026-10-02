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
	var refused *qrdbsdk.AuthMethodNotPermittedError
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
	var refused *qrdbsdk.AuthMethodNotPermittedError
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

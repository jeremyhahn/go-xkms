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
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
)

// mockUserStore implements UserStore for testing.
type mockUserStore struct {
	user MTLSUser
	err  error
}

func (m *mockUserStore) GetByCertFingerprint(ctx context.Context, fingerprint string) (MTLSUser, error) {
	return m.user, m.err
}

func TestNewMTLSAuthenticator_NilConfig(t *testing.T) {
	auth := NewMTLSAuthenticator(nil)

	require.NotNil(t, auth)
	assert.NotNil(t, auth.extractClaims)
	assert.NotNil(t, auth.extractSubject)
}

func TestNewMTLSAuthenticator_CustomExtractSubject(t *testing.T) {
	customSubject := func(cert *x509.Certificate) string {
		return "custom-subject"
	}

	auth := NewMTLSAuthenticator(&MTLSConfig{
		ExtractSubject: customSubject,
	})

	require.NotNil(t, auth)

	// Test that custom function is used
	ca, err := testutil.GenerateTestCA()
	require.NoError(t, err)

	clientCert, err := testutil.GenerateTestClientCert(ca, "test-client")
	require.NoError(t, err)

	subject := auth.extractSubject(clientCert.Cert)
	assert.Equal(t, "custom-subject", subject)
}

func TestNewMTLSAuthenticator_CustomExtractClaims(t *testing.T) {
	customClaims := func(cert *x509.Certificate) map[string]interface{} {
		return map[string]interface{}{
			"custom": "claim",
		}
	}

	auth := NewMTLSAuthenticator(&MTLSConfig{
		ExtractClaims: customClaims,
	})

	require.NotNil(t, auth)

	// Test that custom function is used
	ca, err := testutil.GenerateTestCA()
	require.NoError(t, err)

	clientCert, err := testutil.GenerateTestClientCert(ca, "test-client")
	require.NoError(t, err)

	claims := auth.extractClaims(clientCert.Cert)
	assert.Equal(t, "claim", claims["custom"])
}

func TestMTLSAuthenticator_AuthenticateHTTP_ValidCert(t *testing.T) {
	ca, err := testutil.GenerateTestCA()
	require.NoError(t, err)

	clientCert, err := testutil.GenerateTestClientCert(ca, "test-client")
	require.NoError(t, err)

	auth := NewMTLSAuthenticator(nil)

	req := &http.Request{
		TLS: &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{clientCert.Cert},
		},
		RemoteAddr: "192.168.1.1:12345",
	}

	identity, err := auth.AuthenticateHTTP(req)

	require.NoError(t, err)
	require.NotNil(t, identity)
	assert.Equal(t, "test-client", identity.Subject)
	assert.Equal(t, "mtls", identity.Attributes["auth_method"])
	assert.NotEmpty(t, identity.Attributes["cert_serial"])
	assert.NotEmpty(t, identity.Attributes["cert_issuer"])
	assert.Equal(t, "192.168.1.1:12345", identity.Attributes["remote_addr"])
}

func TestMTLSAuthenticator_AuthenticateHTTP_NoTLS(t *testing.T) {
	auth := NewMTLSAuthenticator(nil)

	req := &http.Request{
		TLS: nil,
	}

	identity, err := auth.AuthenticateHTTP(req)

	require.Error(t, err)
	assert.Nil(t, identity)
	assert.True(t, errors.Is(err, ErrNoPeerCertificate))
	assert.Equal(t, "no client certificate provided", err.Error())
}

func TestMTLSAuthenticator_AuthenticateHTTP_NoPeerCertificates(t *testing.T) {
	auth := NewMTLSAuthenticator(nil)

	req := &http.Request{
		TLS: &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{},
		},
	}

	identity, err := auth.AuthenticateHTTP(req)

	require.Error(t, err)
	assert.Nil(t, identity)
	assert.True(t, errors.Is(err, ErrNoPeerCertificate))
	assert.Equal(t, "no client certificate provided", err.Error())
}

func TestMTLSAuthenticator_AuthenticateGRPC_ValidCert(t *testing.T) {
	ca, err := testutil.GenerateTestCA()
	require.NoError(t, err)

	clientCert, err := testutil.GenerateTestClientCert(ca, "grpc-client")
	require.NoError(t, err)

	auth := NewMTLSAuthenticator(nil)

	// Create peer with TLS info
	p := &peer.Peer{
		Addr: &net.TCPAddr{
			IP:   net.ParseIP("192.168.1.1"),
			Port: 12345,
		},
		AuthInfo: credentials.TLSInfo{
			State: tls.ConnectionState{
				PeerCertificates: []*x509.Certificate{clientCert.Cert},
			},
		},
	}

	ctx := peer.NewContext(context.Background(), p)
	md := metadata.New(map[string]string{})

	identity, err := auth.AuthenticateGRPC(ctx, md)

	require.NoError(t, err)
	require.NotNil(t, identity)
	assert.Equal(t, "grpc-client", identity.Subject)
	assert.Equal(t, "mtls", identity.Attributes["auth_method"])
	assert.NotEmpty(t, identity.Attributes["cert_serial"])
	assert.NotEmpty(t, identity.Attributes["peer_addr"])
}

func TestMTLSAuthenticator_AuthenticateGRPC_NoPeerInfo(t *testing.T) {
	auth := NewMTLSAuthenticator(nil)

	ctx := context.Background()
	md := metadata.New(map[string]string{})

	identity, err := auth.AuthenticateGRPC(ctx, md)

	require.Error(t, err)
	assert.Nil(t, identity)
	assert.True(t, errors.Is(err, ErrNoPeerInfo))
	assert.Equal(t, "no peer information in context", err.Error())
}

func TestMTLSAuthenticator_AuthenticateGRPC_NoTLSInfo(t *testing.T) {
	auth := NewMTLSAuthenticator(nil)

	// Create peer without TLS info
	p := &peer.Peer{
		Addr: &net.TCPAddr{
			IP:   net.ParseIP("192.168.1.1"),
			Port: 12345,
		},
		AuthInfo: nil,
	}

	ctx := peer.NewContext(context.Background(), p)
	md := metadata.New(map[string]string{})

	identity, err := auth.AuthenticateGRPC(ctx, md)

	require.Error(t, err)
	assert.Nil(t, identity)
	assert.True(t, errors.Is(err, ErrNoTLSInfo))
	assert.Equal(t, "no TLS information in peer", err.Error())
}

func TestMTLSAuthenticator_AuthenticateGRPC_NoPeerCertificates(t *testing.T) {
	auth := NewMTLSAuthenticator(nil)

	// Create peer with empty certificates
	p := &peer.Peer{
		Addr: &net.TCPAddr{
			IP:   net.ParseIP("192.168.1.1"),
			Port: 12345,
		},
		AuthInfo: credentials.TLSInfo{
			State: tls.ConnectionState{
				PeerCertificates: []*x509.Certificate{},
			},
		},
	}

	ctx := peer.NewContext(context.Background(), p)
	md := metadata.New(map[string]string{})

	identity, err := auth.AuthenticateGRPC(ctx, md)

	require.Error(t, err)
	assert.Nil(t, identity)
	assert.True(t, errors.Is(err, ErrNoPeerCertificate))
	assert.Equal(t, "no client certificate provided", err.Error())
}

func TestMTLSAuthenticator_Name(t *testing.T) {
	auth := NewMTLSAuthenticator(nil)

	assert.Equal(t, "mtls", auth.Name())
}

func TestDefaultExtractSubject(t *testing.T) {
	tests := []struct {
		name     string
		cert     *x509.Certificate
		expected string
	}{
		{
			name: "common name present",
			cert: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "test.example.com",
				},
			},
			expected: "test.example.com",
		},
		{
			name: "no common name, use DNS name",
			cert: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "",
				},
				DNSNames: []string{"fallback.example.com", "other.example.com"},
			},
			expected: "fallback.example.com",
		},
		{
			name: "no common name or DNS, use serial",
			cert: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "",
				},
				DNSNames:     []string{},
				SerialNumber: big.NewInt(12345),
			},
			expected: "12345",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := defaultExtractSubject(tt.cert)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestDefaultExtractClaims(t *testing.T) {
	ca, err := testutil.GenerateTestCA()
	require.NoError(t, err)

	clientCert, err := testutil.GenerateTestClientCert(ca, "test-client")
	require.NoError(t, err)

	claims := defaultExtractClaims(clientCert.Cert)

	require.NotNil(t, claims)
	assert.Equal(t, "test-client", claims["common_name"])

	// Check that organization is present
	if org, ok := claims["organization"]; ok {
		if orgSlice, ok := org.([]string); ok {
			if len(orgSlice) == 1 {
				assert.Equal(t, "Test Client", orgSlice[0])
			}
		}
	}

	// Check permissions are set based on ExtKeyUsage
	if perms, ok := claims["permissions"]; ok {
		if permSlice, ok := perms.([]string); ok {
			found := false
			for _, p := range permSlice {
				if p == "client_auth" {
					found = true
					break
				}
			}
			assert.True(t, found, "permissions should contain 'client_auth'")
		}
	}
}

func TestKeyUsageString(t *testing.T) {
	tests := []struct {
		usage    x509.ExtKeyUsage
		expected string
	}{
		{x509.ExtKeyUsageAny, "any"},
		{x509.ExtKeyUsageServerAuth, "server_auth"},
		{x509.ExtKeyUsageClientAuth, "client_auth"},
		{x509.ExtKeyUsageCodeSigning, "code_signing"},
		{x509.ExtKeyUsageEmailProtection, "email_protection"},
		{x509.ExtKeyUsageTimeStamping, "time_stamping"},
		{x509.ExtKeyUsageOCSPSigning, "ocsp_signing"},
		{x509.ExtKeyUsage(999), "unknown_999"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := keyUsageString(tt.usage)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// Tests for UserStore integration

func TestMTLSAuthenticator_WithUserStore_HTTP_Success(t *testing.T) {
	ca, err := testutil.GenerateTestCA()
	require.NoError(t, err)

	clientCert, err := testutil.GenerateTestClientCert(ca, "cert-client")
	require.NoError(t, err)

	store := &mockUserStore{
		user: MTLSUser{
			Username:    "alice",
			DisplayName: "Alice Smith",
			Role:        "admin",
			Enabled:     true,
		},
	}

	auth := NewMTLSAuthenticator(&MTLSConfig{
		UserStore: store,
	})

	req := &http.Request{
		TLS: &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{clientCert.Cert},
		},
		RemoteAddr: "10.0.0.1:443",
	}

	identity, err := auth.AuthenticateHTTP(req)
	require.NoError(t, err)

	assert.Equal(t, "alice", identity.Subject)

	roles, ok := identity.Claims["roles"].([]string)
	require.True(t, ok)
	assert.Equal(t, []string{"admin"}, roles)
	assert.Equal(t, "Alice Smith", identity.Claims["display_name"])
	assert.Equal(t, "mtls", identity.Attributes["auth_method"])
	assert.NotEmpty(t, identity.Attributes["cert_fingerprint"])
	assert.Equal(t, "10.0.0.1:443", identity.Attributes["remote_addr"])
}

func TestMTLSAuthenticator_WithUserStore_GRPC_Success(t *testing.T) {
	ca, err := testutil.GenerateTestCA()
	require.NoError(t, err)

	clientCert, err := testutil.GenerateTestClientCert(ca, "cert-client")
	require.NoError(t, err)

	store := &mockUserStore{
		user: MTLSUser{
			Username:    "bob",
			DisplayName: "Bob Jones",
			Role:        "operator",
			Enabled:     true,
		},
	}

	auth := NewMTLSAuthenticator(&MTLSConfig{
		UserStore: store,
	})

	p := &peer.Peer{
		Addr: &net.TCPAddr{
			IP:   net.ParseIP("10.0.0.2"),
			Port: 9090,
		},
		AuthInfo: credentials.TLSInfo{
			State: tls.ConnectionState{
				PeerCertificates: []*x509.Certificate{clientCert.Cert},
			},
		},
	}

	ctx := peer.NewContext(context.Background(), p)
	md := metadata.New(map[string]string{})

	identity, err := auth.AuthenticateGRPC(ctx, md)
	require.NoError(t, err)

	assert.Equal(t, "bob", identity.Subject)

	roles, ok := identity.Claims["roles"].([]string)
	require.True(t, ok)
	assert.Equal(t, []string{"operator"}, roles)
	assert.NotEmpty(t, identity.Attributes["peer_addr"])
}

func TestMTLSAuthenticator_WithUserStore_DisabledUser(t *testing.T) {
	ca, err := testutil.GenerateTestCA()
	require.NoError(t, err)

	clientCert, err := testutil.GenerateTestClientCert(ca, "disabled-client")
	require.NoError(t, err)

	store := &mockUserStore{
		user: MTLSUser{
			Username:    "disabled-alice",
			DisplayName: "Alice Disabled",
			Role:        "user",
			Enabled:     false,
		},
	}

	auth := NewMTLSAuthenticator(&MTLSConfig{
		UserStore: store,
	})

	req := &http.Request{
		TLS: &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{clientCert.Cert},
		},
		RemoteAddr: "10.0.0.3:443",
	}

	identity, err := auth.AuthenticateHTTP(req)
	require.Error(t, err)
	assert.Nil(t, identity)
	assert.True(t, errors.Is(err, ErrUserDisabled))
}

func TestMTLSAuthenticator_WithUserStore_NotFound_FallsBack(t *testing.T) {
	ca, err := testutil.GenerateTestCA()
	require.NoError(t, err)

	clientCert, err := testutil.GenerateTestClientCert(ca, "unknown-client")
	require.NoError(t, err)

	store := &mockUserStore{
		err: errors.New("not found"),
	}

	auth := NewMTLSAuthenticator(&MTLSConfig{
		UserStore: store,
	})

	req := &http.Request{
		TLS: &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{clientCert.Cert},
		},
		RemoteAddr: "10.0.0.4:443",
	}

	identity, err := auth.AuthenticateHTTP(req)
	require.NoError(t, err)

	// Should fall back to certificate CN
	assert.Equal(t, "unknown-client", identity.Subject)
	assert.Equal(t, "mtls", identity.Attributes["auth_method"])

	// Should NOT have cert_fingerprint attribute when falling back
	_, ok := identity.Attributes["cert_fingerprint"]
	assert.False(t, ok, "cert_fingerprint should not be set when falling back to cert extraction")
}

func TestMTLSAuthenticator_WithUserStore_NoRole(t *testing.T) {
	ca, err := testutil.GenerateTestCA()
	require.NoError(t, err)

	clientCert, err := testutil.GenerateTestClientCert(ca, "norole-client")
	require.NoError(t, err)

	store := &mockUserStore{
		user: MTLSUser{
			Username:    "norole-user",
			DisplayName: "No Role",
			Role:        "",
			Enabled:     true,
		},
	}

	auth := NewMTLSAuthenticator(&MTLSConfig{
		UserStore: store,
	})

	req := &http.Request{
		TLS: &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{clientCert.Cert},
		},
		RemoteAddr: "10.0.0.5:443",
	}

	identity, err := auth.AuthenticateHTTP(req)
	require.NoError(t, err)

	assert.Equal(t, "norole-user", identity.Subject)

	// Should NOT have roles claim when role is empty
	_, ok := identity.Claims["roles"]
	assert.False(t, ok, "roles claim should not be set when user has no role")
}

func TestComputeCertFingerprint(t *testing.T) {
	ca, err := testutil.GenerateTestCA()
	require.NoError(t, err)

	clientCert, err := testutil.GenerateTestClientCert(ca, "fingerprint-test")
	require.NoError(t, err)

	fp := ComputeCertFingerprint(clientCert.Cert)
	assert.NotEmpty(t, fp)

	// SHA-256 hex digest is always 64 characters
	assert.Len(t, fp, 64)

	// Same cert should produce same fingerprint (deterministic)
	fp2 := ComputeCertFingerprint(clientCert.Cert)
	assert.Equal(t, fp, fp2)

	// Different cert should produce different fingerprint
	clientCert2, err := testutil.GenerateTestClientCert(ca, "fingerprint-test-2")
	require.NoError(t, err)

	fp3 := ComputeCertFingerprint(clientCert2.Cert)
	assert.NotEqual(t, fp, fp3)
}

func TestMTLSAuthenticator_WithUserStore_DisabledUser_GRPC(t *testing.T) {
	ca, err := testutil.GenerateTestCA()
	require.NoError(t, err)

	clientCert, err := testutil.GenerateTestClientCert(ca, "grpc-disabled")
	require.NoError(t, err)

	store := &mockUserStore{
		user: MTLSUser{
			Username: "grpc-disabled-user",
			Enabled:  false,
		},
	}

	auth := NewMTLSAuthenticator(&MTLSConfig{
		UserStore: store,
	})

	p := &peer.Peer{
		Addr: &net.TCPAddr{
			IP:   net.ParseIP("10.0.0.6"),
			Port: 9090,
		},
		AuthInfo: credentials.TLSInfo{
			State: tls.ConnectionState{
				PeerCertificates: []*x509.Certificate{clientCert.Cert},
			},
		},
	}

	ctx := peer.NewContext(context.Background(), p)
	md := metadata.New(map[string]string{})

	identity, err := auth.AuthenticateGRPC(ctx, md)
	require.Error(t, err)
	assert.Nil(t, identity)
	assert.True(t, errors.Is(err, ErrUserDisabled))
}

func TestMTLSAuthenticator_WithoutUserStore_NoChange(t *testing.T) {
	// Verify that existing behavior is unchanged when UserStore is nil.
	ca, err := testutil.GenerateTestCA()
	require.NoError(t, err)

	clientCert, err := testutil.GenerateTestClientCert(ca, "no-store-client")
	require.NoError(t, err)

	auth := NewMTLSAuthenticator(&MTLSConfig{
		UserStore: nil,
	})

	req := &http.Request{
		TLS: &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{clientCert.Cert},
		},
		RemoteAddr: "10.0.0.7:443",
	}

	identity, err := auth.AuthenticateHTTP(req)
	require.NoError(t, err)

	assert.Equal(t, "no-store-client", identity.Subject)
}

// Tests for TenantID extraction

func TestMTLSAuthenticator_TenantID_FromUserStore(t *testing.T) {
	ca, err := testutil.GenerateTestCA()
	require.NoError(t, err)

	clientCert, err := testutil.GenerateTestClientCert(ca, "tenant-client")
	require.NoError(t, err)

	store := &mockUserStore{
		user: MTLSUser{
			Username:    "tenant-user",
			DisplayName: "Tenant User",
			Role:        "admin",
			TenantID:    "tenant-123",
			Enabled:     true,
		},
	}

	auth := NewMTLSAuthenticator(&MTLSConfig{
		UserStore: store,
	})

	req := &http.Request{
		TLS: &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{clientCert.Cert},
		},
		RemoteAddr: "10.0.0.8:443",
	}

	identity, err := auth.AuthenticateHTTP(req)
	require.NoError(t, err)
	require.NotNil(t, identity)

	assert.Equal(t, "tenant-user", identity.Subject)
	assert.Equal(t, "tenant-123", identity.TenantID)
	assert.False(t, identity.IsCrossTenant())
}

func TestMTLSAuthenticator_TenantID_FromOU(t *testing.T) {
	// When no UserStore is configured, the first OU from the cert is used as TenantID.
	cert := &x509.Certificate{
		Subject: pkix.Name{
			CommonName:         "ou-client",
			OrganizationalUnit: []string{"tenant-from-ou", "other-ou"},
			Organization:       []string{"TestOrg"},
		},
		SerialNumber: big.NewInt(99999),
		Raw:          []byte("fake-raw-cert-data"),
	}

	auth := NewMTLSAuthenticator(nil)

	req := &http.Request{
		TLS: &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{cert},
		},
		RemoteAddr: "10.0.0.9:443",
	}

	identity, err := auth.AuthenticateHTTP(req)
	require.NoError(t, err)
	require.NotNil(t, identity)

	assert.Equal(t, "ou-client", identity.Subject)
	assert.Equal(t, "tenant-from-ou", identity.TenantID)
	assert.False(t, identity.IsCrossTenant())
}

func TestMTLSAuthenticator_TenantID_NoOU(t *testing.T) {
	// When no UserStore is configured and the cert has no OU, TenantID should be empty.
	cert := &x509.Certificate{
		Subject: pkix.Name{
			CommonName:         "no-ou-client",
			OrganizationalUnit: []string{},
			Organization:       []string{"TestOrg"},
		},
		SerialNumber: big.NewInt(88888),
		Raw:          []byte("fake-raw-cert-data-2"),
	}

	auth := NewMTLSAuthenticator(nil)

	req := &http.Request{
		TLS: &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{cert},
		},
		RemoteAddr: "10.0.0.10:443",
	}

	identity, err := auth.AuthenticateHTTP(req)
	require.NoError(t, err)
	require.NotNil(t, identity)

	assert.Equal(t, "no-ou-client", identity.Subject)
	assert.Empty(t, identity.TenantID)
	assert.True(t, identity.IsCrossTenant())
}

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

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
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
	// queriedFingerprint records the identifier the authenticator looked up,
	// so tests can assert it is the canonical SPKI thumbprint.
	queriedFingerprint string
}

func (m *mockUserStore) GetByCertFingerprint(ctx context.Context, fingerprint string) (MTLSUser, error) {
	m.queriedFingerprint = fingerprint
	return m.user, m.err
}

func TestNewMTLSAuthenticator_NilConfig(t *testing.T) {
	auth := NewMTLSAuthenticator(nil)

	require.NotNil(t, auth)
	assert.NotNil(t, auth.extractMetadata)
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

func TestNewMTLSAuthenticator_CustomExtractMetadata(t *testing.T) {
	customMetadata := func(cert *x509.Certificate) CertMetadata {
		return CertMetadata{
			CommonName: "custom-cn",
		}
	}

	auth := NewMTLSAuthenticator(&MTLSConfig{
		ExtractMetadata: customMetadata,
	})

	require.NotNil(t, auth)

	ca, err := testutil.GenerateTestCA()
	require.NoError(t, err)

	clientCert, err := testutil.GenerateTestClientCert(ca, "test-client")
	require.NoError(t, err)

	cm := auth.extractMetadata(clientCert.Cert)
	assert.Equal(t, "custom-cn", cm.CommonName)
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
	assert.Equal(t, "mtls", identity.Metadata["auth_method"])
	assert.NotEmpty(t, identity.Metadata["cert_serial"])
	assert.NotEmpty(t, identity.Metadata["cert_issuer"])
	assert.Equal(t, "192.168.1.1:12345", identity.Metadata["remote_addr"])
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
	assert.Equal(t, "mtls", identity.Metadata["auth_method"])
	assert.NotEmpty(t, identity.Metadata["cert_serial"])
	assert.NotEmpty(t, identity.Metadata["peer_addr"])
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

func TestDefaultExtractCertMetadata(t *testing.T) {
	ca, err := testutil.GenerateTestCA()
	require.NoError(t, err)

	clientCert, err := testutil.GenerateTestClientCert(ca, "test-client")
	require.NoError(t, err)

	cm := defaultExtractCertMetadata(clientCert.Cert)

	assert.Equal(t, "test-client", cm.CommonName)

	// Organization should be the comma-joined cert organization list.
	if cm.Organization != "" {
		assert.Contains(t, cm.Organization, "Test Client")
	}

	// Extended key usages should include the certificate's client_auth usage.
	if cm.ExtKeyUsage != "" {
		assert.Contains(t, cm.ExtKeyUsage, "client_auth")
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
			Email:       "alice@example.com",
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

	assert.Equal(t, []string{"admin"}, identity.Roles)
	assert.Equal(t, "Alice Smith", identity.Metadata["display_name"])
	assert.Equal(t, "alice@example.com", identity.Metadata["email"], "the canonical login key must reach the identity")
	assert.Equal(t, "mtls", identity.Metadata["auth_method"])
	assert.NotEmpty(t, identity.Metadata["cert_fingerprint"])
	assert.Equal(t, "10.0.0.1:443", identity.Metadata["remote_addr"])
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

	assert.Equal(t, []string{"operator"}, identity.Roles)
	assert.NotEmpty(t, identity.Metadata["peer_addr"])
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
	assert.Equal(t, "mtls", identity.Metadata["auth_method"])

	// Should NOT have cert_fingerprint attribute when falling back
	_, ok := identity.Metadata["cert_fingerprint"]
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

	// Should NOT have roles when user has no role
	assert.Empty(t, identity.Roles, "Roles should be empty when user has no role")
}

// TestMTLSAuthenticator_LooksUpBySPKIThumbprint verifies the cert-to-user lookup
// uses qrdb's canonical SPKI thumbprint as the binding identifier, so xkms admin
// mTLS bindings resolve consistently with qrdb and quicbaas.
func TestMTLSAuthenticator_LooksUpBySPKIThumbprint(t *testing.T) {
	ca, err := testutil.GenerateTestCA()
	require.NoError(t, err)

	clientCert, err := testutil.GenerateTestClientCert(ca, "spki-lookup")
	require.NoError(t, err)

	store := &mockUserStore{
		user: MTLSUser{
			Username: "spki-user",
			Role:     "admin",
			Enabled:  true,
		},
	}

	a := NewMTLSAuthenticator(&MTLSConfig{UserStore: store})

	identity, err := a.buildIdentity(context.Background(), clientCert.Cert)
	require.NoError(t, err)
	assert.Equal(t, "spki-user", identity.Subject)

	// The authenticator must have queried the store with the canonical SPKI
	// thumbprint, not a full-cert SHA-256 fingerprint.
	want := qrdbsdk.ComputeSPKIThumbprint(clientCert.Cert)
	assert.Equal(t, want, store.queriedFingerprint)
	assert.Equal(t, want, identity.Metadata["cert_fingerprint"])
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
	assert.False(t, IsCrossTenant(identity))
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
	assert.False(t, IsCrossTenant(identity))
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
	assert.True(t, IsCrossTenant(identity))
}

// TestMTLSAuthenticator_WithUserStore_NoEmail_OmitsKey proves a cert-bound
// user without an email login key (a bootstrap or service account) yields an
// identity with no email key at all — absent, not empty (go-xkms#194).
func TestMTLSAuthenticator_WithUserStore_NoEmail_OmitsKey(t *testing.T) {
	ca, err := testutil.GenerateTestCA()
	require.NoError(t, err)

	clientCert, err := testutil.GenerateTestClientCert(ca, "svc-client")
	require.NoError(t, err)

	store := &mockUserStore{
		user: MTLSUser{
			Username: "svc-backup",
			Role:     "operator",
			Enabled:  true,
		},
	}

	auth := NewMTLSAuthenticator(&MTLSConfig{UserStore: store})

	req := &http.Request{
		TLS: &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{clientCert.Cert},
		},
		RemoteAddr: "10.0.0.2:443",
	}

	identity, err := auth.AuthenticateHTTP(req)
	require.NoError(t, err)

	assert.Equal(t, "svc-backup", identity.Subject)
	_, present := identity.Metadata["email"]
	assert.False(t, present, "an absent login key must not be recorded as empty: %v", identity.Metadata)
}

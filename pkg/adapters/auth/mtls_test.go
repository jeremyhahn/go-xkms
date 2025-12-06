// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
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
	"math/big"
	"net"
	"net/http"
	"testing"

	"github.com/jeremyhahn/go-keychain/internal/testutil"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
)

func TestNewMTLSAuthenticator_NilConfig(t *testing.T) {
	auth := NewMTLSAuthenticator(nil)

	if auth == nil {
		t.Fatal("NewMTLSAuthenticator() returned nil")
		return
	}

	if auth.extractClaims == nil {
		t.Error("extractClaims should not be nil")
	}

	if auth.extractSubject == nil {
		t.Error("extractSubject should not be nil")
	}
}

func TestNewMTLSAuthenticator_CustomExtractSubject(t *testing.T) {
	customSubject := func(cert *x509.Certificate) string {
		return "custom-subject"
	}

	auth := NewMTLSAuthenticator(&MTLSConfig{
		ExtractSubject: customSubject,
	})

	if auth == nil {
		t.Fatal("NewMTLSAuthenticator() returned nil")
		return
	}

	// Test that custom function is used
	ca, err := testutil.GenerateTestCA()
	if err != nil {
		t.Fatalf("Failed to generate CA: %v", err)
	}

	clientCert, err := testutil.GenerateTestClientCert(ca, "test-client")
	if err != nil {
		t.Fatalf("Failed to generate client cert: %v", err)
	}

	subject := auth.extractSubject(clientCert.Cert)

	if subject != "custom-subject" {
		t.Errorf("extractSubject() = %v, want custom-subject", subject)
	}
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

	if auth == nil {
		t.Fatal("NewMTLSAuthenticator() returned nil")
		return
	}

	// Test that custom function is used
	ca, err := testutil.GenerateTestCA()
	if err != nil {
		t.Fatalf("Failed to generate CA: %v", err)
	}

	clientCert, err := testutil.GenerateTestClientCert(ca, "test-client")
	if err != nil {
		t.Fatalf("Failed to generate client cert: %v", err)
	}

	claims := auth.extractClaims(clientCert.Cert)

	if claims["custom"] != "claim" {
		t.Errorf("extractClaims() = %v, want custom claim", claims)
	}
}

func TestMTLSAuthenticator_AuthenticateHTTP_ValidCert(t *testing.T) {
	ca, err := testutil.GenerateTestCA()
	if err != nil {
		t.Fatalf("Failed to generate CA: %v", err)
	}

	clientCert, err := testutil.GenerateTestClientCert(ca, "test-client")
	if err != nil {
		t.Fatalf("Failed to generate client cert: %v", err)
	}

	auth := NewMTLSAuthenticator(nil)

	req := &http.Request{
		TLS: &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{clientCert.Cert},
		},
		RemoteAddr: "192.168.1.1:12345",
	}

	identity, err := auth.AuthenticateHTTP(req)

	if err != nil {
		t.Fatalf("AuthenticateHTTP() error = %v, want nil", err)
	}

	if identity == nil {
		t.Fatal("AuthenticateHTTP() returned nil identity")
		return
	}

	if identity.Subject != "test-client" {
		t.Errorf("Subject = %v, want test-client", identity.Subject)
	}

	if identity.Attributes["auth_method"] != "mtls" {
		t.Errorf("auth_method = %v, want mtls", identity.Attributes["auth_method"])
	}

	if identity.Attributes["cert_serial"] == "" {
		t.Error("cert_serial should not be empty")
	}

	if identity.Attributes["cert_issuer"] == "" {
		t.Error("cert_issuer should not be empty")
	}

	if identity.Attributes["remote_addr"] != "192.168.1.1:12345" {
		t.Errorf("remote_addr = %v, want 192.168.1.1:12345", identity.Attributes["remote_addr"])
	}
}

func TestMTLSAuthenticator_AuthenticateHTTP_NoTLS(t *testing.T) {
	auth := NewMTLSAuthenticator(nil)

	req := &http.Request{
		TLS: nil,
	}

	identity, err := auth.AuthenticateHTTP(req)

	if err == nil {
		t.Fatal("AuthenticateHTTP() should return error for no TLS")
	}

	if identity != nil {
		t.Errorf("AuthenticateHTTP() returned identity %v, want nil", identity)
	}

	if err.Error() != "no client certificate provided" {
		t.Errorf("error = %v, want 'no client certificate provided'", err)
	}
}

func TestMTLSAuthenticator_AuthenticateHTTP_NoPeerCertificates(t *testing.T) {
	auth := NewMTLSAuthenticator(nil)

	req := &http.Request{
		TLS: &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{},
		},
	}

	identity, err := auth.AuthenticateHTTP(req)

	if err == nil {
		t.Fatal("AuthenticateHTTP() should return error for no peer certificates")
	}

	if identity != nil {
		t.Errorf("AuthenticateHTTP() returned identity %v, want nil", identity)
	}

	if err.Error() != "no client certificate provided" {
		t.Errorf("error = %v, want 'no client certificate provided'", err)
	}
}

func TestMTLSAuthenticator_AuthenticateGRPC_ValidCert(t *testing.T) {
	ca, err := testutil.GenerateTestCA()
	if err != nil {
		t.Fatalf("Failed to generate CA: %v", err)
	}

	clientCert, err := testutil.GenerateTestClientCert(ca, "grpc-client")
	if err != nil {
		t.Fatalf("Failed to generate client cert: %v", err)
	}

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

	if err != nil {
		t.Fatalf("AuthenticateGRPC() error = %v, want nil", err)
	}

	if identity == nil {
		t.Fatal("AuthenticateGRPC() returned nil identity")
		return
	}

	if identity.Subject != "grpc-client" {
		t.Errorf("Subject = %v, want grpc-client", identity.Subject)
	}

	if identity.Attributes["auth_method"] != "mtls" {
		t.Errorf("auth_method = %v, want mtls", identity.Attributes["auth_method"])
	}

	if identity.Attributes["cert_serial"] == "" {
		t.Error("cert_serial should not be empty")
	}

	if identity.Attributes["peer_addr"] == "" {
		t.Error("peer_addr should not be empty")
	}
}

func TestMTLSAuthenticator_AuthenticateGRPC_NoPeerInfo(t *testing.T) {
	auth := NewMTLSAuthenticator(nil)

	ctx := context.Background()
	md := metadata.New(map[string]string{})

	identity, err := auth.AuthenticateGRPC(ctx, md)

	if err == nil {
		t.Fatal("AuthenticateGRPC() should return error for no peer info")
	}

	if identity != nil {
		t.Errorf("AuthenticateGRPC() returned identity %v, want nil", identity)
	}

	if err.Error() != "no peer information in context" {
		t.Errorf("error = %v, want 'no peer information in context'", err)
	}
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

	if err == nil {
		t.Fatal("AuthenticateGRPC() should return error for no TLS info")
	}

	if identity != nil {
		t.Errorf("AuthenticateGRPC() returned identity %v, want nil", identity)
	}

	if err.Error() != "no TLS information in peer" {
		t.Errorf("error = %v, want 'no TLS information in peer'", err)
	}
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

	if err == nil {
		t.Fatal("AuthenticateGRPC() should return error for no peer certificates")
	}

	if identity != nil {
		t.Errorf("AuthenticateGRPC() returned identity %v, want nil", identity)
	}

	if err.Error() != "no client certificate provided" {
		t.Errorf("error = %v, want 'no client certificate provided'", err)
	}
}

func TestMTLSAuthenticator_Name(t *testing.T) {
	auth := NewMTLSAuthenticator(nil)

	name := auth.Name()

	if name != "mtls" {
		t.Errorf("Name() = %v, want mtls", name)
	}
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

			if result != tt.expected {
				t.Errorf("defaultExtractSubject() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestDefaultExtractClaims(t *testing.T) {
	ca, err := testutil.GenerateTestCA()
	if err != nil {
		t.Fatalf("Failed to generate CA: %v", err)
	}

	clientCert, err := testutil.GenerateTestClientCert(ca, "test-client")
	if err != nil {
		t.Fatalf("Failed to generate client cert: %v", err)
	}

	claims := defaultExtractClaims(clientCert.Cert)

	if claims == nil {
		t.Fatal("defaultExtractClaims() returned nil")
	}

	if claims["common_name"] != "test-client" {
		t.Errorf("common_name = %v, want test-client", claims["common_name"])
	}

	// Check that organization is present
	if org, ok := claims["organization"]; ok {
		if orgSlice, ok := org.([]string); ok {
			if len(orgSlice) != 1 || orgSlice[0] != "Test Client" {
				t.Errorf("organization = %v, want [Test Client]", orgSlice)
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
			if !found {
				t.Error("permissions should contain 'client_auth'")
			}
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

			if result != tt.expected {
				t.Errorf("keyUsageString(%v) = %v, want %v", tt.usage, result, tt.expected)
			}
		})
	}
}

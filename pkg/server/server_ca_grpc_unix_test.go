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

// server_ca_grpc_unix_test.go is the go-xkms#951 end-to-end regression test:
// it drives the real xkmsd composition root (New + Start) and proves a CA
// RPC over the Unix socket gRPC listener succeeds when a CA is configured
// and answers codes.Unavailable when none is. Before the fix, the gRPC
// service's CA servicer came from a package-level grpcinternal.SetCA global
// that startUnix never called, so this RPC answered Unavailable even with a
// fully configured CA.
package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/ca/provider"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// mockProviderCA implements pkg/ca/provider.CA, standing in for the real
// *ca.CA the composition root wires into XKMSService.SetCA during New. Using
// it here exercises the identical delegation chain production traffic uses:
// the gRPC handler forwards to *xkms.XKMSService, which forwards to this
// provider.CA.
type mockProviderCA struct {
	cert *x509.Certificate
}

func (m *mockProviderCA) CABundle() ([]byte, error)                 { return nil, nil }
func (m *mockProviderCA) CACertificate() (*x509.Certificate, error) { return m.cert, nil }
func (m *mockProviderCA) SignCSRRaw(context.Context, []byte, string, int) (*x509.Certificate, error) {
	return nil, nil
}
func (m *mockProviderCA) SignCSRWithSPIFFE(context.Context, []byte, string, int, string, string, string, string) (*x509.Certificate, error) {
	return nil, nil
}
func (m *mockProviderCA) IssueCertificateRaw(context.Context, string, string, []string, int, string, string, string) ([]byte, []byte, []byte, string, error) {
	return nil, nil, nil, "", nil
}
func (m *mockProviderCA) Revoke(context.Context, *big.Int, int) error { return nil }
func (m *mockProviderCA) CertificateTenant(context.Context, *big.Int) (string, error) {
	return "", nil
}
func (m *mockProviderCA) GenerateCRL(context.Context) ([]byte, error) { return nil, nil }
func (m *mockProviderCA) CRL(context.Context) ([]byte, error)         { return nil, nil }
func (m *mockProviderCA) IsRevoked(*big.Int) (bool, error)            { return false, nil }
func (m *mockProviderCA) Identity() string                            { return "mock-ca" }
func (m *mockProviderCA) IsInitialized() bool                         { return true }

var _ provider.CA = (*mockProviderCA)(nil)

// generateServerTestCACert creates a self-signed RSA CA certificate for the
// tests in this file.
func generateServerTestCACert(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(9),
		Subject:               pkix.Name{CommonName: "Unix E2E Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

// dialServerUnixGRPC opens a client connection to a Unix-socket gRPC
// listener started by the real composition root, waiting for the socket
// file to appear first.
func dialServerUnixGRPC(t *testing.T, socketPath string) *grpc.ClientConn {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(socketPath); err == nil {
			time.Sleep(100 * time.Millisecond)
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	conn, err := grpc.NewClient("unix://"+socketPath,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)
	return conn
}

// TestServer_UnixGRPC_GetCACertificate_NoCA verifies a CA RPC over the Unix
// socket gRPC listener answers codes.Unavailable when the server composed
// no CA (go-xkms#951).
func TestServer_UnixGRPC_GetCACertificate_NoCA(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	cfg := createMinimalConfig(t)
	cfg.Protocols.REST = false
	cfg.Protocols.GRPC = false
	cfg.Protocols.QUIC = false
	cfg.Protocols.MCP = false
	cfg.Metrics.Enabled = false

	server, err := New(cfg)
	require.NoError(t, err)

	require.NoError(t, server.Start())
	defer func() { _ = server.Shutdown() }()

	conn := dialServerUnixGRPC(t, cfg.Unix.SocketPath)
	defer func() { _ = conn.Close() }()
	client := pb.NewKeystoreServiceClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err = client.GetCACertificate(ctx, &pb.GetCACertificateRequest{})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	require.Equal(t, codes.Unavailable, st.Code())
}

// TestServer_UnixGRPC_GetCACertificate_WithCA verifies a CA RPC over the
// Unix socket gRPC listener succeeds through the real composition root
// (New + Start) when a CA is configured (go-xkms#951 regression: this used
// to answer Unavailable even with a CA configured, because startUnix never
// called the gRPC package's SetCA global).
func TestServer_UnixGRPC_GetCACertificate_WithCA(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	cfg := createMinimalConfig(t)
	cfg.Protocols.REST = false
	cfg.Protocols.GRPC = false
	cfg.Protocols.QUIC = false
	cfg.Protocols.MCP = false
	cfg.Metrics.Enabled = false

	server, err := New(cfg)
	require.NoError(t, err)

	// Wire a CA the same way real composition does: s.ca gates whether the
	// CA servicer is forwarded to the gRPC/REST transports, and
	// XKMSService.SetCA is the delegation target the transports actually
	// call through.
	cert := generateServerTestCACert(t)
	server.ca = &mockTrustedCA{initialized: true, caCert: cert}
	server.xkmsService.SetCA(&mockProviderCA{cert: cert})

	require.NoError(t, server.Start())
	defer func() { _ = server.Shutdown() }()

	conn := dialServerUnixGRPC(t, cfg.Unix.SocketPath)
	defer func() { _ = conn.Close() }()
	client := pb.NewKeystoreServiceClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := client.GetCACertificate(ctx, &pb.GetCACertificateRequest{})
	require.NoError(t, err)
	require.Equal(t, cert.SerialNumber.Text(16), resp.SerialNumber)
}

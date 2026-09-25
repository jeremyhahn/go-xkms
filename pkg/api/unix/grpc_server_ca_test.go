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

// grpc_server_ca_test.go proves the go-xkms#951 fix end to end through the
// real composition seam: GRPCConfig.CA reaches the keystore gRPC service's
// CA RPCs over the Unix socket. Before the fix, the CA servicer for those
// RPCs came from a package-level grpcinternal.SetCA global that no
// production composition root ever called, so GetCACertificate (and every
// other CA RPC) answered codes.Unavailable even when GRPCConfig.XKMSService
// carried a fully configured CA.
package unix

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// mockCAServicer implements the transport-shaped GetCACertificate method the
// keystore gRPC service's CA handlers duck-type against
// (grpcCAMethodCert in pkg/api/grpc/service_ca.go). It stands in for the
// real *xkms.XKMSService the composition root forwards as GRPCConfig.CA.
type mockCAServicer struct {
	cert *x509.Certificate
}

func (m *mockCAServicer) GetCACertificate(_ context.Context, _ *transport.GetCACertificateRequest) (*transport.GetCACertificateResponse, error) {
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: m.cert.Raw})
	return &transport.GetCACertificateResponse{
		CertificatePEM: certPEM,
		Subject:        m.cert.Subject.String(),
		Issuer:         m.cert.Issuer.String(),
		SerialNumber:   m.cert.SerialNumber.Text(16),
		IsCA:           m.cert.IsCA,
	}, nil
}

// generateUnixTestCACert creates a self-signed ECDSA CA certificate for
// CA-RPC tests in this file.
func generateUnixTestCACert(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(7),
		Subject:               pkix.Name{CommonName: "Unix Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}
	return cert
}

// dialUnixGRPC opens a client connection to the Unix-socket gRPC listener at
// socketPath. The caller closes the returned connection.
func dialUnixGRPC(t *testing.T, socketPath string) *grpc.ClientConn {
	t.Helper()
	conn, err := grpc.NewClient("unix://"+socketPath,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("failed to connect to gRPC server: %v", err)
	}
	return conn
}

// waitForCASocket blocks until socketPath exists or the test fails on
// timeout, then gives the listener a short grace period to finish
// registering its services.
func waitForCASocket(t *testing.T, socketPath string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(socketPath); err == nil {
			time.Sleep(100 * time.Millisecond)
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("socket file never appeared")
}

// TestGRPCServer_GetCACertificate_NoCA verifies a CA RPC over the Unix
// socket returns codes.Unavailable when GRPCConfig.CA is unset.
func TestGRPCServer_GetCACertificate_NoCA(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "ca-none.sock")

	server, err := NewGRPCServer(&GRPCConfig{SocketPath: socketPath})
	if err != nil {
		t.Fatalf("NewGRPCServer() error = %v", err)
	}

	go func() { _ = server.Start() }()
	waitForCASocket(t, socketPath)

	conn := dialUnixGRPC(t, socketPath)
	defer func() { _ = conn.Close() }()
	client := pb.NewKeystoreServiceClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err = client.GetCACertificate(ctx, &pb.GetCACertificateRequest{})
	if err == nil {
		t.Fatal("expected error when no CA is configured")
	}
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got %v", err)
	}
	if st.Code() != codes.Unavailable {
		t.Errorf("expected codes.Unavailable, got %v: %s", st.Code(), st.Message())
	}

	_ = server.Stop(context.Background())
}

// TestGRPCServer_GetCACertificate_WithCA verifies a CA RPC over the Unix
// socket succeeds when GRPCConfig.CA is wired (go-xkms#951 regression: the
// old package-level grpcinternal.SetCA global was never called by this
// listener, so this RPC answered Unavailable even with a CA configured).
func TestGRPCServer_GetCACertificate_WithCA(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "ca-configured.sock")
	cert := generateUnixTestCACert(t)

	server, err := NewGRPCServer(&GRPCConfig{
		SocketPath: socketPath,
		CA:         &mockCAServicer{cert: cert},
	})
	if err != nil {
		t.Fatalf("NewGRPCServer() error = %v", err)
	}

	go func() { _ = server.Start() }()
	waitForCASocket(t, socketPath)

	conn := dialUnixGRPC(t, socketPath)
	defer func() { _ = conn.Close() }()
	client := pb.NewKeystoreServiceClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := client.GetCACertificate(ctx, &pb.GetCACertificateRequest{})
	if err != nil {
		t.Fatalf("GetCACertificate RPC failed: %v", err)
	}
	if resp.SerialNumber != cert.SerialNumber.Text(16) {
		t.Errorf("expected serial %s, got %s", cert.SerialNumber.Text(16), resp.SerialNumber)
	}
	if resp.Subject == "" {
		t.Error("expected non-empty subject")
	}

	_ = server.Stop(context.Background())
}

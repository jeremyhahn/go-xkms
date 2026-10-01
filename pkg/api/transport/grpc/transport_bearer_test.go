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

package grpc

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
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// authRecordingServer records the authorization metadata of each Health
// call.
type authRecordingServer struct {
	pb.UnimplementedKeystoreServiceServer
	mu   sync.Mutex
	auth []string
}

func (s *authRecordingServer) Health(ctx context.Context, _ *pb.HealthRequest) (*pb.HealthResponse, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	s.mu.Lock()
	s.auth = append(s.auth, md.Get("authorization")...)
	s.mu.Unlock()
	return &pb.HealthResponse{Status: "ok"}, nil
}

// tlsServer serves srv over TLS on a loopback port with a self-signed
// certificate, and returns its address and a pool trusting it.
func tlsServer(t *testing.T, srv pb.KeystoreServiceServer) (string, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "localhost"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	pool := x509.NewCertPool()
	pool.AddCert(leaf)

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	server := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		MinVersion:   tls.VersionTLS13,
	})))
	pb.RegisterKeystoreServiceServer(server, srv)
	go func() {
		if serveErr := server.Serve(lis); serveErr != nil {
			return
		}
	}()
	t.Cleanup(server.Stop)
	return lis.Addr().String(), pool
}

// TestConnect_UsesCallerTLSConfigAndBearerToken proves the two settings a
// caller hands the SDK in memory reach the wire: the caller-built tls.Config
// verifies the server (a CA bundle the system pool does not hold), and the
// JWT rides every RPC as bearer metadata.
func TestConnect_UsesCallerTLSConfigAndBearerToken(t *testing.T) {
	srv := &authRecordingServer{}
	addr, pool := tlsServer(t, srv)

	tr, err := New(transport.WithAddress(addr),
		transport.WithTLSConfig(&tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}),
		transport.WithJWTToken("tok-123"))
	require.NoError(t, err)
	require.NoError(t, tr.Connect(context.Background()))
	t.Cleanup(func() { assert.NoError(t, tr.Close()) })

	srv.mu.Lock()
	defer srv.mu.Unlock()
	assert.Equal(t, []string{"Bearer tok-123"}, srv.auth)
}

// TestConnect_NoTokenSendsNoAuthorization proves no authorization metadata
// is invented when no token is configured.
func TestConnect_NoTokenSendsNoAuthorization(t *testing.T) {
	srv := &authRecordingServer{}
	addr, pool := tlsServer(t, srv)

	tr, err := New(transport.WithAddress(addr), transport.WithTLSConfig(&tls.Config{RootCAs: pool}))
	require.NoError(t, err)
	require.NoError(t, tr.Connect(context.Background()))
	t.Cleanup(func() { assert.NoError(t, tr.Close()) })

	srv.mu.Lock()
	defer srv.mu.Unlock()
	assert.Empty(t, srv.auth)
}

// TestConnect_UntrustedServerIsRefused proves the caller's tls.Config is
// enforced, not bypassed: a pool without the server's certificate fails.
func TestConnect_UntrustedServerIsRefused(t *testing.T) {
	addr, _ := tlsServer(t, &authRecordingServer{})
	tr, err := New(transport.WithAddress(addr), transport.WithTLSConfig(&tls.Config{RootCAs: x509.NewCertPool()}))
	require.NoError(t, err)
	assert.Error(t, tr.Connect(context.Background()))
}

func TestBearerCredentials(t *testing.T) {
	md, err := bearerCredentials{token: "t"}.GetRequestMetadata(context.Background())
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"authorization": "Bearer t"}, md)
	assert.True(t, bearerCredentials{}.RequireTransportSecurity(), "a bearer token never crosses plaintext")
}

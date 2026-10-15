// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

package ssh_test

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
	"path/filepath"
	"sync"
	"testing"
	"time"

	googlegrpc "google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"

	apigrpc "github.com/jeremyhahn/go-xkms/pkg/api/grpc"
	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// authRecorder records the authorization metadata of every RPC.
type authRecorder struct {
	mu   sync.Mutex
	seen []string
}

func (r *authRecorder) intercept(ctx context.Context, req any, _ *googlegrpc.UnaryServerInfo, handler googlegrpc.UnaryHandler) (any, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	r.mu.Lock()
	r.seen = append(r.seen, md.Get("authorization")...)
	r.mu.Unlock()
	return handler(ctx, req)
}

func (r *authRecorder) values() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.seen...)
}

// serveSSHKeystore serves the real KeystoreService SSH RPCs on lis with the
// given server options, recording each RPC's authorization metadata.
func serveSSHKeystore(t *testing.T, lis net.Listener, opts ...googlegrpc.ServerOption) *authRecorder {
	t.Helper()
	embedded, err := sdkssh.NewEmbedded(sdkssh.EmbeddedOptions{Stores: newStores(t)})
	if err != nil {
		t.Fatalf("NewEmbedded: %v", err)
	}
	svc := apigrpc.NewService(nil, nil, nil)
	svc.SetSSHClient(embedded)

	rec := &authRecorder{}
	srv := googlegrpc.NewServer(append(opts, googlegrpc.UnaryInterceptor(rec.intercept))...)
	pb.RegisterKeystoreServiceServer(srv, svc)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = srv.Serve(lis)
	}()
	t.Cleanup(func() {
		srv.Stop()
		<-done
		_ = embedded.Close()
	})
	return rec
}

func listKeys(t *testing.T, client sdkssh.Client) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := client.Keys().List(ctx, sdkssh.ListKeysRequest{Scope: "user", Owner: "alice"}); err != nil {
		t.Fatalf("List: %v", err)
	}
}

// serveUnixTLS serves the SSH keystore over TLS on a Unix socket, as xkmsd's
// qrdb node listener does, and returns the socket URL and the root that
// verifies it.
func serveUnixTLS(t *testing.T) (string, *x509.CertPool, *authRecorder) {
	t.Helper()
	cert, pool := selfSignedLoopbackCert(t)
	sock := filepath.Join(t.TempDir(), "xkms.sock")
	lis, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	rec := serveSSHKeystore(t, lis, googlegrpc.Creds(credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13,
	})))
	return "unix://" + sock, pool, rec
}

// TestNewClientForServerWith_UnixPresentsToken proves the socket is dialed
// over TLS with the caller's tls.Config and the bearer token rides it.
func TestNewClientForServerWith_UnixPresentsToken(t *testing.T) {
	server, pool, rec := serveUnixTLS(t)

	client, err := sdkssh.NewClientForServerWith(server, sdkssh.ServerOptions{
		TLSConfig: &tls.Config{RootCAs: pool, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS13},
		Token:     "tok-unix",
	})
	if err != nil {
		t.Fatalf("NewClientForServerWith: %v", err)
	}
	defer func() { _ = client.Close() }()
	listKeys(t, client)

	if got := rec.values(); len(got) != 1 || got[0] != "Bearer tok-unix" {
		t.Fatalf("authorization = %v, want [Bearer tok-unix]", got)
	}
}

// TestNewClientForServerWith_UnixUntrustedRefused proves the socket's TLS is
// enforced: a pool without the node's root fails.
func TestNewClientForServerWith_UnixUntrustedRefused(t *testing.T) {
	server, _, _ := serveUnixTLS(t)

	client, err := sdkssh.NewClientForServerWith(server, sdkssh.ServerOptions{
		TLSConfig: &tls.Config{RootCAs: x509.NewCertPool(), ServerName: "127.0.0.1", MinVersion: tls.VersionTLS13},
	})
	if err != nil {
		t.Fatalf("NewClientForServerWith: %v", err)
	}
	defer func() { _ = client.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := client.Keys().List(ctx, sdkssh.ListKeysRequest{Scope: "user", Owner: "alice"}); err == nil {
		t.Fatal("an untrusted socket must be refused")
	}
}

// TestNewClientForServerWith_GRPCSUsesCallerTLSConfig proves a caller-built
// tls.Config (here, a private root the system pool does not hold) verifies
// the server, and the token rides the TLS channel.
func TestNewClientForServerWith_GRPCSUsesCallerTLSConfig(t *testing.T) {
	cert, pool := selfSignedLoopbackCert(t)
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	rec := serveSSHKeystore(t, lis, googlegrpc.Creds(credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13,
	})))

	client, err := sdkssh.NewClientForServerWith("grpcs://"+lis.Addr().String(), sdkssh.ServerOptions{
		TLSConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13},
		Token:     "tok-grpcs",
	})
	if err != nil {
		t.Fatalf("NewClientForServerWith: %v", err)
	}
	defer func() { _ = client.Close() }()
	listKeys(t, client)

	if got := rec.values(); len(got) != 1 || got[0] != "Bearer tok-grpcs" {
		t.Fatalf("authorization = %v, want [Bearer tok-grpcs]", got)
	}
}

// TestNewClientForServerWith_UntrustedServerRefused proves the caller's
// tls.Config is enforced: a pool without the server's root fails.
func TestNewClientForServerWith_UntrustedServerRefused(t *testing.T) {
	cert, _ := selfSignedLoopbackCert(t)
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	serveSSHKeystore(t, lis, googlegrpc.Creds(credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13,
	})))

	client, err := sdkssh.NewClientForServerWith("grpcs://"+lis.Addr().String(), sdkssh.ServerOptions{
		TLSConfig: &tls.Config{RootCAs: x509.NewCertPool(), MinVersion: tls.VersionTLS13},
	})
	if err != nil {
		t.Fatalf("NewClientForServerWith: %v", err)
	}
	defer func() { _ = client.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := client.Keys().List(ctx, sdkssh.ListKeysRequest{Scope: "user", Owner: "alice"}); err == nil {
		t.Fatal("an untrusted server must be refused")
	}
}

// TestNewClientForServerWith_MCPPresentsToken proves the bearer token rides
// the MCP transport's HTTP requests.
func TestNewClientForServerWith_MCPPresentsToken(t *testing.T) {
	srv := newFakeMCPServer(t)
	client, err := sdkssh.NewClientForServerWith("mcp://"+srv.addr(), sdkssh.ServerOptions{Token: "tok-mcp"})
	if err != nil {
		t.Fatalf("NewClientForServerWith: %v", err)
	}
	defer func() { _ = client.Close() }()

	srv.mu.Lock()
	defer srv.mu.Unlock()
	if len(srv.auth) == 0 {
		t.Fatal("no request reached the server")
	}
	for _, a := range srv.auth {
		if a != "Bearer tok-mcp" {
			t.Fatalf("authorization = %q, want Bearer tok-mcp", a)
		}
	}
}

// TestNewClientForServerWith_EmptyServerRefused proves the required server
// is checked.
func TestNewClientForServerWith_EmptyServerRefused(t *testing.T) {
	if _, err := sdkssh.NewClientForServerWith("", sdkssh.ServerOptions{}); err == nil {
		t.Fatal("an empty server must be refused")
	}
}

// selfSignedLoopbackCert returns a self-signed 127.0.0.1 server certificate
// and a pool trusting it.
func selfSignedLoopbackCert(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pool
}

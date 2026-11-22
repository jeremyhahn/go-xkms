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
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	googlegrpc "google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
	"github.com/jeremyhahn/go-xkms/sdk/go/internal/testsupport"
)

// clientCredential is an mTLS client certificate and key written to PEM
// files, and the pool a server verifies it with.
type clientCredential struct {
	certFile, keyFile string
	pool              *x509.CertPool
}

// writeClientCredential writes a self-signed client-auth certificate and its
// key to dir.
func writeClientCredential(t *testing.T, dir, cn string) clientCredential {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	cred := clientCredential{
		certFile: filepath.Join(dir, cn+"-cert.pem"),
		keyFile:  filepath.Join(dir, cn+"-key.pem"),
		pool:     x509.NewCertPool(),
	}
	cred.pool.AddCert(leaf)
	if err := os.WriteFile(cred.certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(cred.keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return cred
}

// mtlsServerConfig is a server tls.Config that refuses a handshake without a
// client certificate verified by clients.
func mtlsServerConfig(cert tls.Certificate, clients *x509.CertPool) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clients,
		MinVersion:   tls.VersionTLS13,
	}
}

func listKeysErr(client sdkssh.Client) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := client.Keys().List(ctx, sdkssh.ListKeysRequest{Scope: "user", Owner: "alice"})
	return err
}

// TestNewClientForServerWith_ClientCertificateOnGRPCTransports proves the
// TLSCertFile/TLSKeyFile option presents the client certificate on the gRPC
// transports (grpcs and the unix TLS socket) to a server that requires and
// verifies one, and that the same server refuses a client without it.
func TestNewClientForServerWith_ClientCertificateOnGRPCTransports(t *testing.T) {
	cred := writeClientCredential(t, t.TempDir(), "admin")
	serverCert, serverPool := selfSignedLoopbackCert(t)

	listeners := map[string]func(t *testing.T) (net.Listener, string){
		"grpcs": func(t *testing.T) (net.Listener, string) {
			lis, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("listen: %v", err)
			}
			return lis, "grpcs://" + lis.Addr().String()
		},
		"unix": func(t *testing.T) (net.Listener, string) {
			sock := filepath.Join(testsupport.SocketDir(t), "xkms.sock")
			lis, err := net.Listen("unix", sock)
			if err != nil {
				t.Fatalf("listen: %v", err)
			}
			return lis, "unix://" + sock
		},
	}
	for name, listen := range listeners {
		t.Run(name, func(t *testing.T) {
			lis, server := listen(t)
			serveSSHKeystore(t, lis, googlegrpc.Creds(credentials.NewTLS(mtlsServerConfig(serverCert, cred.pool))))

			with, err := sdkssh.NewClientForServerWith(server, sdkssh.ServerOptions{
				TLSConfig:   &tls.Config{RootCAs: serverPool, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS13},
				TLSCertFile: cred.certFile,
				TLSKeyFile:  cred.keyFile,
			})
			if err != nil {
				t.Fatalf("NewClientForServerWith: %v", err)
			}
			defer func() { _ = with.Close() }()
			if err := listKeysErr(with); err != nil {
				t.Fatalf("List with the client certificate: %v", err)
			}

			without, err := sdkssh.NewClientForServerWith(server, sdkssh.ServerOptions{
				TLSConfig: &tls.Config{RootCAs: serverPool, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS13},
			})
			if err != nil {
				t.Fatalf("NewClientForServerWith: %v", err)
			}
			defer func() { _ = without.Close() }()
			if err := listKeysErr(without); err == nil {
				t.Fatal("a client without a certificate must be refused")
			}
		})
	}
}

// TestNewClientForServerWith_ClientCertificateOnREST proves the option
// presents the client certificate on the https transport: the server sees it.
func TestNewClientForServerWith_ClientCertificateOnREST(t *testing.T) {
	cred := writeClientCredential(t, t.TempDir(), "admin")
	serverCert, serverPool := selfSignedLoopbackCert(t)

	var (
		mu   sync.Mutex
		seen []string
	)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		for _, c := range r.TLS.PeerCertificates {
			seen = append(seen, c.Subject.CommonName)
		}
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"keys":[]}`))
	}))
	srv.TLS = mtlsServerConfig(serverCert, cred.pool)
	srv.StartTLS()
	t.Cleanup(srv.Close)

	client, err := sdkssh.NewClientForServerWith(srv.URL, sdkssh.ServerOptions{
		TLSConfig:   &tls.Config{RootCAs: serverPool, MinVersion: tls.VersionTLS13},
		TLSCertFile: cred.certFile,
		TLSKeyFile:  cred.keyFile,
	})
	if err != nil {
		t.Fatalf("NewClientForServerWith: %v", err)
	}
	defer func() { _ = client.Close() }()
	_ = listKeysErr(client)

	mu.Lock()
	defer mu.Unlock()
	if len(seen) == 0 || seen[0] != "admin" {
		t.Fatalf("server saw client certificates %v, want [admin]", seen)
	}
}

// TestNewClientForServerWith_ClientCertificateRefusals proves a half pair, an
// unreadable file and a mismatched pair are refused with a typed error when
// the client is constructed, before any connection (the server address is
// never dialed).
func TestNewClientForServerWith_ClientCertificateRefusals(t *testing.T) {
	dir := t.TempDir()
	a := writeClientCredential(t, dir, "a")
	b := writeClientCredential(t, dir, "b")
	missing := filepath.Join(dir, "missing.pem")

	cases := map[string]struct {
		cert, key string
		nilInput  bool
	}{
		"key without cert": {key: a.keyFile, nilInput: true},
		"cert without key": {cert: a.certFile, nilInput: true},
		"unreadable cert":  {cert: missing, key: a.keyFile},
		"unreadable key":   {cert: a.certFile, key: missing},
		"mismatched pair":  {cert: a.certFile, key: b.keyFile},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			for _, server := range []string{"grpcs://127.0.0.1:1", "https://127.0.0.1:1", "unix:///nonexistent.sock", "quic://127.0.0.1:1", "mcps://127.0.0.1:1"} {
				_, err := sdkssh.NewClientForServerWith(server, sdkssh.ServerOptions{TLSCertFile: tc.cert, TLSKeyFile: tc.key})
				if err == nil {
					t.Fatalf("%s: expected a refusal", server)
				}
				var nilErr *sdkssh.NilInputError
				var protoErr *sdkssh.ProtocolError
				switch {
				case tc.nilInput && !errors.As(err, &nilErr):
					t.Fatalf("%s: got %T %v, want *NilInputError", server, err, err)
				case !tc.nilInput && !errors.As(err, &protoErr):
					t.Fatalf("%s: got %T %v, want *ProtocolError", server, err, err)
				}
			}
		})
	}
}

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

package cmd

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"

	restapi "github.com/jeremyhahn/go-xkms/pkg/api/rest"
	unixapi "github.com/jeremyhahn/go-xkms/pkg/api/unix"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/backend/software"
	pkgca "github.com/jeremyhahn/go-xkms/pkg/ca"
	"github.com/jeremyhahn/go-xkms/pkg/ca/provider"
	"github.com/jeremyhahn/go-xkms/pkg/certstore"
	"github.com/jeremyhahn/go-xkms/pkg/crypto/spki"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	pkgxkms "github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// testOperatorAuthenticator is a minimal, real implementation of
// auth.Authenticator (the same interface auth.NewNoOpAuthenticator
// satisfies) that authenticates every caller as carrying the "operator"
// role. It stands in for the mTLS/JWT identity a real client would present;
// pkg/auth's own NoOpAuthenticator deliberately returns a role-less
// "anonymous" identity, which XKMSService.SignCSR's RBAC gate (see
// pkg/xkms/servicer_ca.go's "CSR signing denied" check) correctly refuses,
// so a REST harness that wants to reach SignCSR's success path needs an
// authenticator that actually grants a role -- there is no exported
// production authenticator that does this without a real credential.
type testOperatorAuthenticator struct{}

func (testOperatorAuthenticator) AuthenticateHTTP(*http.Request) (*auth.Identity, error) {
	return &auth.Identity{Subject: "xkey-harness-operator", TenantID: "system", Roles: []string{"operator"}}, nil
}

func (testOperatorAuthenticator) AuthenticateGRPC(context.Context, metadata.MD) (*auth.Identity, error) {
	return &auth.Identity{Subject: "xkey-harness-operator", TenantID: "system", Roles: []string{"operator"}}, nil
}

func (testOperatorAuthenticator) Name() string { return "xkey-test-operator" }

// This file builds a real, in-process xkmsd for the ca and cert command
// tests to talk to. It is not a mock: every component (the software key
// backend, the certstore, the TrustedCA, the XKMSService, and the REST/gRPC
// transports) is the exact production type the real xkmsd binary composes;
// only the composition root (normally cmd/xkmsd / pkg/server) is replaced by
// this test file, exactly the way pkg/ca's own setupTestCA and
// pkg/apimodule's newModuleRESTServer test helpers build the same real
// stack for their in-process tests.

// testXKMSdQuietLogger discards server-side logging so `go test -v` output
// stays readable; failures are still visible through the client-observed
// errors the tests assert on.
func testXKMSdQuietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// newTestXKMSService builds a real *pkgxkms.XKMSService backed by a real,
// initialized TrustedCA (software key backend, in-memory storage) — the same
// construction pkg/ca/service_adapter_test.go:setupTestCA uses internally,
// reassembled here from the same exported production constructors because
// setupTestCA itself lives in a _test.go file pkg/ca does not export.
func newTestXKMSService(t *testing.T) *pkgxkms.XKMSService {
	t.Helper()

	swBackend, err := software.NewBackend(&software.Config{KeyStorage: storage.NewMemory()})
	require.NoError(t, err)

	backend, err := pkgxkms.New(&pkgxkms.BackendConfig{
		Backend:     swBackend,
		CertStorage: storage.NewMemory(),
	})
	require.NoError(t, err)

	certAdapter := storage.NewCertAdapter(storage.NewMemory())
	certStore, err := certstore.New(&certstore.Config{CertStorage: certAdapter})
	require.NoError(t, err)

	config := pkgca.DefaultMultiIdentityCAConfig()
	config.Identity[0].Subject.CommonName = "xkey harness root CA"
	config.Identity[0].Subject.Organization = "xkey"
	config.Identity[0].Keys[0].KeyType = "CA"

	caIface, err := pkgca.NewFromMultiIdentityConfig(&pkgca.MultiIdentityParams{
		Config:   config,
		KeyStore: backend,
		BackendForStore: func(string, types.StoreType) (pkgxkms.Backend, error) {
			return backend, nil
		},
		RevocationStore: storage.NewMemory(),
		CertStore:       certStore,
	})
	require.NoError(t, err)
	require.NoError(t, caIface.Init(context.Background()))

	caProvider, ok := caIface.(provider.CA)
	require.True(t, ok, "test CA must implement provider.CA, same as pkg/server's production wiring")

	svc := &pkgxkms.XKMSService{}
	svc.SetCA(caProvider)
	return svc
}

// startTestXKMSd starts a real xkmsd gRPC service on a Unix domain socket
// inside t.TempDir(), using pkg/api/unix.NewGRPCServer — the exact listener
// cmd/xkmsd binds in production. It returns the "unix://" address xkey's own
// connectXKMSdClient dispatch table expects and a cleanup func that stops the
// server; cleanup also runs automatically via t.Cleanup.
//
// The CA is supplied through unix.GRPCConfig.CA, the same per-Service
// wiring pkg/server's startUnix uses in production (go-xkms#951).
func startTestXKMSd(t *testing.T) (address string, cleanup func()) {
	t.Helper()

	svc := newTestXKMSService(t)

	// The unix gRPC server refuses a group- or world-writable socket
	// directory (#1299), so the socket lives in a private directory.
	socketPath := filepath.Join(privateTempDir(t), "xkmsd.sock")
	srv, err := unixapi.NewGRPCServer(&unixapi.GRPCConfig{
		SocketPath:  socketPath,
		XKMSService: svc,
		CA:          svc,
		Logger:      testXKMSdQuietLogger(),
	})
	require.NoError(t, err)

	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Start() }()

	waitForSocket(t, socketPath)

	stopped := false
	cleanup = func() {
		if stopped {
			return
		}
		stopped = true
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Stop(ctx)
		select {
		case <-serveErr:
		case <-time.After(5 * time.Second):
			t.Log("startTestXKMSd: server goroutine did not exit before cleanup timeout")
		}
	}
	t.Cleanup(cleanup)

	return "unix://" + socketPath, cleanup
}

// waitForSocket polls until the Unix socket file exists (or gives up),
// avoiding a race between the server goroutine's Start() and the client's
// first dial.
func waitForSocket(t *testing.T, path string) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("unix", path, 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("startTestXKMSd: socket %s did not become ready in time", path)
}

// startTestXKMSdREST starts a real xkmsd REST service over HTTPS on a
// loopback ephemeral port, using pkg/api/rest.NewServer — the same
// constructor pkg/apimodule's newModuleRESTServer test helper uses — wired
// with a self-signed server certificate. It returns the https:// base URL,
// the hex-encoded SPKI pin of that certificate (computed with the real
// pkg/crypto/spki.ComputePin, the same helper xkey's own trust-bootstrap
// commands use), and a cleanup func; cleanup also runs via t.Cleanup.
func startTestXKMSdREST(t *testing.T) (baseURL, spkiPin string) {
	t.Helper()

	svc := newTestXKMSService(t)

	cert, leaf := newTestServerCertificate(t)
	pin, err := spki.ComputePin(leaf)
	require.NoError(t, err)

	swBackend, err := software.NewBackend(&software.Config{KeyStorage: storage.NewMemory()})
	require.NoError(t, err)
	backend, err := pkgxkms.New(&pkgxkms.BackendConfig{
		Backend:     swBackend,
		CertStorage: storage.NewMemory(),
	})
	require.NoError(t, err)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	srv, err := restapi.NewServer(&restapi.Config{
		Authenticator: testOperatorAuthenticator{},
		Backends:      map[string]pkgxkms.Backend{"software": backend},
		XKMSService:   svc,
		CA:            svc,
		Listener:      listener,
		TLSConfig:     &tls.Config{Certificates: []tls.Certificate{cert}},
		Logger:        testXKMSdQuietLogger(),
	})
	require.NoError(t, err)

	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Start() }()

	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Stop(ctx)
		select {
		case <-serveErr:
		case <-time.After(5 * time.Second):
			t.Log("startTestXKMSdREST: server goroutine did not exit before cleanup timeout")
		}
	})

	return "https://" + listener.Addr().String(), pin
}

// newTestServerCertificate mints a real, self-signed ECDSA server
// certificate for 127.0.0.1, returning both the tls.Certificate the REST
// listener serves and the parsed leaf so the caller can pin its SPKI hash.
func newTestServerCertificate(t *testing.T) (tls.Certificate, *x509.Certificate) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	leaf, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)

	return tlsCert, leaf
}

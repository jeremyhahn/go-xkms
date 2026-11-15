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

//go:build integration

package signing

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	grpclib "google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	xkmsgrpc "github.com/jeremyhahn/go-xkms/pkg/api/grpc"
	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/api/rest"
	"github.com/jeremyhahn/go-xkms/pkg/api/rest/wire"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/appraisal"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/refvalue"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/releasesigningtest"
)

// signingKeyAppKey is the tenant key a repository binding names.
const signingKeyAppKey = "app-release"

// TestSigningKeyCLI_EveryTransport drives the xkmsctl key signing-key verbs
// (sign, set, get, list, resolve, delete) end to end against the signing-key
// service served over REST, gRPC and QUIC, and verifies each signed CoRIM
// with the public key of the key the repository resolves to.
func TestSigningKeyCLI_EveryTransport(t *testing.T) {
	bin := xkmsctlBinary(t)
	cert, caFile := loopbackCert(t)
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}}

	transports := []struct {
		name  string
		serve func(t *testing.T, f *releasesigningtest.Fixture) string
	}{
		{"rest", func(t *testing.T, f *releasesigningtest.Fixture) string {
			srv := httptest.NewUnstartedServer(signingKeyRouter(f))
			srv.TLS = tlsCfg
			srv.StartTLS()
			t.Cleanup(srv.Close)
			return srv.URL
		}},
		{"grpc", func(t *testing.T, f *releasesigningtest.Fixture) string {
			return "grpcs://" + serveSigningKeyGRPC(t, tlsCfg, f)
		}},
		{"quic", func(t *testing.T, f *releasesigningtest.Fixture) string {
			return "quic://" + serveSigningKeyHTTP3(t, tlsCfg, signingKeyRouter(f))
		}},
	}
	for _, tc := range transports {
		t.Run(tc.name, func(t *testing.T) {
			f := signingKeyFixture(t)
			appKey := generateAppKey(t, f)
			server := tc.serve(t, f)
			run := func(args ...string) string {
				t.Helper()
				full := append([]string{"--server", server, "--tls-ca", caFile, "-o", "json", "key", "signing-key"}, args...)
				cmd := exec.Command(bin, full...)
				cmd.Env = append(os.Environ(), "HOME="+t.TempDir())
				out, err := cmd.CombinedOutput()
				require.NoError(t, err, "xkmsctl %s: %s", strings.Join(args, " "), out)
				return string(out)
			}
			repo := releasesigningtest.Repository
			corimFile := filepath.Join(t.TempDir(), "corim.cbor")
			require.NoError(t, os.WriteFile(corimFile, releasesigningtest.UnsignedCoRIM(t), 0o600))

			res := decodeResolution(t, run("resolve", repo))
			assert.True(t, res.Default)
			assert.Equal(t, appraisal.ReleaseSigningKeyID, res.KeyID)
			signAndVerify(t, run, repo, corimFile, f.ReleaseKey)

			bound := decodeJSON[appraisal.SigningKeyBinding](t, run("set", repo, signingKeyAppKey, "--key-backend", "software"))
			assert.Equal(t, signingKeyAppKey, bound.KeyID)

			got := decodeJSON[appraisal.SigningKeyBinding](t, run("get", repo))
			assert.Equal(t, signingKeyAppKey, got.KeyID)
			assert.Equal(t, "software", got.Backend)

			list := decodeJSON[appraisal.ListSigningKeyBindingsResponse](t, run("list"))
			require.Len(t, list.Bindings, 1)
			assert.Equal(t, repo, list.Bindings[0].Repository)

			res = decodeResolution(t, run("resolve", repo))
			assert.False(t, res.Default)
			assert.Equal(t, signingKeyAppKey, res.KeyID)
			signAndVerify(t, run, repo, corimFile, appKey)

			run("delete", repo)
			res = decodeResolution(t, run("resolve", repo))
			assert.True(t, res.Default)
			assert.Equal(t, appraisal.ReleaseSigningKeyID, res.KeyID)
		})
	}
}

// signAndVerify signs the CoRIM through the CLI and verifies the signed
// CoRIM with pub, the public key of the key the repository resolves to.
func signAndVerify(t *testing.T, run func(args ...string) string, repo, corimFile string, pub crypto.PublicKey) {
	t.Helper()
	outFile := filepath.Join(t.TempDir(), "corim.signed.cbor")
	run("sign", repo, corimFile, "--out", outFile)
	signed, err := os.ReadFile(outFile)
	require.NoError(t, err)
	m, err := refvalue.VerifySigned(signed, refvalue.VerifyOptions{PublicKey: pub})
	require.NoError(t, err, "the signed CoRIM verifies with the resolved key")
	assert.Equal(t, repo, m.Signer)
}

func decodeResolution(t *testing.T, out string) appraisal.SigningKeyResolution {
	t.Helper()
	return decodeJSON[appraisal.SigningKeyResolution](t, out)
}

func decodeJSON[T any](t *testing.T, out string) T {
	t.Helper()
	var v T
	start := strings.IndexAny(out, "{[")
	require.GreaterOrEqual(t, start, 0, "no JSON in %q", out)
	require.NoError(t, json.Unmarshal([]byte(out[start:]), &v), "decode %q", out)
	return v
}

func signingKeyFixture(t *testing.T) *releasesigningtest.Fixture {
	t.Helper()
	perm := func(action string) string { return auth.ResourceAttestationSigningKeys + ":" + action }
	return releasesigningtest.New(t, releasesigningtest.Tenant, releasesigningtest.SignPermission,
		perm(auth.ActionGet), perm(auth.ActionList), perm(auth.ActionBind))
}

// generateAppKey makes the tenant key a binding names and returns its public key.
func generateAppKey(t *testing.T, f *releasesigningtest.Fixture) crypto.PublicKey {
	t.Helper()
	resp, err := f.Service.GenerateKey(context.Background(), &transport.GenerateKeyRequest{
		KeyID: signingKeyAppKey, Backend: "software", KeyType: "signing",
		Algorithm: "ecdsa", Curve: "P-256", TenantID: releasesigningtest.Tenant,
	})
	require.NoError(t, err)
	block, _ := pem.Decode([]byte(resp.PublicKeyPEM))
	require.NotNil(t, block)
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	require.NoError(t, err)
	return pub
}

// signingKeyRouter serves the REST signing-key handlers as the tenant's
// identity; QUIC serves the same router over HTTP/3.
func signingKeyRouter(f *releasesigningtest.Fixture) http.Handler {
	h := rest.NewSigningKeyHandlers(f.Service)
	identity := releasesigningtest.Identity(releasesigningtest.Tenant)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"healthy"}`))
	})
	mux.HandleFunc("PUT "+wire.SigningKeysPath, h.SetHandler)
	mux.HandleFunc("GET "+wire.SigningKeysPath, h.ListHandler)
	mux.HandleFunc("GET "+wire.SigningKeyBindingPath, h.GetHandler)
	mux.HandleFunc("DELETE "+wire.SigningKeyBindingPath, h.DeleteHandler)
	mux.HandleFunc("GET "+wire.SigningKeyResolvePath, h.ResolveHandler)
	mux.HandleFunc("POST "+wire.SigningKeySignPath, h.SignHandler)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mux.ServeHTTP(w, r.WithContext(auth.WithIdentity(r.Context(), identity)))
	})
}

// serveSigningKeyGRPC serves the gRPC keystore service over TLS as the
// tenant's identity and returns its address.
func serveSigningKeyGRPC(t *testing.T, tlsCfg *tls.Config, f *releasesigningtest.Fixture) string {
	t.Helper()
	identity := releasesigningtest.Identity(releasesigningtest.Tenant)
	srv := grpclib.NewServer(
		grpclib.Creds(credentials.NewTLS(tlsCfg)),
		grpclib.UnaryInterceptor(func(ctx context.Context, req any, _ *grpclib.UnaryServerInfo, next grpclib.UnaryHandler) (any, error) {
			return next(auth.WithIdentity(ctx, identity), req)
		}),
	)
	pb.RegisterKeystoreServiceServer(srv, xkmsgrpc.NewService(auth.NewAuthorizer(nil), nil, f.Service))
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	return lis.Addr().String()
}

func serveSigningKeyHTTP3(t *testing.T, tlsCfg *tls.Config, handler http.Handler) string {
	t.Helper()
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	require.NoError(t, err)
	srv := &http3.Server{TLSConfig: tlsCfg, Handler: handler}
	go func() { _ = srv.Serve(udpConn) }()
	t.Cleanup(func() {
		_ = srv.Close()
		_ = udpConn.Close()
	})
	addr, ok := udpConn.LocalAddr().(*net.UDPAddr)
	require.True(t, ok)
	return fmt.Sprintf("127.0.0.1:%d", addr.Port)
}

// loopbackCert makes a self-signed 127.0.0.1 server certificate and writes
// it as the CA file the CLI's --tls-ca reads.
func loopbackCert(t *testing.T) (tls.Certificate, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	caFile := filepath.Join(t.TempDir(), "ca.crt")
	require.NoError(t, os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600))
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, caFile
}

// xkmsctlBinary returns $KEYSTORE_CLI_BIN, as the CLI integration suites
// do, or builds xkmsctl with this test binary's build tags less integration.
func xkmsctlBinary(t *testing.T) string {
	t.Helper()
	if bin := os.Getenv("KEYSTORE_CLI_BIN"); bin != "" {
		return bin
	}
	var tags []string
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, s := range info.Settings {
			if s.Key != "-tags" {
				continue
			}
			for _, tag := range strings.Split(s.Value, ",") {
				if tag != "" && tag != "integration" {
					tags = append(tags, tag)
				}
			}
		}
	}
	_, here, _, ok := runtime.Caller(0)
	require.True(t, ok)
	root := filepath.Join(filepath.Dir(here), "..", "..", "..")
	bin := filepath.Join(t.TempDir(), "xkmsctl")
	cmd := exec.Command("go", "build", "-tags", strings.Join(tags, ","), "-o", bin, "./cmd/xkmsctl")
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "build xkmsctl: %s", out)
	return bin
}

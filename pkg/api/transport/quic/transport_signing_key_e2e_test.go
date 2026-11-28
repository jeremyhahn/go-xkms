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

package quic_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/rest"
	"github.com/jeremyhahn/go-xkms/pkg/api/rest/wire"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport/quic"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/appraisal"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/refvalue"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/releasesigningtest"
)

// TestSigningKeyQUIC_EndToEnd drives the signing-key service through the QUIC
// client transport against the REST signing-key handlers served over a real
// HTTP/3 listener: the default release key signs a CoRIM, and a repository
// binding is set, read, listed, resolved and deleted.
func TestSigningKeyQUIC_EndToEnd(t *testing.T) {
	perm := func(action string) string { return auth.ResourceAttestationSigningKeys + ":" + action }
	f := releasesigningtest.New(t, releasesigningtest.Tenant, releasesigningtest.SignPermission,
		perm(auth.ActionGet), perm(auth.ActionList), perm(auth.ActionBind))
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
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mux.ServeHTTP(w, r.WithContext(auth.WithIdentity(r.Context(), identity)))
	})

	cert, roots := selfSignedLoopbackCert(t)
	addr := serveHTTP3(t, &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}}, handler)

	cfg := transport.DefaultConfig()
	cfg.Address = addr
	cfg.TLSEnabled = true
	cfg.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}
	tr, err := quic.NewWithConfig(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = tr.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	require.NoError(t, tr.Connect(ctx))

	signed, err := tr.SignReleaseCoRIM(ctx, releasesigningtest.Request(releasesigningtest.UnsignedCoRIM(t)))
	require.NoError(t, err)
	assert.Equal(t, appraisal.ReleaseSigningKeyID, signed.KeyID)
	m, err := refvalue.VerifySigned(signed.SignedCoRIM, refvalue.VerifyOptions{PublicKey: f.ReleaseKey})
	require.NoError(t, err)
	assert.Equal(t, releasesigningtest.Repository, m.Signer)

	repo := releasesigningtest.Repository
	resolved, err := tr.ResolveSigningKey(ctx, &transport.ResolveSigningKeyRequest{Repository: repo})
	require.NoError(t, err)
	assert.True(t, resolved.Default)

	bound, err := tr.SetSigningKeyBinding(ctx, &transport.SetSigningKeyBindingRequest{Repository: repo, KeyID: "app-release"})
	require.NoError(t, err)
	assert.Equal(t, repo, bound.Repository)

	got, err := tr.GetSigningKeyBinding(ctx, &transport.GetSigningKeyBindingRequest{Repository: repo})
	require.NoError(t, err)
	assert.Equal(t, "app-release", got.KeyID)

	list, err := tr.ListSigningKeyBindings(ctx)
	require.NoError(t, err)
	require.Len(t, list.Bindings, 1)
	assert.Equal(t, repo, list.Bindings[0].Repository)

	resolved, err = tr.ResolveSigningKey(ctx, &transport.ResolveSigningKeyRequest{Repository: repo})
	require.NoError(t, err)
	assert.Equal(t, "app-release", resolved.KeyID)
	assert.False(t, resolved.Default)

	require.NoError(t, tr.DeleteSigningKeyBinding(ctx, &transport.DeleteSigningKeyBindingRequest{Repository: repo}))
	_, err = tr.GetSigningKeyBinding(ctx, &transport.GetSigningKeyBindingRequest{Repository: repo})
	require.Error(t, err, "the deleted binding is gone")

	resolved, err = tr.ResolveSigningKey(ctx, &transport.ResolveSigningKeyRequest{Repository: repo})
	require.NoError(t, err)
	assert.True(t, resolved.Default)
}

// serveHTTP3 runs handler behind an HTTP/3 listener on an ephemeral loopback
// UDP port for the test's lifetime and returns its host:port.
func serveHTTP3(t *testing.T, tlsConfig *tls.Config, handler http.Handler) string {
	t.Helper()
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	require.NoError(t, err)
	srv := &http3.Server{TLSConfig: tlsConfig, Handler: handler}
	go func() { _ = srv.Serve(udpConn) }()
	t.Cleanup(func() {
		_ = srv.Close()
		_ = udpConn.Close()
	})
	addr, ok := udpConn.LocalAddr().(*net.UDPAddr)
	require.True(t, ok)
	return fmt.Sprintf("127.0.0.1:%d", addr.Port)
}

// selfSignedLoopbackCert returns a server certificate for 127.0.0.1 and a
// pool that trusts it.
func selfSignedLoopbackCert(t *testing.T) (tls.Certificate, *x509.CertPool) {
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
	leaf, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}

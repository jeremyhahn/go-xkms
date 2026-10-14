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

package serverid

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// serverCert returns a self-signed localhost/127.0.0.1 certificate and a
// pool trusting it.
func serverCert(t *testing.T) (tls.Certificate, *x509.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "localhost"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		DNSNames:              []string{"localhost"},
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
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, leaf, pool
}

// tcpServer serves TLS handshakes with cert and returns its address.
func tcpServer(t *testing.T, cert tls.Certificate) string {
	t.Helper()
	lis, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13})
	require.NoError(t, err)
	t.Cleanup(func() { _ = lis.Close() })
	go func() {
		for {
			conn, err := lis.Accept()
			if err != nil {
				return
			}
			_ = conn.(*tls.Conn).Handshake()
			_ = conn.Close()
		}
	}()
	return lis.Addr().String()
}

func TestProbe_TCPSchemesReadTheLeafIdentity(t *testing.T) {
	cert, leaf, pool := serverCert(t)
	addr := tcpServer(t, cert)
	cfg := &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}

	for _, scheme := range []string{"https", "grpcs", "mcps"} {
		id, err := Probe(context.Background(), scheme+"://"+addr, cfg)
		require.NoError(t, err, scheme)
		assert.Equal(t, Of(leaf), id, scheme)
	}
}

func TestProbe_QUICReadsTheLeafIdentity(t *testing.T) {
	cert, leaf, pool := serverCert(t)
	lis, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert}, NextProtos: []string{"h3"}, MinVersion: tls.VersionTLS13,
	}, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = lis.Close() })
	go func() {
		for {
			conn, err := lis.Accept(context.Background())
			if err != nil {
				return
			}
			<-conn.Context().Done()
		}
	}()

	id, err := Probe(context.Background(), "quic://"+lis.Addr().String(), &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13})
	require.NoError(t, err)
	assert.Equal(t, Of(leaf), id)
}

func TestProbe_DifferentCertificateDifferentIdentity(t *testing.T) {
	certA, _, poolA := serverCert(t)
	certB, _, poolB := serverCert(t)
	addrA, addrB := tcpServer(t, certA), tcpServer(t, certB)

	idA, err := Probe(context.Background(), "https://"+addrA, &tls.Config{RootCAs: poolA, MinVersion: tls.VersionTLS13})
	require.NoError(t, err)
	idB, err := Probe(context.Background(), "https://"+addrB, &tls.Config{RootCAs: poolB, MinVersion: tls.VersionTLS13})
	require.NoError(t, err)
	assert.NotEqual(t, idA, idB, "two certificates on one host are two servers")
}

func TestProbe_UntrustedServerRefused(t *testing.T) {
	cert, _, _ := serverCert(t)
	addr := tcpServer(t, cert)
	_, err := Probe(context.Background(), "https://"+addr, &tls.Config{RootCAs: x509.NewCertPool(), MinVersion: tls.VersionTLS13})
	var probeErr *ProbeError
	assert.True(t, errors.As(err, &probeErr), "an unverifiable server yields no identity: %v", err)
}

func TestProbe_NoTLSSchemes(t *testing.T) {
	for _, u := range []string{"unix:///run/xkms.sock", "http://h:1", "grpc://h:1", "mcp://h:1"} {
		_, err := Probe(context.Background(), u, nil)
		assert.ErrorIs(t, err, ErrNoTLS, u)
	}
}

func TestProbe_BadURLs(t *testing.T) {
	_, err := Probe(context.Background(), "://bad", nil)
	var probeErr *ProbeError
	assert.True(t, errors.As(err, &probeErr))
	_, err = Probe(context.Background(), "https://", nil)
	assert.True(t, errors.As(err, &probeErr), "a URL without a host is refused")
}

// TestProbe_CancelledContextIsAProbeError proves a probe the caller has
// already cancelled fails on both transports, reports the URL it was asked
// about, and keeps the cancellation reachable through errors.Is. The URLs
// carry no port, so the scheme's default port is what gets dialled.
func TestProbe_CancelledContextIsAProbeError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	for _, rawURL := range []string{"https://127.0.0.1", "quic://127.0.0.1"} {
		_, err := Probe(ctx, rawURL, nil)
		var probeErr *ProbeError
		require.True(t, errors.As(err, &probeErr), "%s: %v", rawURL, err)
		assert.Equal(t, rawURL, probeErr.URL)
		assert.Contains(t, err.Error(), "serverid: identify "+rawURL)
		assert.ErrorIs(t, err, context.Canceled, "%s: the cause must survive Unwrap", rawURL)
	}
}

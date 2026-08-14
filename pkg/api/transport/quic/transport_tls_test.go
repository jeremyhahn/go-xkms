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

package quic

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
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/crypto/spki"
)

// ============================================================================
// End-to-end proof: a caller-supplied TLS config is actually presented
// ============================================================================

// TestConnect_PresentsCallerSuppliedClientCertificate is the regression test
// for the defect where the QUIC transport built its tls.Config from scratch and
// never consulted transport.Config.TLSConfig. A BackendConfig carrying a
// pre-built (e.g. PKCS#11-backed) mTLS config connected WITHOUT the client
// certificate and nothing errored, so mTLS authentication silently did not
// happen.
//
// It runs a real HTTP/3 listener that requests — but does not require — a
// client certificate, so the handshake completes either way and the assertion
// is about what the server actually observed.
func TestConnect_PresentsCallerSuppliedClientCertificate(t *testing.T) {
	ca := newTestCA(t)
	serverCert := ca.issue(t, "127.0.0.1", true)
	clientCert := ca.issue(t, "xkms-client", false)

	var peerCertCount atomic.Int64
	addr := startTestHTTP3Server(t, &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequestClientCert,
		ClientCAs:    ca.pool(),
	}, func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil {
			peerCertCount.Store(int64(len(r.TLS.PeerCertificates)))
		}
		writeHealthy(w)
	})

	cfg := transport.DefaultConfig()
	cfg.Address = addr
	cfg.TLSEnabled = true
	cfg.TLSConfig = &tls.Config{
		MinVersion:   tls.VersionTLS13,
		RootCAs:      ca.pool(),
		Certificates: []tls.Certificate{clientCert},
	}

	tr, err := NewWithConfig(cfg)
	require.NoError(t, err)
	defer func() { _ = tr.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	require.NoError(t, tr.Connect(ctx))

	assert.Positive(t, peerCertCount.Load(),
		"server saw no client certificate: the caller-supplied TLSConfig was dropped and mTLS did not happen")
}

// TestConnect_CallerClientCertWithCAFile isolates the client certificate from
// the trust anchors: the CA comes from TLSCAFile (which the pre-fix code did
// honor) while the client certificate comes only from the caller's TLSConfig
// (which the pre-fix code dropped). The handshake therefore succeeds either
// way, and the failure is precisely "the server saw no client certificate".
func TestConnect_CallerClientCertWithCAFile(t *testing.T) {
	ca := newTestCA(t)
	serverCert := ca.issue(t, "127.0.0.1", true)
	clientCert := ca.issue(t, "xkms-client", false)

	caPath := filepath.Join(t.TempDir(), "ca.pem")
	require.NoError(t, os.WriteFile(caPath, ca.certPEM, 0600))

	var peerCertCount atomic.Int64
	addr := startTestHTTP3Server(t, &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequestClientCert,
		ClientCAs:    ca.pool(),
	}, func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil {
			peerCertCount.Store(int64(len(r.TLS.PeerCertificates)))
		}
		writeHealthy(w)
	})

	cfg := transport.DefaultConfig()
	cfg.Address = addr
	cfg.TLSEnabled = true
	cfg.TLSCAFile = caPath
	cfg.TLSConfig = &tls.Config{
		MinVersion:   tls.VersionTLS13,
		RootCAs:      ca.pool(),
		Certificates: []tls.Certificate{clientCert},
	}

	tr, err := NewWithConfig(cfg)
	require.NoError(t, err)
	defer func() { _ = tr.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	require.NoError(t, tr.Connect(ctx))

	assert.Positive(t, peerCertCount.Load(),
		"server saw no client certificate: the caller-supplied TLSConfig was dropped and mTLS did not happen")
}

// TestConnect_CallerConfigSatisfiesRequiredClientAuth proves the presented
// certificate is not merely present but actually satisfies a server that
// REQUIRES and verifies client certificates. Without the caller's config the
// handshake is rejected outright.
func TestConnect_CallerConfigSatisfiesRequiredClientAuth(t *testing.T) {
	ca := newTestCA(t)
	serverCert := ca.issue(t, "127.0.0.1", true)
	clientCert := ca.issue(t, "xkms-client", false)

	addr := startTestHTTP3Server(t, &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    ca.pool(),
	}, func(w http.ResponseWriter, _ *http.Request) {
		writeHealthy(w)
	})

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	withCert := transport.DefaultConfig()
	withCert.Address = addr
	withCert.TLSEnabled = true
	withCert.TLSConfig = &tls.Config{
		MinVersion:   tls.VersionTLS13,
		RootCAs:      ca.pool(),
		Certificates: []tls.Certificate{clientCert},
	}

	tr, err := NewWithConfig(withCert)
	require.NoError(t, err)
	defer func() { _ = tr.Close() }()
	require.NoError(t, tr.Connect(ctx), "caller-supplied client certificate must satisfy mTLS")

	// The same server rejects a client that presents no certificate, which is
	// what the transport used to do with a caller-supplied config.
	withoutCert := transport.DefaultConfig()
	withoutCert.Address = addr
	withoutCert.TLSEnabled = true
	withoutCert.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: ca.pool()}

	anon, err := NewWithConfig(withoutCert)
	require.NoError(t, err)
	defer func() { _ = anon.Close() }()
	assert.Error(t, anon.Connect(ctx), "server must reject a client with no certificate")
}

// TestConnect_CallerGetClientCertificateIsInvoked covers the hardware-backed
// shape of the same defect: PKCS#11/TPM callers surface their signer through
// GetClientCertificate rather than Certificates.
func TestConnect_CallerGetClientCertificateIsInvoked(t *testing.T) {
	ca := newTestCA(t)
	serverCert := ca.issue(t, "127.0.0.1", true)
	clientCert := ca.issue(t, "xkms-hardware-client", false)

	var peerCertCount atomic.Int64
	addr := startTestHTTP3Server(t, &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequestClientCert,
		ClientCAs:    ca.pool(),
	}, func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil {
			peerCertCount.Store(int64(len(r.TLS.PeerCertificates)))
		}
		writeHealthy(w)
	})

	var callbackInvoked atomic.Bool
	cfg := transport.DefaultConfig()
	cfg.Address = addr
	cfg.TLSEnabled = true
	cfg.TLSConfig = &tls.Config{
		MinVersion: tls.VersionTLS13,
		RootCAs:    ca.pool(),
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			callbackInvoked.Store(true)
			return &clientCert, nil
		},
	}

	tr, err := NewWithConfig(cfg)
	require.NoError(t, err)
	defer func() { _ = tr.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	require.NoError(t, tr.Connect(ctx))

	assert.True(t, callbackInvoked.Load(), "caller GetClientCertificate callback must be invoked")
	assert.Positive(t, peerCertCount.Load(), "server saw no client certificate")
}

// ============================================================================
// buildTLSConfig — caller-supplied config semantics
// ============================================================================

func TestBuildTLSConfig_CallerConfigCarriesCertificates(t *testing.T) {
	ca := newTestCA(t)
	clientCert := ca.issue(t, "client", false)

	cfg := transport.DefaultConfig()
	cfg.TLSConfig = &tls.Config{
		MinVersion:   tls.VersionTLS13,
		RootCAs:      ca.pool(),
		Certificates: []tls.Certificate{clientCert},
		ServerName:   "xkms.example.com",
	}

	tr, err := NewWithConfig(cfg)
	require.NoError(t, err)

	built, err := tr.buildTLSConfig()
	require.NoError(t, err)
	require.Len(t, built.Certificates, 1, "caller certificate must survive")
	assert.Equal(t, clientCert.Certificate, built.Certificates[0].Certificate)
	assert.Equal(t, "xkms.example.com", built.ServerName)
	assert.Same(t, cfg.TLSConfig.RootCAs, built.RootCAs)
}

// TestBuildTLSConfig_CallerConfigTakesPrecedenceOverFiles pins the same
// precedence the REST, MCP and Unix transports use: a pre-built config wins
// over the TLSCertFile/TLSKeyFile/TLSCAFile fields.
func TestBuildTLSConfig_CallerConfigTakesPrecedenceOverFiles(t *testing.T) {
	ca := newTestCA(t)
	callerCert := ca.issue(t, "caller", false)
	fileCertPath, fileKeyPath := ca.writeKeyPair(t, "from-file")

	cfg := transport.DefaultConfig()
	cfg.TLSCertFile = fileCertPath
	cfg.TLSKeyFile = fileKeyPath
	cfg.TLSConfig = &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{callerCert},
	}

	tr, err := NewWithConfig(cfg)
	require.NoError(t, err)

	built, err := tr.buildTLSConfig()
	require.NoError(t, err)
	require.Len(t, built.Certificates, 1)
	assert.Equal(t, callerCert.Certificate, built.Certificates[0].Certificate,
		"caller-supplied TLSConfig must take precedence over the file-based fields")
}

// TestBuildTLSConfig_CallerMinVersionRaisedToTLS13 documents that QUIC mandates
// TLS 1.3 (RFC 9001 4.2), so a weaker caller floor is raised rather than
// silently accepted.
func TestBuildTLSConfig_CallerMinVersionRaisedToTLS13(t *testing.T) {
	for name, minVersion := range map[string]uint16{
		"unset":   0,
		"tls1.0":  tls.VersionTLS10,
		"tls1.2":  tls.VersionTLS12,
		"tls1.3":  tls.VersionTLS13,
		"unknown": 0x0300,
	} {
		t.Run(name, func(t *testing.T) {
			cfg := transport.DefaultConfig()
			cfg.TLSConfig = &tls.Config{MinVersion: minVersion} //nolint:gosec // deliberately weak input under test

			tr, err := NewWithConfig(cfg)
			require.NoError(t, err)

			built, err := tr.buildTLSConfig()
			require.NoError(t, err)
			assert.Equal(t, uint16(tls.VersionTLS13), built.MinVersion,
				"QUIC requires TLS 1.3; a weaker caller floor must be raised")
		})
	}
}

// TestBuildTLSConfig_DoesNotMutateCallerConfig ensures the caller's config
// object — which may be shared with other clients — is never modified.
func TestBuildTLSConfig_DoesNotMutateCallerConfig(t *testing.T) {
	callerConfig := &tls.Config{MinVersion: tls.VersionTLS12} //nolint:gosec // deliberately weak input under test

	cfg := transport.DefaultConfig()
	cfg.SPKIPin = "0000000000000000000000000000000000000000000000000000000000000000"
	cfg.TLSConfig = callerConfig

	tr, err := NewWithConfig(cfg)
	require.NoError(t, err)

	built, err := tr.buildTLSConfig()
	require.NoError(t, err)
	assert.NotSame(t, callerConfig, built, "the caller config must be cloned")
	assert.Equal(t, uint16(tls.VersionTLS12), callerConfig.MinVersion, "caller MinVersion must not be mutated")
	assert.Empty(t, callerConfig.NextProtos, "caller NextProtos must not be mutated")
	assert.Nil(t, callerConfig.VerifyConnection, "caller VerifyConnection must not be mutated")
}

func TestBuildTLSConfig_CallerConfigGetsHTTP3ALPN(t *testing.T) {
	cfg := transport.DefaultConfig()
	cfg.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS13}

	tr, err := NewWithConfig(cfg)
	require.NoError(t, err)

	built, err := tr.buildTLSConfig()
	require.NoError(t, err)
	assert.Equal(t, []string{"h3"}, built.NextProtos)
}

func TestBuildTLSConfig_CallerConfigKeepsExplicitALPN(t *testing.T) {
	cfg := transport.DefaultConfig()
	cfg.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{"h3-29"}}

	tr, err := NewWithConfig(cfg)
	require.NoError(t, err)

	built, err := tr.buildTLSConfig()
	require.NoError(t, err)
	assert.Equal(t, []string{"h3-29"}, built.NextProtos)
}

// ============================================================================
// buildTLSConfig — SPKI pin interaction with a caller-supplied config
// ============================================================================

// TestBuildTLSConfig_CallerConfigWithSPKIPinIsAdditive proves the pin is layered
// on top of the caller's config instead of replacing it. Replacing it (as the
// file-based bootstrap path does) would discard the client certificate and
// silently disable mTLS.
func TestBuildTLSConfig_CallerConfigWithSPKIPinIsAdditive(t *testing.T) {
	ca := newTestCA(t)
	clientCert := ca.issue(t, "client", false)
	peer := ca.issue(t, "server", true)
	peerLeaf, err := x509.ParseCertificate(peer.Certificate[0])
	require.NoError(t, err)

	pin, err := spki.ComputePin(peerLeaf)
	require.NoError(t, err)

	cfg := transport.DefaultConfig()
	cfg.SPKIPin = pin
	cfg.TLSConfig = &tls.Config{
		MinVersion:   tls.VersionTLS13,
		RootCAs:      ca.pool(),
		Certificates: []tls.Certificate{clientCert},
	}

	tr, err := NewWithConfig(cfg)
	require.NoError(t, err)

	built, err := tr.buildTLSConfig()
	require.NoError(t, err)
	require.Len(t, built.Certificates, 1, "the SPKI pin must not discard the caller's client certificate")
	assert.False(t, built.InsecureSkipVerify, "the caller's trust anchors must still be validated")
	require.NotNil(t, built.VerifyConnection)

	// The pin is genuinely enforced.
	require.NoError(t, built.VerifyConnection(tls.ConnectionState{PeerCertificates: []*x509.Certificate{peerLeaf}}))

	other := ca.issue(t, "impostor", true)
	otherLeaf, err := x509.ParseCertificate(other.Certificate[0])
	require.NoError(t, err)
	assert.Error(t, built.VerifyConnection(tls.ConnectionState{PeerCertificates: []*x509.Certificate{otherLeaf}}),
		"a mismatching peer key must fail the pin check")
}

// TestBuildTLSConfig_CallerVerifyConnectionIsPreserved ensures layering the pin
// does not silently drop verification the caller already installed.
func TestBuildTLSConfig_CallerVerifyConnectionIsPreserved(t *testing.T) {
	callerErr := errors.New("caller verification rejected the peer")

	var callerInvoked atomic.Bool
	cfg := transport.DefaultConfig()
	cfg.SPKIPin = "0000000000000000000000000000000000000000000000000000000000000000"
	cfg.TLSConfig = &tls.Config{
		MinVersion: tls.VersionTLS13,
		VerifyConnection: func(tls.ConnectionState) error {
			callerInvoked.Store(true)
			return callerErr
		},
	}

	tr, err := NewWithConfig(cfg)
	require.NoError(t, err)

	built, err := tr.buildTLSConfig()
	require.NoError(t, err)
	require.NotNil(t, built.VerifyConnection)

	err = built.VerifyConnection(tls.ConnectionState{})
	assert.True(t, callerInvoked.Load(), "the caller's VerifyConnection must still run")
	assert.ErrorIs(t, err, callerErr)
}

// ============================================================================
// buildTLSConfig — file-based path (unchanged behavior)
// ============================================================================

func TestBuildTLSConfig_NilCallerConfigDefaults(t *testing.T) {
	cfg := transport.DefaultConfig()

	tr, err := NewWithConfig(cfg)
	require.NoError(t, err)

	built, err := tr.buildTLSConfig()
	require.NoError(t, err)
	assert.Equal(t, uint16(tls.VersionTLS13), built.MinVersion)
	assert.Equal(t, []string{"h3"}, built.NextProtos)
	assert.Nil(t, built.RootCAs)
	assert.Empty(t, built.Certificates)
	assert.Nil(t, built.VerifyConnection)
	assert.False(t, built.InsecureSkipVerify)
}

func TestBuildTLSConfig_FileBasedCAAndClientCert(t *testing.T) {
	ca := newTestCA(t)
	certPath, keyPath := ca.writeKeyPair(t, "file-client")
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	require.NoError(t, os.WriteFile(caPath, ca.certPEM, 0600))

	cfg := transport.DefaultConfig()
	cfg.TLSCAFile = caPath
	cfg.TLSCertFile = certPath
	cfg.TLSKeyFile = keyPath

	tr, err := NewWithConfig(cfg)
	require.NoError(t, err)

	built, err := tr.buildTLSConfig()
	require.NoError(t, err)
	assert.NotNil(t, built.RootCAs)
	assert.Len(t, built.Certificates, 1)
	assert.Equal(t, uint16(tls.VersionTLS13), built.MinVersion)
}

func TestBuildTLSConfig_FileBasedSPKIPinBootstrap(t *testing.T) {
	cfg := transport.DefaultConfig()
	cfg.SPKIPin = "0000000000000000000000000000000000000000000000000000000000000000"

	tr, err := NewWithConfig(cfg)
	require.NoError(t, err)

	built, err := tr.buildTLSConfig()
	require.NoError(t, err)
	assert.True(t, built.InsecureSkipVerify, "pin-only bootstrap replaces CA validation with the pin")
	assert.True(t, built.SessionTicketsDisabled, "resumption must stay off so VerifyConnection always runs")
	assert.NotNil(t, built.VerifyConnection)
	assert.Equal(t, []string{"h3"}, built.NextProtos, "the pinned bootstrap config still needs the HTTP/3 ALPN")
	assert.Equal(t, uint16(tls.VersionTLS13), built.MinVersion)
}

func TestBuildTLSConfig_FileBasedSPKIPinAdditiveOverCAFile(t *testing.T) {
	ca := newTestCA(t)
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	require.NoError(t, os.WriteFile(caPath, ca.certPEM, 0600))

	cfg := transport.DefaultConfig()
	cfg.TLSCAFile = caPath
	cfg.SPKIPin = "0000000000000000000000000000000000000000000000000000000000000000"

	tr, err := NewWithConfig(cfg)
	require.NoError(t, err)

	built, err := tr.buildTLSConfig()
	require.NoError(t, err)
	assert.False(t, built.InsecureSkipVerify)
	assert.NotNil(t, built.RootCAs)
	assert.NotNil(t, built.VerifyConnection)
}

func TestBuildTLSConfig_CAFileMissing(t *testing.T) {
	cfg := transport.DefaultConfig()
	cfg.TLSCAFile = filepath.Join(t.TempDir(), "does-not-exist.pem")

	tr, err := NewWithConfig(cfg)
	require.NoError(t, err)

	built, err := tr.buildTLSConfig()
	require.Error(t, err)
	assert.Nil(t, built)
	assert.Contains(t, err.Error(), "failed to read CA certificate")
}

func TestBuildTLSConfig_CAFileNotPEM(t *testing.T) {
	caPath := filepath.Join(t.TempDir(), "garbage.pem")
	require.NoError(t, os.WriteFile(caPath, []byte("not a certificate"), 0600))

	cfg := transport.DefaultConfig()
	cfg.TLSCAFile = caPath

	tr, err := NewWithConfig(cfg)
	require.NoError(t, err)

	built, err := tr.buildTLSConfig()
	require.Error(t, err)
	assert.Nil(t, built)
	assert.Contains(t, err.Error(), "failed to parse CA certificate")
}

func TestBuildTLSConfig_ClientKeyPairInvalid(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	require.NoError(t, os.WriteFile(certPath, []byte("not a cert"), 0600))
	require.NoError(t, os.WriteFile(keyPath, []byte("not a key"), 0600))

	cfg := transport.DefaultConfig()
	cfg.TLSCertFile = certPath
	cfg.TLSKeyFile = keyPath

	tr, err := NewWithConfig(cfg)
	require.NoError(t, err)

	built, err := tr.buildTLSConfig()
	require.Error(t, err)
	assert.Nil(t, built)
	assert.Contains(t, err.Error(), "failed to load client certificate")
}

// TestConnect_PropagatesTLSConfigError ensures Connect surfaces a TLS
// construction failure instead of dialing with a half-built config.
func TestConnect_PropagatesTLSConfigError(t *testing.T) {
	cfg := transport.DefaultConfig()
	cfg.Address = "127.0.0.1:1"
	cfg.TLSCAFile = filepath.Join(t.TempDir(), "missing.pem")

	tr, err := NewWithConfig(cfg)
	require.NoError(t, err)

	err = tr.Connect(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read CA certificate")
	assert.Nil(t, tr.httpClient, "no HTTP client may be built from a failed TLS config")
	assert.False(t, tr.IsConnected())
}

// ============================================================================
// chainVerifyConnection
// ============================================================================

func TestChainVerifyConnection(t *testing.T) {
	firstErr := errors.New("first failed")
	secondErr := errors.New("second failed")

	ok := func(tls.ConnectionState) error { return nil }
	failFirst := func(tls.ConnectionState) error { return firstErr }
	failSecond := func(tls.ConnectionState) error { return secondErr }

	t.Run("nil first returns second", func(t *testing.T) {
		chained := chainVerifyConnection(nil, failSecond)
		assert.ErrorIs(t, chained(tls.ConnectionState{}), secondErr)
	})

	t.Run("both pass", func(t *testing.T) {
		assert.NoError(t, chainVerifyConnection(ok, ok)(tls.ConnectionState{}))
	})

	t.Run("first failure short-circuits", func(t *testing.T) {
		var secondRan bool
		chained := chainVerifyConnection(failFirst, func(tls.ConnectionState) error {
			secondRan = true
			return nil
		})
		assert.ErrorIs(t, chained(tls.ConnectionState{}), firstErr)
		assert.False(t, secondRan, "the second callback must not run once the first rejected")
	})

	t.Run("second failure propagates", func(t *testing.T) {
		assert.ErrorIs(t, chainVerifyConnection(ok, failSecond)(tls.ConnectionState{}), secondErr)
	})
}

// ============================================================================
// Test helpers
// ============================================================================

// testCA is a throwaway certificate authority for the TLS tests.
type testCA struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	certPEM []byte
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "go-xkms quic transport test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	return &testCA{
		cert:    cert,
		key:     key,
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
	}
}

func (ca *testCA) pool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	return pool
}

// issue mints a leaf certificate signed by the CA. When server is true the
// certificate carries a 127.0.0.1 IP SAN and the server-auth EKU.
func (ca *testCA) issue(t *testing.T, commonName string, server bool) tls.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 96))
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	if server {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		tmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
		tmpl.DNSNames = []string{"localhost"}
	} else {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	require.NoError(t, err)

	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// writeKeyPair issues a leaf certificate and writes it plus its key to temp
// files, returning the cert and key paths.
func (ca *testCA) writeKeyPair(t *testing.T, commonName string) (string, string) {
	t.Helper()

	cert := ca.issue(t, commonName, false)
	key, ok := cert.PrivateKey.(*ecdsa.PrivateKey)
	require.True(t, ok)

	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)

	dir := t.TempDir()
	certPath := filepath.Join(dir, commonName+".crt")
	keyPath := filepath.Join(dir, commonName+".key")

	require.NoError(t, os.WriteFile(certPath,
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}), 0600))
	require.NoError(t, os.WriteFile(keyPath,
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0600))

	return certPath, keyPath
}

// startTestHTTP3Server runs an HTTP/3 listener on an ephemeral loopback UDP
// port for the duration of the test and returns its host:port address. The
// handler is mounted at /health, which is what Transport.Connect probes.
func startTestHTTP3Server(t *testing.T, tlsConfig *tls.Config, handler http.HandlerFunc) string {
	t.Helper()

	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	require.NoError(t, err)

	mux := http.NewServeMux()
	mux.HandleFunc("/health", handler)

	srv := &http3.Server{
		TLSConfig: tlsConfig,
		Handler:   mux,
	}

	go func() {
		// Serve returns http.ErrServerClosed (or a closed-conn error) on
		// shutdown; the test asserts on client-side behavior instead.
		_ = srv.Serve(udpConn)
	}()

	t.Cleanup(func() {
		_ = srv.Close()
		_ = udpConn.Close()
	})

	addr, ok := udpConn.LocalAddr().(*net.UDPAddr)
	require.True(t, ok)

	return fmt.Sprintf("127.0.0.1:%d", addr.Port)
}

// writeHealthy writes the response Transport.Health expects.
func writeHealthy(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"status":"healthy"}`))
}

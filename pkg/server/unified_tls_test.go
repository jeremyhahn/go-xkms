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

package server

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/config"
)

func newTLSTestServer(t *testing.T, cfg *config.Config) *Server {
	t.Helper()
	return &Server{
		config: cfg,
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

// TestBuildUnifiedTLSConfig_OperatorFiles proves operator-supplied cert/key
// files are served verbatim through the rotating provider.
func TestBuildUnifiedTLSConfig_OperatorFiles(t *testing.T) {
	certFile, keyFile, _ := createTestTLSFiles(t)
	s := newTLSTestServer(t, &config.Config{
		TLS: config.TLSConfig{Enabled: true, CertFile: certFile, KeyFile: keyFile},
	})

	cfg, err := s.buildUnifiedTLSConfig()
	require.NoError(t, err)
	require.NotNil(t, cfg.GetCertificate)
	assert.Equal(t, uint16(tls.VersionTLS13), cfg.MinVersion)

	cert, err := cfg.GetCertificate(&tls.ClientHelloInfo{})
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	require.NoError(t, err)
	assert.Contains(t, leaf.DNSNames, "localhost")
}

// TestBuildUnifiedTLSConfig_BootstrapGeneratedAndPersisted proves the
// no-files path generates a self-signed bootstrap certificate, persists it
// under the storage path, and reuses the identical certificate on the next
// build (stable identity across restarts).
func TestBuildUnifiedTLSConfig_BootstrapGeneratedAndPersisted(t *testing.T) {
	dir := t.TempDir()
	mk := func() *Server {
		return newTLSTestServer(t, &config.Config{
			Server:  config.ServerConfig{Host: "127.0.0.1"},
			TLS:     config.TLSConfig{Enabled: true, ServerCN: "unit.example"},
			Storage: config.StorageConfig{Path: dir},
		})
	}

	cfg1, err := mk().buildUnifiedTLSConfig()
	require.NoError(t, err)
	cert1, err := cfg1.GetCertificate(&tls.ClientHelloInfo{})
	require.NoError(t, err)
	leaf1, err := x509.ParseCertificate(cert1.Certificate[0])
	require.NoError(t, err)
	assert.Contains(t, leaf1.DNSNames, "unit.example")
	assert.Contains(t, leaf1.DNSNames, "localhost")

	cfg2, err := mk().buildUnifiedTLSConfig()
	require.NoError(t, err)
	cert2, err := cfg2.GetCertificate(&tls.ClientHelloInfo{})
	require.NoError(t, err)
	assert.Equal(t, cert1.Certificate[0], cert2.Certificate[0],
		"persisted bootstrap certificate must be reused across restarts")
}

// TestBuildUnifiedTLSConfig_ExtraSANs proves configured extra SANs (DNS
// names and IP addresses) land in the auto-issued bootstrap certificate, so
// clients dialing a deployment alias pass hostname verification.
func TestBuildUnifiedTLSConfig_ExtraSANs(t *testing.T) {
	s := newTLSTestServer(t, &config.Config{
		Server: config.ServerConfig{Host: "127.0.0.1"},
		TLS: config.TLSConfig{
			Enabled:   true,
			ServerCN:  "unit.example",
			ExtraSANs: []string{"alias.example.test", "192.0.2.7"},
		},
		Storage: config.StorageConfig{Path: t.TempDir()},
	})

	cfg, err := s.buildUnifiedTLSConfig()
	require.NoError(t, err)
	cert, err := cfg.GetCertificate(&tls.ClientHelloInfo{})
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	require.NoError(t, err)
	assert.Contains(t, leaf.DNSNames, "alias.example.test")
	ipFound := false
	for _, ip := range leaf.IPAddresses {
		if ip.String() == "192.0.2.7" {
			ipFound = true
		}
	}
	assert.True(t, ipFound, "extra IP SAN must be present: %v", leaf.IPAddresses)
}

// TestUpgradeUnifiedTLSCert_NoProviderIsNoop proves the upgrade hook is
// safe when the unified server is not serving (local-only deployments).
func TestUpgradeUnifiedTLSCert_NoProviderIsNoop(t *testing.T) {
	s := newTLSTestServer(t, &config.Config{})
	assert.NoError(t, s.upgradeUnifiedTLSCert(nil))
}

// TestUnifiedTLSProvider_RotationServesNewCert proves a stored certificate
// swap is observed by subsequent handshake callbacks.
func TestUnifiedTLSProvider_RotationServesNewCert(t *testing.T) {
	certFile, keyFile, _ := createTestTLSFiles(t)
	first, err := tls.LoadX509KeyPair(certFile, keyFile)
	require.NoError(t, err)

	p := &unifiedTLSProvider{}
	_, err = p.getCertificate(&tls.ClientHelloInfo{})
	require.ErrorIs(t, err, ErrNoTLSCertAvailable)

	p.cert.Store(&first)
	got, err := p.getCertificate(&tls.ClientHelloInfo{})
	require.NoError(t, err)
	assert.Equal(t, first.Certificate[0], got.Certificate[0])
}

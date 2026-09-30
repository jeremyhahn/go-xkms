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
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
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
			Server:    config.ServerConfig{Host: "127.0.0.1"},
			TLS:       config.TLSConfig{Enabled: true, ServerCN: "unit.example", IncludeLocalhostSANs: true},
			Datastore: config.DatastoreConfig{Path: dir},
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

// TestEnsureBootstrapCert_PersistFailureLogsAndDegradesToEphemeral is the
// failure-injection test for issue #687: a bootstrap-certificate persistence
// failure used to be discarded with `_ =`. It proves the discarded
// os.WriteFile errors are now surfaced through a logged warning, while
// ensureBootstrapCert still degrades to serving the freshly generated
// ephemeral certificate rather than failing TLS setup outright (the
// documented, deliberate degrade-not-fail behavior this fix must preserve).
func TestEnsureBootstrapCert_PersistFailureLogsAndDegradesToEphemeral(t *testing.T) {
	storageDir := t.TempDir()
	certDir := filepath.Join(storageDir, unifiedBootstrapCertDir)
	require.NoError(t, os.MkdirAll(certDir, 0o700))
	// Pre-create cert.pem and key.pem as directories so os.WriteFile fails
	// writing both (EISDIR on Linux), exercising the errors.Join of both
	// discarded write errors.
	require.NoError(t, os.Mkdir(filepath.Join(certDir, "cert.pem"), 0o700))
	require.NoError(t, os.Mkdir(filepath.Join(certDir, "key.pem"), 0o700))

	var logBuf bytes.Buffer
	s := &Server{
		config: &config.Config{
			Server:    config.ServerConfig{Host: "127.0.0.1"},
			TLS:       config.TLSConfig{ServerCN: "unit.example"},
			Datastore: config.DatastoreConfig{Path: storageDir},
		},
		logger: slog.New(slog.NewTextHandler(&logBuf, nil)),
	}

	cert, err := s.ensureBootstrapCert()
	require.NoError(t, err, "a persistence failure must still yield an ephemeral certificate, not fail bootstrap TLS setup")
	require.NotNil(t, cert)

	logged := logBuf.String()
	assert.Contains(t, logged, "failed to persist bootstrap TLS certificate",
		"the discarded certificate write error must be logged, not silently dropped")
	assert.Contains(t, logged, "failed to persist bootstrap TLS key",
		"the discarded key write error must be logged, not silently dropped")
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
		Datastore: config.DatastoreConfig{Path: t.TempDir()},
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

// TestBuildUnifiedTLSConfig_LoopbackSANsAreConfiguration proves the loopback
// names in the auto-issued certificate come from tls.include_localhost_sans
// and nowhere else: off, the certificate presents no localhost, 127.0.0.1 or
// ::1; on, all three. Before this they were literals in localCertSANs that
// no configuration could switch off, bypassing the knob the owner ruling of
// 2026-08-26 requires (#140).
func TestBuildUnifiedTLSConfig_LoopbackSANsAreConfiguration(t *testing.T) {
	leafFor := func(t *testing.T, include bool) *x509.Certificate {
		t.Helper()
		s := newTLSTestServer(t, &config.Config{
			Server: config.ServerConfig{Host: "192.0.2.10"},
			TLS: config.TLSConfig{
				Enabled:              true,
				ServerCN:             "unit.example",
				IncludeLocalhostSANs: include,
			},
			Datastore: config.DatastoreConfig{Path: t.TempDir()},
		})
		cfg, err := s.buildUnifiedTLSConfig()
		require.NoError(t, err)
		cert, err := cfg.GetCertificate(&tls.ClientHelloInfo{})
		require.NoError(t, err)
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		require.NoError(t, err)
		return leaf
	}
	hasIP := func(leaf *x509.Certificate, want string) bool {
		for _, ip := range leaf.IPAddresses {
			if ip.String() == want {
				return true
			}
		}
		return false
	}

	t.Run("off: no loopback name is presented", func(t *testing.T) {
		leaf := leafFor(t, false)
		assert.NotContains(t, leaf.DNSNames, "localhost")
		assert.False(t, hasIP(leaf, "127.0.0.1"), "IPs: %v", leaf.IPAddresses)
		assert.False(t, hasIP(leaf, "::1"), "IPs: %v", leaf.IPAddresses)
		assert.True(t, hasIP(leaf, "192.0.2.10"), "server.host must still be covered: %v", leaf.IPAddresses)
		assert.Contains(t, leaf.DNSNames, "unit.example")
	})

	t.Run("on: every loopback name is presented", func(t *testing.T) {
		leaf := leafFor(t, true)
		assert.Contains(t, leaf.DNSNames, "localhost")
		assert.True(t, hasIP(leaf, "127.0.0.1"), "IPs: %v", leaf.IPAddresses)
		assert.True(t, hasIP(leaf, "::1"), "IPs: %v", leaf.IPAddresses)
	})
}

// TestLocalCertSANs pins the builder both issuance paths share: the loopback
// set is the switch, server.host and extras are added as IP or DNS by shape,
// duplicates collapse, and a wildcard address is never a SAN.
func TestLocalCertSANs(t *testing.T) {
	dns, ips := localCertSANs("node.example", "10.0.0.5", true, true, "alias.example", "10.0.0.5", "node.example")
	assert.Equal(t, []string{"localhost", "node.example", hostnameForTest(t), "alias.example"}, dedupeKeepOrder(dns))
	var got []string
	for _, ip := range ips {
		got = append(got, ip.String())
	}
	assert.Equal(t, []string{"127.0.0.1", "::1", "10.0.0.5"}, got)

	dns, ips = localCertSANs("node.example", "", false, false)
	assert.NotContains(t, dns, "localhost")
	assert.Empty(t, ips, "no host, no loopback: no IP SAN at all, and never 0.0.0.0")
	for _, ip := range ips {
		assert.NotEqual(t, "0.0.0.0", ip.String())
	}
}

// hostnameForTest returns the machine hostname localCertSANs adds, or fails
// the test if it cannot be read.
func hostnameForTest(t *testing.T) string {
	t.Helper()
	h, err := os.Hostname()
	require.NoError(t, err)
	return h
}

// dedupeKeepOrder returns names in first-seen order, so the assertion holds
// whether or not the machine hostname equals one of the other names.
func dedupeKeepOrder(names []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, n := range names {
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	return out
}

// TestBuildUnifiedTLSConfig_PersistedBootstrapCertFollowsSANConfiguration
// proves a persisted bootstrap certificate is reissued when the configured
// SAN set changes: a node that set tls.include_localhost_sans: false after
// first boot must not keep serving localhost for the rest of the year.
func TestBuildUnifiedTLSConfig_PersistedBootstrapCertFollowsSANConfiguration(t *testing.T) {
	dir := t.TempDir()
	mk := func(include bool) *Server {
		return newTLSTestServer(t, &config.Config{
			Server:    config.ServerConfig{Host: "127.0.0.1"},
			TLS:       config.TLSConfig{Enabled: true, ServerCN: "unit.example", IncludeLocalhostSANs: include},
			Datastore: config.DatastoreConfig{Path: dir},
		})
	}
	leafFor := func(t *testing.T, s *Server) (*x509.Certificate, []byte) {
		t.Helper()
		cfg, err := s.buildUnifiedTLSConfig()
		require.NoError(t, err)
		cert, err := cfg.GetCertificate(&tls.ClientHelloInfo{})
		require.NoError(t, err)
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		require.NoError(t, err)
		return leaf, cert.Certificate[0]
	}

	first, firstDER := leafFor(t, mk(true))
	assert.Contains(t, first.DNSNames, "localhost")

	second, secondDER := leafFor(t, mk(false))
	assert.NotContains(t, second.DNSNames, "localhost", "the persisted certificate must be reissued without the loopback names")
	assert.NotEqual(t, firstDER, secondDER)

	_, thirdDER := leafFor(t, mk(false))
	assert.Equal(t, secondDER, thirdDER, "with the configuration unchanged the reissued certificate is reused")
}

// TestCertSANsMatch pins the set comparison both certificate paths use.
func TestCertSANsMatch(t *testing.T) {
	leaf := &x509.Certificate{
		DNSNames:    []string{"b.example", "a.example"},
		IPAddresses: []net.IP{net.ParseIP("10.0.0.5"), net.IPv4(127, 0, 0, 1)},
	}
	assert.True(t, certSANsMatch(leaf, []string{"a.example", "b.example"}, []net.IP{net.IPv4(127, 0, 0, 1), net.ParseIP("10.0.0.5")}), "order must not matter")
	assert.False(t, certSANsMatch(leaf, []string{"a.example"}, []net.IP{net.IPv4(127, 0, 0, 1), net.ParseIP("10.0.0.5")}), "a name the configuration dropped")
	assert.False(t, certSANsMatch(leaf, []string{"a.example", "b.example", "c.example"}, []net.IP{net.IPv4(127, 0, 0, 1), net.ParseIP("10.0.0.5")}), "a name the configuration added")
	assert.False(t, certSANsMatch(leaf, []string{"a.example", "b.example"}, []net.IP{net.ParseIP("10.0.0.5")}), "an address the configuration dropped")
}

// TestLocalCertSANs_WildcardHostIsNeverASAN pins that a bind host of every
// interface -- 0.0.0.0 or :: as server.host, or the same values among the
// extra hosts -- never reaches the certificate: it is not an address a
// client dials, and a wildcard is not a name a certificate presents.
func TestLocalCertSANs_WildcardHostIsNeverASAN(t *testing.T) {
	for _, host := range []string{"0.0.0.0", "::"} {
		dns, ips := localCertSANs("node.example", host, false, false, "0.0.0.0", "::", "10.0.0.5")
		assert.NotContains(t, dns, host)
		var got []string
		for _, ip := range ips {
			got = append(got, ip.String())
		}
		assert.Equal(t, []string{"10.0.0.5"}, got, "host %q: only the dialable address survives", host)
	}
}

// TestLocalCertSANs_IPLiteralCNIsAnIPSAN pins that a tls.server_cn set to
// an address becomes an IP SAN rather than being dropped: clients dialing
// an address verify it against IP SANs, never against the Common Name.
func TestLocalCertSANs_IPLiteralCNIsAnIPSAN(t *testing.T) {
	dns, ips := localCertSANs("10.0.0.9", "", false, false)
	assert.NotContains(t, dns, "10.0.0.9")
	var got []string
	for _, ip := range ips {
		got = append(got, ip.String())
	}
	assert.Equal(t, []string{"10.0.0.9"}, got)

	dns, ips = localCertSANs("::", "", false, false)
	assert.NotContains(t, dns, "::")
	assert.Empty(t, ips, "a wildcard CN is still never a SAN")
}

// TestServerCertSANs_CAIssuedSetIsDeterministic pins the cluster invariant
// codex raised on #504: the CA-issued certificate is shared by every node
// through replicated storage, so its SAN set must not depend on which node
// computes it. The machine hostname is node-local and stays in the
// bootstrap certificate only; a node dialed by another name lists it in
// tls.extra_sans.
func TestServerCertSANs_CAIssuedSetIsDeterministic(t *testing.T) {
	s := newTLSTestServer(t, &config.Config{
		Server:    config.ServerConfig{Host: "10.0.0.5"},
		TLS:       config.TLSConfig{Enabled: true, ServerCN: "unit.example", ExtraSANs: []string{"alias.example"}},
		Datastore: config.DatastoreConfig{Path: t.TempDir()},
	})
	hostname := hostnameForTest(t)

	dns, _ := s.serverCertSANs("unit.example", false)
	assert.NotContains(t, dns, hostname, "the shared CA-issued certificate must not carry node-local material")
	assert.Equal(t, []string{"unit.example", "alias.example"}, dedupeKeepOrder(dns))

	dns, _ = s.serverCertSANs("unit.example", true)
	assert.Contains(t, dns, hostname, "the node-local bootstrap certificate covers the machine hostname")
}

package server

import (
	"bytes"
	"crypto/tls"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/config"
)

func TestBuildUnifiedTLSConfig_UnloadableKeyPairFails(t *testing.T) {
	certFile, _, _ := createTestTLSFiles(t)
	s := newTLSTestServer(t, &config.Config{
		TLS: config.TLSConfig{Enabled: true, CertFile: certFile, KeyFile: filepath.Join(t.TempDir(), "missing.key")},
	})

	cfg, err := s.buildUnifiedTLSConfig()
	require.Nil(t, cfg)
	var certErr *ErrTLSCertOp
	require.ErrorAs(t, err, &certErr)
	assert.Equal(t, "load unified server certificate", certErr.Operation)
	assert.Nil(t, s.unifiedTLS, "a failed build must not publish a provider")
}

// TestBuildUnifiedTLSConfig_UnpersistableBootstrapCertIsEphemeral puts a
// regular file where the storage directory should be: the bootstrap
// certificate cannot be persisted, so it is served ephemerally and the
// failure is logged rather than refusing to serve.
func TestBuildUnifiedTLSConfig_UnpersistableBootstrapCertIsEphemeral(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "storage")
	require.NoError(t, os.WriteFile(blocker, []byte("not a directory"), 0o600))
	s := newTLSTestServer(t, &config.Config{
		Server:    config.ServerConfig{Host: "127.0.0.1"},
		TLS:       config.TLSConfig{Enabled: true, ServerCN: "unit.example"},
		Datastore: config.DatastoreConfig{Path: blocker},
	})
	var logs bytes.Buffer
	s.logger = slog.New(slog.NewTextHandler(&logs, nil))

	cfg, err := s.buildUnifiedTLSConfig()
	require.NoError(t, err)
	cert, err := cfg.GetCertificate(&tls.ClientHelloInfo{})
	require.NoError(t, err)
	require.NotEmpty(t, cert.Certificate)
	assert.Contains(t, logs.String(), "serving an ephemeral certificate")
	assert.Contains(t, logs.String(), "create bootstrap TLS certificate directory")
}

// TestBuildUnifiedTLSConfig_ClientAuthResolvesCurrentPool proves that with
// client authentication on, each connection's config carries the provider's
// client-CA pool as it is at handshake time, not as it was at build time.
func TestBuildUnifiedTLSConfig_ClientAuthResolvesCurrentPool(t *testing.T) {
	certFile, keyFile, _ := createTestTLSFiles(t)
	_, _, caPEM := generateCAKeyAndCert(t, "client-ca")
	caFile := filepath.Join(t.TempDir(), "client-ca.pem")
	require.NoError(t, os.WriteFile(caFile, caPEM, 0o600))

	s := newTLSTestServer(t, &config.Config{
		TLS: config.TLSConfig{
			Enabled:    true,
			CertFile:   certFile,
			KeyFile:    keyFile,
			CAFile:     caFile,
			ClientAuth: "require_and_verify",
		},
	})

	cfg, err := s.buildUnifiedTLSConfig()
	require.NoError(t, err)
	assert.Equal(t, tls.RequireAndVerifyClientCert, cfg.ClientAuth)
	require.NotNil(t, cfg.GetConfigForClient)

	seeded := s.unifiedTLS.clientCAs.Load()
	require.NotNil(t, seeded, "the configured CA file must seed the client-CA pool")
	conn, err := cfg.GetConfigForClient(&tls.ClientHelloInfo{})
	require.NoError(t, err)
	assert.Same(t, seeded, conn.ClientCAs)
	assert.Nil(t, conn.GetConfigForClient, "the per-connection config must not recurse")

	rotated, err := loadClientCAsUnion([]string{caFile}, nil)
	require.NoError(t, err)
	s.unifiedTLS.clientCAs.Store(rotated)
	conn, err = cfg.GetConfigForClient(&tls.ClientHelloInfo{})
	require.NoError(t, err)
	assert.Same(t, rotated, conn.ClientCAs)
}

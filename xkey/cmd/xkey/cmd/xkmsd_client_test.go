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

package cmd

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io/fs"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
	grpctransport "github.com/jeremyhahn/go-xkms/sdk/go/transport/grpc"
	mcptransport "github.com/jeremyhahn/go-xkms/sdk/go/transport/mcp"
	quictransport "github.com/jeremyhahn/go-xkms/sdk/go/transport/quic"
	resttransport "github.com/jeremyhahn/go-xkms/sdk/go/transport/rest"
	unixtransport "github.com/jeremyhahn/go-xkms/sdk/go/transport/unix"
	xkeyconfig "github.com/jeremyhahn/go-xkms/xkey/pkg/config"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/serverid"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/serverid/serveridtest"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/tokenstore"
)

// configuredTransport exposes the resolved transport configuration. Every SDK
// transport implements it, which lets these tests verify scheme dispatch and
// option threading without contacting a server.
type configuredTransport interface {
	Config() *transport.Config
}

// isolateXKMSdEndpoint neutralizes every endpoint source (flag, environment,
// viper key, loaded config) for the duration of a test and restores the
// previous values afterwards.
func isolateXKMSdEndpoint(t *testing.T) {
	t.Helper()

	previousFlag := xkmsdURL
	previousViper := viper.Get(cfgKeyXKMSdURL)
	previousConfig := loadedConfig

	xkmsdURL = ""
	viper.Set(cfgKeyXKMSdURL, "")
	loadedConfig = nil

	t.Setenv(envXKMSdURL, "")
	t.Setenv(envXKeyXKMSdURL, "")
	t.Setenv(envXKMSdToken, "")
	t.Setenv(envXKMSdTLSCA, "")
	t.Setenv(envXKMSdTLSCert, "")
	t.Setenv(envXKMSdTLSKey, "")
	// The stored-login lookup reads the xKey data directory: keep it in a
	// temp dir so no test reads or writes the host's.
	t.Setenv("XKEY_DATA_DIR", t.TempDir())

	t.Cleanup(func() {
		xkmsdURL = previousFlag
		viper.Set(cfgKeyXKMSdURL, previousViper)
		loadedConfig = previousConfig
	})
}

// --- endpoint resolution ---

func TestResolveXKMSdEndpoint_FlagBeatsEnvAndConfig(t *testing.T) {
	isolateXKMSdEndpoint(t)

	xkmsdURL = "unix:///run/flag.sock"
	t.Setenv(envXKMSdURL, "unix:///run/env.sock")
	viper.Set(cfgKeyXKMSdURL, "unix:///run/viper.sock")
	loadedConfig = &xkeyconfig.Config{XKMSD: xkeyconfig.XKMSDConfig{Address: "unix:///run/config.sock"}}

	endpoint, err := resolveXKMSdEndpoint(nil)
	require.NoError(t, err)
	assert.Equal(t, "unix:///run/flag.sock", endpoint.URL)
}

func TestResolveXKMSdEndpoint_EnvBeatsConfig(t *testing.T) {
	isolateXKMSdEndpoint(t)

	t.Setenv(envXKMSdURL, "grpc://env.example.com:9443")
	viper.Set(cfgKeyXKMSdURL, "grpc://viper.example.com:9443")
	loadedConfig = &xkeyconfig.Config{XKMSD: xkeyconfig.XKMSDConfig{Address: "grpc://config.example.com:9443"}}

	endpoint, err := resolveXKMSdEndpoint(nil)
	require.NoError(t, err)
	assert.Equal(t, "grpc://env.example.com:9443", endpoint.URL)
}

func TestResolveXKMSdEndpoint_XKeyEnvAliasUsed(t *testing.T) {
	isolateXKMSdEndpoint(t)

	t.Setenv(envXKeyXKMSdURL, "https://alias.example.com:8443")

	endpoint, err := resolveXKMSdEndpoint(nil)
	require.NoError(t, err)
	assert.Equal(t, "https://alias.example.com:8443", endpoint.URL)
}

func TestResolveXKMSdEndpoint_ViperKeyBeatsLoadedConfig(t *testing.T) {
	isolateXKMSdEndpoint(t)

	viper.Set(cfgKeyXKMSdURL, "quic://viper.example.com:8444")
	loadedConfig = &xkeyconfig.Config{XKMSD: xkeyconfig.XKMSDConfig{Address: "quic://config.example.com:8444"}}

	endpoint, err := resolveXKMSdEndpoint(nil)
	require.NoError(t, err)
	assert.Equal(t, "quic://viper.example.com:8444", endpoint.URL)
}

func TestResolveXKMSdEndpoint_LoadedConfigAddressUsedLast(t *testing.T) {
	isolateXKMSdEndpoint(t)

	loadedConfig = &xkeyconfig.Config{XKMSD: xkeyconfig.XKMSDConfig{Address: "mcp://config.example.com:9444"}}

	endpoint, err := resolveXKMSdEndpoint(nil)
	require.NoError(t, err)
	assert.Equal(t, "mcp://config.example.com:9444", endpoint.URL)
}

func TestResolveXKMSdEndpoint_MissingURL(t *testing.T) {
	isolateXKMSdEndpoint(t)

	endpoint, err := resolveXKMSdEndpoint(nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrXKMSdURLRequired), "want ErrXKMSdURLRequired, got %v", err)
	assert.Equal(t, XKMSdEndpoint{}, endpoint)
}

func TestResolveXKMSdEndpoint_WhitespaceOnlyURLTreatedAsMissing(t *testing.T) {
	isolateXKMSdEndpoint(t)

	xkmsdURL = "   "

	_, err := resolveXKMSdEndpoint(nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrXKMSdURLRequired), "want ErrXKMSdURLRequired, got %v", err)
}

func TestResolveXKMSdEndpoint_TokenFromEnvironment(t *testing.T) {
	isolateXKMSdEndpoint(t)

	xkmsdURL = "https://xkmsd.example.com:8443"
	t.Setenv(envXKMSdToken, "  header.payload.signature  ")

	endpoint, err := resolveXKMSdEndpoint(nil)
	require.NoError(t, err)
	assert.Equal(t, "header.payload.signature", endpoint.Token)
}

func TestResolveXKMSdEndpoint_TLSCAFlagBeatsEnvAndConfig(t *testing.T) {
	isolateXKMSdEndpoint(t)

	xkmsdURL = "https://xkmsd.example.com:8443"
	t.Setenv(envXKMSdTLSCA, "/etc/env-ca.pem")
	loadedConfig = &xkeyconfig.Config{XKMSD: xkeyconfig.XKMSDConfig{TLSCAFile: "/etc/config-ca.pem"}}

	cmd := &cobra.Command{Use: "probe"}
	cmd.Flags().String(tlsCAFlagName, "", "")
	require.NoError(t, setFlagForTest(t, cmd.Flags(), tlsCAFlagName, "/etc/flag-ca.pem"))

	endpoint, err := resolveXKMSdEndpoint(cmd)
	require.NoError(t, err)
	assert.Equal(t, "/etc/flag-ca.pem", endpoint.TLSCAFile)
}

func TestResolveXKMSdEndpoint_TLSCAEnvBeatsConfig(t *testing.T) {
	isolateXKMSdEndpoint(t)

	xkmsdURL = "https://xkmsd.example.com:8443"
	t.Setenv(envXKMSdTLSCA, "/etc/env-ca.pem")
	loadedConfig = &xkeyconfig.Config{XKMSD: xkeyconfig.XKMSDConfig{TLSCAFile: "/etc/config-ca.pem"}}

	endpoint, err := resolveXKMSdEndpoint(nil)
	require.NoError(t, err)
	assert.Equal(t, "/etc/env-ca.pem", endpoint.TLSCAFile)
}

func TestResolveXKMSdEndpoint_TLSCAFromLoadedConfig(t *testing.T) {
	isolateXKMSdEndpoint(t)

	xkmsdURL = "https://xkmsd.example.com:8443"
	loadedConfig = &xkeyconfig.Config{XKMSD: xkeyconfig.XKMSDConfig{TLSCAFile: "/etc/config-ca.pem"}}

	endpoint, err := resolveXKMSdEndpoint(nil)
	require.NoError(t, err)
	assert.Equal(t, "/etc/config-ca.pem", endpoint.TLSCAFile)
}

// --- flag lookup helper ---

func TestCommandFlagString_NilCommand(t *testing.T) {
	assert.Equal(t, "", commandFlagString(nil, tlsCAFlagName))
}

func TestCommandFlagString_UndeclaredFlag(t *testing.T) {
	cmd := &cobra.Command{Use: "probe"}
	assert.Equal(t, "", commandFlagString(cmd, tlsCAFlagName))
}

func TestCommandFlagString_PersistentFlagOnParent(t *testing.T) {
	parent := &cobra.Command{Use: "parent"}
	parent.PersistentFlags().String(tlsCAFlagName, "", "")
	require.NoError(t, setFlagForTest(t, parent.PersistentFlags(), tlsCAFlagName, "/etc/persistent-ca.pem"))

	assert.Equal(t, "/etc/persistent-ca.pem", commandFlagString(parent, tlsCAFlagName))
}

func TestCommandFlagString_UnsetFlagIsEmpty(t *testing.T) {
	cmd := &cobra.Command{Use: "probe"}
	cmd.Flags().String(tlsCAFlagName, "", "")

	assert.Equal(t, "", commandFlagString(cmd, tlsCAFlagName))
}

func TestCommandFlagBool_NilCommand(t *testing.T) {
	value, err := commandFlagBool(nil, "force")
	require.NoError(t, err)
	assert.False(t, value)
}

func TestCommandFlagBool_UndeclaredFlag(t *testing.T) {
	cmd := &cobra.Command{Use: "probe"}
	value, err := commandFlagBool(cmd, "force")
	require.NoError(t, err)
	assert.False(t, value)
}

func TestCommandFlagBool_ReturnsFlagValue(t *testing.T) {
	cmd := &cobra.Command{Use: "probe"}
	cmd.Flags().Bool("force", false, "")
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "force", "true"))

	value, err := commandFlagBool(cmd, "force")
	require.NoError(t, err)
	assert.True(t, value)
}

func TestCommandFlagBool_PersistentFlagOnParent(t *testing.T) {
	parent := &cobra.Command{Use: "parent"}
	parent.PersistentFlags().Bool("force", false, "")
	require.NoError(t, setFlagForTest(t, parent.PersistentFlags(), "force", "true"))

	value, err := commandFlagBool(parent, "force")
	require.NoError(t, err)
	assert.True(t, value)
}

func TestCommandFlagBool_WrongFlagTypeReturnsTypedError(t *testing.T) {
	cmd := &cobra.Command{Use: "probe"}
	cmd.Flags().String("force", "", "")

	_, err := commandFlagBool(cmd, "force")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrCommandFlagInvalid), "want ErrCommandFlagInvalid, got %v", err)
}

func TestCommandFlagDuration_NilCommand(t *testing.T) {
	value, err := commandFlagDuration(nil, "timeout")
	require.NoError(t, err)
	assert.Equal(t, time.Duration(0), value)
}

func TestCommandFlagDuration_UndeclaredFlag(t *testing.T) {
	cmd := &cobra.Command{Use: "probe"}
	value, err := commandFlagDuration(cmd, "timeout")
	require.NoError(t, err)
	assert.Equal(t, time.Duration(0), value)
}

func TestCommandFlagDuration_ReturnsFlagValue(t *testing.T) {
	cmd := &cobra.Command{Use: "probe"}
	cmd.Flags().Duration("timeout", 30*time.Second, "")
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "timeout", "90s"))

	value, err := commandFlagDuration(cmd, "timeout")
	require.NoError(t, err)
	assert.Equal(t, 90*time.Second, value)
}

func TestCommandFlagDuration_WrongFlagTypeReturnsTypedError(t *testing.T) {
	cmd := &cobra.Command{Use: "probe"}
	cmd.Flags().String("timeout", "", "")

	_, err := commandFlagDuration(cmd, "timeout")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrCommandFlagInvalid), "want ErrCommandFlagInvalid, got %v", err)
}

func TestCommandFlagChanged_NilCommand(t *testing.T) {
	assert.False(t, commandFlagChanged(nil, "timeout"))
}

func TestCommandFlagChanged_UndeclaredFlag(t *testing.T) {
	cmd := &cobra.Command{Use: "probe"}
	assert.False(t, commandFlagChanged(cmd, "timeout"))
}

func TestCommandFlagChanged_FalseUntilSet(t *testing.T) {
	cmd := &cobra.Command{Use: "probe"}
	cmd.Flags().Duration("timeout", 30*time.Second, "")

	assert.False(t, commandFlagChanged(cmd, "timeout"))

	require.NoError(t, setFlagForTest(t, cmd.Flags(), "timeout", "90s"))
	assert.True(t, commandFlagChanged(cmd, "timeout"))
}

func TestCommandFlagChanged_PersistentFlagOnParent(t *testing.T) {
	parent := &cobra.Command{Use: "parent"}
	parent.PersistentFlags().Bool("trust-new-devices", false, "")

	assert.False(t, commandFlagChanged(parent, "trust-new-devices"))

	require.NoError(t, setFlagForTest(t, parent.PersistentFlags(), "trust-new-devices", "true"))
	assert.True(t, commandFlagChanged(parent, "trust-new-devices"))
}

// --- scheme dispatch ---

func TestXKMSdEndpoint_Client_SchemeDispatch(t *testing.T) {
	tests := []struct {
		name       string
		url        string
		wantClient any
		wantAddr   string
		wantTLS    bool
	}{
		{
			name:       "unix socket strips scheme and uses tls",
			url:        "unix:///run/xkms/xkms.sock",
			wantClient: &unixtransport.Transport{},
			wantAddr:   "/run/xkms/xkms.sock",
			wantTLS:    true,
		},
		{
			name:       "unix socket keeps relative path",
			url:        "unix://xkms-data/xkms.sock",
			wantClient: &unixtransport.Transport{},
			wantAddr:   "xkms-data/xkms.sock",
			wantTLS:    true,
		},
		{
			name:       "http uses full url",
			url:        "http://xkmsd.example.com:8443",
			wantClient: &resttransport.Transport{},
			wantAddr:   "http://xkmsd.example.com:8443",
		},
		{
			name:       "https enables tls",
			url:        "https://xkmsd.example.com:8443",
			wantClient: &resttransport.Transport{},
			wantAddr:   "https://xkmsd.example.com:8443",
			wantTLS:    true,
		},
		{
			name:       "grpc uses host port",
			url:        "grpc://xkmsd.example.com:9443",
			wantClient: &grpctransport.Transport{},
			wantAddr:   "xkmsd.example.com:9443",
		},
		{
			name:       "grpcs enables tls",
			url:        "grpcs://xkmsd.example.com:9443",
			wantClient: &grpctransport.Transport{},
			wantAddr:   "xkmsd.example.com:9443",
			wantTLS:    true,
		},
		{
			name:       "quic always uses tls",
			url:        "quic://xkmsd.example.com:8444",
			wantClient: &quictransport.Transport{},
			wantAddr:   "xkmsd.example.com:8444",
			wantTLS:    true,
		},
		{
			name:       "mcp uses host port",
			url:        "mcp://xkmsd.example.com:9444",
			wantClient: &mcptransport.Transport{},
			wantAddr:   "xkmsd.example.com:9444",
		},
		{
			name:       "mcps enables tls",
			url:        "mcps://xkmsd.example.com:9444",
			wantClient: &mcptransport.Transport{},
			wantAddr:   "xkmsd.example.com:9444",
			wantTLS:    true,
		},
		{
			name:       "scheme comparison is case insensitive",
			url:        "GRPC://xkmsd.example.com:9443",
			wantClient: &grpctransport.Transport{},
			wantAddr:   "xkmsd.example.com:9443",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client, err := XKMSdEndpoint{URL: test.url}.Client()
			require.NoError(t, err)
			require.NotNil(t, client)
			defer func() { _ = client.Close() }()

			assert.IsType(t, test.wantClient, client)

			configured, ok := client.(configuredTransport)
			require.True(t, ok, "transport should expose its configuration")
			assert.Equal(t, test.wantAddr, configured.Config().Address)
			assert.Equal(t, test.wantTLS, configured.Config().TLSEnabled)
		})
	}
}

func TestXKMSdEndpoint_Client_ThreadsTokenAndCABundle(t *testing.T) {
	caFile := writeTestCABundle(t)

	client, err := XKMSdEndpoint{
		URL:       "https://xkmsd.example.com:8443",
		Token:     "header.payload.signature",
		TLSCAFile: caFile,
	}.Client()
	require.NoError(t, err)
	defer func() { _ = client.Close() }()

	configured, ok := client.(configuredTransport)
	require.True(t, ok)
	assert.Equal(t, "header.payload.signature", configured.Config().JWTToken)
	assert.True(t, configured.Config().TLSEnabled)
	require.NotNil(t, configured.Config().TLSConfig, "TLS transports must receive a TLS config")
	assert.NotNil(t, configured.Config().TLSConfig.RootCAs, "the configured CA bundle must be the trust anchor")
}

func TestResolveXKMSdEndpoint_ClientCertificateFromEnv(t *testing.T) {
	isolateXKMSdEndpoint(t)

	xkmsdURL = "grpcs://xkmsd.example.com:9443"
	t.Setenv(envXKMSdTLSCert, " /etc/xkey/admin-cert.pem ")
	t.Setenv(envXKMSdTLSKey, "/etc/xkey/admin-key.pem")

	endpoint, err := resolveXKMSdEndpoint(nil)
	require.NoError(t, err)
	assert.Equal(t, "/etc/xkey/admin-cert.pem", endpoint.TLSCertFile)
	assert.Equal(t, "/etc/xkey/admin-key.pem", endpoint.TLSKeyFile)
}

func TestXKMSdEndpoint_Client_ThreadsClientCertificate(t *testing.T) {
	certFile, keyFile := writeTestClientCredential(t)

	client, err := XKMSdEndpoint{
		URL:         "grpcs://xkmsd.example.com:9443",
		TLSCAFile:   writeTestCABundle(t),
		TLSCertFile: certFile,
		TLSKeyFile:  keyFile,
	}.Client()
	require.NoError(t, err)
	defer func() { _ = client.Close() }()

	configured, ok := client.(configuredTransport)
	require.True(t, ok)
	require.NotNil(t, configured.Config().TLSConfig)
	assert.Len(t, configured.Config().TLSConfig.Certificates, 1, "the mTLS client credential is presented")
}

// TestXKMSdEndpoint_Client_UnreadableClientCertificate verifies every TLS
// transport, xkmsd's unix socket included, refuses to build a client whose
// client certificate cannot be loaded.
func TestXKMSdEndpoint_Client_UnreadableClientCertificate(t *testing.T) {
	for _, rawURL := range []string{"grpcs://xkmsd.example.com:9443", "unix:///run/xkms/xkms.sock"} {
		t.Run(rawURL, func(t *testing.T) {
			client, err := XKMSdEndpoint{
				URL:         rawURL,
				TLSCertFile: filepath.Join(t.TempDir(), "absent-cert.pem"),
				TLSKeyFile:  filepath.Join(t.TempDir(), "absent-key.pem"),
			}.Client()
			assert.Nil(t, client)
			assert.ErrorIs(t, err, ErrXKMSdTLSConfigFailed)
		})
	}
}

// writeTestClientCredential writes a self-signed client certificate and its
// key, and returns their paths.
func writeTestClientCredential(t *testing.T) (certFile, keyFile string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "admin"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	dir := t.TempDir()
	certFile = filepath.Join(dir, "cert.pem")
	keyFile = filepath.Join(dir, "key.pem")
	require.NoError(t, os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600))
	require.NoError(t, os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600))
	return certFile, keyFile
}

func TestXKMSdEndpoint_Client_TokenOnPlaintextTransport(t *testing.T) {
	client, err := XKMSdEndpoint{
		URL:   "grpc://xkmsd.example.com:9443",
		Token: "header.payload.signature",
	}.Client()
	require.NoError(t, err)
	defer func() { _ = client.Close() }()

	configured, ok := client.(configuredTransport)
	require.True(t, ok)
	assert.Equal(t, "header.payload.signature", configured.Config().JWTToken)
	assert.False(t, configured.Config().TLSEnabled)
}

func TestXKMSdEndpoint_Client_UnreadableCABundle(t *testing.T) {
	client, err := XKMSdEndpoint{
		URL:       "grpcs://xkmsd.example.com:9443",
		TLSCAFile: filepath.Join(t.TempDir(), "absent-ca.pem"),
	}.Client()
	assert.Nil(t, client)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrXKMSdTLSConfigFailed), "want ErrXKMSdTLSConfigFailed, got %v", err)
}

func TestXKMSdEndpoint_Client_MalformedCABundle(t *testing.T) {
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	require.NoError(t, os.WriteFile(caFile, []byte("not a certificate"), 0600))

	client, err := XKMSdEndpoint{
		URL:       "https://xkmsd.example.com:8443",
		TLSCAFile: caFile,
	}.Client()
	assert.Nil(t, client)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrXKMSdTLSConfigFailed), "want ErrXKMSdTLSConfigFailed, got %v", err)
}

// writeTestCABundle writes a self-signed CA certificate to a temp file and
// returns its path.
func writeTestCABundle(t *testing.T) string {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "xkey test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	path := filepath.Join(t.TempDir(), "ca.pem")
	require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600))
	return path
}

func TestXKMSdEndpoint_Client_EmptyURL(t *testing.T) {
	client, err := XKMSdEndpoint{}.Client()
	assert.Nil(t, client)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrXKMSdURLRequired), "want ErrXKMSdURLRequired, got %v", err)
}

func TestXKMSdEndpoint_Client_UnsupportedScheme(t *testing.T) {
	tests := []string{
		"ftp://xkmsd.example.com:21",
		"embedded://local",
		"xkmsd.example.com:8443",
	}

	for _, rawURL := range tests {
		t.Run(rawURL, func(t *testing.T) {
			client, err := XKMSdEndpoint{URL: rawURL}.Client()
			assert.Nil(t, client)
			require.Error(t, err)
			assert.True(t, errors.Is(err, ErrXKMSdUnsupportedScheme), "want ErrXKMSdUnsupportedScheme, got %v", err)
			assert.Contains(t, err.Error(), "unix://", "error should list the supported schemes")
		})
	}
}

func TestXKMSdEndpoint_Client_UnparsableURL(t *testing.T) {
	client, err := XKMSdEndpoint{URL: "grpc://xkmsd.example.com:port]"}.Client()
	assert.Nil(t, client)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrXKMSdURLInvalid), "want ErrXKMSdURLInvalid, got %v", err)
}

func TestXKMSdEndpoint_Client_SchemeWithoutAddress(t *testing.T) {
	client, err := XKMSdEndpoint{URL: "grpc://"}.Client()
	assert.Nil(t, client)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrXKMSdURLInvalid), "want ErrXKMSdURLInvalid, got %v", err)
}

func TestXKMSdSupportedSchemes_ListsEveryTransport(t *testing.T) {
	schemes := xkmsdSupportedSchemes()
	for scheme := range xkmsdTransports {
		assert.Contains(t, schemes, scheme+"://")
	}
}

// --- client construction entry points ---

func TestNewXKMSdClient_NoURLConfigured(t *testing.T) {
	isolateXKMSdEndpoint(t)

	client, err := newXKMSdClient(nil)
	assert.Nil(t, client)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrXKMSdURLRequired), "want ErrXKMSdURLRequired, got %v", err)
}

func TestNewXKMSdClient_UsesResolvedEndpoint(t *testing.T) {
	isolateXKMSdEndpoint(t)

	xkmsdURL = "grpc://xkmsd.example.com:9443"

	client, err := newXKMSdClient(nil)
	require.NoError(t, err)
	require.NotNil(t, client)
	defer func() { _ = client.Close() }()

	configured, ok := client.(configuredTransport)
	require.True(t, ok)
	assert.Equal(t, "xkmsd.example.com:9443", configured.Config().Address)
}

func TestConnectXKMSdClient_NoURLConfigured(t *testing.T) {
	isolateXKMSdEndpoint(t)

	client, err := connectXKMSdClient(nil)
	assert.Nil(t, client)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrXKMSdURLRequired), "want ErrXKMSdURLRequired, got %v", err)
}

func TestConnectXKMSdClient_UnreachableServer(t *testing.T) {
	isolateXKMSdEndpoint(t)

	xkmsdURL = "unix://" + filepath.Join(t.TempDir(), "absent.sock")

	client, err := connectXKMSdClient(nil)
	assert.Nil(t, client)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrXKMSdConnectFailed), "want ErrXKMSdConnectFailed, got %v", err)
}

// --- platform-store client factory ---

// TestDefaultClientFactory_NoURLConfigured verifies the platform-store
// factory reports the shared missing-endpoint error instead of constructing
// an unusable client.
func TestDefaultClientFactory_NoURLConfigured(t *testing.T) {
	isolateXKMSdEndpoint(t)

	client, err := defaultClientFactory()
	assert.Nil(t, client)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrXKMSdURLRequired), "want ErrXKMSdURLRequired, got %v", err)
}

// TestDefaultClientFactory_BuildsTransportClient verifies the factory returns
// a real SDK transport client for the resolved endpoint.
func TestDefaultClientFactory_BuildsTransportClient(t *testing.T) {
	isolateXKMSdEndpoint(t)

	xkmsdURL = "unix:///run/xkms/xkms.sock"

	client, err := defaultClientFactory()
	require.NoError(t, err)
	require.NotNil(t, client)
	defer func() { _ = client.Close() }()

	configured, ok := client.(configuredTransport)
	require.True(t, ok)
	assert.Equal(t, "/run/xkms/xkms.sock", configured.Config().Address)
}

// --- stored login token ---

// storeLogin saves a login entry the way `xkey auth login` does, into the
// isolated data directory.
func storeLogin(t *testing.T, entry *tokenstore.TokenEntry) {
	t.Helper()
	store, cleanup, err := openTokenStore(slog.Default())
	require.NoError(t, err)
	defer cleanup()
	if entry.IssuedAt.IsZero() {
		entry.IssuedAt = time.Now()
	}
	require.NoError(t, store.Save(context.Background(), entry))
}

// loginTarget is an HTTPS server standing in for xkmsd: it answers every
// request with body and records each Authorization header.
type loginTarget struct {
	srv    *httptest.Server
	caFile string
	mu     sync.Mutex
	seen   []string
}

// newLoginTarget starts a loginTarget with its own certificate, trusted
// through a CA file.
func newLoginTarget(t *testing.T, body string) *loginTarget {
	t.Helper()
	lt := &loginTarget{}
	lt.srv, lt.caFile = serveridtest.NewTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lt.mu.Lock()
		lt.seen = append(lt.seen, r.Header.Get("Authorization"))
		lt.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	return lt
}

// id is the target's server identity.
func (lt *loginTarget) id() string { return serverid.Of(lt.srv.Certificate()) }

// authorizations returns the Authorization headers received so far.
func (lt *loginTarget) authorizations() []string {
	lt.mu.Lock()
	defer lt.mu.Unlock()
	return append([]string(nil), lt.seen...)
}

func TestResolveXKMSdEndpoint_UsesStoredLoginOfTheServerIdentity(t *testing.T) {
	isolateXKMSdEndpoint(t)
	target := newLoginTarget(t, "{}")
	t.Setenv(envXKMSdTLSCA, target.caFile)
	// The login was made through another URL of the same server: the
	// identity, not the URL, selects it.
	storeLogin(t, &tokenstore.TokenEntry{
		ServerURL: "https://login.example:1", ServerID: target.id(), ServerName: "login.example",
		Token: "stored.jwt", ExpiresAt: time.Now().Add(time.Hour),
	})
	xkmsdURL = target.srv.URL

	endpoint, err := resolveXKMSdEndpoint(nil)
	require.NoError(t, err)
	assert.Equal(t, "stored.jwt", endpoint.Token)
}

func TestResolveXKMSdEndpoint_SameHostOtherCertificateGetsNoLogin(t *testing.T) {
	isolateXKMSdEndpoint(t)
	loggedIn := newLoginTarget(t, "{}")
	other := newLoginTarget(t, "{}")
	storeLogin(t, &tokenstore.TokenEntry{
		ServerURL: loggedIn.srv.URL, ServerID: loggedIn.id(), ServerName: "127.0.0.1",
		Token: "stored.jwt", ExpiresAt: time.Now().Add(time.Hour),
	})
	t.Setenv(envXKMSdTLSCA, other.caFile)
	xkmsdURL = other.srv.URL

	endpoint, err := resolveXKMSdEndpoint(nil)
	require.NoError(t, err)
	assert.Empty(t, endpoint.Token, "another certificate on the same host is another server")
}

func TestResolveXKMSdEndpoint_ExplicitTokenBeatsStoredLogin(t *testing.T) {
	isolateXKMSdEndpoint(t)
	target := newLoginTarget(t, "{}")
	t.Setenv(envXKMSdTLSCA, target.caFile)
	storeLogin(t, &tokenstore.TokenEntry{ServerURL: target.srv.URL, ServerID: target.id(), Token: "stored.jwt"})
	t.Setenv(envXKMSdToken, "explicit.jwt")
	xkmsdURL = target.srv.URL

	endpoint, err := resolveXKMSdEndpoint(nil)
	require.NoError(t, err)
	assert.Equal(t, "explicit.jwt", endpoint.Token)
}

func TestResolveXKMSdEndpoint_UnixUsesTheConfiguredServerName(t *testing.T) {
	isolateXKMSdEndpoint(t)
	storeLogin(t, &tokenstore.TokenEntry{
		ServerURL: "https://xkmsd.local:8443", ServerID: "id-local", ServerName: "xkmsd.local",
		Token: "local.jwt", ExpiresAt: time.Now().Add(time.Hour),
	})
	xkmsdURL = "unix:///run/xkms.sock"

	endpoint, err := resolveXKMSdEndpoint(nil)
	require.NoError(t, err)
	assert.Empty(t, endpoint.Token, "without a configured server name a socket gets no login")

	t.Setenv(envXKMSdServerName, "xkmsd.local")
	endpoint, err = resolveXKMSdEndpoint(nil)
	require.NoError(t, err)
	assert.Equal(t, "local.jwt", endpoint.Token)
}

func TestResolveXKMSdEndpoint_NoStoreIsNotCreated(t *testing.T) {
	isolateXKMSdEndpoint(t)
	xkmsdURL = "https://xkmsd.example.com:8443"

	endpoint, err := resolveXKMSdEndpoint(nil)
	require.NoError(t, err)
	assert.Empty(t, endpoint.Token)
	_, statErr := os.Stat(filepath.Join(os.Getenv("XKEY_DATA_DIR"), defaultAuthStoragePath))
	assert.True(t, errors.Is(statErr, fs.ErrNotExist), "resolving a token must not create the login store")
}

func TestResolveXKMSdEndpoint_UnreachableServerFails(t *testing.T) {
	isolateXKMSdEndpoint(t)
	storeLogin(t, &tokenstore.TokenEntry{ServerURL: "https://x:1", ServerID: "id", Token: "t"})
	xkmsdURL = "https://127.0.0.1:1"

	_, err := resolveXKMSdEndpoint(nil)
	assert.ErrorIs(t, err, ErrXKMSdConnectFailed, "an unidentifiable server is an error, not an anonymous call")
}

func TestResolveXKMSdEndpoint_ExpiredLoginFails(t *testing.T) {
	isolateXKMSdEndpoint(t)
	target := newLoginTarget(t, "{}")
	t.Setenv(envXKMSdTLSCA, target.caFile)
	storeLogin(t, &tokenstore.TokenEntry{
		ServerURL: target.srv.URL, ServerID: target.id(), Token: "old.jwt", ExpiresAt: time.Now().Add(-time.Minute),
	})
	xkmsdURL = target.srv.URL

	_, err := resolveXKMSdEndpoint(nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrAuthTokenLoadFailed)
	assert.ErrorIs(t, err, tokenstore.ErrTokenExpired)
}

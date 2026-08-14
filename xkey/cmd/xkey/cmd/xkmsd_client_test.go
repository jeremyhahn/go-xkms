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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
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
	require.NoError(t, cmd.Flags().Set(tlsCAFlagName, "/etc/flag-ca.pem"))

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
	require.NoError(t, parent.PersistentFlags().Set(tlsCAFlagName, "/etc/persistent-ca.pem"))

	assert.Equal(t, "/etc/persistent-ca.pem", commandFlagString(parent, tlsCAFlagName))
}

func TestCommandFlagString_UnsetFlagIsEmpty(t *testing.T) {
	cmd := &cobra.Command{Use: "probe"}
	cmd.Flags().String(tlsCAFlagName, "", "")

	assert.Equal(t, "", commandFlagString(cmd, tlsCAFlagName))
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
			name:       "unix socket strips scheme",
			url:        "unix:///run/xkms/xkms.sock",
			wantClient: &unixtransport.Transport{},
			wantAddr:   "/run/xkms/xkms.sock",
		},
		{
			name:       "unix socket keeps relative path",
			url:        "unix://xkms-data/xkms.sock",
			wantClient: &unixtransport.Transport{},
			wantAddr:   "xkms-data/xkms.sock",
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

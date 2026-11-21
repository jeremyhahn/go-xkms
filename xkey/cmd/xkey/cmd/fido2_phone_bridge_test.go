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

//go:build ble

package cmd

import (
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/sdk/go/pairingproto"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/phone"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestPhoneBackend creates a PhoneKeyBackend with the given mock transport.
// It uses default configuration with TrustNewDevices enabled to allow
// backend creation without a pre-configured expected remote static key,
// simulating an initial pairing scenario.
func newTestPhoneBackend(t *testing.T, tr pairingproto.Transport) *phone.PhoneKeyBackend {
	t.Helper()
	cfg := phone.DefaultPhoneKeyBackendConfig()
	cfg.TrustNewDevices = true
	backend, err := phone.NewPhoneKeyBackendWithTransport(cfg, tr)
	require.NoError(t, err)
	return backend
}

func TestLoadXKMSdBridgeConfig_Defaults(t *testing.T) {
	resetViperForTest(t)

	// Load config with no viper values set.
	cfg := loadXKMSdBridgeConfig()

	// All fields should be zero values.
	assert.False(t, cfg.Enabled)
	assert.Empty(t, cfg.Protocol)
	assert.Empty(t, cfg.Address)
	assert.Equal(t, time.Duration(0), cfg.ConnectTimeout)
	assert.Equal(t, time.Duration(0), cfg.RequestTimeout)
	assert.Empty(t, cfg.TLSCAFile)
	assert.Empty(t, cfg.TLSCertFile)
	assert.Empty(t, cfg.TLSKeyFile)
	assert.Empty(t, cfg.AllowedBackends)
	assert.Empty(t, cfg.DeniedBackends)

	// Apply defaults and verify.
	cfg.applyDefaults()

	assert.Equal(t, "unix", cfg.Protocol)
	assert.Equal(t, "xkms-data/xkms.sock", cfg.Address)
	assert.Equal(t, 10*time.Second, cfg.ConnectTimeout)
	assert.Equal(t, 30*time.Second, cfg.RequestTimeout)
}

func TestLoadXKMSdBridgeConfig_FromViper(t *testing.T) {
	resetViperForTest(t)

	viper.Set("xkmsd.enabled", true)
	viper.Set("xkmsd.protocol", "unix")
	viper.Set("xkmsd.address", "/tmp/test.sock")
	viper.Set("xkmsd.sharing.allowed_backends", []string{"tpm2", "software"})
	viper.Set("xkmsd.sharing.denied_backends", []string{"vault"})
	viper.Set("xkmsd.request_timeout", "45s")
	viper.Set("xkmsd.tls_ca_file", "/etc/xkey/ca.pem")
	viper.Set("xkmsd.tls_cert_file", "/etc/xkey/client.pem")
	viper.Set("xkmsd.tls_key_file", "/etc/xkey/client-key.pem")

	cfg := loadXKMSdBridgeConfig()

	assert.True(t, cfg.Enabled)
	assert.Equal(t, "unix", cfg.Protocol)
	assert.Equal(t, "/tmp/test.sock", cfg.Address)
	assert.Equal(t, "/etc/xkey/ca.pem", cfg.TLSCAFile)
	assert.Equal(t, "/etc/xkey/client.pem", cfg.TLSCertFile)
	assert.Equal(t, "/etc/xkey/client-key.pem", cfg.TLSKeyFile)
	assert.Equal(t, 45*time.Second, cfg.RequestTimeout)
	assert.Equal(t, []string{"tpm2", "software"}, cfg.AllowedBackends)
	assert.Equal(t, []string{"vault"}, cfg.DeniedBackends)
}

func TestPhoneBackendWithBridge_Close(t *testing.T) {
	mockTransport := &mockCloserTransport{}
	backend := newTestPhoneBackend(t, mockTransport)

	mockClient := &mockSDKClient{}
	wrapper := &phoneBackendWithBridge{
		PhoneKeyBackend: backend,
		xkmsdClient:     mockClient,
		logger:          newTestLogger(),
	}

	err := wrapper.Close()
	require.NoError(t, err)

	// Both the phone backend transport and the SDK client should be closed.
	assert.True(t, mockTransport.closed, "phone backend transport should be closed")
	assert.True(t, mockClient.closed, "xkmsd SDK client should be closed")
}

func TestPhoneBackendWithBridge_Close_NilClient(t *testing.T) {
	mockTransport := &mockCloserTransport{}
	backend := newTestPhoneBackend(t, mockTransport)

	wrapper := &phoneBackendWithBridge{
		PhoneKeyBackend: backend,
		xkmsdClient:     nil,
		logger:          newTestLogger(),
	}

	// Should not panic with nil xkmsdClient.
	err := wrapper.Close()
	require.NoError(t, err)

	assert.True(t, mockTransport.closed, "phone backend transport should be closed")
}

func TestConnectXKMSdBridge_Disabled(t *testing.T) {
	resetViperForTest(t)

	viper.Set("xkmsd.enabled", false)

	mockTransport := &mockCloserTransport{}
	backend := newTestPhoneBackend(t, mockTransport)
	logger := newTestLogger()

	result, err := connectXKMSdBridge(backend, &cobra.Command{}, &PairedDevice{Name: "test-phone"}, logger)

	assert.Nil(t, result, "should return nil when xkmsd is disabled")
	assert.NoError(t, err, "should return nil error when xkmsd is disabled")
}

// TestConnectXKMSdBridge_DisabledIgnoresNilCmd proves the disabled path never
// reaches buildListenBridgeConfig's cmd.Flags() lookups: cfg.Enabled is
// checked, and connectXKMSdBridge returns, before cmd is dereferenced at all.
// A nil cmd here would panic if that ordering ever regressed.
func TestConnectXKMSdBridge_DisabledIgnoresNilCmd(t *testing.T) {
	resetViperForTest(t)

	viper.Set("xkmsd.enabled", false)

	mockTransport := &mockCloserTransport{}
	backend := newTestPhoneBackend(t, mockTransport)
	logger := newTestLogger()

	result, err := connectXKMSdBridge(backend, nil, &PairedDevice{Name: "test-phone"}, logger)

	assert.Nil(t, result, "should return nil when xkmsd is disabled")
	assert.NoError(t, err, "should return nil error when xkmsd is disabled")
}

func TestCreateXKMSdClient_Unix(t *testing.T) {
	cfg := &XKMSdBridgeConfig{
		Protocol: "unix",
		Address:  "/tmp/test.sock",
	}

	client, err := createXKMSdClient(cfg)
	require.NoError(t, err)
	require.NotNil(t, client)
	defer func() { _ = client.Close() }()

	configured, ok := client.(configuredTransport)
	require.True(t, ok)
	assert.Equal(t, "/tmp/test.sock", configured.Config().Address)
	assert.True(t, configured.Config().TLSEnabled, "xkmsd's socket is a TLS listener")
}

func TestCreateXKMSdClient_UnsupportedProtocol(t *testing.T) {
	cfg := &XKMSdBridgeConfig{
		Protocol: "websocket",
		Address:  "ws://localhost:8080",
	}

	client, err := createXKMSdClient(cfg)
	assert.Nil(t, client)
	assert.ErrorIs(t, err, ErrXKMSdUnsupportedProtocol)
}

func TestXKMSdBridgeConfig_ApplyDefaults_CustomValues(t *testing.T) {
	cfg := &XKMSdBridgeConfig{
		Protocol:       "unix",
		Address:        "/custom.sock",
		RequestTimeout: 60 * time.Second,
	}

	cfg.applyDefaults()

	// Custom values should be preserved.
	assert.Equal(t, "unix", cfg.Protocol)
	assert.Equal(t, "/custom.sock", cfg.Address)
	assert.Equal(t, 60*time.Second, cfg.RequestTimeout)

	// Only ConnectTimeout had a zero value and should get the default.
	assert.Equal(t, 10*time.Second, cfg.ConnectTimeout)
}

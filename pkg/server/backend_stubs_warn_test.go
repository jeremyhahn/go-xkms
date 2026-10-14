//go:build !awskms && !azurekv && !gcpkms && !pkcs11 && !vault

package server

import (
	"bytes"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/config"
)

// TestBackendStubs_EnabledButNotCompiledWarns checks each warn-and-continue
// stub names the missing build tag when its backend is enabled, without
// failing startup.
func TestBackendStubs_EnabledButNotCompiledWarns(t *testing.T) {
	cases := []struct {
		name     string
		backends config.BackendsConfig
		init     func(*Server) error
		tag      string
	}{
		{"awskms", config.BackendsConfig{AWSKMS: &config.AWSKMSConfig{Enabled: true}}, (*Server).initAWSKMSBackend, "-tags awskms"},
		{"azurekv", config.BackendsConfig{AzureKV: &config.AzureKVConfig{Enabled: true}}, (*Server).initAzureKVBackend, "-tags azurekv"},
		{"gcpkms", config.BackendsConfig{GCPKMS: &config.GCPKMSConfig{Enabled: true}}, (*Server).initGCPKMSBackend, "-tags gcpkms"},
		{"pkcs11", config.BackendsConfig{PKCS11: &config.PKCS11Config{Enabled: true}}, (*Server).initPKCS11Backend, "-tags pkcs11"},
		{"vault", config.BackendsConfig{Vault: &config.VaultConfig{Enabled: true}}, (*Server).initVaultBackend, "-tags vault"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var logs bytes.Buffer
			s := newMinimalServer(t, &config.Config{Backends: tc.backends})
			s.logger = slog.New(slog.NewTextHandler(&logs, nil))

			require.NoError(t, tc.init(s))
			assert.Contains(t, logs.String(), "not compiled in")
			assert.Contains(t, logs.String(), tc.tag)
		})
	}
}

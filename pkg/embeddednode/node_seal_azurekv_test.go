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

//go:build azurekv

package embeddednode

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/backend/azurekv"
	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

func TestAzureKVNodeSealConfig_MapsBackendsAzureKV(t *testing.T) {
	metadata := storage.NewMemory()
	cfg := &config.Config{Backends: config.BackendsConfig{AzureKV: &config.AzureKVConfig{
		VaultURL:           "http://localhost:8443",
		ClientID:           "ignored-by-the-node-seal",
		AllowLocalVaultURL: true,
	}}}

	got, err := azureKVNodeSealConfig(cfg, metadata, testLogger())
	require.NoError(t, err)
	require.Equal(t, &azurekv.Config{
		VaultURL:           "http://localhost:8443",
		AllowLocalVaultURL: true,
		KeyStorage:         metadata,
		CertStorage:        metadata,
	}, got)
}

func TestBuildAzureKVNodeSealBackend_RequiresBackendsAzureKV(t *testing.T) {
	provider, err := buildAzureKVNodeSealBackend(context.Background(), &config.Config{}, storage.NewMemory(), testLogger())
	var nodeErr *NodeSealError
	require.ErrorAs(t, err, &nodeErr)
	require.Nil(t, provider)
}

// TestBuildAzureKVNodeSealBackend_RefusesAnInvalidBackendsAzureKV proves a
// backends.azurekv section the Azure Key Vault backend cannot be built from
// refuses the node seal with the backend's typed error and no provider.
func TestBuildAzureKVNodeSealBackend_RefusesAnInvalidBackendsAzureKV(t *testing.T) {
	tests := []struct {
		name     string
		azureCfg *config.AzureKVConfig
		want     error
	}{
		{name: "missing vault URL", azureCfg: &config.AzureKVConfig{}, want: azurekv.ErrInvalidConfig},
		{name: "malformed vault URL", azureCfg: &config.AzureKVConfig{VaultURL: "not a url"}, want: azurekv.ErrInvalidVaultURL},
		{name: "local vault URL without opt-in", azureCfg: &config.AzureKVConfig{VaultURL: "https://localhost:8443"}, want: azurekv.ErrLocalVaultURLNotAllowed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Config{Backends: config.BackendsConfig{AzureKV: tt.azureCfg}}

			provider, err := buildAzureKVNodeSealBackend(context.Background(), cfg, storage.NewMemory(), testLogger())
			require.ErrorIs(t, err, tt.want)
			require.Nil(t, provider)
		})
	}
}

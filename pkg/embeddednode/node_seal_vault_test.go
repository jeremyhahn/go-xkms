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

//go:build vault

package embeddednode

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/backend/vault"
	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

func TestVaultNodeSealConfig_MapsBackendsVaultAndTheToken(t *testing.T) {
	metadata := storage.NewMemory()
	vaultCfg := &config.VaultConfig{
		Address:   "https://vault.example.com:8200",
		Namespace: "xkms",
		MountPath: "transit-xkms",
	}

	require.Equal(t, &vault.Config{
		Address:     "https://vault.example.com:8200",
		Token:       "hvs.node-seal",
		TransitPath: "transit-xkms",
		Namespace:   "xkms",
		KeyStorage:  metadata,
		CertStorage: metadata,
	}, vaultNodeSealConfig(vaultCfg, "hvs.node-seal", metadata))
}

func TestBuildVaultNodeSealBackend_RequiresBackendsVault(t *testing.T) {
	provider, err := buildVaultNodeSealBackend(context.Background(), &config.Config{}, storage.NewMemory(), testLogger())
	var nodeErr *NodeSealError
	require.ErrorAs(t, err, &nodeErr)
	require.Nil(t, provider)
}

// TestBuildVaultNodeSealBackend_RequiresThePreBarrierStore proves the vault
// node seal fails closed when the token's pre-barrier store cannot open.
func TestBuildVaultNodeSealBackend_RequiresThePreBarrierStore(t *testing.T) {
	cfg := cloudNodeSealConfig(t, seal.StrategyVault)
	cfg.Backends.Vault = &config.VaultConfig{Address: "https://vault.example.com:8200"}

	provider, err := buildVaultNodeSealBackend(context.Background(), cfg, storage.NewMemory(), testLogger())
	var nodeErr *NodeSealError
	require.ErrorAs(t, err, &nodeErr, "without backends.tpm2 there is no store to release the token from")
	require.Nil(t, provider)
}

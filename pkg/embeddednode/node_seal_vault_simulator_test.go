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

//go:build vault && tpm_simulator

package embeddednode

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
	"github.com/jeremyhahn/go-xkms/pkg/preseal"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

func simulatorVaultNodeSealConfig(t *testing.T) *config.Config {
	cfg := cloudNodeSealConfig(t, seal.StrategyVault)
	cfg.Backends.TPM2 = &config.TPM2Config{UseSimulator: true}
	cfg.Backends.Vault = &config.VaultConfig{Address: "https://vault.example.com:8200"}
	return cfg
}

func TestPresealedVaultToken_ReleasesTheSealedToken(t *testing.T) {
	cfg := simulatorVaultNodeSealConfig(t)
	store, closeStore, err := OpenPreseal(cfg, testLogger())
	require.NoError(t, err)
	require.NoError(t, store.Put(context.Background(), preseal.VaultToken, []byte("hvs.node-seal")))
	require.NoError(t, closeStore())

	token, err := presealedVaultToken(context.Background(), cfg, testLogger())
	require.NoError(t, err)
	require.Equal(t, []byte("hvs.node-seal"), token)
}

func TestPresealedVaultToken_WithoutASealedTokenFailsClosed(t *testing.T) {
	token, err := presealedVaultToken(context.Background(), simulatorVaultNodeSealConfig(t), testLogger())
	var nodeErr *NodeSealError
	require.ErrorAs(t, err, &nodeErr)
	var notFound *preseal.NotFoundError
	require.ErrorAs(t, err, &notFound)
	require.Nil(t, token)
}

// TestBuildVaultNodeSealBackend_RefusesAnInvalidBackendsVault proves a
// backends.vault section the Vault backend cannot be built from refuses the
// node seal even once the token is released, with no provider.
func TestBuildVaultNodeSealBackend_RefusesAnInvalidBackendsVault(t *testing.T) {
	cfg := simulatorVaultNodeSealConfig(t)
	store, closeStore, err := OpenPreseal(cfg, testLogger())
	require.NoError(t, err)
	require.NoError(t, store.Put(context.Background(), preseal.VaultToken, []byte("hvs.node-seal")))
	require.NoError(t, closeStore())
	cfg.Backends.Vault.Address = ""

	provider, err := buildVaultNodeSealBackend(context.Background(), cfg, storage.NewMemory(), testLogger())
	var msgErr *errs.Message
	require.ErrorAs(t, err, &msgErr)
	require.Equal(t, "vault address is required", msgErr.Msg)
	require.Nil(t, provider)
}

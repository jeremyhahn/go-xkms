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
	"log/slog"

	"github.com/jeremyhahn/go-xkms/pkg/backend/azurekv"
	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

func init() {
	registerCloudNodeSeal(seal.StrategyAzureKV, types.StoreAzureKV, buildAzureKVNodeSealBackend)
}

// buildAzureKVNodeSealBackend builds the Azure Key Vault backend the azurekv
// node seal seals through.
func buildAzureKVNodeSealBackend(_ context.Context, cfg *config.Config, metadata storage.Backend, logger *slog.Logger) (types.KeyProvider, error) {
	backendCfg, err := azureKVNodeSealConfig(cfg, metadata, logger)
	if err != nil {
		return nil, err
	}
	return azurekv.NewBackend(backendCfg)
}

// azureKVNodeSealConfig maps backends.azurekv onto the node seal's backend
// configuration. The node seal authenticates with DefaultAzureCredential
// (environment, workload or managed identity): a configured client_secret
// is a credential-service reference, and the credential service only exists
// once the node is unsealed.
func azureKVNodeSealConfig(cfg *config.Config, metadata storage.Backend, logger *slog.Logger) (*azurekv.Config, error) {
	azureCfg := cfg.Backends.AzureKV
	if azureCfg == nil {
		return nil, &NodeSealError{
			Reason: "strategy azurekv configured for the node seal but backends.azurekv is not set",
		}
	}
	if azureCfg.ClientID != "" || azureCfg.ClientSecret != nil {
		logger.Warn("node barrier: the azurekv node seal authenticates with DefaultAzureCredential; the configured service principal is not used for it")
	}
	return &azurekv.Config{
		VaultURL:           azureCfg.VaultURL,
		AllowLocalVaultURL: azureCfg.AllowLocalVaultURL,
		KeyStorage:         metadata,
		CertStorage:        metadata,
	}, nil
}

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

package cmd

import (
	"context"
	"io"
	"path/filepath"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

func init() {
	registerCloudKMSStrategyBuilder(xkms.StrategyAzureKV, buildAzureKVBarrierStrategy)
}

// buildAzureKVBarrierStrategy builds the azure_kv barrier sealing strategy
// from the operator's persisted xkey configuration (Barrier.CloudKMS.AzureKV),
// resolving any explicit *xkms.SecretValue client secret reference and
// falling back to Azure's DefaultAzureCredential ambient chain when none is
// configured. ClientSecret is handed to the backend unresolved-in-shape (its
// own Config.ClientSecret field is itself a *xkms.SecretValue): resolution
// fills the SAME enclave in place, and the backend borrows the plaintext
// through it at connect time, exactly like xkmsd's backend_azurekv.go. The
// seal key itself needs no configured identifier: see
// buildAWSKMSBarrierStrategy's doc.
func buildAzureKVBarrierStrategy(ctx context.Context, dataDir string) (xkms.SealingStrategy, io.Closer, error) {
	azureCfg := GetConfig().Barrier.CloudKMS.AzureKV
	if azureCfg != nil {
		azureCfg.ClientSecret = normalizeAmbientSecret(azureCfg.ClientSecret)
	}
	if err := azureCfg.Validate(); err != nil {
		return nil, nil, err
	}

	if err := resolveBarrierCloudSecrets(ctx, azureCfg); err != nil {
		return nil, nil, &BarrierError{Operation: "resolve_credentials", Err: err}
	}

	storageDir := filepath.Join(dataDir, "barrier", "cloudkms", "azurekv")
	metaStorage, err := xkms.NewFileStorageBackend(storageDir)
	if err != nil {
		return nil, nil, &BarrierError{Operation: "create_storage", Err: err}
	}

	backend, err := xkms.NewAzureKVBackend(&xkms.AzureKVBackendConfig{
		VaultURL:           azureCfg.VaultURL,
		TenantID:           azureCfg.TenantID,
		ClientID:           azureCfg.ClientID,
		ClientSecret:       azureCfg.ClientSecret,
		AllowLocalVaultURL: azureCfg.AllowLocalVaultURL,
		KeyStorage:         metaStorage,
		CertStorage:        metaStorage,
	})
	if err != nil {
		_ = metaStorage.Close()
		return nil, nil, &BarrierError{Operation: "create_backend", Err: err}
	}

	strategy, err := xkms.BuildCloudKMSStrategy(ctx, xkms.StrategyAzureKV, xkms.StoreAzureKV, backend)
	if err != nil {
		_ = backend.Close()
		return nil, nil, &BarrierError{Operation: "build_strategy", Err: err}
	}

	return strategy, backend, nil
}

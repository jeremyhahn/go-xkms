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

package cmd

import (
	"context"
	"errors"
	"io"
	"path/filepath"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

func init() {
	registerCloudKMSStrategyBuilder(xkms.StrategyVault, buildVaultBarrierStrategy)
}

// buildVaultBarrierStrategy builds the vault barrier sealing strategy from
// the operator's persisted xkey configuration (Barrier.CloudKMS.Vault),
// resolving any explicit *xkms.SecretValue token reference and falling back
// to the Vault Go client's ambient VAULT_TOKEN environment variable when
// none is configured. The seal key itself needs no configured identifier:
// see buildAWSKMSBarrierStrategy's doc.
func buildVaultBarrierStrategy(ctx context.Context, dataDir string) (xkms.SealingStrategy, io.Closer, error) {
	vaultCfg := GetConfig().Barrier.CloudKMS.Vault
	if vaultCfg != nil {
		vaultCfg.Token = normalizeAmbientSecret(vaultCfg.Token)
	}
	if err := vaultCfg.Validate(); err != nil {
		return nil, nil, err
	}

	if err := resolveBarrierCloudSecrets(ctx, vaultCfg); err != nil {
		return nil, nil, &BarrierError{Operation: "resolve_credentials", Err: err}
	}

	// The backend config takes the token as a string, so the byte copy only
	// bridges to that conversion and is wiped on the way out.
	token, err := xkms.SecretValueBytes(vaultCfg.Token)
	if err != nil {
		return nil, nil, &BarrierError{Operation: "resolve_credentials", Err: err}
	}
	defer secure.Wipe(token)

	storageDir := filepath.Join(dataDir, "barrier", "cloudkms", "vault")
	metaStorage, err := xkms.NewFileStorageBackend(storageDir)
	if err != nil {
		return nil, nil, &BarrierError{Operation: "create_storage", Err: err}
	}

	backend, err := xkms.NewVaultBackend(&xkms.VaultBackendConfig{
		Address:     vaultCfg.Address,
		Token:       string(token),
		TransitPath: vaultCfg.MountPath,
		Namespace:   vaultCfg.Namespace,
		KeyStorage:  metaStorage,
		CertStorage: metaStorage,
	})
	if err != nil {
		return nil, nil, &BarrierError{Operation: "create_backend", Err: errors.Join(err, metaStorage.Close())}
	}

	strategy, err := xkms.BuildCloudKMSStrategy(ctx, xkms.StrategyVault, xkms.StoreVault, backend)
	if err != nil {
		return nil, nil, &BarrierError{Operation: "build_strategy", Err: errors.Join(err, backend.Close())}
	}

	return strategy, backend, nil
}

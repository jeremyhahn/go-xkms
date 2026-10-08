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
	"log/slog"

	"github.com/jeremyhahn/go-xkms/pkg/backend/vault"
	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/preseal"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

func init() {
	registerCloudNodeSeal(seal.StrategyVault, types.StoreVault, buildVaultNodeSealBackend)
}

// buildVaultNodeSealBackend builds the Vault Transit backend the vault node
// seal seals through. Vault has no ambient credential to fall back on, so
// the node seal authenticates with the token sealed into the pre-barrier
// store by `xkmsd seal-vault-token`, released under the PSRK and the
// platform PCR policy exactly like the PKCS#11 node seal's PIN.
func buildVaultNodeSealBackend(ctx context.Context, cfg *config.Config, metadata storage.Backend, logger *slog.Logger) (types.KeyProvider, error) {
	vaultCfg := cfg.Backends.Vault
	if vaultCfg == nil {
		return nil, &NodeSealError{
			Reason: "strategy vault configured for the node seal but backends.vault is not set",
		}
	}
	token, err := presealedVaultToken(ctx, cfg, logger)
	if err != nil {
		return nil, err
	}
	// The backend config takes the token as a string, so the byte copy only
	// bridges to that conversion and is wiped on the way out.
	defer clear(token)
	return vault.NewBackend(vaultNodeSealConfig(vaultCfg, string(token), metadata))
}

// presealedVaultToken releases the vault node seal's token from the
// pre-barrier store.
func presealedVaultToken(ctx context.Context, cfg *config.Config, logger *slog.Logger) ([]byte, error) {
	store, closeStore, err := OpenPreseal(cfg, logger)
	if err != nil {
		return nil, err
	}
	token, err := store.Get(ctx, preseal.VaultToken)
	if closeErr := closeStore(); closeErr != nil {
		logger.Warn("node barrier: closing the pre-barrier secret store failed", "error", closeErr)
	}
	if err != nil {
		return nil, &NodeSealError{
			Reason: "releasing the vault node seal token (seal it with `xkmsd seal-vault-token`)",
			Err:    err,
		}
	}
	return token, nil
}

// vaultNodeSealConfig maps backends.vault and the released token onto the
// node seal's backend configuration.
func vaultNodeSealConfig(vaultCfg *config.VaultConfig, token string, metadata storage.Backend) *vault.Config {
	return &vault.Config{
		Address:     vaultCfg.Address,
		Token:       token,
		TransitPath: vaultCfg.MountPath,
		Namespace:   vaultCfg.Namespace,
		KeyStorage:  metadata,
		CertStorage: metadata,
	}
}

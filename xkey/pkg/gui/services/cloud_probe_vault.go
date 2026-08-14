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

//go:build vault

package services

import (
	"context"
	"log/slog"
	"os"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

// vaultDefaultTransitPath is the mount path Vault uses for the transit
// secrets engine when the operator has not remounted it.
const vaultDefaultTransitPath = "transit"

// The HashiCorp Vault liveness probe is only compiled when the vault backend
// is, so availability reported to the Add Backend dialog is genuine.
func init() {
	registerCloudProbe(CloudProviderVault, probeVault)
}

// probeVault verifies connectivity to HashiCorp Vault by listing the keys of
// the transit mount. ListKeys issues a real LIST on <mount>/keys, so it proves
// the server is reachable and the token is accepted. It creates no keys.
func probeVault(ctx context.Context, config map[string]string) error {
	token := config["token"]
	if token == "" {
		// The Add Backend form documents VAULT_TOKEN as the fallback when the
		// token field is left empty.
		token = os.Getenv("VAULT_TOKEN")
	}
	if token == "" {
		return &DetailError{Err: ErrCloudConfigMissing, Detail: ": vault token (set the Token field or VAULT_TOKEN)"}
	}

	transitPath := config["mount_path"]
	if transitPath == "" {
		transitPath = vaultDefaultTransitPath
	}

	backend, err := xkms.NewVaultBackend(&xkms.VaultBackendConfig{
		Address:     config["address"],
		Token:       token,
		TransitPath: transitPath,
		Namespace:   config["namespace"],
		KeyStorage:  xkms.NewStorageMemory(),
		CertStorage: xkms.NewStorageMemory(),
	})
	if err != nil {
		return &WrappedError{Msg: "HashiCorp Vault client", Err: err}
	}
	defer func() {
		if closeErr := backend.Close(); closeErr != nil {
			slog.Warn("vault connection probe: failed to close backend", "error", closeErr)
		}
	}()

	if _, err := backend.ListKeys(ctx); err != nil {
		return &WrappedError{Msg: "HashiCorp Vault transit mount " + transitPath, Err: err}
	}
	return nil
}

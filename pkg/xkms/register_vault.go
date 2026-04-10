//go:build vault

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

// Package xkms provides HashiCorp Vault backend registration and factory.
//
// The Vault backend integrates with HashiCorp Vault for secret management
// and key storage operations.
//
// This file is only compiled when the 'vault' build tag is specified.
package xkms

import (
	"github.com/jeremyhahn/go-xkms/pkg/backend/vault"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

func init() {
	RegisterBackend(BackendVault)
	RegisterBackendFactory(BackendVault, newVaultKeyProvider)
}

// newVaultKeyProvider creates a HashiCorp Vault backend KeyProvider from configuration.
//
// Supported configuration keys:
//   - "address" (string): Vault server address (required)
//   - "token" (string): Vault authentication token (required)
//   - "transit_path" (string): Transit secrets engine path (default: "transit")
//   - "namespace" (string): Vault namespace (optional, Enterprise feature)
//   - "tls_skip_verify" (bool): Disable TLS verification (not for production)
func newVaultKeyProvider(config map[string]interface{}) (types.KeyProvider, error) {
	vaultConfig := &vault.Config{
		KeyStorage: storage.New(),
	}

	if address, ok := config["address"].(string); ok {
		vaultConfig.Address = address
	}
	if token, ok := config["token"].(string); ok {
		vaultConfig.Token = token
	}
	if transitPath, ok := config["transit_path"].(string); ok {
		vaultConfig.TransitPath = transitPath
	}
	if namespace, ok := config["namespace"].(string); ok {
		vaultConfig.Namespace = namespace
	}
	if skipVerify, ok := config["tls_skip_verify"].(bool); ok {
		vaultConfig.TLSSkipVerify = skipVerify
	}

	return vault.NewBackend(vaultConfig)
}

//go:build azurekv

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

// Package xkms provides Azure Key Vault backend registration and factory.
//
// The Azure Key Vault backend integrates with Microsoft Azure Key Vault
// for cloud-based key storage and cryptographic operations.
//
// This file is only compiled when the 'azurekv' build tag is specified.
package xkms

import (
	"github.com/jeremyhahn/go-xkms/pkg/backend/azurekv"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

func init() {
	RegisterBackend(BackendAzureKV)
	RegisterBackendFactory(BackendAzureKV, newAzureKVKeyProvider)
}

// newAzureKVKeyProvider creates an Azure Key Vault backend KeyProvider from configuration.
//
// Supported configuration keys:
//   - "vault_url" (string): Azure Key Vault URL (required)
//   - "tenant_id" (string): Azure AD tenant ID (optional)
//   - "client_id" (string): Azure service principal client ID (optional)
//   - "client_secret" (string): Azure service principal secret (optional)
func newAzureKVKeyProvider(config map[string]interface{}) (types.KeyProvider, error) {
	azConfig := &azurekv.Config{
		KeyStorage: storage.New(),
	}

	if vaultURL, ok := config["vault_url"].(string); ok {
		azConfig.VaultURL = vaultURL
	}
	if tenantID, ok := config["tenant_id"].(string); ok {
		azConfig.TenantID = tenantID
	}
	if clientID, ok := config["client_id"].(string); ok {
		azConfig.ClientID = clientID
	}
	if clientSecret, ok := config["client_secret"].(string); ok {
		azConfig.ClientSecret = clientSecret
	}

	return azurekv.NewBackend(azConfig)
}

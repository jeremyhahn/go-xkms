// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

//go:build azurekv

package server

import (
	"fmt"

	"github.com/jeremyhahn/go-keychain/pkg/backend/azurekv"
	"github.com/jeremyhahn/go-keychain/pkg/storage/file"
)

// initAzureKVBackend initializes the Azure Key Vault backend if enabled in configuration
func (s *Server) initAzureKVBackend() error {
	if s.config.Backends.AzureKV == nil || !s.config.Backends.AzureKV.Enabled {
		return nil
	}

	// Create storage for Azure KV metadata
	storage, err := file.New(s.config.Storage.Path + "/azurekv")
	if err != nil {
		return fmt.Errorf("failed to create Azure KV storage: %w", err)
	}

	azureBackend, err := azurekv.NewBackend(&azurekv.Config{
		VaultURL:     s.config.Backends.AzureKV.VaultURL,
		TenantID:     s.config.Backends.AzureKV.TenantID,
		ClientID:     s.config.Backends.AzureKV.ClientID,
		ClientSecret: s.config.Backends.AzureKV.ClientSecret,
		KeyStorage:   storage,
	})
	if err != nil {
		return fmt.Errorf("failed to create Azure Key Vault backend: %w", err)
	}

	s.backends["azurekv"] = azureBackend
	s.logger.Info("Azure Key Vault backend initialized", "backend", "azurekv", "vault_url", s.config.Backends.AzureKV.VaultURL)
	return nil
}

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

//go:build azurekv

package server

import (
	"github.com/jeremyhahn/go-xkms/pkg/backend/azurekv"
)

// initAzureKVBackend initializes the Azure Key Vault backend if enabled in configuration
func (s *Server) initAzureKVBackend() error {
	if s.config.Backends.AzureKV == nil || !s.config.Backends.AzureKV.Enabled {
		return nil
	}

	// Create storage for Azure KV metadata
	storage, err := s.createStorage("azurekv")
	if err != nil {
		return &ErrStorageCreate{Resource: "Azure KV storage", Err: err}
	}

	azureBackend, err := azurekv.NewBackend(&azurekv.Config{
		VaultURL:     s.config.Backends.AzureKV.VaultURL,
		TenantID:     s.config.Backends.AzureKV.TenantID,
		ClientID:     s.config.Backends.AzureKV.ClientID,
		ClientSecret: s.config.Backends.AzureKV.ClientSecret,
		KeyStorage:   storage,
	})
	if err != nil {
		return &ErrBackendCreate{Backend: "Azure Key Vault", Err: err}
	}

	s.keyProviders["azurekv"] = azureBackend
	s.logger.Info("Azure Key Vault backend initialized", "backend", "azurekv", "vault_url", s.config.Backends.AzureKV.VaultURL)
	return nil
}

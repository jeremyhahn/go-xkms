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

//go:build vault

package server

import (
	"fmt"

	"github.com/jeremyhahn/go-keychain/pkg/backend/vault"
	"github.com/jeremyhahn/go-keychain/pkg/storage/file"
)

// initVaultBackend initializes the HashiCorp Vault backend if enabled in configuration
func (s *Server) initVaultBackend() error {
	if s.config.Backends.Vault == nil || !s.config.Backends.Vault.Enabled {
		return nil
	}

	// Create storage for Vault metadata
	storage, err := file.New(s.config.Storage.Path + "/vault")
	if err != nil {
		return fmt.Errorf("failed to create Vault storage: %w", err)
	}

	transitPath := s.config.Backends.Vault.MountPath
	if transitPath == "" {
		transitPath = "transit"
	}

	vaultBackend, err := vault.NewBackend(&vault.Config{
		Address:     s.config.Backends.Vault.Address,
		Token:       s.config.Backends.Vault.Token,
		TransitPath: transitPath,
		Namespace:   s.config.Backends.Vault.Namespace,
		KeyStorage:  storage,
	})
	if err != nil {
		return fmt.Errorf("failed to create Vault backend: %w", err)
	}

	s.backends["vault"] = vaultBackend
	s.logger.Info("Vault backend initialized", "backend", "vault", "address", s.config.Backends.Vault.Address)
	return nil
}

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
	"github.com/jeremyhahn/go-keychain/pkg/storage"
	"github.com/jeremyhahn/go-keychain/pkg/storage/file"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

func createAzureKVBackend(config BackendConfig) (types.Backend, error) {
	vaultURL, _ := config.Config["vault_url"].(string)
	if vaultURL == "" {
		return nil, fmt.Errorf("vault_url is required for Azure Key Vault backend")
	}

	tenantID, _ := config.Config["tenant_id"].(string)
	clientID, _ := config.Config["client_id"].(string)
	clientSecret, _ := config.Config["client_secret"].(string)
	debug, _ := config.Config["debug"].(bool)

	// Create storage
	keyDir, ok := config.Config["key_dir"].(string)
	if !ok || keyDir == "" {
		keyDir = "/tmp/keystore/azurekv/keys"
	}
	certDir, ok := config.Config["cert_dir"].(string)
	if !ok || certDir == "" {
		certDir = "/tmp/keystore/azurekv/certs"
	}

	var keyStorage storage.Backend
	var err error
	if keyDir == "memory" {
		keyStorage = storage.New()
	} else {
		keyStorage, err = file.New(keyDir)
		if err != nil {
			return nil, fmt.Errorf("failed to create key storage: %w", err)
		}
	}

	var certStorage storage.Backend
	if certDir == "memory" {
		certStorage = storage.New()
	} else {
		certStorage, err = file.New(certDir)
		if err != nil {
			return nil, fmt.Errorf("failed to create cert storage: %w", err)
		}
	}

	azureConfig := &azurekv.Config{
		VaultURL:     vaultURL,
		TenantID:     tenantID,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Debug:        debug,
		KeyStorage:   keyStorage,
		CertStorage:  certStorage,
	}

	return azurekv.NewBackend(azureConfig)
}

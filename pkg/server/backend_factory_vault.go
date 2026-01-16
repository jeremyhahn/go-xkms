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
	"os"

	"github.com/jeremyhahn/go-keychain/pkg/backend/vault"
	"github.com/jeremyhahn/go-keychain/pkg/storage"
	"github.com/jeremyhahn/go-keychain/pkg/storage/file"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

func createVaultBackend(config BackendConfig) (types.Backend, error) {
	address, _ := config.Config["address"].(string)
	if address == "" {
		address = os.Getenv("VAULT_ADDR")
		if address == "" {
			return nil, fmt.Errorf("address is required for Vault backend (or set VAULT_ADDR)")
		}
	}

	token, _ := config.Config["token"].(string)
	if token == "" {
		token = os.Getenv("VAULT_TOKEN")
		if token == "" {
			return nil, fmt.Errorf("token is required for Vault backend (or set VAULT_TOKEN)")
		}
	}

	transitPath, _ := config.Config["transit_path"].(string)
	if transitPath == "" {
		transitPath = "transit"
	}

	namespace, _ := config.Config["namespace"].(string)
	tlsSkipVerify, _ := config.Config["tls_skip_verify"].(bool)

	// Create storage
	keyDir, ok := config.Config["key_dir"].(string)
	if !ok || keyDir == "" {
		keyDir = "/tmp/keystore/vault/keys"
	}
	certDir, ok := config.Config["cert_dir"].(string)
	if !ok || certDir == "" {
		certDir = "/tmp/keystore/vault/certs"
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

	vaultConfig := &vault.Config{
		Address:       address,
		Token:         token,
		TransitPath:   transitPath,
		Namespace:     namespace,
		TLSSkipVerify: tlsSkipVerify,
		KeyStorage:    keyStorage,
		CertStorage:   certStorage,
	}

	return vault.NewBackend(vaultConfig)
}

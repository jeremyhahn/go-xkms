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

//go:build pkcs11

package server

import (
	"fmt"

	"github.com/jeremyhahn/go-keychain/pkg/backend/pkcs11"
	"github.com/jeremyhahn/go-keychain/pkg/storage"
	"github.com/jeremyhahn/go-keychain/pkg/storage/file"
	"github.com/jeremyhahn/go-keychain/pkg/storage/memory"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

func createPKCS11Backend(config BackendConfig) (types.Backend, error) {
	// Extract configuration values
	library, _ := config.Config["library_path"].(string)
	if library == "" {
		return nil, fmt.Errorf("library_path is required for PKCS11 backend")
	}

	tokenLabel, _ := config.Config["token_label"].(string)
	if tokenLabel == "" {
		return nil, fmt.Errorf("token_label is required for PKCS11 backend")
	}

	pin, _ := config.Config["pin"].(string)
	soPin, _ := config.Config["so_pin"].(string)
	cn, _ := config.Config["cn"].(string)
	libraryConfig, _ := config.Config["library_config"].(string)
	platformPolicy, _ := config.Config["platform_policy"].(bool)

	// Handle slot (can be nil or int)
	var slot *int
	if slotVal, ok := config.Config["slot"]; ok {
		if slotInt, ok := slotVal.(int); ok {
			slot = &slotInt
		}
	}

	// Create storage
	keyDir, ok := config.Config["key_dir"].(string)
	if !ok || keyDir == "" {
		keyDir = "/tmp/keystore/pkcs11/keys"
	}
	certDir, ok := config.Config["cert_dir"].(string)
	if !ok || certDir == "" {
		certDir = "/tmp/keystore/pkcs11/certs"
	}

	var keyStorage storage.Backend
	var err error
	if keyDir == "memory" {
		keyStorage = memory.New()
	} else {
		keyStorage, err = file.New(keyDir)
		if err != nil {
			return nil, fmt.Errorf("failed to create key storage: %w", err)
		}
	}

	var certStorage storage.Backend
	if certDir == "memory" {
		certStorage = memory.New()
	} else {
		certStorage, err = file.New(certDir)
		if err != nil {
			return nil, fmt.Errorf("failed to create cert storage: %w", err)
		}
	}

	pkcs11Config := &pkcs11.Config{
		CN:             cn,
		Library:        library,
		LibraryConfig:  libraryConfig,
		PIN:            pin,
		SOPIN:          soPin,
		PlatformPolicy: platformPolicy,
		Slot:           slot,
		TokenLabel:     tokenLabel,
		KeyStorage:     keyStorage,
		CertStorage:    certStorage,
	}

	return pkcs11.NewBackend(pkcs11Config)
}

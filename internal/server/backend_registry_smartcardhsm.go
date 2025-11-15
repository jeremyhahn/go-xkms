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
	"github.com/jeremyhahn/go-keychain/pkg/backend/smartcardhsm"
	"github.com/jeremyhahn/go-keychain/pkg/storage"
	"github.com/jeremyhahn/go-keychain/pkg/storage/file"
	"github.com/jeremyhahn/go-keychain/pkg/storage/memory"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

func createSmartCardHSMBackend(config BackendConfig) (types.Backend, error) {
	// Extract PKCS#11 configuration values (SmartCard-HSM uses PKCS#11)
	library, _ := config.Config["library_path"].(string)
	if library == "" {
		return nil, fmt.Errorf("library_path is required for SmartCard-HSM backend")
	}

	tokenLabel, _ := config.Config["token_label"].(string)
	if tokenLabel == "" {
		return nil, fmt.Errorf("token_label is required for SmartCard-HSM backend")
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

	// DKEK configuration
	dkekShares, _ := config.Config["dkek_shares"].(int)
	if dkekShares == 0 {
		dkekShares = 5 // default
	}

	dkekThreshold, _ := config.Config["dkek_threshold"].(int)
	if dkekThreshold == 0 {
		dkekThreshold = 3 // default
	}

	// Create storage
	keyDir, ok := config.Config["key_dir"].(string)
	if !ok || keyDir == "" {
		keyDir = "/tmp/keystore/smartcardhsm/keys"
	}
	certDir, ok := config.Config["cert_dir"].(string)
	if !ok || certDir == "" {
		certDir = "/tmp/keystore/smartcardhsm/certs"
	}
	dkekDir, ok := config.Config["dkek_dir"].(string)
	if !ok || dkekDir == "" {
		dkekDir = "/tmp/keystore/smartcardhsm/dkek"
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

	// DKEK storage
	var dkekStorage storage.Backend
	if dkekDir == "memory" {
		dkekStorage = memory.New()
	} else {
		dkekStorage, err = file.New(dkekDir)
		if err != nil {
			return nil, fmt.Errorf("failed to create dkek storage: %w", err)
		}
	}

	// Create PKCS#11 config for SmartCard-HSM
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

	// Create SmartCard-HSM config
	scConfig := &smartcardhsm.Config{
		PKCS11Config:  pkcs11Config,
		DKEKShares:    dkekShares,
		DKEKThreshold: dkekThreshold,
		DKEKStorage:   dkekStorage,
	}

	return smartcardhsm.NewBackend(scConfig)
}

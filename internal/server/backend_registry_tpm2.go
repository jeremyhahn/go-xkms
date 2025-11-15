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

//go:build tpm2

package server

import (
	"fmt"

	"github.com/jeremyhahn/go-keychain/pkg/storage"
	"github.com/jeremyhahn/go-keychain/pkg/storage/file"
	"github.com/jeremyhahn/go-keychain/pkg/storage/memory"
	"github.com/jeremyhahn/go-keychain/pkg/tpm2"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

func createTPM2Backend(config BackendConfig) (types.Backend, error) {
	// Extract configuration values
	cn, _ := config.Config["cn"].(string)
	if cn == "" {
		cn = "keychain"
	}

	devicePath, _ := config.Config["device"].(string)
	useSimulator, _ := config.Config["use_simulator"].(bool)
	simulatorType, _ := config.Config["simulator_type"].(string)
	simulatorHost, _ := config.Config["simulator_host"].(string)
	simulatorPort, _ := config.Config["simulator_port"].(int)

	srkHandle, ok := config.Config["srk_handle"].(uint32)
	if !ok {
		if srkHandleInt, ok := config.Config["srk_handle"].(int); ok {
			srkHandle = uint32(srkHandleInt)
		} else {
			srkHandle = 0x81000001 // Default SRK handle
		}
	}

	hierarchy, _ := config.Config["hierarchy"].(string)
	platformPolicy, _ := config.Config["platform_policy"].(bool)
	encryptSession, _ := config.Config["encrypt_session"].(bool)

	// Handle PCR selection
	var pcrSelection []int
	if pcrSel, ok := config.Config["pcr_selection"].([]interface{}); ok {
		for _, v := range pcrSel {
			if pcr, ok := v.(int); ok {
				pcrSelection = append(pcrSelection, pcr)
			}
		}
	}

	// Create storage
	keyDir, ok := config.Config["key_dir"].(string)
	if !ok || keyDir == "" {
		keyDir = "/tmp/keystore/tpm2/keys"
	}
	certDir, ok := config.Config["cert_dir"].(string)
	if !ok || certDir == "" {
		certDir = "/tmp/keystore/tpm2/certs"
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

	tpm2Config := &tpm2.Config{
		CN:             cn,
		DevicePath:     devicePath,
		UseSimulator:   useSimulator,
		SimulatorType:  simulatorType,
		SimulatorHost:  simulatorHost,
		SimulatorPort:  simulatorPort,
		SRKHandle:      srkHandle,
		Hierarchy:      hierarchy,
		PlatformPolicy: platformPolicy,
		PCRSelection:   pcrSelection,
		EncryptSession: encryptSession,
		SessionConfig:  nil, // Use default session config
	}

	// Create TPM2 keystore
	keystore, err := tpm2.NewTPM2KeyStore(tpm2Config, nil, keyStorage, certStorage, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create TPM2 keystore: %w", err)
	}

	// Initialize the TPM (provision SRK)
	// Pass nil for PINs - TPM2 backend will use defaults or handle as appropriate
	if err := keystore.Initialize(nil, nil); err != nil {
		return nil, fmt.Errorf("failed to initialize TPM2 keystore: %w", err)
	}

	// Return the keystore as a backend
	return keystore, nil
}

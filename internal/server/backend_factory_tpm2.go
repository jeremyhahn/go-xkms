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

package server

import (
	"fmt"

	tpm2backend "github.com/jeremyhahn/go-keychain/pkg/backend/tpm2"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

func createTPM2Backend(config BackendConfig) (types.Backend, error) {
	// Extract configuration values
	cn, _ := config.Config["cn"].(string)
	if cn == "" {
		cn = "keychain"
	}

	device, _ := config.Config["device"].(string)
	if device == "" {
		device = "/dev/tpmrm0"
	}

	useSimulator, _ := config.Config["use_simulator"].(bool)
	encryptSession, _ := config.Config["encrypt_session"].(bool)
	platformPolicy, _ := config.Config["platform_policy"].(bool)

	srkHandle, ok := config.Config["srk_handle"].(uint32)
	if !ok {
		if srkHandleInt, ok := config.Config["srk_handle"].(int); ok {
			srkHandle = uint32(srkHandleInt)
		} else {
			srkHandle = 0x81000001 // Default SRK handle
		}
	}

	ekHandle, ok := config.Config["ek_handle"].(uint32)
	if !ok {
		if ekHandleInt, ok := config.Config["ek_handle"].(int); ok {
			ekHandle = uint32(ekHandleInt)
		} else {
			ekHandle = 0x81010001 // Default EK handle
		}
	}

	keyDir, _ := config.Config["key_dir"].(string)
	if keyDir == "" {
		keyDir = "./tpm2-keys"
	}

	hash, _ := config.Config["hash"].(string)
	if hash == "" {
		hash = "SHA-256"
	}

	platformPCR, ok := config.Config["platform_pcr"].(uint)
	if !ok {
		if pcrInt, ok := config.Config["platform_pcr"].(int); ok {
			platformPCR = uint(pcrInt)
		} else {
			platformPCR = 0
		}
	}

	platformPCRBank, _ := config.Config["platform_pcr_bank"].(string)
	if platformPCRBank == "" {
		platformPCRBank = "SHA256"
	}

	// Create TPM2 backend configuration
	tpmConfig := &tpm2backend.Config{
		Device:          device,
		KeyDir:          keyDir,
		UseSimulator:    useSimulator,
		EncryptSession:  encryptSession,
		SRKHandle:       srkHandle,
		EKHandle:        ekHandle,
		Hash:            hash,
		PlatformPolicy:  platformPolicy,
		PlatformPCR:     platformPCR,
		PlatformPCRBank: platformPCRBank,
		CN:              cn,
	}

	backend, err := tpm2backend.NewBackend(tpmConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create TPM2 backend: %w", err)
	}

	return backend, nil
}

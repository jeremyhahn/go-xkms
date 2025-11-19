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

	"github.com/jeremyhahn/go-keychain/internal/tpm/store"
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

	device, _ := config.Config["device"].(string)
	if device == "" {
		device = "/dev/tpmrm0"
	}

	useSimulator, _ := config.Config["use_simulator"].(bool)
	encryptSession, _ := config.Config["encrypt_session"].(bool)

	srkHandle, ok := config.Config["srk_handle"].(uint32)
	if !ok {
		if srkHandleInt, ok := config.Config["srk_handle"].(int); ok {
			srkHandle = uint32(srkHandleInt)
		} else {
			srkHandle = 0x81000001 // Default SRK handle
		}
	}

	platformPolicy, _ := config.Config["platform_policy"].(bool)

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

	// Create TPM2 config with new structure
	tpm2Config := &tpm2.Config{
		Device:         device,
		UseSimulator:   useSimulator,
		EncryptSession: encryptSession,
		KeyStore: &tpm2.KeyStoreConfig{
			CN:             cn,
			SRKHandle:      srkHandle,
			PlatformPolicy: platformPolicy,
		},
	}

	// Create TPM2 params
	params := &tpm2.Params{
		Config:    tpm2Config,
		BlobStore: keyStorage.(store.BlobStorer),
		CertStore: certStorage.(store.CertificateStorer),
	}

	// Create TPM2 instance
	tpmBackend, err := tpm2.NewTPM2(params)
	if err != nil {
		return nil, fmt.Errorf("failed to create TPM2 instance: %w", err)
	}

	// Return the TPM backend
	return tpmBackend.(types.Backend), nil
}

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
	"github.com/jeremyhahn/go-keychain/pkg/storage/file"
	"github.com/jeremyhahn/go-keychain/pkg/tpm2"
)

// initTPM2Backend initializes the TPM2 backend if enabled in configuration
func (s *Server) initTPM2Backend() error {
	if s.config.Backends.TPM2 == nil || !s.config.Backends.TPM2.Enabled {
		return nil
	}

	// Create storage for TPM2 metadata
	keyStorage, err := file.New(s.config.Storage.Path + "/tpm2")
	if err != nil {
		return fmt.Errorf("failed to create TPM2 key storage: %w", err)
	}

	certStorage, err := file.New(s.config.Storage.Path + "/tpm2/certs")
	if err != nil {
		return fmt.Errorf("failed to create TPM2 cert storage: %w", err)
	}

	// Create TPM2 config with new structure
	devicePath := s.config.Backends.TPM2.DevicePath
	if devicePath == "" {
		devicePath = "/dev/tpmrm0"
	}

	tpm2Config := &tpm2.Config{
		Device:         devicePath,
		UseSimulator:   false,
		EncryptSession: false,
		KeyStore: &tpm2.KeyStoreConfig{
			CN:             "tpm2-backend",
			SRKHandle:      0x81000001,
			PlatformPolicy: false,
		},
	}

	// Create TPM2 params
	params := &tpm2.Params{
		Config:    tpm2Config,
		BlobStore: keyStorage.(store.BlobStorer),
		CertStore: certStorage.(store.CertificateStorer),
	}

	// Create TPM2 instance
	tpm2Backend, err := tpm2.NewTPM2(params)
	if err != nil {
		return fmt.Errorf("failed to create TPM2 backend: %w", err)
	}

	// TODO: TPM2 needs a Backend wrapper to implement types.Backend interface
	// The TrustedPlatformModule interface doesn't have all required methods:
	// Type(), Capabilities(), GenerateKey(), GetKey(), ListKeys(), Signer(), Decrypter(), RotateKey()
	// For now, TPM2 is initialized but not added to backends map.
	// A proper pkg/backend/tpm2 wrapper should be created similar to awskms, azurekv, etc.
	// s.backends["tpm2"] = tpm2Backend

	_ = tpm2Backend // Prevent unused variable error
	s.logger.Info("TPM2 backend initialized", "backend", "tpm2", "device", devicePath)
	return nil
}

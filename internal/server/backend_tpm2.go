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

	// TPM2KeyStore now implements types.Backend interface
	tpm2Config := &tpm2.Config{
		CN:           "tpm2-backend",
		DevicePath:   s.config.Backends.TPM2.DevicePath,
		UseSimulator: false,
	}

	// nil for tpmTransport means NewTPM2KeyStore will open its own TPM connection
	tpm2Backend, err := tpm2.NewTPM2KeyStore(tpm2Config, nil, keyStorage, certStorage, nil)
	if err != nil {
		return fmt.Errorf("failed to create TPM2 backend: %w", err)
	}

	// Store as backend (TPM2KeyStore implements types.Backend)
	s.backends["tpm2"] = tpm2Backend
	s.logger.Info("TPM2 backend initialized", "backend", "tpm2", "device", s.config.Backends.TPM2.DevicePath)
	return nil
}

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
)

// initTPM2Backend initializes the TPM2 backend if enabled in configuration
func (s *Server) initTPM2Backend() error {
	if s.config.Backends.TPM2 == nil || !s.config.Backends.TPM2.Enabled {
		return nil
	}

	// Get device path with default
	devicePath := s.config.Backends.TPM2.DevicePath
	if devicePath == "" {
		devicePath = "/dev/tpmrm0"
	}

	// Create TPM2 backend configuration
	tpmConfig := &tpm2backend.Config{
		Device: devicePath,
		KeyDir: s.config.Storage.Path + "/tpm2-keys",
		CN:     "keychain",
	}

	// Create TPM2 backend
	tpmBackend, err := tpm2backend.NewBackend(tpmConfig)
	if err != nil {
		return fmt.Errorf("failed to create TPM2 backend: %w", err)
	}

	s.backends["tpm2"] = tpmBackend
	s.logger.Info("TPM2 backend initialized", "backend", "tpm2", "device", devicePath)
	return nil
}

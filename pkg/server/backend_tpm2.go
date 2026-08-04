// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package server

import (
	tpm2backend "github.com/jeremyhahn/go-xkms/pkg/backend/tpm2"
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

	// When the seal autodetect already opened this TPM (node-barrier flip),
	// reuse that single open: build the general backend over the SAME TPM
	// connection via NewBackendWithTPM. A second independent open would hang a
	// swtpm emulator; sharing the connection also keeps one PlatformKeyStore /
	// policy state. The shared TPM is closed once, at node shutdown
	// (nodeSealClose), not by this backend (externalTPM).
	if shared, ok := s.nodeSealTPM.(*tpm2backend.Backend); ok {
		tpmBackend, err := tpm2backend.NewBackendWithTPM(&tpm2backend.ExternalTPMConfig{
			TPM:    shared.TPM(),
			KeyDir: s.config.Storage.Path + "/tpm2-keys",
			Logger: s.logger,
		})
		if err != nil {
			return &ErrBackendCreate{Backend: "TPM2", Err: err}
		}
		s.keyProviders["tpm2"] = tpmBackend
		s.logger.Info("TPM2 backend reuses the seal autodetect's single TPM open", "backend", "tpm2", "device", devicePath)
		return nil
	}

	// Create TPM2 backend configuration
	tpmConfig := &tpm2backend.Config{
		Device:          devicePath,
		KeyDir:          s.config.Storage.Path + "/tpm2-keys",
		CN:              "xkms",
		UseSimulator:    s.config.Backends.TPM2.UseSimulator,
		SimulatorHost:   s.config.Backends.TPM2.SimulatorHost,
		SimulatorPort:   s.config.Backends.TPM2.SimulatorPort,
		SRKHandle:       s.config.Backends.TPM2.SRKHandle,
		PlatformPolicy:  s.config.Backends.TPM2.PlatformPolicy,
		PlatformPCR:     s.config.Backends.TPM2.PlatformPCR,
		PlatformPCRBank: s.config.Backends.TPM2.PlatformPCRBank,
	}

	// Create TPM2 backend
	tpmBackend, err := tpm2backend.NewBackend(tpmConfig)
	if err != nil {
		return &ErrBackendCreate{Backend: "TPM2", Err: err}
	}

	s.keyProviders["tpm2"] = tpmBackend
	s.logger.Info("TPM2 backend initialized", "backend", "tpm2", "device", devicePath)
	return nil
}

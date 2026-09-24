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

// tpm2KeyDirSubdir is the fixed subdirectory, under the configured storage
// path, where the TPM2 backend and the TPM2 node-barrier seal strategy
// persist sealed key blobs.
const tpm2KeyDirSubdir = "tpm2-keys"

// resolveTPM2KeyDir resolves the directory where TPM2-sealed key material is
// persisted. It is always derived from the configured storage path and must
// never fall back to a directory resolved relative to the process's working
// directory: some callers of this package (embedded/programmatic
// construction of *config.Config) never run config.Config.Validate, so an
// empty Storage.Path cannot be assumed to have already been rejected.
func (s *Server) resolveTPM2KeyDir() (string, error) {
	return resolveTPM2KeyDir(s.config)
}

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

	keyDir, err := s.resolveTPM2KeyDir()
	if err != nil {
		return &ErrBackendCreate{Backend: "TPM2", Err: err}
	}

	// When an earlier step already opened this TPM -- the seal autodetect for
	// the node-barrier flip (s.nodeSealTPM), or the platform store's tpm2
	// credential strategy (s.platformStoreTPM, initializePlatformStore, which
	// runs before this) -- reuse that single open: build the general backend
	// over the SAME TPM connection via NewBackendWithTPM. A second independent
	// open hangs the simulator (and a real swtpm); sharing the connection also
	// keeps one PlatformKeyStore / policy state. Whichever field opened it owns
	// closing it (nodeSealClose at node shutdown, or platformStoreTPMClose at
	// server shutdown) -- not this backend (externalTPM).
	shared, ok := s.nodeSealTPM.(*tpm2backend.Backend)
	sharedFrom := "the seal autodetect's single TPM open"
	if !ok {
		shared, ok = s.platformStoreTPM.(*tpm2backend.Backend)
		sharedFrom = "the platform store's tpm2 credential strategy TPM open"
	}
	if ok {
		keyBackend, err := tpm2backend.NewFileKeyBackend(s.logger, keyDir)
		if err != nil {
			return &ErrBackendCreate{Backend: "TPM2", Err: err}
		}
		tpmBackend, err := tpm2backend.NewBackendWithTPM(&tpm2backend.ExternalTPMConfig{
			TPM:        shared.TPM(),
			KeyBackend: keyBackend,
			KeyDir:     keyDir,
			Logger:     s.logger,
		})
		if err != nil {
			return &ErrBackendCreate{Backend: "TPM2", Err: err}
		}
		s.keyProviders["tpm2"] = tpmBackend
		s.logger.Info("TPM2 backend reuses "+sharedFrom, "backend", "tpm2", "device", devicePath)
		return nil
	}

	// Create TPM2 backend configuration
	tpmConfig := &tpm2backend.Config{
		Device:          devicePath,
		KeyDir:          keyDir,
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

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

// initTPM2Backend initializes the TPM2 backend if enabled in configuration
func (s *Server) initTPM2Backend() error {
	if s.config.Backends.TPM2 == nil || !s.config.Backends.TPM2.Enabled {
		return nil
	}

	// Get device path for logging
	devicePath := s.config.Backends.TPM2.DevicePath
	if devicePath == "" {
		devicePath = "/dev/tpmrm0"
	}

	// TODO: TPM2 backend not yet fully integrated
	// The following issues need to be resolved:
	// 1. Interface conflicts between storage.Backend and store.CertificateStorer
	//    - Conflicting Delete method signatures prevent type assertions
	//    - Requires adapter pattern for storage.Backend -> store.BlobStorer/CertificateStorer
	// 2. Interface conflict between TrustedPlatformModule and types.Backend
	//    - Missing Capabilities() (types.Capabilities, error) method
	//    - Conflicting DeleteKey signature
	//    - Requires adapter wrapper to implement types.Backend interface
	// 3. TPM2.NewTPM2() panics with nil BlobStore/CertStore
	//
	// A proper pkg/backend/tpm2 wrapper should be created similar to awskms, azurekv, etc.
	s.logger.Info("TPM2 backend not enabled (not yet integrated)", "backend", "tpm2", "device", devicePath)
	return nil
}

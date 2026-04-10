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

// Package xkms provides the TPM 2.0 backend registration and factory.
//
// The TPM 2.0 backend leverages hardware-based key storage and cryptographic
// operations through a Trusted Platform Module. Keys are protected by the TPM's
// hardware security boundary.
//
// This backend is always compiled in. The factory will return an error at
// runtime if no TPM device is available, which AutoInitialize handles by
// skipping the backend.
package xkms

import (
	tpm2backend "github.com/jeremyhahn/go-xkms/pkg/backend/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

func init() {
	RegisterBackend(BackendTPM2)
	RegisterBackendFactory(BackendTPM2, newTPM2KeyProvider)
}

// newTPM2KeyProvider creates a TPM 2.0 backend KeyProvider from configuration.
//
// Supported configuration keys:
//   - "device" (string): Path to TPM device (default: "/dev/tpmrm0")
//   - "key_dir" (string): Directory for TPM key blob storage (default: "./tpm2-keys")
//   - "use_simulator" (bool): Use TPM simulator instead of hardware
//   - "simulator_host" (string): Simulator hostname (default: "localhost")
//   - "simulator_port" (int): Simulator port (default: 2321)
//   - "encrypt_session" (bool): Enable encrypted TPM sessions
func newTPM2KeyProvider(config map[string]interface{}) (types.KeyProvider, error) {
	tpmConfig := &tpm2backend.Config{}

	if device, ok := config["device"].(string); ok {
		tpmConfig.Device = device
	}
	if keyDir, ok := config["key_dir"].(string); ok {
		tpmConfig.KeyDir = keyDir
	}
	if useSim, ok := config["use_simulator"].(bool); ok {
		tpmConfig.UseSimulator = useSim
	}
	if host, ok := config["simulator_host"].(string); ok {
		tpmConfig.SimulatorHost = host
	}
	if port, ok := config["simulator_port"].(int); ok {
		tpmConfig.SimulatorPort = port
	}
	if encrypt, ok := config["encrypt_session"].(bool); ok {
		tpmConfig.EncryptSession = encrypt
	}

	return tpm2backend.NewBackend(tpmConfig)
}

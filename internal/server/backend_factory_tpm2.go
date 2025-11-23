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

	// Suppress unused variable warnings for config values
	_ = cn
	_ = device
	_ = useSimulator
	_ = encryptSession
	_ = srkHandle
	_ = config.Config["platform_policy"]

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
	return nil, fmt.Errorf("TPM2 backend not yet fully integrated - requires adapter for types.Backend interface")
}

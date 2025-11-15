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

package software

import (
	"fmt"

	"github.com/jeremyhahn/go-keychain/pkg/storage"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// Config contains configuration for the unified SoftwareBackend.
// This backend provides BOTH asymmetric (via PKCS#8) and symmetric (via AES)
// operations through a single unified interface.
type Config struct {
	// KeyStorage is the underlying storage for key material.
	// This can be file-based, memory-based, or any implementation
	// of the storage.Backend interface.
	//
	// The same storage is used for both asymmetric and symmetric keys,
	// which are differentiated by their key IDs.
	KeyStorage storage.Backend

	// Tracker is the AEAD safety tracker for nonce/bytes tracking.
	// If nil, a default memory-based tracker will be created.
	// For production systems, provide a persistent tracker.
	Tracker types.AEADSafetyTracker
}

// Validate checks if the Config is valid.
func (c *Config) Validate() error {
	if c == nil {
		return fmt.Errorf("config is nil")
	}
	if c.KeyStorage == nil {
		return fmt.Errorf("KeyStorage is required")
	}
	return nil
}

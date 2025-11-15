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

package pkcs8

import (
	"fmt"

	"github.com/jeremyhahn/go-keychain/pkg/storage"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// Config contains configuration for the PKCS8Backend.
type Config struct {
	// KeyStorage is the underlying storage for key material.
	// This can be file-based, memory-based, or any implementation
	// of the storage.Backend interface.
	KeyStorage storage.Backend
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

// NewBackend creates a new PKCS#8 backend with the given configuration.
//
// Example usage:
//
//	storage := memory.New()
//	config := &pkcs8.Config{
//	    KeyStorage: storage,
//	}
//	backend, err := pkcs8.NewBackend(config)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer backend.Close()
//
//	// Generate a new RSA key
//	attrs := &types.KeyAttributes{
//	    CN:           "example.com",
//	    KeyType:      backend.KEY_TYPE_TLS,
//	    StoreType:    backend.STORE_SW,
//	    KeyAlgorithm: backend.ALG_RSA,
//	    RSAAttributes: &types.RSAAttributes{
//	        KeySize: 2048,
//	        Hash:    backend.HASH_SHA256,
//	    },
//	}
//	key, err := backend.GenerateKey(attrs)
func NewBackend(config *Config) (types.Backend, error) {
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	return &PKCS8Backend{
		storage: config.KeyStorage,
		closed:  false,
	}, nil
}

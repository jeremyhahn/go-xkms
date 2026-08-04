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

package pkcs8

import (
	"github.com/jeremyhahn/go-xkms/pkg/errs"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// Config contains configuration for the PKCS8Backend.
type Config struct {
	// KeyStorage is the underlying storage for key material.
	// This can be file-based, memory-based, or any implementation
	// of the storage.Backend interface.
	KeyStorage storage.Backend

	// AllowPlaintextKeys controls whether the backend permits key persistence
	// without a password. The default (false) is fail-closed: GenerateKey
	// returns ErrPlaintextKeyNotAllowed when no password is supplied for a
	// software key. Set to true only when plaintext storage is intentional
	// (e.g., ephemeral test backends or keys that are encrypted at the
	// filesystem/volume layer instead).
	AllowPlaintextKeys bool
}

// Validate checks if the Config is valid.
func (c *Config) Validate() error {
	if c == nil {
		return &errs.Message{Msg: "config is nil"}
	}
	if c.KeyStorage == nil {
		return &errs.Message{Msg: "KeyStorage is required"}
	}
	return nil
}

// NewBackend creates a new PKCS#8 backend with the given configuration.
//
// Example usage:
//
//	storage := storage.New()
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
//	    KeyAlgorithm: x509.RSA,
//	    RSAAttributes: &types.RSAAttributes{
//	        KeySize: 2048,
//	        Hash:    backend.HASH_SHA256,
//	    },
//	}
//	key, err := backend.GenerateKey(attrs)
func NewBackend(config *Config) (types.KeyProvider, error) {
	if err := config.Validate(); err != nil {
		return nil, &errs.Wrapped{Msg: "invalid config", Err: err}
	}

	return &PKCS8Backend{
		storage:        config.KeyStorage,
		closed:         false,
		allowPlaintext: config.AllowPlaintextKeys,
	}, nil
}

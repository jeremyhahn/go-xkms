//go:build pkcs11

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

// Package xkms provides external PKCS#11/HSM backend registration and factory.
//
// The PKCS#11 backend allows integration with external Hardware Security Modules
// (HSMs) and smart cards that provide a PKCS#11 interface.
//
// This file is only compiled when the 'pkcs11' build tag is specified.
package xkms

import (
	"fmt"

	"github.com/jeremyhahn/go-xkms/pkg/backend/pkcs11"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/storage/file"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

func init() {
	RegisterBackend(BackendPKCS11)
	RegisterBackendFactory(BackendPKCS11, newPKCS11KeyProvider)
}

// newPKCS11KeyProvider creates a PKCS#11 backend KeyProvider from configuration.
//
// Supported configuration keys:
//   - "library" (string): Path to PKCS#11 library (required)
//   - "config" (string): Path to library configuration file (optional)
//   - "pin" (string): User PIN for token access (optional)
//   - "so_pin" (string): Security Officer PIN (optional)
//   - "label" (string): Token label for identification (optional)
//   - "slot" (int): Token slot number (optional, alternative to label)
func newPKCS11KeyProvider(config map[string]interface{}) (types.KeyProvider, error) {
	p11Config := &pkcs11.Config{}

	// Accept pre-built storage backends from callers (e.g., dynamic registration).
	if ks, ok := config["key_storage"].(storage.Backend); ok {
		p11Config.KeyStorage = ks
	}
	if cs, ok := config["cert_storage"].(storage.Backend); ok {
		p11Config.CertStorage = cs
	}

	// Create file-based storage from key_dir when no pre-built backends provided.
	if keyDir, ok := config["key_dir"].(string); ok && keyDir != "" && keyDir != "memory" {
		if p11Config.KeyStorage == nil {
			fs, err := file.New(keyDir)
			if err != nil {
				return nil, fmt.Errorf("pkcs11: failed to create key storage at %s: %w", keyDir, err)
			}
			p11Config.KeyStorage = fs
		}
		if p11Config.CertStorage == nil {
			certDir := keyDir + "/certs"
			fs, err := file.New(certDir)
			if err != nil {
				return nil, fmt.Errorf("pkcs11: failed to create cert storage at %s: %w", certDir, err)
			}
			p11Config.CertStorage = fs
		}
	}

	// Fall back to in-memory storage for testing or when no key_dir is set.
	if p11Config.KeyStorage == nil {
		p11Config.KeyStorage = storage.New()
	}
	if p11Config.CertStorage == nil {
		p11Config.CertStorage = storage.New()
	}

	if library, ok := config["library"].(string); ok {
		p11Config.Library = library
	}
	if libConfig, ok := config["config"].(string); ok {
		p11Config.LibraryConfig = libConfig
	}
	if pin, ok := config["pin"].(string); ok {
		p11Config.PIN = pin
	}
	if sopin, ok := config["so_pin"].(string); ok {
		p11Config.SOPIN = sopin
	}
	if label, ok := config["label"].(string); ok {
		p11Config.TokenLabel = label
	}
	if slot, ok := config["slot"].(int); ok {
		p11Config.Slot = &slot
	}

	return pkcs11.NewBackend(p11Config)
}

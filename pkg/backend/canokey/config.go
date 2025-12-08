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

//go:build pkcs11

package canokey

import (
	"os"

	"github.com/jeremyhahn/go-keychain/pkg/storage"
)

// DefaultPIN is the factory default PIN for CanoKey PIV
const DefaultPIN = "123456"

// Config holds CanoKey backend configuration
type Config struct {
	// PIN is the CanoKey PIV PIN (default: "123456")
	PIN string

	// Library is the path to the PKCS#11 library (opensc-pkcs11.so)
	// If empty, will attempt to auto-detect from common locations
	// Default: /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so
	Library string

	// TokenLabel is the PKCS#11 token label for CanoKey
	// If empty, will auto-detect the first available CanoKey
	// CanoKey shows as "Canokeys [OpenPGP PIV OATH]" in pcsc_scan
	TokenLabel string

	// Slot is the CanoKey PIV slot number (e.g., 0x9a for Authentication)
	// Use canokey.Slot* constants to specify the slot
	// This must be set when using the CanoKey backend for key operations
	Slot *uint

	// KeyStorage is the backend for key metadata storage
	KeyStorage storage.Backend

	// CertStorage is the backend for certificate storage
	CertStorage storage.Backend

	// IsVirtual indicates if using CanoKey QEMU (virtual device)
	// Set to true when using software emulation for testing
	// This affects the HardwareBacked capability flag
	IsVirtual bool

	// Debug enables detailed logging
	Debug bool
}

// Validate checks if the configuration is valid
func (c *Config) Validate() error {
	if c.PIN == "" {
		return ErrPINRequired
	}

	if len(c.PIN) < 6 || len(c.PIN) > 8 {
		return ErrInvalidPINLength
	}

	if c.KeyStorage == nil {
		return ErrKeyStorageRequired
	}

	if c.CertStorage == nil {
		return ErrCertStorageRequired
	}

	return nil
}

// SetDefaults applies default values to empty configuration fields
func (c *Config) SetDefaults() {
	if c.PIN == "" {
		c.PIN = DefaultPIN
	}

	if c.Library == "" {
		c.Library = autoDetectLibrary()
	}
}

// autoDetectLibrary attempts to find the OpenSC PKCS#11 library
func autoDetectLibrary() string {
	candidates := []string{
		"/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so", // Debian/Ubuntu default
		"/usr/lib64/opensc-pkcs11.so",                // RHEL/CentOS/Fedora
		"/usr/lib/opensc-pkcs11.so",                  // Generic Linux
		"/usr/local/lib/opensc-pkcs11.so",            // Custom install
		"/usr/local/lib/opensc-pkcs11.dylib",         // macOS
		"/opt/homebrew/lib/opensc-pkcs11.dylib",      // macOS ARM (Homebrew)
	}

	// Check environment variable first
	if envLib := os.Getenv("CANOKEY_PKCS11_LIBRARY"); envLib != "" {
		if _, err := os.Stat(envLib); err == nil {
			return envLib
		}
	}

	// Try common locations
	for _, path := range candidates {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}

	// Return default and let initialization fail with helpful error
	return "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so"
}

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

package yubikey

import (
	"encoding/hex"
	"fmt"
	"os"

	"github.com/jeremyhahn/go-keychain/pkg/storage"
)

// DefaultMgmtKey is the default YubiKey PIV management key
// This is the factory default for all YubiKeys
var DefaultMgmtKey = mustDecodeHex("010203040506070801020304050607080102030405060708")

// DefaultPIN is the factory default PIN for YubiKey PIV
const DefaultPIN = "123456"

// DefaultPUK is the factory default PUK for YubiKey PIV
const DefaultPUK = "12345678"

// Config holds YubiKey backend configuration
type Config struct {
	// PIN is the YubiKey PIV PIN (default: "123456")
	PIN string

	// ManagementKey is used for administrative operations like key generation
	// Default: 010203040506070801020304050607080102030405060708 (hex)
	ManagementKey []byte

	// Library is the path to the YubiKey PKCS#11 library (libykcs11.so)
	// If empty, will attempt to auto-detect from common locations
	Library string

	// TokenLabel is the PKCS#11 token label (format: "YubiKey PIV #SERIALNUMBER")
	// If empty, will auto-detect the first available YubiKey
	TokenLabel string

	// Slot is the YubiKey PIV slot number (e.g., 0x9a for Authentication)
	// Use yubikey.Slot* constants to specify the slot
	// This must be set when using the YubiKey backend
	Slot *uint

	// KeyStorage is the backend for key metadata storage
	KeyStorage storage.Backend

	// CertStorage is the backend for certificate storage
	CertStorage storage.Backend

	// Debug enables detailed logging
	Debug bool
}

// Validate checks if the configuration is valid
func (c *Config) Validate() error {
	if c.PIN == "" {
		return fmt.Errorf("yubikey: PIN is required")
	}

	if len(c.PIN) < 6 || len(c.PIN) > 8 {
		return fmt.Errorf("yubikey: PIN must be 6-8 characters")
	}

	if c.ManagementKey == nil {
		return fmt.Errorf("yubikey: management key is required")
	}

	if len(c.ManagementKey) != 24 {
		return fmt.Errorf("yubikey: management key must be 24 bytes (192 bits)")
	}

	if c.KeyStorage == nil {
		return fmt.Errorf("yubikey: key storage is required")
	}

	if c.CertStorage == nil {
		return fmt.Errorf("yubikey: certificate storage is required")
	}

	return nil
}

// SetDefaults applies default values to empty configuration fields
func (c *Config) SetDefaults() {
	if c.PIN == "" {
		c.PIN = DefaultPIN
	}

	if c.ManagementKey == nil {
		c.ManagementKey = DefaultMgmtKey
	}

	if c.Library == "" {
		c.Library = autoDetectLibrary()
	}
}

// autoDetectLibrary attempts to find the YubiKey PKCS#11 library
func autoDetectLibrary() string {
	candidates := []string{
		"/usr/lib/x86_64-linux-gnu/libykcs11.so", // Debian/Ubuntu default
		"/usr/lib/libykcs11.so",                  // Generic Linux
		"/usr/local/lib/libykcs11.so",            // Custom install
		"/usr/local/lib/libykcs11.dylib",         // macOS
		"/opt/homebrew/lib/libykcs11.dylib",      // macOS ARM (Homebrew)
	}

	// Check environment variable first
	if envLib := os.Getenv("YUBIKEY_PKCS11_LIBRARY"); envLib != "" {
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
	return "/usr/lib/x86_64-linux-gnu/libykcs11.so"
}

// mustDecodeHex decodes a hex string or panics
func mustDecodeHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(fmt.Sprintf("failed to decode hex string: %v", err))
	}
	return b
}

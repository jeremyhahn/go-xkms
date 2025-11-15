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

package pkcs11

import (
	"fmt"
	"os"
	"strings"

	"github.com/jeremyhahn/go-keychain/pkg/storage"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// Config contains configuration for PKCS#11 backend operations.
// It specifies the PKCS#11 library to use, token identification,
// and authentication credentials.
type Config struct {
	// CN is the common name identifier for this PKCS#11 instance.
	// Used for logging and identification purposes.
	CN string `yaml:"cn,omitempty" json:"cn,omitempty" mapstructure:"cn"`

	// Library is the path to the PKCS#11 library file.
	// Examples:
	//   - /usr/lib/softhsm/libsofthsm2.so (SoftHSM)
	//   - /usr/lib/libykcs11.so (YubiKey)
	//   - /opt/nfast/toolkits/pkcs11/libcknfast.so (nCipher)
	Library string `yaml:"library" json:"library" mapstructure:"library"`

	// LibraryConfig is the path to the PKCS#11 library configuration file.
	// For SoftHSM, this is typically the softhsm2.conf file path.
	LibraryConfig string `yaml:"config" json:"config" mapstructure:"config"`

	// PIN is the user PIN for the PKCS#11 token.
	// This is used for normal cryptographic operations.
	PIN string `yaml:"pin,omitempty" json:"pin,omitempty" mapstructure:"pin"`

	// SOPIN is the Security Officer PIN for the PKCS#11 token.
	// This is used for administrative operations like token initialization.
	SOPIN string `yaml:"so-pin,omitempty" json:"so_pin,omitempty" mapstructure:"so-pin"`

	// PlatformPolicy indicates whether platform-specific policies should be applied.
	// This may affect key generation, storage, and usage policies.
	PlatformPolicy bool `yaml:"platform-policy" json:"platform_policy" mapstructure:"platform-policy"`

	// Slot is the slot number where the token is located.
	// Can be nil if TokenLabel is used instead.
	//
	// For YubiKey PIV: This is the PIV slot number (e.g., 0x9a, 0x9c, 0x9d, 0x9e)
	// For standard PKCS#11: This is the physical token slot number (e.g., 0, 1, 2)
	Slot *int `yaml:"slot,omitempty" json:"slot,omitempty" mapstructure:"slot"`

	// TokenLabel is the label of the PKCS#11 token to use.
	// This is an alternative to specifying a slot number.
	TokenLabel string `yaml:"label" json:"label" mapstructure:"label"`

	// KeyStorage is the underlying storage for key metadata.
	// This can be file-based, memory-based, or any implementation
	// of the storage.Backend interface.
	// Note: Actual key material stays in the HSM, this is for metadata only.
	KeyStorage storage.Backend `yaml:"-" json:"-" mapstructure:"-"`

	// CertStorage is the underlying storage for certificate material.
	// This can be file-based, memory-based, or any implementation
	// of the storage.Backend interface.
	CertStorage storage.Backend `yaml:"-" json:"-" mapstructure:"-"`

	// Tracker is the AEAD safety tracker for nonce/bytes tracking.
	// If nil, a default memory-based tracker will be created.
	// For production systems, provide a persistent tracker.
	Tracker types.AEADSafetyTracker `yaml:"-" json:"-" mapstructure:"-"`
}

// Validate checks if the configuration is valid and returns an error if not.
// It verifies that required fields are set and that values meet minimum requirements.
func (c *Config) Validate() error {
	if c == nil {
		return ErrInvalidConfig
	}

	// Library path is required
	if c.Library == "" {
		return fmt.Errorf("%w: library path is required", ErrInvalidConfig)
	}

	// Check if library file exists
	if _, err := os.Stat(c.Library); os.IsNotExist(err) {
		return fmt.Errorf("%w: %s", ErrLibraryNotFound, c.Library)
	}

	// Token label is required
	if c.TokenLabel == "" {
		return fmt.Errorf("%w: token label is required", ErrInvalidConfig)
	}

	// If PIN is set, validate length
	if c.PIN != "" && len(c.PIN) < 4 {
		return ErrInvalidPINLength
	}

	// If SOPIN is set, validate length
	if c.SOPIN != "" && len(c.SOPIN) < 4 {
		return ErrInvalidSOPINLength
	}

	// Storage providers are required
	if c.KeyStorage == nil {
		return fmt.Errorf("%w: key storage is required", ErrInvalidConfig)
	}
	if c.CertStorage == nil {
		return fmt.Errorf("%w: cert storage is required", ErrInvalidConfig)
	}

	return nil
}

// IsSoftHSM returns true if the library path indicates SoftHSM is being used.
func (c *Config) IsSoftHSM() bool {
	return strings.Contains(c.Library, "libsofthsm")
}

// IsYubiKeyPIV returns true if the library path indicates YubiKey PIV is being used.
func (c *Config) IsYubiKeyPIV() bool {
	return strings.Contains(c.Library, "libykcs11") || strings.Contains(c.Library, "ykcs11")
}

// String returns a string representation of the config with sensitive data masked.
func (c *Config) String() string {
	pinMask := "****"
	if c.PIN == "" {
		pinMask = "<not set>"
	}
	sopinMask := "****"
	if c.SOPIN == "" {
		sopinMask = "<not set>"
	}

	slot := "<not set>"
	if c.Slot != nil {
		slot = fmt.Sprintf("%d", *c.Slot)
	}

	return fmt.Sprintf("PKCS#11 Config{CN: %s, Library: %s, TokenLabel: %s, Slot: %s, PIN: %s, SOPIN: %s}",
		c.CN, c.Library, c.TokenLabel, slot, pinMask, sopinMask)
}

// SoftHSMConfig generates a SoftHSM v2 configuration file content.
// The tokenDir parameter specifies where SoftHSM should store token data.
func SoftHSMConfig(tokenDir string) string {
	return fmt.Sprintf(`# SoftHSM v2 configuration file

directories.tokendir = %s
objectstore.backend = file
objectstore.umask = 0077

# ERROR, WARNING, INFO, DEBUG
log.level = ERROR

# If CKF_REMOVABLE_DEVICE flag should be set
slots.removable = false

# Enable and disable PKCS#11 mechanisms using slots.mechanisms.
slots.mechanisms = ALL

# If the library should reset the state on fork
library.reset_on_fork = false
`, tokenDir)
}

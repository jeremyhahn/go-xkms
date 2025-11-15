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

package smartcardhsm

import (
	"fmt"

	"github.com/jeremyhahn/go-keychain/pkg/backend/pkcs11"
	"github.com/jeremyhahn/go-keychain/pkg/storage"
)

// Config contains configuration for SmartCard-HSM backend operations.
// SmartCard-HSM wraps a PKCS#11 backend and adds DKEK (Device Key Encryption Key)
// support for secure key backup and restore operations.
type Config struct {
	// PKCS11Config is the underlying PKCS#11 configuration for the SmartCard-HSM.
	// SmartCard-HSM devices are accessed through PKCS#11 interface.
	PKCS11Config *pkcs11.Config `yaml:"pkcs11" json:"pkcs11" mapstructure:"pkcs11"`

	// DKEKShares is the number of DKEK shares to create (N in M-of-N scheme).
	// Must be between 1 and 255. Default is 5.
	DKEKShares int `yaml:"dkek_shares" json:"dkek_shares" mapstructure:"dkek_shares"`

	// DKEKThreshold is the minimum number of shares needed to reconstruct the DKEK (M in M-of-N).
	// Must be between 1 and DKEKShares. Default is 3.
	DKEKThreshold int `yaml:"dkek_threshold" json:"dkek_threshold" mapstructure:"dkek_threshold"`

	// DKEKStorage is the storage backend for DKEK shares.
	// This should be a secure storage location as DKEK shares are sensitive.
	DKEKStorage storage.Backend `yaml:"-" json:"-" mapstructure:"-"`
}

// Validate checks if the configuration is valid and returns an error if not.
func (c *Config) Validate() error {
	if c == nil {
		return fmt.Errorf("config is nil")
	}

	// Validate underlying PKCS#11 config
	if c.PKCS11Config == nil {
		return fmt.Errorf("pkcs11 config is required")
	}
	if err := c.PKCS11Config.Validate(); err != nil {
		return fmt.Errorf("invalid pkcs11 config: %w", err)
	}

	// Validate DKEK share configuration
	if c.DKEKShares < 1 || c.DKEKShares > 255 {
		return fmt.Errorf("dkek_shares must be between 1 and 255, got %d", c.DKEKShares)
	}

	if c.DKEKThreshold < 1 || c.DKEKThreshold > c.DKEKShares {
		return fmt.Errorf("dkek_threshold must be between 1 and %d, got %d", c.DKEKShares, c.DKEKThreshold)
	}

	// DKEK storage is required
	if c.DKEKStorage == nil {
		return fmt.Errorf("dkek_storage is required")
	}

	return nil
}

// SetDefaults sets reasonable default values for the configuration.
func (c *Config) SetDefaults() {
	if c.DKEKShares == 0 {
		c.DKEKShares = 5
	}
	if c.DKEKThreshold == 0 {
		c.DKEKThreshold = 3
	}
}

// String returns a string representation of the config with sensitive data masked.
func (c *Config) String() string {
	return fmt.Sprintf("SmartCard-HSM Config{PKCS11: %s, DKEKShares: %d, DKEKThreshold: %d}",
		c.PKCS11Config.String(), c.DKEKShares, c.DKEKThreshold)
}

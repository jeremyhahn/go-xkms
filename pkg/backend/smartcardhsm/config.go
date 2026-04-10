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

//go:build smartcardhsm

package smartcardhsm

import (
	pkcs11backend "github.com/jeremyhahn/go-xkms/pkg/backend/pkcs11"
)

// Config holds the configuration for the SmartCard-HSM backend.
type Config struct {
	// PKCS11Config is the underlying PKCS#11 configuration.
	// This is used for standard cryptographic operations.
	*pkcs11backend.Config

	// DKEKShares is the total number of DKEK shares (N in M-of-N).
	// Set to 0 to disable DKEK (keys cannot be exported/imported).
	DKEKShares int `json:"dkek_shares" yaml:"dkek_shares"`

	// DKEKThreshold is the minimum shares required to reconstruct DKEK (M in M-of-N).
	// Must be >= 1 and <= DKEKShares.
	DKEKThreshold int `json:"dkek_threshold" yaml:"dkek_threshold"`

	// ReaderName is the PC/SC reader name for direct APDU communication.
	// If empty, the reader will be auto-detected based on the PKCS#11 slot.
	ReaderName string `json:"reader_name,omitempty" yaml:"reader_name,omitempty"`

	// SOPIN is the Security Officer PIN for device initialization.
	// Only required for initialization operations.
	SOPIN string `json:"so_pin,omitempty" yaml:"so_pin,omitempty"`

	// RetryCounter is the number of PIN retry attempts before lockout.
	// Default is 3 if not specified during initialization.
	RetryCounter int `json:"retry_counter,omitempty" yaml:"retry_counter,omitempty"`
}

// NewConfig creates a new SmartCard-HSM configuration with defaults.
func NewConfig() *Config {
	return &Config{
		Config:        pkcs11backend.NewConfig(),
		DKEKShares:    0,
		DKEKThreshold: 0,
		RetryCounter:  3,
	}
}

// Validate validates the SmartCard-HSM configuration.
func (c *Config) Validate() error {
	if c.Config == nil {
		return ErrInvalidConfig
	}
	if err := c.Config.Validate(); err != nil {
		return err
	}

	// Validate DKEK settings
	if c.DKEKShares > 0 {
		if c.DKEKThreshold < 1 || c.DKEKThreshold > c.DKEKShares {
			return ErrDKEKThresholdInvalid
		}
	}

	// Validate retry counter
	if c.RetryCounter < 1 || c.RetryCounter > 15 {
		c.RetryCounter = 3 // Default to 3
	}

	return nil
}

// WithDKEK configures DKEK with M-of-N threshold scheme.
func (c *Config) WithDKEK(shares, threshold int) *Config {
	c.DKEKShares = shares
	c.DKEKThreshold = threshold
	return c
}

// WithReaderName sets the PC/SC reader name.
func (c *Config) WithReaderName(name string) *Config {
	c.ReaderName = name
	return c
}

// WithSOPIN sets the Security Officer PIN.
func (c *Config) WithSOPIN(pin string) *Config {
	c.SOPIN = pin
	return c
}

// WithRetryCounter sets the PIN retry counter.
func (c *Config) WithRetryCounter(count int) *Config {
	c.RetryCounter = count
	return c
}

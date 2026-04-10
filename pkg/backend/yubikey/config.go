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

//go:build pkcs11

package yubikey

import (
	"errors"

	pkcs11backend "github.com/jeremyhahn/go-xkms/pkg/backend/pkcs11"
)

var (
	// ErrInvalidConfig is returned when the configuration is invalid.
	ErrInvalidConfig = errors.New("yubikey: invalid configuration")
)

// Config holds the configuration for the YubiKey backend.
type Config struct {
	// Config is the underlying PKCS#11 configuration.
	*pkcs11backend.Config

	// Serial is the YubiKey serial number (auto-detected if empty).
	Serial string `json:"serial,omitempty" yaml:"serial,omitempty"`

	// FirmwareVersion is the YubiKey firmware version (auto-detected if empty).
	FirmwareVersion string `json:"firmware_version,omitempty" yaml:"firmware_version,omitempty"`

	// AttestationSlot is the slot used for attestation (default: 0xF9).
	// This should not normally be changed as 0xF9 is the standard PIV attestation slot.
	AttestationSlot uint `json:"attestation_slot,omitempty" yaml:"attestation_slot,omitempty"`
}

// NewConfig creates a new YubiKey configuration with defaults.
func NewConfig() *Config {
	return &Config{
		Config:          &pkcs11backend.Config{},
		AttestationSlot: SlotAttestation,
	}
}

// Validate validates the YubiKey configuration.
func (c *Config) Validate() error {
	if c.Config == nil {
		return ErrInvalidConfig
	}
	if err := c.Config.Validate(); err != nil {
		return err
	}

	// Default attestation slot
	if c.AttestationSlot == 0 {
		c.AttestationSlot = SlotAttestation
	}

	return nil
}

// WithSerial sets the YubiKey serial number.
func (c *Config) WithSerial(serial string) *Config {
	c.Serial = serial
	return c
}

// WithFirmwareVersion sets the firmware version.
func (c *Config) WithFirmwareVersion(version string) *Config {
	c.FirmwareVersion = version
	return c
}

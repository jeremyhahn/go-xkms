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

// Package virtualfido provides a software-based virtual security key backend
// that wraps the github.com/bulwarkid/virtual-fido library. It implements
// the go-keychain types.Backend interface for PIV operations and provides
// FIDO2/U2F device emulation for WebAuthn testing without hardware.
package virtualfido

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/jeremyhahn/go-keychain/pkg/storage"
)

const (
	// DefaultPIN is the default user PIN for the virtual device.
	DefaultPIN = "123456"

	// DefaultPUK is the default PUK for PIN recovery.
	DefaultPUK = "12345678"

	// DefaultManufacturer is the default manufacturer name.
	DefaultManufacturer = "go-keychain"

	// DefaultProduct is the default product name.
	DefaultProduct = "VirtualFIDO"

	// DefaultPINRetries is the default number of PIN retry attempts.
	DefaultPINRetries = 3

	// DefaultPUKRetries is the default number of PUK retry attempts.
	DefaultPUKRetries = 3

	// ManagementKeySize is the size of the 3DES management key in bytes.
	ManagementKeySize = 24
)

// Config contains configuration for the VirtualFIDO backend.
type Config struct {
	// Storage is the backend for persisting device state and credentials.
	// Uses the storage.Backend interface for go-objstore compatibility.
	// If nil, an in-memory storage is used (ephemeral, for tests).
	Storage storage.Backend

	// SerialNumber is the virtual device serial number.
	// If empty, a random serial number is generated.
	SerialNumber string

	// Manufacturer is the manufacturer name for the virtual device.
	// Defaults to "go-keychain".
	Manufacturer string

	// Product is the product name for the virtual device.
	// Defaults to "VirtualFIDO".
	Product string

	// PIN is the user PIN for PIV and FIDO2 operations.
	// Defaults to "123456".
	PIN string

	// PUK is the PIN Unblock Key for PIN recovery.
	// Defaults to "12345678".
	PUK string

	// ManagementKey is the 24-byte 3DES key for administrative operations.
	// If nil, a default management key is used.
	ManagementKey []byte

	// Passphrase is used to encrypt credentials at rest.
	// Required when using persistent storage.
	Passphrase string

	// PINRetries is the number of PIN retry attempts before blocking.
	// Defaults to 3.
	PINRetries int

	// PUKRetries is the number of PUK retry attempts before blocking.
	// Defaults to 3.
	PUKRetries int

	// AutoApprove enables automatic approval of FIDO2 operations.
	// This is useful for automated testing without user interaction.
	// Defaults to true.
	AutoApprove bool
}

// Validate checks if the configuration is valid.
func (c *Config) Validate() error {
	if c == nil {
		return ErrConfigNil
	}

	// PIN validation (PIV standard: 6-8 characters)
	if len(c.PIN) > 0 && (len(c.PIN) < 4 || len(c.PIN) > 8) {
		return fmt.Errorf("virtualfido: PIN must be 4-8 characters")
	}

	// PUK validation (PIV standard: 8 characters)
	if len(c.PUK) > 0 && len(c.PUK) != 8 {
		return fmt.Errorf("virtualfido: PUK must be 8 characters")
	}

	// Management key validation
	if c.ManagementKey != nil && len(c.ManagementKey) != ManagementKeySize {
		return fmt.Errorf("virtualfido: management key must be %d bytes", ManagementKeySize)
	}

	// Note: Passphrase is recommended for persistent storage but not required.
	// Unencrypted storage is allowed for testing purposes.

	return nil
}

// SetDefaults sets default values for any unset fields.
func (c *Config) SetDefaults() {
	if c.SerialNumber == "" {
		c.SerialNumber = generateSerialNumber()
	}

	if c.Manufacturer == "" {
		c.Manufacturer = DefaultManufacturer
	}

	if c.Product == "" {
		c.Product = DefaultProduct
	}

	if c.PIN == "" {
		c.PIN = DefaultPIN
	}

	if c.PUK == "" {
		c.PUK = DefaultPUK
	}

	if c.ManagementKey == nil {
		c.ManagementKey = defaultManagementKey()
	}

	if c.PINRetries == 0 {
		c.PINRetries = DefaultPINRetries
	}

	if c.PUKRetries == 0 {
		c.PUKRetries = DefaultPUKRetries
	}

	// AutoApprove defaults to true for testing convenience
	// Users who want interactive approval should explicitly set to false
	c.AutoApprove = true
}

// generateSerialNumber creates a random 8-character serial number.
func generateSerialNumber() string {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		// Fallback if random fails
		return "VFIDO001"
	}
	return "VF" + hex.EncodeToString(b)[:6]
}

// defaultManagementKey returns the default PIV management key.
// This is the well-known default key - should be changed for production use.
func defaultManagementKey() []byte {
	return []byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	}
}

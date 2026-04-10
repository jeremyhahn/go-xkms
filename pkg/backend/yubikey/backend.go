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

// Package yubikey provides a backend for YubiKey PIV devices.
//
// YubiKey PIV provides hardware-backed key storage with support for
// key attestation using the dedicated attestation slot (0xF9).
//
// This backend embeds the standard PKCS#11 backend and adds YubiKey-specific
// features like attestation certificate retrieval.
package yubikey

import (
	"crypto/x509"
	"fmt"
	"sync"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	pkcs11backend "github.com/jeremyhahn/go-xkms/pkg/backend/pkcs11"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// YubiKey PIV slot identifiers
const (
	// SlotAuthentication is the PIV Authentication slot (9A)
	SlotAuthentication = 0x9A

	// SlotSignature is the Digital Signature slot (9C)
	SlotSignature = 0x9C

	// SlotKeyManagement is the Key Management slot (9D)
	SlotKeyManagement = 0x9D

	// SlotCardAuthentication is the Card Authentication slot (9E)
	SlotCardAuthentication = 0x9E

	// SlotAttestation is the Attestation slot (F9) - YubiKey specific
	SlotAttestation = 0xF9
)

// Backend implements the types.KeyProvider interface for YubiKey PIV devices.
// It embeds the PKCS#11 backend for standard cryptographic operations and adds
// YubiKey-specific features like key attestation.
type Backend struct {
	*pkcs11backend.Backend // Embedded PKCS#11 backend (inherits all methods)

	config *Config
	mu     sync.RWMutex
}

// Compile-time interface check.
var _ types.KeyProvider = (*Backend)(nil)

// NewBackend creates a new YubiKey backend instance.
func NewBackend(config *Config) (*Backend, error) {
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("yubikey: %w", err)
	}

	// Create embedded PKCS#11 backend
	pkcs11Backend, err := pkcs11backend.NewBackend(config.Config)
	if err != nil {
		return nil, fmt.Errorf("yubikey: failed to create PKCS#11 backend: %w", err)
	}

	return &Backend{
		Backend: pkcs11Backend,
		config:  config,
	}, nil
}

// Type returns the backend type identifier.
func (b *Backend) Type() types.BackendType {
	return backend.BackendTypeYubiKey
}

// Capabilities returns the capabilities of this backend.
func (b *Backend) Capabilities() types.Capabilities {
	caps := b.Backend.Capabilities()

	// YubiKey specific capabilities
	caps.Attestation = true
	caps.HardwareBacked = true

	return caps
}

// GetAttestationCertificate retrieves the attestation certificate for a key.
// YubiKey PIV generates attestation certificates in slot F9 that chain to
// Yubico's attestation CA, proving the key was generated on genuine YubiKey hardware.
//
// Parameters:
//   - keySlot: The PIV slot containing the key to attest (0x9A, 0x9C, 0x9D, 0x9E)
//
// Returns the X.509 attestation certificate.
func (b *Backend) GetAttestationCertificate(keySlot uint) (*x509.Certificate, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	// Read the attestation certificate from slot F9
	// The attestation certificate is generated when a key is created
	// and proves the key was generated on the YubiKey
	certData, err := b.readCertificateFromSlot(b.config.AttestationSlot)
	if err != nil {
		return nil, fmt.Errorf("yubikey: failed to read attestation certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certData)
	if err != nil {
		return nil, fmt.Errorf("yubikey: failed to parse attestation certificate: %w", err)
	}

	return cert, nil
}

// GenerateAttestationStatement generates an attestation statement for a key.
// This creates or retrieves the attestation certificate that proves the key
// was generated on genuine YubiKey hardware.
//
// Parameters:
//   - keySlot: The PIV slot containing the key to attest
//
// Returns the attestation certificate chain (attestation cert + intermediate CA).
func (b *Backend) GenerateAttestationStatement(keySlot uint) ([]*x509.Certificate, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	// Get the attestation certificate
	attestCert, err := b.GetAttestationCertificate(keySlot)
	if err != nil {
		return nil, err
	}

	// The attestation certificate chains to Yubico's intermediate CA
	// which is available at: https://developers.yubico.com/PIV/Introduction/piv-attestation-ca.pem
	return []*x509.Certificate{attestCert}, nil
}

// readCertificateFromSlot reads a certificate from a PIV slot.
// This uses the PKCS#11 interface to read the certificate object.
func (b *Backend) readCertificateFromSlot(slot uint) ([]byte, error) {
	// TODO: Implement certificate reading from PIV slot via PKCS#11
	// This requires finding the certificate object with CKA_ID matching the slot
	// and reading its CKA_VALUE attribute.
	return nil, fmt.Errorf("certificate reading not yet implemented for slot 0x%02X", slot)
}

// Config returns the backend configuration.
func (b *Backend) Config() *Config {
	return b.config
}

// GetSerialNumber returns the YubiKey serial number.
func (b *Backend) GetSerialNumber() string {
	return b.config.Serial
}

// GetFirmwareVersion returns the YubiKey firmware version.
func (b *Backend) GetFirmwareVersion() string {
	return b.config.FirmwareVersion
}

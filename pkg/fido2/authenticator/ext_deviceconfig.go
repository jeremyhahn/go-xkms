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

package authenticator

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"

	"github.com/fxamacker/cbor/v2"
)

// Extension identifier for deviceConfig.
const ExtensionDeviceConfig = "deviceConfig"

// DeviceConfig extension errors.
var (
	// ErrDeviceConfigEncodingFailed indicates CBOR encoding of the extension failed.
	ErrDeviceConfigEncodingFailed = errors.New("authenticator: deviceConfig encoding failed")

	// ErrDeviceConfigHashFailed indicates config hash computation failed.
	ErrDeviceConfigHashFailed = errors.New("authenticator: deviceConfig hash computation failed")

	// ErrDeviceConfigNilConfig indicates a nil config was provided.
	ErrDeviceConfigNilConfig = errors.New("authenticator: deviceConfig nil config")
)

// DeviceConfigExtension represents the deviceConfig FIDO2 extension output.
// This extension is included in authenticatorData extensions during both
// MakeCredential and GetAssertion operations. It reports device configuration
// and provides tamper detection by comparing attested and current config hashes.
//
// The extension allows relying parties to verify that the authenticator's
// configuration has not been modified since the Security Officer installed
// the attestation key.
type DeviceConfigExtension struct {
	// MinPINLength is the minimum PIN length configured on the authenticator.
	MinPINLength int `cbor:"minPINLength,omitempty"`

	// AlwaysUV indicates if user verification is always required.
	AlwaysUV bool `cbor:"alwaysUV,omitempty"`

	// PINProtocol is the PIN protocol version in use.
	PINProtocol int `cbor:"pinProtocol,omitempty"`

	// AttestedHash is the SHA-256 hash of the configuration at the time
	// the Security Officer installed the attestation key. This serves as
	// the baseline for tamper detection.
	AttestedHash []byte `cbor:"attestedHash,omitempty"`

	// CurrentHash is the SHA-256 hash of the current configuration.
	// The RP can compare this with AttestedHash to detect tampering.
	CurrentHash []byte `cbor:"currentHash,omitempty"`

	// Tampered indicates whether the configuration has been modified
	// since the attestation key was installed. True if AttestedHash
	// and CurrentHash do not match.
	Tampered bool `cbor:"tampered,omitempty"`

	// Vendor contains vendor-specific extension data. Keys should be
	// namespaced to avoid collisions (e.g., "com.example.feature").
	Vendor map[string]interface{} `cbor:"vendor,omitempty"`
}

// ConfigForHash represents the canonical configuration structure used for
// deterministic hash computation. Only security-relevant fields are included
// to ensure that cosmetic changes do not affect the hash.
//
// The structure is serialized to JSON with sorted keys before hashing
// to ensure deterministic output across different Go versions and platforms.
type ConfigForHash struct {
	// MinPINLength is the minimum PIN length requirement.
	MinPINLength int `json:"minPINLength"`

	// AlwaysUV indicates if user verification is always required.
	AlwaysUV bool `json:"alwaysUV"`

	// PINProtocol is the PIN protocol version.
	PINProtocol int `json:"pinProtocol"`
}

// ComputeConfigHash computes a SHA-256 hash of the canonical configuration.
// The hash is computed over a JSON-serialized representation of the
// security-relevant configuration fields to ensure deterministic output.
//
// This function is used both when the SO installs the attestation key
// (to compute the attested hash) and during operations (to compute the
// current hash for tamper detection).
func ComputeConfigHash(cfg *Config) ([]byte, error) {
	if cfg == nil {
		return nil, ErrDeviceConfigNilConfig
	}

	// Build canonical config for hashing
	canonical := ConfigForHash{
		MinPINLength: cfg.PINMinLength,
		AlwaysUV:     cfg.AlwaysUV,
		PINProtocol:  PINProtocolVersion1,
	}

	// Marshal to JSON with sorted keys (Go's encoding/json sorts by default)
	jsonBytes, err := json.Marshal(canonical)
	if err != nil {
		return nil, ErrDeviceConfigHashFailed
	}

	// Compute SHA-256 hash
	hash := sha256.Sum256(jsonBytes)
	return hash[:], nil
}

// BuildDeviceConfigExtension constructs a DeviceConfigExtension from the
// current authenticator configuration and the attested hash that was
// computed when the SO installed the attestation key.
//
// The function computes the current configuration hash and compares it
// with the attested hash to determine if tampering has occurred.
//
// Parameters:
//   - cfg: The current authenticator configuration
//   - attestedHash: The hash computed when SO installed attestation key (may be nil)
//
// Returns the populated extension or an error if hash computation fails.
func BuildDeviceConfigExtension(cfg *Config, attestedHash []byte) (*DeviceConfigExtension, error) {
	if cfg == nil {
		return nil, ErrDeviceConfigNilConfig
	}

	// Compute current config hash
	currentHash, err := ComputeConfigHash(cfg)
	if err != nil {
		return nil, err
	}

	// Determine if config has been tampered with
	tampered := false
	if len(attestedHash) > 0 {
		tampered = !bytes.Equal(attestedHash, currentHash)
	}

	ext := &DeviceConfigExtension{
		MinPINLength: cfg.PINMinLength,
		AlwaysUV:     cfg.AlwaysUV,
		PINProtocol:  PINProtocolVersion1,
		AttestedHash: attestedHash,
		CurrentHash:  currentHash,
		Tampered:     tampered,
	}

	return ext, nil
}

// Encode serializes the DeviceConfigExtension to CBOR format for inclusion
// in the authenticatorData extensions field.
//
// The encoding uses canonical CBOR with sorted keys as required by CTAP2.
func (ext *DeviceConfigExtension) Encode() ([]byte, error) {
	if ext == nil {
		return nil, ErrDeviceConfigEncodingFailed
	}

	encoded, err := cryptoCBOREncMode.Marshal(ext)
	if err != nil {
		return nil, ErrDeviceConfigEncodingFailed
	}

	return encoded, nil
}

// IsValid returns true if the configuration has not been tampered with.
// This is a convenience method that returns the inverse of the Tampered flag.
//
// A configuration is considered valid if:
//   - No attested hash was provided (fresh authenticator), or
//   - The current hash matches the attested hash
func (ext *DeviceConfigExtension) IsValid() bool {
	if ext == nil {
		return false
	}
	return !ext.Tampered
}

// DecodeDeviceConfigExtension decodes a CBOR-encoded DeviceConfigExtension.
// This is useful for relying parties that need to parse and verify the
// extension data from authenticatorData.
func DecodeDeviceConfigExtension(data []byte) (*DeviceConfigExtension, error) {
	if len(data) == 0 {
		return nil, ErrDeviceConfigEncodingFailed
	}

	var ext DeviceConfigExtension
	if err := cbor.Unmarshal(data, &ext); err != nil {
		return nil, ErrDeviceConfigEncodingFailed
	}

	return &ext, nil
}

// WithVendorExtension adds a vendor-specific extension field to the
// DeviceConfigExtension. Keys should be namespaced to avoid collisions
// (e.g., "com.automatethethings.feature").
//
// This method returns the extension for method chaining.
func (ext *DeviceConfigExtension) WithVendorExtension(key string, value interface{}) *DeviceConfigExtension {
	if ext == nil {
		return nil
	}

	if ext.Vendor == nil {
		ext.Vendor = make(map[string]interface{})
	}
	ext.Vendor[key] = value

	return ext
}

// HasVendorExtension checks if a vendor extension with the given key exists.
func (ext *DeviceConfigExtension) HasVendorExtension(key string) bool {
	if ext == nil || ext.Vendor == nil {
		return false
	}
	_, exists := ext.Vendor[key]
	return exists
}

// GetVendorExtension retrieves a vendor extension value by key.
// Returns nil if the extension does not exist or the DeviceConfigExtension is nil.
func (ext *DeviceConfigExtension) GetVendorExtension(key string) interface{} {
	if ext == nil || ext.Vendor == nil {
		return nil
	}
	return ext.Vendor[key]
}

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

package pairing

import (
	"time"

	"gopkg.in/yaml.v3"
)

// PairedDevice is the persisted record of a device paired with this xKey
// instance.
//
// It is the ONE owned shape for the pairing file: the CLI's devices.yaml and
// the GUI's mirror of the same file both read and write this exact type
// (#130). Before this, the CLI and the GUI each hand-maintained their own
// struct for the same file, and the drift between them silently dropped a
// security field three times — `attestation_protocol_version` missing from
// the GUI's mirror (#95, #124 round 1) being the recurring instance. The
// fix is structural: there is nothing left to drift, because there is only
// one definition of what a paired device record contains.
//
// The GUI's Wails-facing view model is a projection of this type (see
// pkg/gui/services' deviceView), never a parallel definition; the fields
// below are the complete union of what either surface persists, so a value
// read by one and re-saved by the other round-trips every field the other
// wrote.
type PairedDevice struct {
	// Name is the human-readable device name.
	Name string `yaml:"name" json:"name"`

	// Address is the BLE MAC address.
	Address string `yaml:"address" json:"address"`

	// NoisePublicKey is the phone's Noise static public key (base64 encoded).
	NoisePublicKey string `yaml:"noise_public_key" json:"noise_public_key"`

	// LocalNoisePrivateKey is our local Noise static private key (base64
	// encoded). #42 tracks the custody of this key material; this
	// unification carries the field forward exactly as it persists today.
	LocalNoisePrivateKey string `yaml:"local_noise_private_key" json:"local_noise_private_key"`

	// PairedAt is the timestamp when the device was paired.
	PairedAt time.Time `yaml:"paired_at" json:"paired_at"`

	// LastDeviceAttestationTime is the timestamp of the last successful device attestation.
	LastDeviceAttestationTime time.Time `yaml:"last_device_attestation_time,omitempty" json:"last_device_attestation_time,omitempty"`

	// DeviceBootHashHex is the hex-encoded hash of the device boot state.
	DeviceBootHashHex string `yaml:"device_boot_hash_hex,omitempty" json:"device_boot_hash_hex,omitempty"`

	// AttestationGracePeriod is the per-device attestation validity window.
	AttestationGracePeriod Duration `yaml:"attestation_grace_period,omitempty" json:"attestation_grace_period,omitempty"`

	// SecurityLevel indicates the device's hardware security level (e.g., "tee", "strongbox").
	SecurityLevel string `yaml:"security_level,omitempty" json:"security_level,omitempty"`

	// BootStateVerified indicates whether the device boot state has been verified.
	BootStateVerified bool `yaml:"boot_state_verified,omitempty" json:"boot_state_verified,omitempty"`

	// DeviceFingerprint is a unique identifier derived from device attestation:
	// the SHA-256 of the device's persistent attested key's
	// SubjectPublicKeyInfo (#93/#129), hex encoded.
	DeviceFingerprint string `yaml:"device_fingerprint,omitempty" json:"device_fingerprint,omitempty"`

	// AttestationProtocolVersion records which attestation model bound this
	// device: 2 for challenge-response (#129), absent or 1 for a record
	// established before it.
	//
	// It is the anti-downgrade term. A device bound under version 2 must prove
	// liveness on every reconnect, and a peer that answers a version 2 record
	// with a version 1 attestation is refused rather than accommodated —
	// otherwise the protocol version would be chosen at connect time by the
	// party being checked, which is the one party that must not choose it.
	// Records that predate the change keep working in the weaker mode until
	// the device is re-paired; they are not silently reported as if they had
	// the stronger binding.
	AttestationProtocolVersion int `yaml:"attestation_protocol_version,omitempty" json:"attestation_protocol_version,omitempty"`

	// LastAttestation records the outcome of the last successful attestation,
	// so a surface can auto-refresh or offer to pin it as a policy baseline
	// without a fresh BLE round trip. Only the GUI populates it today; the
	// CLI round-trips it unchanged rather than dropping it on save.
	LastAttestation *PairedDeviceAttestationSnapshot `yaml:"last_attestation,omitempty" json:"last_attestation,omitempty"`

	// AttestationPolicy pins this device's later attestations to a
	// previously observed baseline, so a drift from it is flagged instead of
	// silently accepted. Only the GUI populates it today; the CLI
	// round-trips it unchanged.
	AttestationPolicy *PairedDeviceAttestationPolicy `yaml:"attestation_policy,omitempty" json:"attestation_policy,omitempty"`

	// IsBackend marks the device as usable as a key backend, so it appears
	// in backend-selection lists. Only the GUI sets it today; the CLI
	// round-trips it unchanged.
	IsBackend bool `yaml:"is_backend,omitempty" json:"is_backend,omitempty"`
}

// PairedDeviceAttestationSnapshot records the outcome of a device
// attestation for persistence, so it can be redisplayed or compared against
// a future attestation without a fresh BLE round trip.
type PairedDeviceAttestationSnapshot struct {
	Verified      bool      `yaml:"verified" json:"verified"`
	SecurityLevel string    `yaml:"security_level" json:"security_level"`
	BootHash      string    `yaml:"boot_hash" json:"boot_hash"`
	BootKeyHash   string    `yaml:"boot_key_hash" json:"boot_key_hash"`
	BootState     string    `yaml:"boot_state" json:"boot_state"`
	DeviceLocked  bool      `yaml:"device_locked" json:"device_locked"`
	Timestamp     time.Time `yaml:"timestamp" json:"timestamp"`
}

// PairedDeviceAttestationPolicy defines the expected attestation properties
// for a device. When enabled, later attestations are compared against it and
// a mismatch is reported rather than silently accepted.
type PairedDeviceAttestationPolicy struct {
	Enabled       bool      `yaml:"enabled" json:"enabled"`
	BootHash      string    `yaml:"boot_hash" json:"boot_hash"`
	BootKeyHash   string    `yaml:"boot_key_hash" json:"boot_key_hash"`
	BootState     string    `yaml:"boot_state" json:"boot_state"`
	DeviceLocked  bool      `yaml:"device_locked" json:"device_locked"`
	SecurityLevel string    `yaml:"min_security_level" json:"min_security_level"`
	SetAt         time.Time `yaml:"set_at" json:"set_at"`
}

// Duration wraps time.Duration for YAML marshaling.
type Duration time.Duration

// UnmarshalYAML implements yaml.Unmarshaler.
func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err != nil {
		return err
	}
	dur, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	*d = Duration(dur)
	return nil
}

// MarshalYAML implements yaml.Marshaler.
func (d Duration) MarshalYAML() (interface{}, error) {
	return time.Duration(d).String(), nil
}

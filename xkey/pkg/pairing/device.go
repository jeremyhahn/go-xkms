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

import "time"

// DeviceType identifies the kind of paired device.
type DeviceType string

const (
	// DeviceTypePhone represents an Android/iOS phone paired via BLE or USB.
	DeviceTypePhone DeviceType = "phone"

	// DeviceTypeAgent represents a remote agent paired via TCP/network.
	DeviceTypeAgent DeviceType = "agent"

	// DeviceTypeUSB represents a USB-connected hardware device.
	DeviceTypeUSB DeviceType = "usb"

	// DeviceTypeDesktop represents a desktop machine paired via TCP.
	DeviceTypeDesktop DeviceType = "desktop"
)

// EnrollmentMethod identifies how the device was paired.
type EnrollmentMethod string

const (
	// EnrollmentMethodBLE indicates pairing via Bluetooth Low Energy.
	EnrollmentMethodBLE EnrollmentMethod = "ble"

	// EnrollmentMethodUSB indicates pairing via USB connection.
	EnrollmentMethodUSB EnrollmentMethod = "usb"

	// EnrollmentMethodTCP indicates pairing via TCP network connection.
	EnrollmentMethodTCP EnrollmentMethod = "tcp"

	// EnrollmentMethodOneTimeCode indicates enrollment via a one-time code.
	EnrollmentMethodOneTimeCode EnrollmentMethod = "one-time-code"

	// EnrollmentMethodAdminApproval indicates enrollment via admin approval.
	EnrollmentMethodAdminApproval EnrollmentMethod = "admin-approval"

	// EnrollmentMethodEnterpriseCA indicates enrollment via enterprise CA certificate.
	EnrollmentMethodEnterpriseCA EnrollmentMethod = "enterprise-ca"

	// EnrollmentMethodNoiseDirect indicates enrollment via direct Noise handshake.
	EnrollmentMethodNoiseDirect EnrollmentMethod = "noise-direct"

	// EnrollmentMethodQR indicates pairing via QR code scan.
	EnrollmentMethodQR EnrollmentMethod = "qr"
)

// TransportType identifies the communication transport used for the device.
type TransportType string

const (
	// TransportTypeBLE indicates BLE GATT transport.
	TransportTypeBLE TransportType = "ble"

	// TransportTypeUSB indicates USB/AOA transport.
	TransportTypeUSB TransportType = "usb"

	// TransportTypeTCP indicates TCP network transport.
	TransportTypeTCP TransportType = "tcp"
)

// PairedDevice represents a device that has been paired with this xKey instance.
type PairedDevice struct {
	// Name is the human-readable device name.
	Name string `json:"name"`

	// DeviceType identifies the kind of device.
	DeviceType DeviceType `json:"device_type"`

	// PublicKey is the device's Noise static public key.
	PublicKey []byte `json:"public_key"`

	// AttestationData contains device attestation evidence (format depends on DeviceType).
	AttestationData []byte `json:"attestation_data,omitempty"`

	// PairedAt is the timestamp when the device was first paired.
	PairedAt time.Time `json:"paired_at"`

	// LastSeen is the timestamp of the last successful connection.
	LastSeen time.Time `json:"last_seen,omitempty"`

	// SecurityLevel describes the security posture (e.g., "tee", "strongbox", "software").
	SecurityLevel string `json:"security_level,omitempty"`

	// AgentAddress is the network address for agent-type devices.
	AgentAddress string `json:"agent_address,omitempty"`

	// CertificateFingerprint is the SHA-256 fingerprint of the device's identity certificate.
	CertificateFingerprint string `json:"certificate_fingerprint,omitempty"`

	// EnrollmentMethod records how the device was paired.
	EnrollmentMethod EnrollmentMethod `json:"enrollment_method,omitempty"`

	// TransportType records the communication transport for this device.
	TransportType TransportType `json:"transport_type,omitempty"`
}

// AttestationPolicy defines requirements for device attestation.
type AttestationPolicy struct {
	// RequireTPM requires the device to have a TPM for hardware-backed attestation.
	RequireTPM bool `json:"require_tpm" yaml:"require_tpm"`

	// RequireSecureBoot requires the device to have verified/secure boot enabled.
	RequireSecureBoot bool `json:"require_secure_boot" yaml:"require_secure_boot"`

	// AllowedPCRBanks restricts which PCR hash algorithms are accepted.
	AllowedPCRBanks []string `json:"allowed_pcr_banks,omitempty" yaml:"allowed_pcr_banks"`

	// MinSecurityLevel specifies the minimum acceptable security level.
	MinSecurityLevel string `json:"min_security_level,omitempty" yaml:"min_security_level"`

	// RequireBiometric requires the device to support biometric authentication.
	RequireBiometric bool `json:"require_biometric" yaml:"require_biometric"`
}

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

package manager

import (
	"path/filepath"
	"strings"
)

// DeviceType identifies the type of PKCS#11 device.
type DeviceType string

const (
	// DeviceTypeYubiKey is a YubiKey PIV device using libykcs11.
	DeviceTypeYubiKey DeviceType = "yubikey"

	// DeviceTypeSmartCardHSM is a SmartCard-HSM device (includes Nitrokey HSM).
	DeviceTypeSmartCardHSM DeviceType = "smartcardhsm"

	// DeviceTypeSoftHSM is a SoftHSM2 software token for development/testing.
	DeviceTypeSoftHSM DeviceType = "softhsm"

	// DeviceTypeGenericPKCS11 is a generic PKCS#11 device.
	DeviceTypeGenericPKCS11 DeviceType = "pkcs11"
)

// DeviceInfo contains detected device information.
type DeviceInfo struct {
	// Type is the detected device type.
	Type DeviceType `json:"type"`

	// DisplayName is a human-readable name for the device.
	DisplayName string `json:"display_name"`

	// SupportsAttestation indicates if the device supports key attestation.
	SupportsAttestation bool `json:"supports_attestation"`

	// AttestationSlot is the slot used for attestation (if supported).
	// For YubiKey PIV this is 0xF9.
	AttestationSlot uint `json:"attestation_slot,omitempty"`

	// SupportsDKEK indicates if the device supports DKEK key wrapping.
	SupportsDKEK bool `json:"supports_dkek"`

	// SupportsThreshold indicates if the device supports M-of-N threshold schemes.
	SupportsThreshold bool `json:"supports_threshold"`
}

// DetectDevice determines the device type from the library path and token information.
// It uses both the library filename and the token's manufacturer/model to identify the device.
func DetectDevice(libraryPath string, slot SlotInfo) DeviceInfo {
	libName := strings.ToLower(filepath.Base(libraryPath))
	manufacturer := strings.ToLower(slot.Manufacturer)
	model := strings.ToLower(slot.Model)
	label := strings.ToLower(slot.Label)

	// YubiKey detection
	// Library: libykcs11.so, ykcs11.dll
	// Manufacturer: "Yubico"
	// Label typically contains "YubiKey PIV"
	if strings.Contains(libName, "ykcs11") ||
		strings.Contains(manufacturer, "yubico") ||
		strings.Contains(label, "yubikey") {
		return DeviceInfo{
			Type:                DeviceTypeYubiKey,
			DisplayName:         buildDisplayName("YubiKey", slot),
			SupportsAttestation: true,
			AttestationSlot:     0xF9, // YubiKey PIV attestation slot
			SupportsDKEK:        false,
			SupportsThreshold:   false,
		}
	}

	// SmartCard-HSM detection (includes Nitrokey HSM)
	// Library: opensc-pkcs11.so, libsc-hsm-pkcs11.so
	// Manufacturer: "CardContact" (original), "Nitrokey" (Nitrokey HSM)
	// Model: "SmartCard-HSM"
	if strings.Contains(libName, "opensc") ||
		strings.Contains(libName, "sc-hsm") ||
		strings.Contains(manufacturer, "cardcontact") ||
		strings.Contains(manufacturer, "nitrokey") ||
		strings.Contains(model, "smartcard-hsm") ||
		strings.Contains(model, "nitrokey") {
		displayName := "SmartCard-HSM"
		if strings.Contains(manufacturer, "nitrokey") || strings.Contains(model, "nitrokey") {
			displayName = "Nitrokey HSM"
		}
		return DeviceInfo{
			Type:                DeviceTypeSmartCardHSM,
			DisplayName:         buildDisplayName(displayName, slot),
			SupportsAttestation: true,
			AttestationSlot:     0, // SmartCard-HSM uses different attestation mechanism
			SupportsDKEK:        true,
			SupportsThreshold:   true, // M-of-N DKEK shares
		}
	}

	// SoftHSM2 detection
	// Library: libsofthsm2.so
	// Manufacturer: "SoftHSM project"
	if strings.Contains(libName, "softhsm") ||
		strings.Contains(manufacturer, "softhsm") {
		return DeviceInfo{
			Type:                DeviceTypeSoftHSM,
			DisplayName:         buildDisplayName("SoftHSM2", slot),
			SupportsAttestation: false,
			SupportsDKEK:        false,
			SupportsThreshold:   false,
		}
	}

	// Generic PKCS#11 fallback
	return DeviceInfo{
		Type:                DeviceTypeGenericPKCS11,
		DisplayName:         buildDisplayName("PKCS#11 Token", slot),
		SupportsAttestation: false,
		SupportsDKEK:        false,
		SupportsThreshold:   false,
	}
}

// buildDisplayName creates a human-readable display name for the device.
func buildDisplayName(baseName string, slot SlotInfo) string {
	if slot.Label != "" {
		return slot.Label
	}
	if slot.Model != "" {
		return slot.Model
	}
	return baseName
}

// String returns the string representation of the device type.
func (dt DeviceType) String() string {
	return string(dt)
}

// IsHardwareBacked returns true if this device type is hardware-backed.
func (dt DeviceType) IsHardwareBacked() bool {
	switch dt {
	case DeviceTypeYubiKey, DeviceTypeSmartCardHSM:
		return true
	default:
		return false
	}
}

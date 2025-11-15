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

package yubikey

import (
	"fmt"
)

// PIVSlot represents a YubiKey PIV slot identifier
type PIVSlot byte

// YubiKey PIV slot constants
//
// These are the standard PIV slots defined by NIST SP 800-73-4
// that YubiKey implements for key storage.
const (
	// SlotAuthentication (9a) - PIV Authentication
	// Used for general authentication. Requires PIN for operations.
	SlotAuthentication PIVSlot = 0x9a

	// SlotSignature (9c) - Digital Signature
	// Used for digital signatures. Always requires PIN for operations.
	// This is the most secure slot as PIN is always checked.
	SlotSignature PIVSlot = 0x9c

	// SlotKeyManagement (9d) - Key Management
	// Used for encryption/decryption operations. Requires PIN.
	SlotKeyManagement PIVSlot = 0x9d

	// SlotCardAuth (9e) - Card Authentication
	// Used for card authentication. Does NOT require PIN for operations.
	// Useful for automatic authentication scenarios.
	SlotCardAuth PIVSlot = 0x9e

	// Retired Key Management slots (82-95)
	// 20 additional slots for key storage
	SlotRetired1  PIVSlot = 0x82
	SlotRetired2  PIVSlot = 0x83
	SlotRetired3  PIVSlot = 0x84
	SlotRetired4  PIVSlot = 0x85
	SlotRetired5  PIVSlot = 0x86
	SlotRetired6  PIVSlot = 0x87
	SlotRetired7  PIVSlot = 0x88
	SlotRetired8  PIVSlot = 0x89
	SlotRetired9  PIVSlot = 0x8a
	SlotRetired10 PIVSlot = 0x8b
	SlotRetired11 PIVSlot = 0x8c
	SlotRetired12 PIVSlot = 0x8d
	SlotRetired13 PIVSlot = 0x8e
	SlotRetired14 PIVSlot = 0x8f
	SlotRetired15 PIVSlot = 0x90
	SlotRetired16 PIVSlot = 0x91
	SlotRetired17 PIVSlot = 0x92
	SlotRetired18 PIVSlot = 0x93
	SlotRetired19 PIVSlot = 0x94
	SlotRetired20 PIVSlot = 0x95
)

// String returns a human-readable name for the PIV slot
func (s PIVSlot) String() string {
	switch s {
	case SlotAuthentication:
		return "PIV Authentication (9a)"
	case SlotSignature:
		return "Digital Signature (9c)"
	case SlotKeyManagement:
		return "Key Management (9d)"
	case SlotCardAuth:
		return "Card Authentication (9e)"
	case SlotRetired1:
		return "Retired Key Management 1 (82)"
	case SlotRetired2:
		return "Retired Key Management 2 (83)"
	case SlotRetired3:
		return "Retired Key Management 3 (84)"
	case SlotRetired4:
		return "Retired Key Management 4 (85)"
	case SlotRetired5:
		return "Retired Key Management 5 (86)"
	case SlotRetired6:
		return "Retired Key Management 6 (87)"
	case SlotRetired7:
		return "Retired Key Management 7 (88)"
	case SlotRetired8:
		return "Retired Key Management 8 (89)"
	case SlotRetired9:
		return "Retired Key Management 9 (8a)"
	case SlotRetired10:
		return "Retired Key Management 10 (8b)"
	case SlotRetired11:
		return "Retired Key Management 11 (8c)"
	case SlotRetired12:
		return "Retired Key Management 12 (8d)"
	case SlotRetired13:
		return "Retired Key Management 13 (8e)"
	case SlotRetired14:
		return "Retired Key Management 14 (8f)"
	case SlotRetired15:
		return "Retired Key Management 15 (90)"
	case SlotRetired16:
		return "Retired Key Management 16 (91)"
	case SlotRetired17:
		return "Retired Key Management 17 (92)"
	case SlotRetired18:
		return "Retired Key Management 18 (93)"
	case SlotRetired19:
		return "Retired Key Management 19 (94)"
	case SlotRetired20:
		return "Retired Key Management 20 (95)"
	default:
		return fmt.Sprintf("Unknown Slot (%02x)", byte(s))
	}
}

// IsValid returns true if the slot is a valid PIV slot
func (s PIVSlot) IsValid() bool {
	switch s {
	case SlotAuthentication, SlotSignature, SlotKeyManagement, SlotCardAuth:
		return true
	case SlotRetired1, SlotRetired2, SlotRetired3, SlotRetired4, SlotRetired5,
		SlotRetired6, SlotRetired7, SlotRetired8, SlotRetired9, SlotRetired10,
		SlotRetired11, SlotRetired12, SlotRetired13, SlotRetired14, SlotRetired15,
		SlotRetired16, SlotRetired17, SlotRetired18, SlotRetired19, SlotRetired20:
		return true
	default:
		return false
	}
}

// RequiresPIN returns true if the slot requires PIN for operations
func (s PIVSlot) RequiresPIN() bool {
	switch s {
	case SlotCardAuth:
		return false // Card auth slot does not require PIN
	default:
		return true
	}
}

// IsRetired returns true if this is a retired key management slot
func (s PIVSlot) IsRetired() bool {
	return s >= SlotRetired1 && s <= SlotRetired20
}

// AllSlots returns a slice of all valid PIV slots
func AllSlots() []PIVSlot {
	return []PIVSlot{
		SlotAuthentication,
		SlotSignature,
		SlotKeyManagement,
		SlotCardAuth,
		SlotRetired1, SlotRetired2, SlotRetired3, SlotRetired4, SlotRetired5,
		SlotRetired6, SlotRetired7, SlotRetired8, SlotRetired9, SlotRetired10,
		SlotRetired11, SlotRetired12, SlotRetired13, SlotRetired14, SlotRetired15,
		SlotRetired16, SlotRetired17, SlotRetired18, SlotRetired19, SlotRetired20,
	}
}

// PrimarySlots returns the four primary PIV slots
func PrimarySlots() []PIVSlot {
	return []PIVSlot{
		SlotAuthentication,
		SlotSignature,
		SlotKeyManagement,
		SlotCardAuth,
	}
}

// RetiredSlots returns all retired key management slots
func RetiredSlots() []PIVSlot {
	return []PIVSlot{
		SlotRetired1, SlotRetired2, SlotRetired3, SlotRetired4, SlotRetired5,
		SlotRetired6, SlotRetired7, SlotRetired8, SlotRetired9, SlotRetired10,
		SlotRetired11, SlotRetired12, SlotRetired13, SlotRetired14, SlotRetired15,
		SlotRetired16, SlotRetired17, SlotRetired18, SlotRetired19, SlotRetired20,
	}
}

// ParseSlot parses a PIV slot from a byte
func ParseSlot(b byte) (PIVSlot, error) {
	slot := PIVSlot(b)
	if !slot.IsValid() {
		return 0, fmt.Errorf("invalid PIV slot: 0x%02x", b)
	}
	return slot, nil
}

// SlotFromKeyID extracts PIV slot from KeyAttributes.KeyID
// If KeyID is empty or invalid, returns the default Authentication slot
func SlotFromKeyID(keyID []byte) PIVSlot {
	if len(keyID) == 0 {
		return SlotAuthentication // Default slot
	}

	slot := PIVSlot(keyID[0])
	if !slot.IsValid() {
		return SlotAuthentication // Default slot for invalid values
	}

	return slot
}

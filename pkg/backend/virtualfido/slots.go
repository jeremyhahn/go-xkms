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

package virtualfido

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"time"
)

// PIVSlot represents a PIV application slot identifier.
// PIV defines slots for different key purposes as per NIST SP 800-73.
type PIVSlot uint8

const (
	// SlotAuthentication (0x9A) is used for PIV Authentication.
	// Used to authenticate the card and cardholder to the system.
	// Supports RSA and ECDSA signing operations.
	SlotAuthentication PIVSlot = 0x9A

	// SlotSignature (0x9C) is used for Digital Signature.
	// Used for document signing with non-repudiation.
	// Always requires PIN verification before use.
	SlotSignature PIVSlot = 0x9C

	// SlotKeyManagement (0x9D) is used for Key Management.
	// Used for key establishment and encryption operations.
	// Supports ECDH key agreement.
	SlotKeyManagement PIVSlot = 0x9D

	// SlotCardAuth (0x9E) is used for Card Authentication.
	// Used to authenticate the card without user intervention.
	// Does not require PIN.
	SlotCardAuth PIVSlot = 0x9E

	// Retired Key Management slots (0x82-0x95)
	// These 20 slots can hold retired key management keys.
	SlotRetired1  PIVSlot = 0x82
	SlotRetired2  PIVSlot = 0x83
	SlotRetired3  PIVSlot = 0x84
	SlotRetired4  PIVSlot = 0x85
	SlotRetired5  PIVSlot = 0x86
	SlotRetired6  PIVSlot = 0x87
	SlotRetired7  PIVSlot = 0x88
	SlotRetired8  PIVSlot = 0x89
	SlotRetired9  PIVSlot = 0x8A
	SlotRetired10 PIVSlot = 0x8B
	SlotRetired11 PIVSlot = 0x8C
	SlotRetired12 PIVSlot = 0x8D
	SlotRetired13 PIVSlot = 0x8E
	SlotRetired14 PIVSlot = 0x8F
	SlotRetired15 PIVSlot = 0x90
	SlotRetired16 PIVSlot = 0x91
	SlotRetired17 PIVSlot = 0x92
	SlotRetired18 PIVSlot = 0x93
	SlotRetired19 PIVSlot = 0x94
	SlotRetired20 PIVSlot = 0x95
)

// SlotData contains the key and certificate data for a PIV slot.
type SlotData struct {
	// PrivateKey is the private key stored in this slot.
	// Can be RSA, ECDSA, or Ed25519.
	PrivateKey crypto.PrivateKey

	// Certificate is the X.509 certificate associated with the key.
	// May be nil if no certificate has been imported.
	Certificate *x509.Certificate

	// Algorithm is the key algorithm used.
	Algorithm x509.PublicKeyAlgorithm

	// CreatedAt is when the key was generated or imported.
	CreatedAt time.Time

	// TouchPolicy indicates if touch is required for operations.
	// For virtual devices, this is typically false.
	TouchPolicy TouchPolicy

	// PINPolicy indicates when PIN is required.
	PINPolicy PINPolicy
}

// TouchPolicy defines when touch is required for slot operations.
type TouchPolicy uint8

const (
	// TouchPolicyNever means touch is never required.
	TouchPolicyNever TouchPolicy = 0x00

	// TouchPolicyAlways means touch is required for every operation.
	TouchPolicyAlways TouchPolicy = 0x01

	// TouchPolicyCached means touch is cached for 15 seconds.
	TouchPolicyCached TouchPolicy = 0x02
)

// PINPolicy defines when PIN is required for slot operations.
type PINPolicy uint8

const (
	// PINPolicyDefault uses the slot's default PIN policy.
	PINPolicyDefault PINPolicy = 0x00

	// PINPolicyNever means PIN is never required.
	PINPolicyNever PINPolicy = 0x01

	// PINPolicyOnce means PIN is required once per session.
	PINPolicyOnce PINPolicy = 0x02

	// PINPolicyAlways means PIN is required for every operation.
	PINPolicyAlways PINPolicy = 0x03
)

// String returns the human-readable name of the slot.
func (s PIVSlot) String() string {
	switch s {
	case SlotAuthentication:
		return "Authentication (9A)"
	case SlotSignature:
		return "Signature (9C)"
	case SlotKeyManagement:
		return "Key Management (9D)"
	case SlotCardAuth:
		return "Card Auth (9E)"
	default:
		if s >= SlotRetired1 && s <= SlotRetired20 {
			return fmt.Sprintf("Retired %d (%02X)", s-SlotRetired1+1, uint8(s))
		}
		return fmt.Sprintf("Unknown (%02X)", uint8(s))
	}
}

// RequiresPIN returns true if this slot requires PIN verification.
// Per PIV specification, the Signature slot (9C) always requires PIN.
func (s PIVSlot) RequiresPIN() bool {
	return s == SlotSignature
}

// IsValid returns true if this is a valid PIV slot.
func (s PIVSlot) IsValid() bool {
	switch s {
	case SlotAuthentication, SlotSignature, SlotKeyManagement, SlotCardAuth:
		return true
	default:
		return s >= SlotRetired1 && s <= SlotRetired20
	}
}

// IsPrimarySlot returns true if this is one of the four primary PIV slots.
func (s PIVSlot) IsPrimarySlot() bool {
	switch s {
	case SlotAuthentication, SlotSignature, SlotKeyManagement, SlotCardAuth:
		return true
	default:
		return false
	}
}

// IsRetiredSlot returns true if this is a retired key management slot.
func (s PIVSlot) IsRetiredSlot() bool {
	return s >= SlotRetired1 && s <= SlotRetired20
}

// StorageKey returns the storage key used to persist this slot's data.
func (s PIVSlot) StorageKey() string {
	return fmt.Sprintf("piv/slots/%02x", uint8(s))
}

// AllPrimarySlots returns all primary PIV slots.
func AllPrimarySlots() []PIVSlot {
	return []PIVSlot{
		SlotAuthentication,
		SlotSignature,
		SlotKeyManagement,
		SlotCardAuth,
	}
}

// AllRetiredSlots returns all retired key management slots.
func AllRetiredSlots() []PIVSlot {
	return []PIVSlot{
		SlotRetired1, SlotRetired2, SlotRetired3, SlotRetired4, SlotRetired5,
		SlotRetired6, SlotRetired7, SlotRetired8, SlotRetired9, SlotRetired10,
		SlotRetired11, SlotRetired12, SlotRetired13, SlotRetired14, SlotRetired15,
		SlotRetired16, SlotRetired17, SlotRetired18, SlotRetired19, SlotRetired20,
	}
}

// AllSlots returns all valid PIV slots.
func AllSlots() []PIVSlot {
	slots := AllPrimarySlots()
	return append(slots, AllRetiredSlots()...)
}

// SlotFromByte converts a byte value to a PIVSlot.
// Returns an error if the slot is invalid.
func SlotFromByte(b byte) (PIVSlot, error) {
	s := PIVSlot(b)
	if !s.IsValid() {
		return 0, fmt.Errorf("%w: 0x%02x", ErrInvalidSlot, b)
	}
	return s, nil
}

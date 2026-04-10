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

package pivcert

// SlotModel describes a PKCS#11 token that organizes keys into predefined
// slots (e.g., YubiKey PIV). Implementations track which slots are occupied
// and provide auto-allocation for FIDO2 credential key generation.
// This interface is optional — generic PKCS#11 tokens do not use it.
type SlotModel interface {
	// AllSlots returns all slot identifiers supported by this model.
	AllSlots() []PIVSlot

	// AvailableSlots returns slots that do not currently hold a key.
	AvailableSlots() ([]PIVSlot, error)

	// OccupiedSlots returns slots that currently hold a key or certificate.
	OccupiedSlots() ([]PIVSlot, error)

	// IsOccupied reports whether the given slot holds a key or certificate.
	IsOccupied(slot PIVSlot) (bool, error)

	// NextAvailable returns the first unoccupied slot, preferring retired
	// slots (82-95) over primary slots (9a-9e) to preserve standard PIV
	// slot assignments. Returns ErrNoAvailableSlot if all slots are full.
	NextAvailable() (PIVSlot, error)

	// SlotOccupancy returns metadata and occupancy state for a single slot.
	SlotOccupancy(slot PIVSlot) (*SlotOccupancyInfo, error)

	// Refresh re-reads occupancy from the token. Must be called after
	// external mutations (key generation, deletion, import).
	Refresh() error
}

// SlotOccupancyInfo describes the current state of a single PIV slot.
type SlotOccupancyInfo struct {
	// Slot is the PIV slot identifier.
	Slot PIVSlot

	// Name is the human-readable slot name (e.g., "PIV Authentication").
	Name string

	// Description is the slot purpose description.
	Description string

	// Occupied is true when the slot holds a private key.
	Occupied bool

	// KeyAlgorithm describes the key type (e.g., "ECDSA P-256").
	// Empty when the slot is unoccupied.
	KeyAlgorithm string

	// HasCert is true when the slot also holds a certificate.
	HasCert bool
}

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

package tpm2

import (
	"errors"
	"sync"

	"github.com/jeremyhahn/go-xkms/pkg/pivcert"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/storage/hardware"
)

// Compile-time interface check.
var _ pivcert.SlotModel = (*PIVSlotModel)(nil)

// pivSlotToCertIDMap maps each PIV slot to the certificate ID under which its
// certificate is filed in TPM NV RAM.
//
// # PIV slot to NV index mapping
//
// hardware.TPM2CertStorage addresses NV RAM by certificate ID, deriving the
// index as BaseIndex + (xxhash64(id) mod 0x00400000) and writing the ID into
// the record header stored at that index. The derivation is a pure function of
// the ID, so pinning one immutable ID per PIV slot pins one NV index per PIV
// slot:
//
//   - Deterministic: the ID for a slot is a compile-time constant, so the same
//     slot always resolves to the same NV index for a given base index.
//   - Stable across restarts: nothing about the mapping lives in process
//     memory or in a host-side index file. A certificate stored today is found
//     tomorrow by recomputing the hash, and the record header lets the storage
//     confirm the index really holds that slot's certificate.
//   - In range: the modulus keeps every index inside
//     [BaseIndex, BaseIndex+0x00400000), the range the storage owns.
//   - Collision-free: the IDs are fixed, so the 25 resulting indices are fixed.
//     TestPIVSlotCertIDs_MapToDistinctNVIndices pins that all 25 are distinct
//     on real hardware behaviour. Should a future slot ever collide, the record
//     header makes the storage refuse the write rather than clobber the
//     occupant, and Store reports pivcert.ErrStorageFull.
//
// These strings are part of the on-device format. Changing one orphans every
// certificate already stored under the old value.
var pivSlotToCertIDMap = map[pivcert.PIVSlot]string{
	pivcert.PIVSlotAuthentication:     "piv-cert-9a",
	pivcert.PIVSlotDigitalSignature:   "piv-cert-9c",
	pivcert.PIVSlotKeyManagement:      "piv-cert-9d",
	pivcert.PIVSlotCardAuthentication: "piv-cert-9e",
	pivcert.PIVSlotAttestation:        "piv-cert-f9",
	pivcert.PIVSlotRetired1:           "piv-cert-82",
	pivcert.PIVSlotRetired2:           "piv-cert-83",
	pivcert.PIVSlotRetired3:           "piv-cert-84",
	pivcert.PIVSlotRetired4:           "piv-cert-85",
	pivcert.PIVSlotRetired5:           "piv-cert-86",
	pivcert.PIVSlotRetired6:           "piv-cert-87",
	pivcert.PIVSlotRetired7:           "piv-cert-88",
	pivcert.PIVSlotRetired8:           "piv-cert-89",
	pivcert.PIVSlotRetired9:           "piv-cert-8a",
	pivcert.PIVSlotRetired10:          "piv-cert-8b",
	pivcert.PIVSlotRetired11:          "piv-cert-8c",
	pivcert.PIVSlotRetired12:          "piv-cert-8d",
	pivcert.PIVSlotRetired13:          "piv-cert-8e",
	pivcert.PIVSlotRetired14:          "piv-cert-8f",
	pivcert.PIVSlotRetired15:          "piv-cert-90",
	pivcert.PIVSlotRetired16:          "piv-cert-91",
	pivcert.PIVSlotRetired17:          "piv-cert-92",
	pivcert.PIVSlotRetired18:          "piv-cert-93",
	pivcert.PIVSlotRetired19:          "piv-cert-94",
	pivcert.PIVSlotRetired20:          "piv-cert-95",
}

// certIDToPIVSlotMap is the reverse mapping from NV certificate ID to PIV slot.
var certIDToPIVSlotMap map[string]pivcert.PIVSlot

func init() {
	certIDToPIVSlotMap = make(map[string]pivcert.PIVSlot, len(pivSlotToCertIDMap))
	for slot, id := range pivSlotToCertIDMap {
		certIDToPIVSlotMap[id] = slot
	}
}

// PIVSlotToCertID returns the NV certificate ID for a PIV slot.
// The second return value reports whether the slot has a mapping.
func PIVSlotToCertID(slot pivcert.PIVSlot) (string, bool) {
	id, ok := pivSlotToCertIDMap[slot]
	return id, ok
}

// CertIDToPIVSlot returns the PIV slot filed under an NV certificate ID.
// The second return value reports whether the ID belongs to a PIV slot; IDs
// written by other subsystems sharing the NV index range report false.
func CertIDToPIVSlot(id string) (pivcert.PIVSlot, bool) {
	slot, ok := certIDToPIVSlotMap[id]
	return slot, ok
}

// certIDFor returns the NV certificate ID for a slot, or pivcert.ErrInvalidSlot
// when the slot is not a recognized PIV slot.
func certIDFor(slot pivcert.PIVSlot) (string, error) {
	id, ok := pivSlotToCertIDMap[slot]
	if !ok {
		return "", pivcert.ErrInvalidSlot
	}
	return id, nil
}

// skipAutoAllocSlots contains primary slots that NextAvailable never returns
// because they serve dedicated PIV authentication roles.
var skipAutoAllocSlots = map[pivcert.PIVSlot]struct{}{
	pivcert.PIVSlotAuthentication:     {},
	pivcert.PIVSlotCardAuthentication: {},
}

// PIVSlotModel implements pivcert.SlotModel for TPM2 NV certificate storage.
// A slot counts as occupied when NV RAM holds a certificate for it; the TPM
// keeps PIV keys outside this storage, so certificate presence is the only
// occupancy signal available here.
type PIVSlotModel struct {
	hw       hardware.HardwareCertStorage
	mu       sync.RWMutex
	occupied map[pivcert.PIVSlot]struct{}
}

// NewPIVSlotModel creates a slot model over TPM2 NV certificate storage.
// It performs an initial Refresh to populate occupancy state.
func NewPIVSlotModel(hw hardware.HardwareCertStorage) (*PIVSlotModel, error) {
	if hw == nil {
		return nil, pivcert.NewStorageTypeError("NewPIVSlotModel", pivcert.StorageTypeTPM2, pivcert.ErrInvalidConfig)
	}

	m := &PIVSlotModel{
		hw:       hw,
		occupied: make(map[pivcert.PIVSlot]struct{}),
	}
	if err := m.Refresh(); err != nil {
		return nil, err
	}
	return m, nil
}

// AllSlots returns all PIV slot identifiers supported by this model.
func (m *PIVSlotModel) AllSlots() []pivcert.PIVSlot {
	return pivcert.AllSlots()
}

// AvailableSlots returns slots that hold no certificate.
func (m *PIVSlotModel) AvailableSlots() ([]pivcert.PIVSlot, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	all := pivcert.AllSlots()
	available := make([]pivcert.PIVSlot, 0, len(all)-len(m.occupied))
	for _, slot := range all {
		if _, ok := m.occupied[slot]; !ok {
			available = append(available, slot)
		}
	}
	return available, nil
}

// OccupiedSlots returns slots that hold a certificate.
func (m *PIVSlotModel) OccupiedSlots() ([]pivcert.PIVSlot, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	slots := make([]pivcert.PIVSlot, 0, len(m.occupied))
	for slot := range m.occupied {
		slots = append(slots, slot)
	}
	return slots, nil
}

// IsOccupied reports whether the given slot holds a certificate.
func (m *PIVSlotModel) IsOccupied(slot pivcert.PIVSlot) (bool, error) {
	if !slot.IsValid() {
		return false, pivcert.ErrInvalidSlot
	}

	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.occupied[slot]
	return ok, nil
}

// NextAvailable returns the first slot holding no certificate, preferring
// retired slots (82-95) over primary slots (9c, 9d). Slots 9a and 9e are
// skipped because they serve dedicated authentication roles and should not be
// auto-allocated. Returns pivcert.ErrNoAvailableSlot when every slot is full.
func (m *PIVSlotModel) NextAvailable() (pivcert.PIVSlot, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, slot := range pivcert.RetiredSlots() {
		if _, ok := m.occupied[slot]; !ok {
			return slot, nil
		}
	}

	for _, slot := range pivcert.PrimarySlots() {
		if _, skip := skipAutoAllocSlots[slot]; skip {
			continue
		}
		if _, ok := m.occupied[slot]; !ok {
			return slot, nil
		}
	}

	return "", pivcert.ErrNoAvailableSlot
}

// SlotOccupancy returns metadata and occupancy state for a single slot.
func (m *PIVSlotModel) SlotOccupancy(slot pivcert.PIVSlot) (*pivcert.SlotOccupancyInfo, error) {
	if !slot.IsValid() {
		return nil, pivcert.ErrInvalidSlot
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	info := &pivcert.SlotOccupancyInfo{
		Slot:        slot,
		Name:        pivcert.SlotName(slot),
		Description: pivcert.SlotDescription(slot),
	}
	if _, ok := m.occupied[slot]; ok {
		info.Occupied = true
		info.HasCert = true
	}
	return info, nil
}

// Refresh re-reads occupancy from NV RAM. Certificate IDs written by other
// subsystems into the same NV index range are ignored.
func (m *PIVSlotModel) Refresh() error {
	ids, err := m.hw.ListCerts()
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			ids = nil
		} else {
			return pivcert.NewStorageTypeError("Refresh", pivcert.StorageTypeTPM2, translate(err))
		}
	}

	occupied := make(map[pivcert.PIVSlot]struct{}, len(ids))
	for _, id := range ids {
		if slot, ok := certIDToPIVSlotMap[id]; ok {
			occupied[slot] = struct{}{}
		}
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.occupied = occupied

	return nil
}

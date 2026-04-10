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

package pkcs11

import (
	"encoding/asn1"
	"fmt"
	"sync"

	"github.com/jeremyhahn/go-xkms/pkg/pivcert"
	"github.com/jeremyhahn/go-xkms/pkg/storage/hardware"
	p11 "github.com/miekg/pkcs11"
)

// Compile-time interface check.
var _ pivcert.SlotModel = (*PIVSlotModel)(nil)

// ckkECEdwards is the PKCS#11 CKK_EC_EDWARDS key type constant (0x00000040).
// Defined locally because miekg/pkcs11 v1.1.x does not export it.
const ckkECEdwards = 0x00000040

// PIVSlotModel implements pivcert.SlotModel for PKCS#11 tokens with
// predefined PIV slots (e.g., YubiKey PIV). It tracks occupancy by
// enumerating private key objects via C_FindObjects and mapping their
// CKA_ID values to PIV slots.
type PIVSlotModel struct {
	pool     hardware.PKCS11SessionProvider
	mu       sync.RWMutex
	occupied map[pivcert.PIVSlot]keyInfo
}

// keyInfo holds algorithm and certificate presence for an occupied slot.
type keyInfo struct {
	algorithm string
	hasCert   bool
}

// skipAutoAllocSlots contains primary slots that should not be returned
// by NextAvailable because they serve dedicated PIV authentication roles.
var skipAutoAllocSlots = map[pivcert.PIVSlot]struct{}{
	pivcert.PIVSlotAuthentication:     {},
	pivcert.PIVSlotCardAuthentication: {},
}

// NewPIVSlotModel creates a PIVSlotModel backed by the given PKCS#11 session
// provider. It performs an initial Refresh to populate occupancy state.
func NewPIVSlotModel(pool hardware.PKCS11SessionProvider) (*PIVSlotModel, error) {
	if pool == nil {
		return nil, pivcert.NewStorageTypeError("NewPIVSlotModel", pivcert.StorageTypePKCS11, pivcert.ErrInvalidConfig)
	}
	m := &PIVSlotModel{
		pool:     pool,
		occupied: make(map[pivcert.PIVSlot]keyInfo),
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

// AvailableSlots returns slots that do not currently hold a key.
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

// OccupiedSlots returns slots that currently hold a key or certificate.
func (m *PIVSlotModel) OccupiedSlots() ([]pivcert.PIVSlot, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	slots := make([]pivcert.PIVSlot, 0, len(m.occupied))
	for slot := range m.occupied {
		slots = append(slots, slot)
	}
	return slots, nil
}

// IsOccupied reports whether the given slot holds a key or certificate.
func (m *PIVSlotModel) IsOccupied(slot pivcert.PIVSlot) (bool, error) {
	if !slot.IsValid() {
		return false, pivcert.ErrInvalidSlot
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.occupied[slot]
	return ok, nil
}

// NextAvailable returns the first unoccupied slot, preferring retired slots
// (82-95) over primary slots (9c, 9d). Slots 9a and 9e are skipped because
// they serve dedicated authentication roles and should not be auto-allocated.
// Returns ErrNoAvailableSlot if all slots are full.
func (m *PIVSlotModel) NextAvailable() (pivcert.PIVSlot, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Prefer retired slots first.
	for _, slot := range pivcert.RetiredSlots() {
		if _, ok := m.occupied[slot]; !ok {
			return slot, nil
		}
	}

	// Fall back to primary slots, skipping authentication slots.
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
	if ki, ok := m.occupied[slot]; ok {
		info.Occupied = true
		info.KeyAlgorithm = ki.algorithm
		info.HasCert = ki.hasCert
	}
	return info, nil
}

// Refresh re-reads occupancy from the token by enumerating private key and
// certificate objects via C_FindObjects.
func (m *PIVSlotModel) Refresh() error {
	keys, err := m.enumeratePrivateKeys()
	if err != nil {
		return pivcert.NewStorageTypeError("Refresh", pivcert.StorageTypePKCS11, err)
	}

	certs, err := m.enumerateCertificates()
	if err != nil {
		return pivcert.NewStorageTypeError("Refresh", pivcert.StorageTypePKCS11, err)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.occupied = make(map[pivcert.PIVSlot]keyInfo, len(keys))
	for slot, ki := range keys {
		m.occupied[slot] = ki
	}

	// Mark certificate presence on already-occupied slots.
	for slot := range certs {
		if ki, ok := m.occupied[slot]; ok {
			ki.hasCert = true
			m.occupied[slot] = ki
		} else {
			// Certificate exists without a private key — still counts as occupied.
			m.occupied[slot] = keyInfo{hasCert: true}
		}
	}

	return nil
}

// enumeratePrivateKeys finds all CKO_PRIVATE_KEY objects on the token and maps
// their CKA_ID to a PIV slot with algorithm metadata.
func (m *PIVSlotModel) enumeratePrivateKeys() (map[pivcert.PIVSlot]keyInfo, error) {
	result := make(map[pivcert.PIVSlot]keyInfo)

	err := m.pool.WithSession(func(session p11.SessionHandle) error {
		template := []*p11.Attribute{
			p11.NewAttribute(p11.CKA_CLASS, p11.CKO_PRIVATE_KEY),
		}

		if err := m.pool.Ctx().FindObjectsInit(session, template); err != nil {
			return fmt.Errorf("FindObjectsInit(CKO_PRIVATE_KEY): %w", err)
		}
		defer m.pool.Ctx().FindObjectsFinal(session)

		for {
			handles, _, findErr := m.pool.Ctx().FindObjects(session, 100)
			if findErr != nil {
				return fmt.Errorf("FindObjects(CKO_PRIVATE_KEY): %w", findErr)
			}
			if len(handles) == 0 {
				break
			}
			for _, handle := range handles {
				slot, ki, ok := m.readKeySlotInfo(session, handle)
				if ok {
					result[slot] = ki
				}
			}
		}

		return nil
	})

	return result, err
}

// enumerateCertificates finds all CKO_CERTIFICATE objects on the token and
// returns the set of PIV slots that have certificates.
func (m *PIVSlotModel) enumerateCertificates() (map[pivcert.PIVSlot]struct{}, error) {
	result := make(map[pivcert.PIVSlot]struct{})

	err := m.pool.WithSession(func(session p11.SessionHandle) error {
		template := []*p11.Attribute{
			p11.NewAttribute(p11.CKA_CLASS, p11.CKO_CERTIFICATE),
		}

		if err := m.pool.Ctx().FindObjectsInit(session, template); err != nil {
			return fmt.Errorf("FindObjectsInit(CKO_CERTIFICATE): %w", err)
		}
		defer m.pool.Ctx().FindObjectsFinal(session)

		for {
			handles, _, findErr := m.pool.Ctx().FindObjects(session, 100)
			if findErr != nil {
				return fmt.Errorf("FindObjects(CKO_CERTIFICATE): %w", findErr)
			}
			if len(handles) == 0 {
				break
			}
			for _, handle := range handles {
				attrs, attrErr := m.pool.Ctx().GetAttributeValue(session, handle, []*p11.Attribute{
					p11.NewAttribute(p11.CKA_ID, nil),
				})
				if attrErr != nil || len(attrs) == 0 || len(attrs[0].Value) == 0 {
					continue
				}
				id := attrs[0].Value
				if len(id) != 1 {
					continue
				}
				if slot, ok := ckaIDToPIVSlotMap[id[0]]; ok {
					result[slot] = struct{}{}
				}
			}
		}

		return nil
	})

	return result, err
}

// readKeySlotInfo reads CKA_ID and CKA_KEY_TYPE from a private key handle.
// It returns the PIV slot, key info, and whether the mapping succeeded.
func (m *PIVSlotModel) readKeySlotInfo(session p11.SessionHandle, handle p11.ObjectHandle) (pivcert.PIVSlot, keyInfo, bool) {
	attrs, err := m.pool.Ctx().GetAttributeValue(session, handle, []*p11.Attribute{
		p11.NewAttribute(p11.CKA_ID, nil),
		p11.NewAttribute(p11.CKA_KEY_TYPE, nil),
	})
	if err != nil || len(attrs) < 2 {
		return "", keyInfo{}, false
	}

	id := attrs[0].Value
	if len(id) != 1 {
		return "", keyInfo{}, false
	}

	slot, ok := ckaIDToPIVSlotMap[id[0]]
	if !ok {
		return "", keyInfo{}, false
	}

	algo := m.keyTypeString(session, handle, attrs[1].Value)
	return slot, keyInfo{algorithm: algo}, true
}

// keyTypeString converts a CKA_KEY_TYPE value to a human-readable algorithm
// string, optionally reading CKA_EC_PARAMS for EC curve detail.
func (m *PIVSlotModel) keyTypeString(session p11.SessionHandle, handle p11.ObjectHandle, keyTypeBytes []byte) string {
	keyType := decodeCKKeyType(keyTypeBytes)

	switch keyType {
	case p11.CKK_RSA:
		return m.rsaKeyString(session, handle)
	case p11.CKK_EC:
		return m.ecKeyString(session, handle)
	case ckkECEdwards:
		return "Ed25519"
	default:
		return "Unknown"
	}
}

// rsaKeyString reads CKA_MODULUS to determine RSA key size from modulus length.
func (m *PIVSlotModel) rsaKeyString(session p11.SessionHandle, handle p11.ObjectHandle) string {
	attrs, err := m.pool.Ctx().GetAttributeValue(session, handle, []*p11.Attribute{
		p11.NewAttribute(p11.CKA_MODULUS, nil),
	})
	if err != nil || len(attrs) == 0 || len(attrs[0].Value) == 0 {
		return "RSA"
	}
	bits := len(attrs[0].Value) * 8
	return fmt.Sprintf("RSA %d", bits)
}

// ecKeyString reads CKA_EC_PARAMS and decodes the OID to a curve name.
func (m *PIVSlotModel) ecKeyString(session p11.SessionHandle, handle p11.ObjectHandle) string {
	attrs, err := m.pool.Ctx().GetAttributeValue(session, handle, []*p11.Attribute{
		p11.NewAttribute(p11.CKA_EC_PARAMS, nil),
	})
	if err != nil || len(attrs) == 0 || len(attrs[0].Value) == 0 {
		return "ECDSA"
	}

	curve := ecCurveFromOID(attrs[0].Value)
	if curve == "" {
		return "ECDSA"
	}
	return "ECDSA " + curve
}

// Well-known EC curve OIDs.
var ecCurveOIDs = map[string]string{
	"1.2.840.10045.3.1.7": "P-256",
	"1.3.132.0.34":        "P-384",
	"1.3.132.0.35":        "P-521",
}

// ecCurveFromOID decodes DER-encoded EC parameters (namedCurve OID) and
// returns the curve name, or "" if unrecognized.
func ecCurveFromOID(der []byte) string {
	var oid asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(der, &oid); err != nil {
		return ""
	}
	if name, ok := ecCurveOIDs[oid.String()]; ok {
		return name
	}
	return ""
}

// decodeCKKeyType decodes a CKA_KEY_TYPE attribute value (big-endian uint)
// into a PKCS#11 CKK_* constant.
func decodeCKKeyType(b []byte) uint {
	if len(b) == 0 {
		return ^uint(0)
	}
	var v uint
	for _, byt := range b {
		v = (v << 8) | uint(byt)
	}
	return v
}

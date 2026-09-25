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
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/pivcert"
	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCKAIDToPIVSlot verifies the reverse CKA_ID-to-PIV-slot mapping,
// including the "no mapping" case, since a wrong entry here would attribute
// a certificate or key to the wrong PIV slot.
func TestCKAIDToPIVSlot(t *testing.T) {
	slot, ok := CKAIDToPIVSlot(0x01)
	require.True(t, ok)
	assert.Equal(t, pivcert.PIVSlotAuthentication, slot)

	slot, ok = CKAIDToPIVSlot(0x19)
	require.True(t, ok)
	assert.Equal(t, pivcert.PIVSlotAttestation, slot)

	// Round trip every mapped slot through PIVSlotToCKAID -> CKAIDToPIVSlot.
	for pivSlot, ckaID := range pivSlotToCKAIDMap {
		got, ok := CKAIDToPIVSlot(ckaID)
		require.True(t, ok, "CKA_ID 0x%02x must map back to a slot", ckaID)
		assert.Equal(t, pivSlot, got)
	}

	_, ok = CKAIDToPIVSlot(0xFF)
	assert.False(t, ok, "unmapped CKA_ID must report false")
}

// TestPinPlaintext verifies pinPlaintext's nil-secret shortcut and its
// success path opening a real *secure.Secret, since a bug here would either
// send an empty PIN to a token that requires one or fail to open a
// configured one.
func TestPinPlaintext(t *testing.T) {
	got, err := pinPlaintext(nil)
	require.NoError(t, err)
	assert.Empty(t, got, "nil secret must produce an empty PIN, not an error")

	sec, err := secure.NewSecret([]byte("123456"))
	require.NoError(t, err)
	got, err = pinPlaintext(sec)
	require.NoError(t, err)
	assert.Equal(t, "123456", got)
}

// TestPIVSlotModel_SlotOccupancy_ECKey verifies SlotOccupancy reports a
// curve-qualified ECDSA algorithm string for an EC-backed slot (ecKeyString
// / keyTypeString's CKK_EC branch), which the RSA-only slot the rest of the
// suite exercises never reaches.
func TestPIVSlotModel_SlotOccupancy_ECKey(t *testing.T) {
	pool := newSlotModelTestPool(t)
	model, err := NewPIVSlotModel(pool)
	require.NoError(t, err)

	// preloadedPIVSlots provisions PIVSlotCardAuthentication with an EC
	// P-256 key pair (see provision_pkcs11_test.go).
	info, err := model.SlotOccupancy(pivcert.PIVSlotCardAuthentication)
	require.NoError(t, err)
	assert.True(t, info.Occupied)
	assert.Equal(t, "ECDSA P-256", info.KeyAlgorithm)
}

// TestPIVSlotModel_NextAvailable_FallsBackToPrimary verifies NextAvailable
// falls back to an unoccupied primary slot once every retired slot is
// taken, and that it returns ErrNoAvailableSlot once every allocatable slot
// (retired plus non-authentication primary) is occupied. The occupancy map
// is populated directly (white-box, same package) rather than by
// provisioning 20+ SoftHSM key pairs, since NextAvailable only ever
// consults m.occupied.
func TestPIVSlotModel_NextAvailable_FallsBackToPrimary(t *testing.T) {
	pool := newSlotModelTestPool(t)
	model, err := NewPIVSlotModel(pool)
	require.NoError(t, err)

	model.mu.Lock()
	model.occupied = make(map[pivcert.PIVSlot]keyInfo, len(pivcert.RetiredSlots()))
	for _, slot := range pivcert.RetiredSlots() {
		model.occupied[slot] = keyInfo{algorithm: "RSA 2048"}
	}
	model.mu.Unlock()

	slot, err := model.NextAvailable()
	require.NoError(t, err)
	// PIVSlotAuthentication and PIVSlotCardAuthentication are skipped by
	// skipAutoAllocSlots, so the first primary slot returned must be one of
	// the two remaining primary slots.
	assert.Contains(t, []pivcert.PIVSlot{pivcert.PIVSlotDigitalSignature, pivcert.PIVSlotKeyManagement}, slot)

	// Occupy every slot NextAvailable is willing to allocate.
	model.mu.Lock()
	for _, slot := range pivcert.PrimarySlots() {
		if _, skip := skipAutoAllocSlots[slot]; skip {
			continue
		}
		model.occupied[slot] = keyInfo{algorithm: "RSA 2048"}
	}
	model.mu.Unlock()

	_, err = model.NextAvailable()
	assert.ErrorIs(t, err, pivcert.ErrNoAvailableSlot)
}

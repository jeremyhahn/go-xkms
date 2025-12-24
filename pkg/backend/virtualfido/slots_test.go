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
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPIVSlotString(t *testing.T) {
	tests := []struct {
		slot     PIVSlot
		expected string
	}{
		{SlotAuthentication, "Authentication (9A)"},
		{SlotSignature, "Signature (9C)"},
		{SlotKeyManagement, "Key Management (9D)"},
		{SlotCardAuth, "Card Auth (9E)"},
		{SlotRetired1, "Retired 1 (82)"},
		{SlotRetired10, "Retired 10 (8B)"},
		{SlotRetired20, "Retired 20 (95)"},
		{PIVSlot(0xFF), "Unknown (FF)"},
	}

	for _, tc := range tests {
		t.Run(tc.expected, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.slot.String())
		})
	}
}

func TestPIVSlotRequiresPIN(t *testing.T) {
	assert.True(t, SlotSignature.RequiresPIN())
	assert.False(t, SlotAuthentication.RequiresPIN())
	assert.False(t, SlotKeyManagement.RequiresPIN())
	assert.False(t, SlotCardAuth.RequiresPIN())
	assert.False(t, SlotRetired1.RequiresPIN())
}

func TestPIVSlotIsValid(t *testing.T) {
	// Primary slots
	assert.True(t, SlotAuthentication.IsValid())
	assert.True(t, SlotSignature.IsValid())
	assert.True(t, SlotKeyManagement.IsValid())
	assert.True(t, SlotCardAuth.IsValid())

	// Retired slots
	assert.True(t, SlotRetired1.IsValid())
	assert.True(t, SlotRetired10.IsValid())
	assert.True(t, SlotRetired20.IsValid())

	// Invalid slots
	assert.False(t, PIVSlot(0x00).IsValid())
	assert.False(t, PIVSlot(0xFF).IsValid())
	assert.False(t, PIVSlot(0x81).IsValid()) // Just before retired range
	assert.False(t, PIVSlot(0x96).IsValid()) // Just after retired range
}

func TestPIVSlotIsPrimarySlot(t *testing.T) {
	assert.True(t, SlotAuthentication.IsPrimarySlot())
	assert.True(t, SlotSignature.IsPrimarySlot())
	assert.True(t, SlotKeyManagement.IsPrimarySlot())
	assert.True(t, SlotCardAuth.IsPrimarySlot())
	assert.False(t, SlotRetired1.IsPrimarySlot())
	assert.False(t, SlotRetired20.IsPrimarySlot())
}

func TestPIVSlotIsRetiredSlot(t *testing.T) {
	assert.False(t, SlotAuthentication.IsRetiredSlot())
	assert.False(t, SlotSignature.IsRetiredSlot())
	assert.True(t, SlotRetired1.IsRetiredSlot())
	assert.True(t, SlotRetired10.IsRetiredSlot())
	assert.True(t, SlotRetired20.IsRetiredSlot())
}

func TestPIVSlotStorageKey(t *testing.T) {
	assert.Equal(t, "piv/slots/9a", SlotAuthentication.StorageKey())
	assert.Equal(t, "piv/slots/9c", SlotSignature.StorageKey())
	assert.Equal(t, "piv/slots/82", SlotRetired1.StorageKey())
}

func TestAllPrimarySlots(t *testing.T) {
	slots := AllPrimarySlots()
	assert.Len(t, slots, 4)
	assert.Contains(t, slots, SlotAuthentication)
	assert.Contains(t, slots, SlotSignature)
	assert.Contains(t, slots, SlotKeyManagement)
	assert.Contains(t, slots, SlotCardAuth)
}

func TestAllRetiredSlots(t *testing.T) {
	slots := AllRetiredSlots()
	assert.Len(t, slots, 20)
	assert.Contains(t, slots, SlotRetired1)
	assert.Contains(t, slots, SlotRetired10)
	assert.Contains(t, slots, SlotRetired20)
}

func TestAllSlots(t *testing.T) {
	slots := AllSlots()
	assert.Len(t, slots, 24) // 4 primary + 20 retired
}

func TestSlotFromByte(t *testing.T) {
	t.Run("valid primary slot", func(t *testing.T) {
		slot, err := SlotFromByte(0x9A)
		assert.NoError(t, err)
		assert.Equal(t, SlotAuthentication, slot)
	})

	t.Run("valid retired slot", func(t *testing.T) {
		slot, err := SlotFromByte(0x82)
		assert.NoError(t, err)
		assert.Equal(t, SlotRetired1, slot)
	})

	t.Run("invalid slot", func(t *testing.T) {
		slot, err := SlotFromByte(0xFF)
		assert.Error(t, err)
		assert.Equal(t, PIVSlot(0), slot)
	})
}

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

package pkcs11mgr

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestModuleState_String(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		state    ModuleState
		expected string
	}{
		{"unloaded", ModuleStateUnloaded, "unloaded"},
		{"loaded", ModuleStateLoaded, "loaded"},
		{"error", ModuleStateError, "error"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.expected, tc.state.String())
		})
	}
}

func TestModuleState_String_Unknown(t *testing.T) {
	t.Parallel()

	unknown := ModuleState(999)
	assert.Equal(t, "unknown", unknown.String())

	negative := ModuleState(-1)
	assert.Equal(t, "unknown", negative.String())
}

func TestModuleState_Constants(t *testing.T) {
	t.Parallel()

	assert.Equal(t, ModuleState(0), ModuleStateUnloaded)
	assert.Equal(t, ModuleState(1), ModuleStateLoaded)
	assert.Equal(t, ModuleState(2), ModuleStateError)
}

func TestSlotInfo_Fields(t *testing.T) {
	t.Parallel()

	slot := SlotInfo{
		SlotID:          1,
		Label:           "YubiKey PIV",
		Serial:          "12345678",
		TokenPresent:    true,
		HardwareVersion: "5.4",
		FirmwareVersion: "5.4.3",
	}

	assert.Equal(t, uint(1), slot.SlotID)
	assert.Equal(t, "YubiKey PIV", slot.Label)
	assert.Equal(t, "12345678", slot.Serial)
	assert.True(t, slot.TokenPresent)
	assert.Equal(t, "5.4", slot.HardwareVersion)
	assert.Equal(t, "5.4.3", slot.FirmwareVersion)
}

func TestSlotInfo_ZeroValue(t *testing.T) {
	t.Parallel()

	var slot SlotInfo
	assert.Equal(t, uint(0), slot.SlotID)
	assert.Equal(t, "", slot.Label)
	assert.Equal(t, "", slot.Serial)
	assert.False(t, slot.TokenPresent)
	assert.Equal(t, "", slot.HardwareVersion)
	assert.Equal(t, "", slot.FirmwareVersion)
}

func TestModuleInfo_Fields(t *testing.T) {
	t.Parallel()

	mod := ModuleInfo{
		ID:          "pkcs11-libykcs11",
		DisplayName: "YubiKey PKCS#11",
		LibraryPath: "/usr/lib/libykcs11.so",
		State:       ModuleStateLoaded,
		Slots: []SlotInfo{
			{SlotID: 0, Label: "PIV", TokenPresent: true},
			{SlotID: 1, Label: "OATH", TokenPresent: false},
		},
		ErrorMsg: "",
	}

	assert.Equal(t, "pkcs11-libykcs11", mod.ID)
	assert.Equal(t, "YubiKey PKCS#11", mod.DisplayName)
	assert.Equal(t, "/usr/lib/libykcs11.so", mod.LibraryPath)
	assert.Equal(t, ModuleStateLoaded, mod.State)
	assert.Len(t, mod.Slots, 2)
	assert.True(t, mod.Slots[0].TokenPresent)
	assert.False(t, mod.Slots[1].TokenPresent)
	assert.Equal(t, "", mod.ErrorMsg)
}

func TestModuleInfo_ErrorState(t *testing.T) {
	t.Parallel()

	mod := ModuleInfo{
		ID:       "pkcs11-broken",
		State:    ModuleStateError,
		ErrorMsg: "library not found",
	}

	assert.Equal(t, ModuleStateError, mod.State)
	assert.Equal(t, "library not found", mod.ErrorMsg)
}

func TestSessionHandle_Fields(t *testing.T) {
	t.Parallel()

	handle := SessionHandle{
		ModuleID: "pkcs11-libykcs11",
		SlotID:   0,
		Handle:   42,
	}

	assert.Equal(t, "pkcs11-libykcs11", handle.ModuleID)
	assert.Equal(t, uint(0), handle.SlotID)
	assert.Equal(t, uint(42), handle.Handle)
}

func TestSessionHandle_ZeroValue(t *testing.T) {
	t.Parallel()

	var handle SessionHandle
	assert.Equal(t, "", handle.ModuleID)
	assert.Equal(t, uint(0), handle.SlotID)
	assert.Equal(t, uint(0), handle.Handle)
}

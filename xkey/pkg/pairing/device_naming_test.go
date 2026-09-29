// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestValidateDeviceName_AcceptsOrdinaryNames verifies a normal, printable
// device name within the length bound passes.
func TestValidateDeviceName_AcceptsOrdinaryNames(t *testing.T) {
	require.NoError(t, ValidateDeviceName("John's Pixel"))
	require.NoError(t, ValidateDeviceName(strings.Repeat("a", MaxDeviceNameLength)))
}

// TestValidateDeviceName_RejectsInvalidNames pins the three failure modes a
// malicious or malfunctioning peer could otherwise advertise into a stored
// record: empty, too long, and containing a non-printable character.
func TestValidateDeviceName_RejectsInvalidNames(t *testing.T) {
	tests := []struct {
		name string
		in   string
	}{
		{name: "empty", in: ""},
		{name: "too long", in: strings.Repeat("a", MaxDeviceNameLength+1)},
		{name: "control character", in: "Pixel\x00Evil"},
		{name: "newline injection", in: "Pixel\nrm -rf /"},
		{name: "escape sequence", in: "Pixel\x1b[31mRED"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateDeviceName(tt.in)
			if !errors.Is(err, ErrDeviceNameInvalid) {
				t.Fatalf("got error %v, want ErrDeviceNameInvalid", err)
			}
		})
	}
}

// TestConflictingPairedDevice_DetectsDifferentDeviceSameName verifies a
// record sharing the requested name but identifying as a different device
// -- neither its address nor its key match -- is reported as a collision.
func TestConflictingPairedDevice_DetectsDifferentDeviceSameName(t *testing.T) {
	devices := []PairedDevice{
		{Name: "Pixel", Address: "AA:AA:AA:AA:AA:AA", NoisePublicKey: "keyA"},
	}

	conflict := ConflictingPairedDevice(devices, "Pixel", "BB:BB:BB:BB:BB:BB", "keyB")
	require.NotNil(t, conflict)
	assert.Equal(t, "AA:AA:AA:AA:AA:AA", conflict.Address)
}

// TestConflictingPairedDevice_AllowsSameDevice verifies re-pairing the SAME
// device is not reported as a collision, whether it is identified by a
// matching address (e.g. the phone's Noise key rotated after a reinstall)
// or a matching key (e.g. Android's RPA rotated the address).
func TestConflictingPairedDevice_AllowsSameDevice(t *testing.T) {
	devices := []PairedDevice{
		{Name: "Pixel", Address: "AA:AA:AA:AA:AA:AA", NoisePublicKey: "keyA"},
	}

	// Same address, rotated key.
	conflict := ConflictingPairedDevice(devices, "Pixel", "AA:AA:AA:AA:AA:AA", "keyB")
	assert.Nil(t, conflict)

	// Same key, rotated address.
	conflict = ConflictingPairedDevice(devices, "Pixel", "ZZ:ZZ:ZZ:ZZ:ZZ:ZZ", "keyA")
	assert.Nil(t, conflict)

	// A different name entirely is never a collision either.
	conflict = ConflictingPairedDevice(devices, "Someone Else's Phone", "ZZ:ZZ:ZZ:ZZ:ZZ:ZZ", "keyZ")
	assert.Nil(t, conflict)
}

// TestSamePairedDeviceIndices_MatchesByAddressOrKey verifies the union
// match: Android's RPA rotation changes the address without changing the
// pinned key, and a reinstall can do the reverse, so either field matching
// is enough to identify the same physical device.
func TestSamePairedDeviceIndices_MatchesByAddressOrKey(t *testing.T) {
	devices := []PairedDevice{
		{Name: "Pixel", Address: "AA:AA:AA:AA:AA:AA", NoisePublicKey: "keyA"},
		{Name: "Old Name", Address: "BB:BB:BB:BB:BB:BB", NoisePublicKey: "keyA"},
		{Name: "Unrelated", Address: "CC:CC:CC:CC:CC:CC", NoisePublicKey: "keyC"},
	}

	// Matches on address alone.
	idx := SamePairedDeviceIndices(devices, "AA:AA:AA:AA:AA:AA", "keyZ")
	assert.Equal(t, []int{0}, idx)

	// Matches on key alone (address rotated).
	idx = SamePairedDeviceIndices(devices, "ZZ:ZZ:ZZ:ZZ:ZZ:ZZ", "keyA")
	assert.Equal(t, []int{0, 1}, idx)

	// No match.
	idx = SamePairedDeviceIndices(devices, "ZZ:ZZ:ZZ:ZZ:ZZ:ZZ", "keyZ")
	assert.Nil(t, idx)

	// Empty address/key never match an empty stored field.
	empty := []PairedDevice{{Name: "Blank", Address: "", NoisePublicKey: ""}}
	idx = SamePairedDeviceIndices(empty, "", "")
	assert.Nil(t, idx)
}

// TestReplacePairedDevices_CollapsesStaleEntries verifies every stale record
// identifying the same device is removed and replaced with exactly one
// fresh record, at the position of the first removed entry, without
// disturbing unrelated records.
func TestReplacePairedDevices_CollapsesStaleEntries(t *testing.T) {
	devices := []PairedDevice{
		{Name: "Unrelated", Address: "CC:CC:CC:CC:CC:CC"},
		{Name: "Old Name 1", Address: "AA:AA:AA:AA:AA:AA"},
		{Name: "Old Name 2", Address: "BB:BB:BB:BB:BB:BB"},
	}
	replacement := PairedDevice{Name: "Pixel", Address: "DD:DD:DD:DD:DD:DD"}

	result := ReplacePairedDevices(devices, []int{1, 2}, replacement)

	require.Len(t, result, 2)
	assert.Equal(t, "Unrelated", result[0].Name)
	assert.Equal(t, "Pixel", result[1].Name)
}

// TestReplacePairedDevices_AppendsWhenNoIndices verifies an empty indices
// slice appends the replacement, matching the "brand new device" case.
func TestReplacePairedDevices_AppendsWhenNoIndices(t *testing.T) {
	devices := []PairedDevice{{Name: "Existing"}}
	replacement := PairedDevice{Name: "New"}

	result := ReplacePairedDevices(devices, nil, replacement)

	require.Len(t, result, 2)
	assert.Equal(t, "Existing", result[0].Name)
	assert.Equal(t, "New", result[1].Name)
}

// TestFindPairedDeviceByName_ReturnsSingleMatch verifies the ordinary case:
// exactly one record has the name.
func TestFindPairedDeviceByName_ReturnsSingleMatch(t *testing.T) {
	devices := []PairedDevice{
		{Name: "Pixel", Address: "AA:AA:AA:AA:AA:AA"},
	}

	found, err := FindPairedDeviceByName(devices, "Pixel")
	require.NoError(t, err)
	require.NotNil(t, found)
	assert.Equal(t, "AA:AA:AA:AA:AA:AA", found.Address)
}

// TestFindPairedDeviceByName_ReturnsNilForNoMatch verifies a name that is
// not present returns (nil, nil), matching callers' existing "not found"
// contract.
func TestFindPairedDeviceByName_ReturnsNilForNoMatch(t *testing.T) {
	devices := []PairedDevice{{Name: "Pixel"}}

	found, err := FindPairedDeviceByName(devices, "Nonexistent")
	require.NoError(t, err)
	assert.Nil(t, found)
}

// TestFindPairedDeviceByName_RefusesAmbiguousMatch pins #1307: a name shared
// by more than one record must fail the lookup instead of silently
// returning whichever record happens to be first in the list -- the one a
// connection would then trust the pinned key of.
func TestFindPairedDeviceByName_RefusesAmbiguousMatch(t *testing.T) {
	devices := []PairedDevice{
		{Name: "Pixel", Address: "AA:AA:AA:AA:AA:AA", NoisePublicKey: "legit-key"},
		{Name: "Pixel", Address: "BB:BB:BB:BB:BB:BB", NoisePublicKey: "attacker-key"},
	}

	found, err := FindPairedDeviceByName(devices, "Pixel")
	assert.Nil(t, found)
	if !errors.Is(err, ErrDeviceNameAmbiguous) {
		t.Fatalf("got error %v, want ErrDeviceNameAmbiguous", err)
	}
}

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

//go:build ble

package cmd

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestResolvePairedDevices_RefusesNameCollisionWithDifferentKey pins #1307:
// a fresh device may not be persisted under a name an existing, differently
// keyed record already uses.
func TestResolvePairedDevices_RefusesNameCollisionWithDifferentKey(t *testing.T) {
	existing := []PairedDevice{
		{Name: "Test Pixel", Address: "AA:AA:AA:AA:AA:AA", NoisePublicKey: "legit-key"},
	}
	fresh := PairedDevice{Name: "Test Pixel", Address: "BB:BB:BB:BB:BB:BB", NoisePublicKey: "attacker-key"}

	updated, err := resolvePairedDevices(existing, fresh)

	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrDeviceNameCollision), "got %v, want ErrDeviceNameCollision", err)
	assert.Nil(t, updated)
	// The existing record must be untouched.
	require.Len(t, existing, 1)
	assert.Equal(t, "legit-key", existing[0].NoisePublicKey)
}

// TestResolvePairedDevices_AppendsANewUnrelatedDevice verifies the ordinary
// case: a name and key that match nothing existing is simply appended.
func TestResolvePairedDevices_AppendsANewUnrelatedDevice(t *testing.T) {
	existing := []PairedDevice{
		{Name: "Other Phone", Address: "AA:AA:AA:AA:AA:AA", NoisePublicKey: "other-key"},
	}
	fresh := PairedDevice{Name: "Test Pixel", Address: "BB:BB:BB:BB:BB:BB", NoisePublicKey: "new-key"}

	updated, err := resolvePairedDevices(existing, fresh)

	require.NoError(t, err)
	require.Len(t, updated, 2)
	assert.Equal(t, "Other Phone", updated[0].Name)
	assert.Equal(t, "Test Pixel", updated[1].Name)
}

// TestResolvePairedDevices_ReplacesSameAddressInPlace verifies the ordinary
// re-pair case: the phone's address did not change, so the stale record is
// replaced rather than duplicated.
func TestResolvePairedDevices_ReplacesSameAddressInPlace(t *testing.T) {
	existing := []PairedDevice{
		{Name: "Test Pixel", Address: "AA:AA:AA:AA:AA:AA", NoisePublicKey: "old-key"},
	}
	fresh := PairedDevice{Name: "Test Pixel", Address: "AA:AA:AA:AA:AA:AA", NoisePublicKey: "new-key"}

	updated, err := resolvePairedDevices(existing, fresh)

	require.NoError(t, err)
	require.Len(t, updated, 1)
	assert.Equal(t, "new-key", updated[0].NoisePublicKey)
}

// TestResolvePairedDevices_ReplacesByKeyAcrossAddressRotation is the #1307
// regression case: a phone whose BLE address rotated (Android RPA) re-pairs
// under a new address but the SAME Noise static key. The stale record for
// the old address must be replaced, not left behind as a duplicate, and
// this must happen whether or not --force was used -- resolvePairedDevices
// takes no force parameter at all, because the identity match makes that
// gate unnecessary.
func TestResolvePairedDevices_ReplacesByKeyAcrossAddressRotation(t *testing.T) {
	existing := []PairedDevice{
		{Name: "Test Pixel", Address: "AA:AA:AA:AA:AA:AA", NoisePublicKey: "stable-key"},
	}
	fresh := PairedDevice{Name: "Test Pixel", Address: "ZZ:ZZ:ZZ:ZZ:ZZ:ZZ", NoisePublicKey: "stable-key"}

	updated, err := resolvePairedDevices(existing, fresh)

	require.NoError(t, err)
	require.Len(t, updated, 1, "the rotated-address re-pair must replace the stale entry, not duplicate it")
	assert.Equal(t, "ZZ:ZZ:ZZ:ZZ:ZZ:ZZ", updated[0].Address)
}

// TestResolvePairedDevices_ForceNeverDeletesAnUnrelatedSameNamedDevice pins
// the exact defect #1307 reported: a re-pair used to delete EVERY record
// sharing the advertised name, including a different physical device that
// happened to have the same display name. That case is now refused as a
// collision before any deletion is considered, so the unrelated device's
// record must survive untouched.
func TestResolvePairedDevices_ForceNeverDeletesAnUnrelatedSameNamedDevice(t *testing.T) {
	unrelated := PairedDevice{Name: "Test Pixel", Address: "CC:CC:CC:CC:CC:CC", NoisePublicKey: "someone-elses-key"}
	existing := []PairedDevice{unrelated}
	fresh := PairedDevice{Name: "Test Pixel", Address: "DD:DD:DD:DD:DD:DD", NoisePublicKey: "my-key"}

	updated, err := resolvePairedDevices(existing, fresh)

	require.Error(t, err, "a colliding name must be refused, not resolved by deleting the other device")
	assert.True(t, errors.Is(err, ErrDeviceNameCollision))
	assert.Nil(t, updated)
	require.Len(t, existing, 1, "the unrelated device's own record must never be touched")
	assert.Equal(t, "someone-elses-key", existing[0].NoisePublicKey)
}

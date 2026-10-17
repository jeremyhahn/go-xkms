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

//go:build ble

package cmd

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestNewPairedDeviceRecord_WritesNoAttestationClaimWhenThereIsNone is the
// invariant the policy setting is NOT allowed to move.
//
// The ruling made refusing configurable. It did not make recording
// configurable: #95 was about a pairing record carrying attestation claims that
// were never verified -- a security level and a fingerprint taken from the
// peer's own JSON -- and every later connection is judged against that record.
// So when pairing proceeds without a verified attestation, the record must
// carry NOTHING about the device's hardware, not a zeroed version of it.
func TestNewPairedDeviceRecord_WritesNoAttestationClaimWhenThereIsNone(t *testing.T) {
	device := newPairedDeviceRecord("pixel", "AA:BB:CC:DD:EE:FF",
		[]byte("remote-public"), "sealed-local-private", nil)

	require.Equal(t, "pixel", device.Name)
	require.Equal(t, "AA:BB:CC:DD:EE:FF", device.Address)
	require.NotEmpty(t, device.NoisePublicKey, "the pairing half of the record is still written")
	require.NotEmpty(t, device.LocalNoisePrivateKey)
	require.False(t, device.PairedAt.IsZero())

	require.Empty(t, device.SecurityLevel,
		"an unverified pairing must not claim a hardware security level")
	require.Empty(t, device.DeviceFingerprint,
		"and must not claim a device identity -- this is the #95 defect itself")
	require.Empty(t, device.DeviceBootHashHex)
	require.False(t, device.BootStateVerified)
	require.True(t, device.LastDeviceAttestationTime.IsZero(),
		"a device that was never attested has no last-attestation time; a zero-valued "+
			"one written here would later read as an attestation that happened")
}

// TestNewPairedDeviceRecord_RecordsAVerifiedAttestation is the other side: when
// the attestation DID verify, every claim reaches the record. Without this the
// test above passes against a record builder that simply never records
// anything.
func TestNewPairedDeviceRecord_RecordsAVerifiedAttestation(t *testing.T) {
	when := time.Now().UTC().Truncate(time.Second)
	device := newPairedDeviceRecord("pixel", "AA:BB:CC:DD:EE:FF",
		[]byte("remote-public"), "sealed-local-private",
		&DeviceAttestationResult{
			AttestationTime:   when,
			SecurityLevel:     "strongbox",
			BootStateVerified: true,
			BootHashHex:       "deadbeef",
			DeviceFingerprint: "SHA256:anchor",
		})

	require.Equal(t, when, device.LastDeviceAttestationTime)
	require.Equal(t, "strongbox", device.SecurityLevel)
	require.True(t, device.BootStateVerified)
	require.Equal(t, "deadbeef", device.DeviceBootHashHex)
	require.Equal(t, "SHA256:anchor", device.DeviceFingerprint)
}

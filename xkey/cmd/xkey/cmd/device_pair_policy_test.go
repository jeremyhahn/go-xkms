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

	xkeyconfig "github.com/jeremyhahn/go-xkms/xkey/pkg/config"
)

// TestAllowUnattestablePairing_ResolvesTheTwoPlanes exercises the whole
// decision surface of the owner ruling of 2026-08-23 on #95: the user setting
// in devices.yaml, the enterprise/SO setting in the sealed PolicySection, and
// the lock that decides whether the second is consulted.
//
// The table is exhaustive over the three inputs rather than illustrative,
// because the interesting cases are the ones where the two planes DISAGREE.
//
// The enterprise plane is MONOTONE: it may only make the answer STRICTER. That
// is not a design preference, it is what this command can honestly enforce.
// Nothing on the CLI path verifies the policy HMAC -- verification needs the SO
// PIN, which a pairing command does not have -- so treating the section as
// authoritative in BOTH directions let anyone who can edit xkey.yaml write
// lock_pairing_attestation_policy: true beside
// pairing_allow_unattestable_devices: true and pair an unattestable device over
// a devices.yaml that refuses. Codex found exactly that. Locking the setting
// OPEN needs authenticated policy and is tracked as #118.
func TestAllowUnattestablePairing_ResolvesTheTwoPlanes(t *testing.T) {
	policy := func(allow, lock bool) *xkeyconfig.Config {
		return &xkeyconfig.Config{Policy: xkeyconfig.PolicySection{
			PairingAllowUnattestableDevices: allow,
			LockPairingAttestationPolicy:    lock,
		}}
	}
	devices := func(allow bool) *DevicesConfig {
		return &DevicesConfig{AttestationPolicy: &AttestationPolicy{AllowUnattestableDevices: allow}}
	}

	tests := []struct {
		name    string
		devices *DevicesConfig
		unified *xkeyconfig.Config
		want    bool
		why     string
	}{
		{
			name: "nothing configured at all", devices: nil, unified: nil, want: false,
			why: "the default the ruling names is fail closed, and it must come from " +
				"the zero value rather than from a defaults table",
		},
		{
			name: "devices.yaml with no attestation_policy block", devices: &DevicesConfig{}, unified: nil, want: false,
			why: "an absent policy block is not a permission",
		},
		{
			name: "user says no, nothing enterprise", devices: devices(false), unified: nil, want: false,
		},
		{
			name: "user says yes, nothing enterprise", devices: devices(true), unified: nil, want: true,
			why: "unlocked, the user's own setting is the answer",
		},
		{
			name: "user says yes, enterprise present but not locked", devices: devices(true), unified: policy(false, false), want: true,
			why: "an enterprise value that has not been locked must not narrow the " +
				"user's setting; the lock is what makes the section authoritative",
		},
		{
			name: "user says no, enterprise present but not locked", devices: devices(false), unified: policy(true, false), want: false,
			why: "and equally must not widen it",
		},
		{
			name: "user says yes, enterprise locks it closed", devices: devices(true), unified: policy(false, true), want: false,
			why: "this is the case the lock exists for: a locked deployment cannot be " +
				"widened by editing devices.yaml",
		},
		{
			name: "user says no, enterprise locks it open", devices: devices(false), unified: policy(true, true), want: false,
			why: "an UNVERIFIED policy section must never widen anything: nothing on " +
				"the CLI path checks the policy HMAC, so honouring this direction " +
				"would let anyone who can edit xkey.yaml pair an unattestable " +
				"device over a devices.yaml that refuses (#118)",
		},
		{
			name: "no user setting, enterprise locks it open", devices: nil, unified: policy(true, true), want: false,
			why: "same, with the user plane absent rather than refusing",
		},
		{
			name: "no user setting, enterprise locks it closed", devices: devices(true), unified: policy(false, true), want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, allowUnattestablePairing(tc.devices, tc.unified), tc.why)
		})
	}
}

// TestAllowUnattestablePairing_DefaultsToRefuseOnAZeroPolicySection pins the
// half of the design that a defaults table would have got wrong.
//
// config.DefaultPolicy() is NOT what a loaded config carries when its file
// holds a partial `policy:` block: viper does not merge a struct default key by
// key, so a file setting only min_pin_length resolves every other policy key to
// its zero value (measured; filed as #114). Both fields here are therefore
// designed so that zero means "not locked, not allowed" -- the same answer as
// no policy at all.
func TestAllowUnattestablePairing_DefaultsToRefuseOnAZeroPolicySection(t *testing.T) {
	require.False(t, allowUnattestablePairing(&DevicesConfig{}, &xkeyconfig.Config{}),
		"a zero PolicySection must read as unlocked and disallowed, because that is "+
			"what a partially-specified policy file actually produces")
}

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
		[]byte("remote-public"), []byte("local-private"), nil)

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
		[]byte("remote-public"), []byte("local-private"),
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

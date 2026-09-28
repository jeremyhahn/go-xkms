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

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"

	xkeyconfig "github.com/jeremyhahn/go-xkms/xkey/pkg/config"
)

// TestAllowUnattestablePairing_ProjectsTheUserPlane pins what is genuinely
// this command's: how devices.yaml becomes the user plane of the shared
// decision. The decision itself, exhaustive over both planes and the
// verification state, is attestation.AllowUnattestablePairing's own table.
func TestAllowUnattestablePairing_ProjectsTheUserPlane(t *testing.T) {
	unlocked := &xkeyconfig.VerifiedPolicy{State: xkeyconfig.PolicyUnsealed}
	lockedOpen := &xkeyconfig.VerifiedPolicy{State: xkeyconfig.PolicySealedVerified, Policy: xkeyconfig.PolicySection{
		LockPairingAttestationPolicy:    true,
		PairingAllowUnattestableDevices: true,
	}}

	tests := []struct {
		name    string
		devices *DevicesConfig
		policy  *xkeyconfig.VerifiedPolicy
		want    bool
		why     string
	}{
		{
			name: "no devices.yaml, unlocked", devices: nil, policy: unlocked, want: false,
			why: "an absent user plane is not a permission",
		},
		{
			name: "devices.yaml with no attestation_policy block, unlocked", devices: &DevicesConfig{}, policy: unlocked, want: false,
			why: "an absent policy block is not a permission either",
		},
		{
			name: "explicit no, unlocked", devices: devicesAllowing(false), policy: unlocked, want: false,
		},
		{
			name: "explicit yes, unlocked", devices: devicesAllowing(true), policy: unlocked, want: true,
			why: "unlocked, the user's own setting is the answer",
		},
		{
			name: "explicit yes, sealed and not verified", devices: devicesAllowing(true), policy: nil, want: false,
			why: "the enterprise plane exists but is unknown, so the answer is the " +
				"fail-closed default whatever devices.yaml says (#118)",
		},
		{
			name: "no devices.yaml, verified and locked open", devices: nil, policy: lockedOpen, want: true,
			why: "a verified policy carries the SO's authority in both directions, " +
				"with the user plane absent rather than refusing",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, allowUnattestablePairing(tc.devices, tc.policy), tc.why)
		})
	}
}

func devicesAllowing(allow bool) *DevicesConfig {
	return &DevicesConfig{AttestationPolicy: &AttestationPolicy{AllowUnattestableDevices: allow}}
}

// newPairingPolicyFixture seals cfg's policy under soPIN into a fresh config
// directory, points the config package at it, and returns a pair command
// carrying the SO PIN flags.
func newPairingPolicyFixture(t *testing.T, cfg *xkeyconfig.Config, soPIN string) *cobra.Command {
	t.Helper()

	configDir := t.TempDir()
	xkeyconfig.SetConfigDir(configDir)
	t.Cleanup(xkeyconfig.ResetConfigDir)
	if soPIN != "" {
		require.NoError(t, xkeyconfig.WritePolicyHMAC(&cfg.Policy, soPIN, xkeyconfig.PolicyHMACPath(configDir)))
	}

	cmd := &cobra.Command{}
	addSOPINFlags(cmd)
	return cmd
}

// lockedOpenConfig is the policy a fleet that pairs development handsets
// would seal: the setting locked OPEN, which only a verified section may grant.
func lockedOpenConfig() *xkeyconfig.Config {
	cfg := xkeyconfig.DefaultConfig()
	cfg.Policy.LockPairingAttestationPolicy = true
	cfg.Policy.PairingAllowUnattestableDevices = true
	return cfg
}

func TestResolvePairingPolicy_UnsealedNeedsNoPIN(t *testing.T) {
	cfg := lockedOpenConfig()
	cmd := newPairingPolicyFixture(t, cfg, "")

	policy, err := resolvePairingPolicy(cmd, cfg, discardLogger())
	require.NoError(t, err)
	require.NotNil(t, policy)
	require.Equal(t, xkeyconfig.PolicyUnsealed, policy.State)
}

// TestResolvePairingPolicy_SealedWithoutPINIsNotConsulted is the ordinary
// enterprise pairing: no SO at the keyboard, so the sealed section is not read
// and the caller fails closed. It is not an error, because an ordinary command
// must not start demanding the SO PIN.
func TestResolvePairingPolicy_SealedWithoutPINIsNotConsulted(t *testing.T) {
	cfg := lockedOpenConfig()
	cmd := newPairingPolicyFixture(t, cfg, testSOPIN)

	policy, err := resolvePairingPolicy(cmd, cfg, discardLogger())
	require.NoError(t, err)
	require.Nil(t, policy, "a sealed section without the SO PIN must not be consulted")
	require.False(t, allowUnattestablePairing(&DevicesConfig{AttestationPolicy: &AttestationPolicy{AllowUnattestableDevices: true}}, policy),
		"and the pairing fails closed whatever devices.yaml says")
}

// TestResolvePairingPolicy_SealedAndVerifiedIsHonouredOpen is the test that
// separates #118 from the monotone mitigation: a correctly sealed policy that
// locks the setting open is obeyed in the permissive direction.
func TestResolvePairingPolicy_SealedAndVerifiedIsHonouredOpen(t *testing.T) {
	cfg := lockedOpenConfig()
	cmd := newPairingPolicyFixture(t, cfg, testSOPIN)
	require.NoError(t, setFlagForTest(t, cmd.Flags(), soPINFlagStdin, "true"))
	stubStdin(t, []byte(testSOPIN+"\n"), nil)

	policy, err := resolvePairingPolicy(cmd, cfg, discardLogger())
	require.NoError(t, err)
	require.NotNil(t, policy)
	require.Equal(t, xkeyconfig.PolicySealedVerified, policy.State)
	require.True(t, allowUnattestablePairing(&DevicesConfig{}, policy),
		"a verified policy locked open permits pairing over a devices.yaml that refuses")
}

// TestResolvePairingPolicy_SealedTamperedPermissivelyIsRefused is the
// fail-open Codex found on #110, now refused rather than obeyed: the SO sealed
// the default (locked closed) policy, a local user edited xkey.yaml to lock it
// open, and the pairing must be refused outright, not continued.
func TestResolvePairingPolicy_SealedTamperedPermissivelyIsRefused(t *testing.T) {
	sealed := xkeyconfig.DefaultConfig()
	cmd := newPairingPolicyFixture(t, sealed, testSOPIN)
	require.NoError(t, setFlagForTest(t, cmd.Flags(), soPINFlagStdin, "true"))
	stubStdin(t, []byte(testSOPIN+"\n"), nil)

	tampered := lockedOpenConfig()
	policy, err := resolvePairingPolicy(cmd, tampered, discardLogger())

	require.Error(t, err)
	require.Nil(t, policy)
	require.ErrorIs(t, err, ErrPairingPolicyRefused)
	require.ErrorIs(t, err, xkeyconfig.ErrPolicyUnverifiable)
	require.ErrorIs(t, err, xkeyconfig.ErrPolicyHMACMismatch)
}

func TestResolvePairingPolicy_SealedWithWrongPINIsRefused(t *testing.T) {
	cfg := lockedOpenConfig()
	cmd := newPairingPolicyFixture(t, cfg, testSOPIN)
	t.Setenv(soPINEnvVar, "not-the-so-pin")

	policy, err := resolvePairingPolicy(cmd, cfg, discardLogger())

	require.Error(t, err)
	require.Nil(t, policy)
	require.ErrorIs(t, err, ErrPairingPolicyRefused)
	require.ErrorIs(t, err, xkeyconfig.ErrPolicyHMACMismatch)
}

func TestResolvePairingPolicy_EmptyStdinIsReported(t *testing.T) {
	cfg := lockedOpenConfig()
	cmd := newPairingPolicyFixture(t, cfg, testSOPIN)
	require.NoError(t, setFlagForTest(t, cmd.Flags(), soPINFlagStdin, "true"))
	stubStdin(t, []byte(""), nil)

	policy, err := resolvePairingPolicy(cmd, cfg, discardLogger())
	require.Error(t, err)
	require.Nil(t, policy)
	require.ErrorIs(t, err, ErrSOPINInputStdinEmpty)
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

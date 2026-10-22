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

package cmd

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/testing/fipstest"
	"github.com/jeremyhahn/go-xkms/pkg/trust/bootstrap"
)

// relayCommand builds a *cobra.Command carrying the same flags
// registerDeviceListenFlags registers on the real deviceRelayCmd, plus
// relay's own --listen flag, so runDeviceRelay can be driven directly in a
// test the same way listenCommand drives runDeviceListen.
func relayCommand(t *testing.T) *cobra.Command {
	t.Helper()
	cmd := listenCommand(t)
	cmd.Flags().String("listen", "", "")
	return cmd
}

func TestDeviceRelayCmd_Structure(t *testing.T) {
	assert.Equal(t, "relay", deviceRelayCmd.Use)
	assert.NotEmpty(t, deviceRelayCmd.Short)
	assert.NotEmpty(t, deviceRelayCmd.Long)
	assert.NotNil(t, deviceRelayCmd.RunE)
}

// TestDeviceRelayCmd_Flags pins the flags relay actually registers: --listen
// (its own) plus the full registerDeviceListenFlags set it shares with
// "xkey device listen" (go-xkms#1306) -- no --qr, which the relay never had
// anything real to show (see the issue's finding that it never read the QR
// Code field and never actually served a pairing confirm).
func TestDeviceRelayCmd_Flags(t *testing.T) {
	for _, name := range []string{
		"listen", "device", "name", "timeout", "attestation-mode",
		"tpm-device", "tpm-enrollment", "tpm-pcr-bank", "allow-sync",
		"so-pin-stdin", "barrier-password-stdin", "barrier-password-file",
	} {
		assert.NotNil(t, deviceRelayCmd.Flags().Lookup(name), "flag %q must be registered", name)
	}
	assert.Nil(t, deviceRelayCmd.Flags().Lookup("qr"), "relay no longer performs first-time pairing, so it has nothing to show a QR code for")
}

func TestDeviceRelayCmd_ListenFlagDefaultsToConfiguration(t *testing.T) {
	listenFlag := deviceRelayCmd.Flags().Lookup("listen")
	require.NotNil(t, listenFlag)
	assert.Equal(t, "", listenFlag.DefValue, "the flag's zero value means \"from configuration\"; the address defaults in phone.relay_listen_address")
}

func TestDeviceRelayCmd_Registered(t *testing.T) {
	found := false
	for _, sub := range deviceCmd.Commands() {
		if sub == deviceRelayCmd {
			found = true
			break
		}
	}
	assert.True(t, found, "deviceRelayCmd must be a subcommand of deviceCmd")
}

func TestDeviceRelayErrors(t *testing.T) {
	t.Run("start_failed", func(t *testing.T) {
		assert.Equal(t, "device: relay server start failed", ErrDeviceRelayStartFailed.Error())
	})

	t.Run("stop_failed", func(t *testing.T) {
		assert.Equal(t, "device: relay server stop failed", ErrDeviceRelayStopFailed.Error())
	})

	t.Run("distinct_errors", func(t *testing.T) {
		assert.NotEqual(t, ErrDeviceRelayStartFailed, ErrDeviceRelayStopFailed)
		assert.NotErrorIs(t, ErrDeviceRelayStartFailed, ErrDeviceRelayStopFailed)
	})
}

// TestRunDeviceRelay_ProceedsWithoutABarrier mirrors
// TestRunDeviceListen_ProceedsWithoutABarrier: the #42 owner ruling applies
// identically to the relay.
func TestRunDeviceRelay_ProceedsWithoutABarrier(t *testing.T) {
	isolateDeviceBarrierHome(t)

	err := runDeviceRelay(relayCommand(t), nil)

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrDeviceNotPaired)
	assert.NotErrorIs(t, err, ErrDeviceBarrierNotInitialized,
		"an uninitialized barrier must never be why this command refuses")
}

// TestRunDeviceRelay_RefusesWithWrongBarrierPassword mirrors the listen
// wrong-password gate for the relay.
func TestRunDeviceRelay_RefusesWithWrongBarrierPassword(t *testing.T) {
	isolateDeviceBarrierHome(t)
	initDeviceBarrier(t, "correct-horse-battery-staple")

	cmd := relayCommand(t)
	t.Setenv("XKEY_BARRIER_PASSWORD", "wrong")

	err := runDeviceRelay(cmd, nil)

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrDeviceBarrierUnsealFailed)
}

// TestRunDeviceRelay_RefusesEmptyPinnedKey pins #1307 for the relay, exactly
// as TestRunDeviceListen_RefusesEmptyPinnedKey pins it for BLE: a
// paired-device record whose NoisePublicKey decodes to nothing usable must
// refuse before the TCP server is ever built, not silently relay with
// nothing pinned (go-xkms#1306).
func TestRunDeviceRelay_RefusesEmptyPinnedKey(t *testing.T) {
	isolateDeviceBarrierHome(t)
	require.NoError(t, saveDevicesConfig(&DevicesConfig{
		Devices: []PairedDevice{{
			Name:           "A",
			Address:        "11:22:33:44:55:66",
			NoisePublicKey: "",
		}},
	}))

	err := runDeviceRelay(relayCommand(t), nil)

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrDevicePinInvalid)
}

// pairedRelayCommand seeds one paired device in an isolated home and returns
// a relay command bound to loopback with an ephemeral port, so the relay
// really listens and stops on its own once timeout elapses.
func pairedRelayCommand(t *testing.T, timeout string) (*cobra.Command, *bytes.Buffer) {
	t.Helper()
	isolateDeviceBarrierHome(t)
	require.NoError(t, saveDevicesConfig(&DevicesConfig{
		Devices: []PairedDevice{{
			Name:                 "Pixel",
			Address:              "11:22:33:44:55:66",
			NoisePublicKey:       validNoisePublicKeyForTest(t),
			LocalNoisePrivateKey: validLocalNoisePrivateKeyForTest(t),
		}},
	}))

	cmd := relayCommand(t)
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "listen", "127.0.0.1:0"))
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "timeout", timeout))
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	return cmd, out
}

// relayOutsideFIPS reports whether the calling test can check runDeviceRelay's
// result err in this process. The relay loads the paired device's local Noise
// static key, an X25519 key that crypto/ecdh refuses under
// GODEBUG=fips140=only (owner ruling 116: refuse what the stdlib refuses), so
// there it asserts the typed refusal, re-runs the test under fips140=off and
// returns false; the caller then returns.
func relayOutsideFIPS(t *testing.T, err error) bool {
	t.Helper()
	return fipstest.OutsideFIPSAfterRefusal(t, err, bootstrap.ErrNoiseFIPSUnsupported)
}

// TestRunDeviceRelay_ServesUntilTimeoutInSoftwareMode pins the relay's whole
// session: it binds the configured address, reports software attestation,
// a disabled bridge and refused sync, then stops cleanly at the timeout.
func TestRunDeviceRelay_ServesUntilTimeoutInSoftwareMode(t *testing.T) {
	cmd, out := pairedRelayCommand(t, "50ms")
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "attestation-mode", "software"))

	err := runDeviceRelay(cmd, nil)
	if !relayOutsideFIPS(t, err) {
		return
	}
	require.NoError(t, err)

	got := out.String()
	assert.Contains(t, got, "TCP pairing relay listening on 127.0.0.1:")
	assert.Contains(t, got, `Serving paired device "Pixel"`)
	assert.Contains(t, got, "Attestation mode: software")
	assert.Contains(t, got, "xkmsd bridge: disabled")
	assert.Contains(t, got, "Phone sync: refused")
	assert.Contains(t, got, "Relay timeout reached")
	assert.Contains(t, got, "Stopping relay server...")
}

// TestRunDeviceRelay_AutoModeFallsBackToSoftwareWithoutATPM covers the auto
// attestation mode: a TPM that cannot be opened is a warning, not a refusal,
// and the session runs with software attestation.
func TestRunDeviceRelay_AutoModeFallsBackToSoftwareWithoutATPM(t *testing.T) {
	cmd, out := pairedRelayCommand(t, "50ms")
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "attestation-mode", "auto"))
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "tpm-device", filepath.Join(t.TempDir(), "no-tpm")))
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "allow-sync", "true"))

	err := runDeviceRelay(cmd, nil)
	if !relayOutsideFIPS(t, err) {
		return
	}
	require.NoError(t, err)

	assert.Contains(t, out.String(), "Attestation mode: software")
	assert.Contains(t, out.String(), "Phone sync: allowed for this session")
}

// TestRunDeviceRelay_TPM2ModeRefusesWithoutATPM is the strict counterpart:
// --attestation-mode tpm2 must not silently degrade to software.
func TestRunDeviceRelay_TPM2ModeRefusesWithoutATPM(t *testing.T) {
	cmd, out := pairedRelayCommand(t, "50ms")
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "attestation-mode", "tpm2"))
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "tpm-device", filepath.Join(t.TempDir(), "no-tpm")))

	err := runDeviceRelay(cmd, nil)
	if !relayOutsideFIPS(t, err) {
		return
	}

	require.ErrorIs(t, err, ErrTPM2InitFailed)
	assert.NotContains(t, out.String(), "TCP pairing relay listening")
}

// TestRunDeviceRelay_UnbindableAddressFailsToStart covers a listen address
// the relay cannot bind: the start failure is reported as such.
func TestRunDeviceRelay_UnbindableAddressFailsToStart(t *testing.T) {
	cmd, _ := pairedRelayCommand(t, "50ms")
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "attestation-mode", "software"))
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "listen", "127.0.0.1:not-a-port"))

	err := runDeviceRelay(cmd, nil)
	if !relayOutsideFIPS(t, err) {
		return
	}

	require.ErrorIs(t, err, ErrDeviceRelayStartFailed)
}

// TestRunDeviceRelay_RefusesAmbiguousDeviceName mirrors #1315/#1307 for the
// relay: two paired records sharing a name must refuse rather than silently
// pinning whichever record happens to be first in the file.
func TestRunDeviceRelay_RefusesAmbiguousDeviceName(t *testing.T) {
	isolateDeviceBarrierHome(t)
	require.NoError(t, saveDevicesConfig(&DevicesConfig{
		Devices: []PairedDevice{
			{Name: "A", Address: "11:22:33:44:55:66"},
			{Name: "A", Address: "AA:BB:CC:DD:EE:FF"},
		},
	}))

	cmd := relayCommand(t)
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "device", "A"))

	err := runDeviceRelay(cmd, nil)

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrDeviceNameAmbiguous)
}

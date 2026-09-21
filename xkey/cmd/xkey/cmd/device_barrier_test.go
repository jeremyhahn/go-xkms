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

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/gui/services"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/pairing"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/xhome"
)

// isolateDeviceBarrierHome gives a test its own xkey home so
// openDeviceBarrier's data directory and root key path never touch a real
// one, and clears SUDO_USER so resolveInvokingUserHome takes the direct path.
func isolateDeviceBarrierHome(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	xhome.SetRoot(root)
	t.Cleanup(xhome.ResetRoot)
	t.Setenv("SUDO_USER", "")
	t.Setenv("XKEY_BARRIER_PASSWORD", "")
	return root
}

// initDeviceBarrier initializes a real barrier at the resolved data
// directory under password, the same way openDeviceBarrierWithPassword would
// find it -- so tests exercise the exact resolution path a device command
// uses rather than a shortcut that could drift from it.
func initDeviceBarrier(t *testing.T, password string) {
	t.Helper()
	home, err := resolveInvokingUserHome()
	require.NoError(t, err)
	dataDir, err := home.EnsureDataDir()
	require.NoError(t, err)

	svc := services.NewBarrierService(home.Root, discardLogger())
	svc.SetDataDir(dataDir)
	require.NoError(t, svc.Initialize(password, "passphrase"))
}

// deviceBarrierCommand returns a bare command carrying the
// --barrier-password[-file] flags openDeviceBarrier reads.
func deviceBarrierCommand(t *testing.T) *cobra.Command {
	t.Helper()
	cmd := &cobra.Command{Use: "test"}
	addDeviceBarrierFlags(cmd)
	return cmd
}

// TestOpenDeviceBarrier_NotInitializedProceedsWithNilBarrier is the #42
// owner ruling: a host that never ran `xkey barrier init` is not refused --
// openDeviceBarrier reports "no barrier" with a nil error, and the caller
// (sealOrWarnLocalNoiseKey, or the unseal path's own nil-barrier handling
// for a legacy record) is what falls back to the legacy plaintext form.
func TestOpenDeviceBarrier_NotInitializedProceedsWithNilBarrier(t *testing.T) {
	isolateDeviceBarrierHome(t)

	barrier, closeBarrier, err := openDeviceBarrier(deviceBarrierCommand(t))

	require.NoError(t, err)
	assert.Nil(t, barrier)
	require.NotNil(t, closeBarrier, "the close function must always be safe to defer")
	closeBarrier()
}

func TestOpenDeviceBarrier_NoPasswordRefuses(t *testing.T) {
	isolateDeviceBarrierHome(t)
	initDeviceBarrier(t, "correct-horse-battery-staple")

	_, _, err := openDeviceBarrier(deviceBarrierCommand(t))

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrDeviceBarrierPasswordRequired)
}

func TestOpenDeviceBarrier_WrongPasswordRefuses(t *testing.T) {
	isolateDeviceBarrierHome(t)
	initDeviceBarrier(t, "correct-horse-battery-staple")

	cmd := deviceBarrierCommand(t)
	require.NoError(t, cmd.Flags().Set("barrier-password", "not-the-password"))

	_, _, err := openDeviceBarrier(cmd)

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrDeviceBarrierUnsealFailed)
}

func TestOpenDeviceBarrier_CorrectPasswordFlagSucceeds(t *testing.T) {
	isolateDeviceBarrierHome(t)
	initDeviceBarrier(t, "correct-horse-battery-staple")

	cmd := deviceBarrierCommand(t)
	require.NoError(t, cmd.Flags().Set("barrier-password", "correct-horse-battery-staple"))

	barrier, closeBarrier, err := openDeviceBarrier(cmd)
	require.NoError(t, err)
	require.NotNil(t, barrier)
	defer closeBarrier()

	sealed, sealErr := pairing.SealLocalNoiseKey(barrier, []byte("a 32-byte-ish private scalar!!!"))
	require.NoError(t, sealErr)
	assert.True(t, pairing.IsSealedNoiseKey(sealed))
}

func TestOpenDeviceBarrier_EnvVarPasswordSucceeds(t *testing.T) {
	isolateDeviceBarrierHome(t)
	initDeviceBarrier(t, "correct-horse-battery-staple")
	t.Setenv("XKEY_BARRIER_PASSWORD", "correct-horse-battery-staple")

	barrier, closeBarrier, err := openDeviceBarrier(deviceBarrierCommand(t))
	require.NoError(t, err)
	require.NotNil(t, barrier)
	closeBarrier()
}

func TestOpenDeviceBarrierWithPassword_NotInitializedRefuses(t *testing.T) {
	isolateDeviceBarrierHome(t)

	_, _, err := openDeviceBarrierWithPassword("whatever")

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrDeviceBarrierNotInitialized)
}

func TestOpenDeviceBarrierWithPassword_RoundTripsASealedValue(t *testing.T) {
	isolateDeviceBarrierHome(t)
	initDeviceBarrier(t, "correct-horse-battery-staple")

	barrier, closeBarrier, err := openDeviceBarrierWithPassword("correct-horse-battery-staple")
	require.NoError(t, err)
	defer closeBarrier()

	priv := []byte("a 32-byte-ish private scalar!!!")
	sealed, err := pairing.SealLocalNoiseKey(barrier, priv)
	require.NoError(t, err)

	buf, err := pairing.UnsealLocalNoiseKey(barrier, sealed)
	require.NoError(t, err)
	defer buf.Destroy()
	assert.Equal(t, priv, buf.Bytes())
}

// attestDeviceCommand and listenCommand return bare commands carrying the
// same flags the real deviceAttestDeviceCmd/deviceListenCmd register in
// init(), so runDeviceAttestDevice/runDeviceListen can be driven directly
// without touching the package-level singletons another test may have
// flags set on.

func attestDeviceCommand(t *testing.T) *cobra.Command {
	t.Helper()
	cmd := &cobra.Command{Use: "attest-device"}
	cmd.Flags().String("device", "", "")
	cmd.Flags().Bool("force", false, "")
	cmd.Flags().Duration("set-grace-period", 0, "")
	addDeviceBarrierFlags(cmd)
	return cmd
}

func listenCommand(t *testing.T) *cobra.Command {
	t.Helper()
	cmd := &cobra.Command{Use: "listen"}
	cmd.Flags().String("device", "", "")
	cmd.Flags().String("name", "", "")
	cmd.Flags().Duration("timeout", 0, "")
	cmd.Flags().String("attestation-mode", "auto", "")
	cmd.Flags().String("tpm-device", "", "")
	cmd.Flags().Bool("tpm-enrollment", false, "")
	cmd.Flags().String("tpm-pcr-bank", "", "")
	addDeviceBarrierFlags(cmd)
	return cmd
}

// TestRunDeviceAttestDevice_ProceedsWithoutABarrier is the #42 owner ruling
// on this verb: a host with no barrier initialized at all is not refused for
// that reason. It still fails here, but for the ordinary, unrelated reason
// that no devices.yaml exists in the isolated home -- proof the barrier
// check itself let the command continue past it.
func TestRunDeviceAttestDevice_ProceedsWithoutABarrier(t *testing.T) {
	isolateDeviceBarrierHome(t)

	err := runDeviceAttestDevice(attestDeviceCommand(t), nil)

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrDeviceNotPaired)
	assert.NotErrorIs(t, err, ErrDeviceBarrierNotInitialized,
		"an uninitialized barrier must never be why this command refuses")
}

// TestRunDeviceAttestDevice_RefusesWithWrongBarrierPassword covers the other
// half: a barrier that exists but cannot be unsealed with what was supplied.
func TestRunDeviceAttestDevice_RefusesWithWrongBarrierPassword(t *testing.T) {
	isolateDeviceBarrierHome(t)
	initDeviceBarrier(t, "correct-horse-battery-staple")

	cmd := attestDeviceCommand(t)
	require.NoError(t, cmd.Flags().Set("barrier-password", "wrong"))

	err := runDeviceAttestDevice(cmd, nil)

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrDeviceBarrierUnsealFailed)
}

// TestRunDeviceListen_ProceedsWithoutABarrier mirrors
// TestRunDeviceAttestDevice_ProceedsWithoutABarrier for `device listen`.
func TestRunDeviceListen_ProceedsWithoutABarrier(t *testing.T) {
	isolateDeviceBarrierHome(t)

	err := runDeviceListen(listenCommand(t), nil)

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrDeviceNotPaired)
	assert.NotErrorIs(t, err, ErrDeviceBarrierNotInitialized,
		"an uninitialized barrier must never be why this command refuses")
}

// TestRunDeviceListen_RefusesWithWrongBarrierPassword mirrors the
// attest-device wrong-password gate for `device listen`.
func TestRunDeviceListen_RefusesWithWrongBarrierPassword(t *testing.T) {
	isolateDeviceBarrierHome(t)
	initDeviceBarrier(t, "correct-horse-battery-staple")

	cmd := listenCommand(t)
	require.NoError(t, cmd.Flags().Set("barrier-password", "wrong"))

	err := runDeviceListen(cmd, nil)

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrDeviceBarrierUnsealFailed)
}

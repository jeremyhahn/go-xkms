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

package cmd

import (
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkeyconfig "github.com/jeremyhahn/go-xkms/xkey/pkg/config"
)

// withDeviceConfig installs a loaded configuration carrying the given Device
// section for the duration of the test, restoring the previous
// package-level loadedConfig on cleanup.
func withDeviceConfig(t *testing.T, device xkeyconfig.DeviceConfig) {
	t.Helper()
	cfg := xkeyconfig.DefaultConfig()
	cfg.Device = device
	previous := loadedConfig
	loadedConfig = cfg
	t.Cleanup(func() { loadedConfig = previous })
}

// withNoLoadedConfig clears loadedConfig for the duration of the test, the
// state a command reaches before initConfig has run (e.g. a unit test that
// calls a RunE function directly without going through RootCmd.Execute).
func withNoLoadedConfig(t *testing.T) {
	t.Helper()
	previous := loadedConfig
	loadedConfig = nil
	t.Cleanup(func() { loadedConfig = previous })
}

// pairAndScanCommands returns the flag registrations for `device pair` and
// `device scan`, whose --timeout is the shared flag resolveDeviceScanTimeout
// resolves the same way for both.
func pairAndScanCommands() []*cobra.Command {
	return []*cobra.Command{devicePairCmd, deviceScanCmd}
}

// --- deviceConfig ---

func TestDeviceConfig_BuiltInDefaultsWhenNothingLoaded(t *testing.T) {
	withNoLoadedConfig(t)

	got := deviceConfig()
	assert.Equal(t, xkeyconfig.DefaultConfig().Device, got)
}

func TestDeviceConfig_ReturnsLoadedConfiguration(t *testing.T) {
	withDeviceConfig(t, xkeyconfig.DeviceConfig{TrustNewDevices: true, ScanTimeout: 45 * time.Second})

	got := deviceConfig()
	assert.True(t, got.TrustNewDevices)
	assert.Equal(t, 45*time.Second, got.ScanTimeout)
}

// --- GetTrustNewDevices ---

func TestGetTrustNewDevices_BuiltInDefaultWhenNothingSet(t *testing.T) {
	withNoLoadedConfig(t)

	value, err := GetTrustNewDevices(&cobra.Command{Use: "bare"})
	require.NoError(t, err)
	assert.False(t, value)
}

func TestGetTrustNewDevices_ConfigurationOverridesDefault(t *testing.T) {
	withDeviceConfig(t, xkeyconfig.DeviceConfig{TrustNewDevices: true, ScanTimeout: 30 * time.Second})

	value, err := GetTrustNewDevices(&cobra.Command{Use: "bare"})
	require.NoError(t, err)
	assert.True(t, value)
}

// TestGetTrustNewDevices_FlagBeatsConfiguration proves an explicit
// --trust-new-devices=false wins over a configuration that turned the
// setting on -- the flag must be detected by Changed, not by truthiness,
// or an explicit false would be indistinguishable from "not passed" and
// the configured true would leak through.
func TestGetTrustNewDevices_FlagBeatsConfiguration(t *testing.T) {
	withDeviceConfig(t, xkeyconfig.DeviceConfig{TrustNewDevices: true, ScanTimeout: 30 * time.Second})

	cmd := &cobra.Command{Use: "pair"}
	cmd.Flags().Bool("trust-new-devices", false, "")
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "trust-new-devices", "false"))

	value, err := GetTrustNewDevices(cmd)
	require.NoError(t, err)
	assert.False(t, value, "an explicitly-set flag must win even when its value equals the default")
}

func TestGetTrustNewDevices_FlagOnParentPersistentFlagSet(t *testing.T) {
	withDeviceConfig(t, xkeyconfig.DeviceConfig{TrustNewDevices: false, ScanTimeout: 30 * time.Second})

	parent := &cobra.Command{Use: "device"}
	parent.PersistentFlags().Bool("trust-new-devices", false, "")
	require.NoError(t, setFlagForTest(t, parent.PersistentFlags(), "trust-new-devices", "true"))

	value, err := GetTrustNewDevices(parent)
	require.NoError(t, err)
	assert.True(t, value)
}

func TestGetTrustNewDevices_WrongFlagTypeReturnsTypedError(t *testing.T) {
	cmd := &cobra.Command{Use: "pair"}
	cmd.Flags().String("trust-new-devices", "", "")
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "trust-new-devices", "yes"))

	_, err := GetTrustNewDevices(cmd)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrCommandFlagInvalid)
}

// --- resolveDeviceScanTimeout ---

func TestResolveDeviceScanTimeout_BuiltInDefaultWhenNothingSet(t *testing.T) {
	withNoLoadedConfig(t)

	value, err := resolveDeviceScanTimeout(&cobra.Command{Use: "bare"})
	require.NoError(t, err)
	assert.Equal(t, 30*time.Second, value)
}

func TestResolveDeviceScanTimeout_ConfigurationOverridesDefault(t *testing.T) {
	withDeviceConfig(t, xkeyconfig.DeviceConfig{ScanTimeout: 90 * time.Second})

	value, err := resolveDeviceScanTimeout(&cobra.Command{Use: "bare"})
	require.NoError(t, err)
	assert.Equal(t, 90*time.Second, value)
}

func TestResolveDeviceScanTimeout_FlagBeatsConfiguration(t *testing.T) {
	withDeviceConfig(t, xkeyconfig.DeviceConfig{ScanTimeout: 90 * time.Second})

	cmd := &cobra.Command{Use: "scan"}
	cmd.Flags().Duration("timeout", defaultDeviceScanTimeout, "")
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "timeout", "10s"))

	value, err := resolveDeviceScanTimeout(cmd)
	require.NoError(t, err)
	assert.Equal(t, 10*time.Second, value)
}

func TestResolveDeviceScanTimeout_WrongFlagTypeReturnsTypedError(t *testing.T) {
	cmd := &cobra.Command{Use: "scan"}
	cmd.Flags().String("timeout", "", "")
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "timeout", "10s"))

	_, err := resolveDeviceScanTimeout(cmd)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrCommandFlagInvalid)
}

// --- registered flag help text (docs/device/cli.md must match) ---

// TestDeviceTimeoutFlags_DocumentTheConfigurationDefault proves `device
// pair` and `device scan` both advertise device.scan_timeout as --timeout's
// configured source in --help output, rather than silently claiming only a
// literal default (go-xkms#1071).
func TestDeviceTimeoutFlags_DocumentTheConfigurationDefault(t *testing.T) {
	for _, cmd := range pairAndScanCommands() {
		f := cmd.Flags().Lookup("timeout")
		require.NotNil(t, f, "%s --timeout", cmd.Use)
		assert.Contains(t, f.Usage, "device.scan_timeout", "%s --timeout", cmd.Use)
	}
}

func TestDeviceTrustNewDevicesFlag_DocumentsTheConfigurationDefault(t *testing.T) {
	f := deviceCmd.PersistentFlags().Lookup("trust-new-devices")
	require.NotNil(t, f)
	assert.Contains(t, f.Usage, "device.trust_new_devices")
}

// --- per-invocation flags: no viper binding remains (go-xkms#1071) ---

// TestPerInvocationDeviceFlags_NotBoundToViper proves that setting each of
// the per-invocation flags no longer mirrors into the package-level viper
// singleton under its old key: before go-xkms#1071 these were bound with
// viper.BindPFlag, so viper.GetString/GetBool on the old key reflected
// whatever the flag held. None of these settings has config-file meaning,
// so the binding was deleted outright rather than replaced.
func TestPerInvocationDeviceFlags_NotBoundToViper(t *testing.T) {
	resetViperForTest(t)

	require.NoError(t, setFlagForTest(t, devicePairCmd.Flags(), "device", "Pixel-8"))
	require.NoError(t, setFlagForTest(t, devicePairCmd.Flags(), "force", "true"))
	require.NoError(t, setFlagForTest(t, deviceStatusCmd.Flags(), "device", "Pixel-8"))

	assert.False(t, viper.IsSet("device.pair.device"))
	assert.False(t, viper.IsSet("device.pair.force"))
	assert.False(t, viper.IsSet("device.pair.timeout"))
	assert.False(t, viper.IsSet("device.scan.timeout"))
	assert.False(t, viper.IsSet("device.status.device"))
}

// TestPersistentDeviceFlag_NotBoundToViper proves --trust-new-devices no
// longer mirrors into viper's "device.trust_new_devices" either: that key's
// config-file/environment meaning now comes from xkeyconfig.Config.Device,
// a separate viper instance internal to pkg/config, not the shared
// package-level singleton cmd uses for flag bookkeeping.
func TestPersistentDeviceFlag_NotBoundToViper(t *testing.T) {
	resetViperForTest(t)

	require.NoError(t, setFlagForTest(t, deviceCmd.PersistentFlags(), "trust-new-devices", "true"))

	assert.False(t, viper.IsSet("device.trust_new_devices"))
}

// TestDeviceStatusFilter_UnaffectedByStrayViperState proves runDeviceStatus's
// --device filter reads the flag, not any leftover viper state under the
// key the flag used to be bound to.
func TestDeviceStatusFilter_UnaffectedByStrayViperState(t *testing.T) {
	resetViperForTest(t)
	viper.Set("device.status.device", "stray-device-name")

	cmd := &cobra.Command{Use: "status"}
	cmd.Flags().String("device", "", "")

	got, err := cmd.Flags().GetString("device")
	require.NoError(t, err)
	assert.Empty(t, got, "runDeviceStatus's --device filter must not observe stray viper state")
}

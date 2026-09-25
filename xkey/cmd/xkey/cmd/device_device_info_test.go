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
	"bytes"
	"errors"
	"io"
	"os"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

// captureDeviceInfoStdout redirects os.Stdout to a pipe for the duration of
// fn(), returning everything fn() printed. printDeviceInfo (and the RunE
// path that calls it) write with fmt.Print*, not cmd.OutOrStdout, so
// os.Stdout capture is the only way to observe them.
func captureDeviceInfoStdout(t *testing.T, fn func()) string {
	t.Helper()

	orig := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdout = w

	fn()

	require.NoError(t, w.Close())
	os.Stdout = orig

	var buf bytes.Buffer
	_, err = io.Copy(&buf, r)
	require.NoError(t, err)
	return buf.String()
}

func TestGetDeviceInfoGracePeriod_DevicePriority(t *testing.T) {
	device := &PairedDevice{AttestationGracePeriod: Duration(10 * time.Minute)}
	cfg := &DevicesConfig{AttestationPolicy: &AttestationPolicy{DefaultGracePeriod: Duration(time.Hour)}}

	got := getDeviceInfoGracePeriod(device, cfg)
	require.Equal(t, 10*time.Minute, got, "a per-device override must win over the policy default")
}

func TestGetDeviceInfoGracePeriod_PolicyFallback(t *testing.T) {
	device := &PairedDevice{}
	cfg := &DevicesConfig{AttestationPolicy: &AttestationPolicy{DefaultGracePeriod: Duration(30 * time.Minute)}}

	got := getDeviceInfoGracePeriod(device, cfg)
	require.Equal(t, 30*time.Minute, got)
}

func TestGetDeviceInfoGracePeriod_SystemDefault(t *testing.T) {
	device := &PairedDevice{}
	cfg := &DevicesConfig{}

	got := getDeviceInfoGracePeriod(device, cfg)
	require.Equal(t, defaultAttestationGracePeriod, got, "with no device override and no policy, the system default applies")
}

func TestCalculateAttestationStatus_Never(t *testing.T) {
	device := &PairedDevice{}

	status, remaining := calculateAttestationStatus(device, time.Hour)
	require.Equal(t, attestationStatusNever, status)
	require.Zero(t, remaining)
}

func TestCalculateAttestationStatus_Current(t *testing.T) {
	device := &PairedDevice{LastDeviceAttestationTime: time.Now().Add(-time.Minute)}

	status, remaining := calculateAttestationStatus(device, time.Hour)
	require.Equal(t, attestationStatusCurrent, status)
	require.Greater(t, remaining, time.Duration(0))
	require.LessOrEqual(t, remaining, time.Hour)
}

func TestCalculateAttestationStatus_Expired(t *testing.T) {
	device := &PairedDevice{LastDeviceAttestationTime: time.Now().Add(-2 * time.Hour)}

	status, remaining := calculateAttestationStatus(device, time.Hour)
	require.Equal(t, attestationStatusExpired, status)
	require.Zero(t, remaining)
}

func TestFormatDeviceInfoDuration(t *testing.T) {
	tests := []struct {
		name string
		d    time.Duration
		want string
	}{
		{"zero", 0, "0s"},
		{"negative", -5 * time.Second, "0s"},
		{"seconds only", 42 * time.Second, "42s"},
		{"minutes and seconds", 90 * time.Second, "1m 30s"},
		{"exact minute", 2 * time.Minute, "2m"},
		{"hours minutes seconds", 3*time.Hour + 5*time.Minute + 9*time.Second, "3h 5m 9s"},
		{"exact hour", time.Hour, "1h"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, formatDeviceInfoDuration(tc.d))
		})
	}
}

func TestTruncateDeviceInfoHash(t *testing.T) {
	require.Equal(t, "deadbeef", truncateDeviceInfoHash("deadbeefcafebabe"))
	require.Equal(t, "short", truncateDeviceInfoHash("short"))
	require.Equal(t, "", truncateDeviceInfoHash(""))
}

func TestPrintDeviceInfo_CurrentDefaultDeviceFullFields(t *testing.T) {
	device := &PairedDevice{
		Name:                      "John's Pixel",
		Address:                   "AA:BB:CC:DD:EE:FF",
		PairedAt:                  time.Date(2025, 1, 15, 10, 30, 0, 0, time.UTC),
		NoisePublicKey:            "dGVzdC1wdWJsaWMta2V5LWJhc2U2NA==",
		LastDeviceAttestationTime: time.Now().Add(-time.Minute),
		SecurityLevel:             "strongbox",
		BootStateVerified:         true,
		DeviceBootHashHex:         "deadbeefcafebabe",
		DeviceFingerprint:         "0123456789abcdef",
	}
	cfg := &DevicesConfig{DefaultDevice: "John's Pixel"}

	out := captureDeviceInfoStdout(t, func() {
		printDeviceInfo(device, cfg, time.Hour, attestationStatusCurrent, 30*time.Minute)
	})

	require.Contains(t, out, "Device Information: John's Pixel")
	require.Contains(t, out, "AA:BB:CC:DD:EE:FF")
	require.Contains(t, out, "Status:           CURRENT")
	require.Contains(t, out, "Time Remaining:   30m")
	require.Contains(t, out, "Security Level:   strongbox")
	require.Contains(t, out, "Boot Verified:    true")
	require.Contains(t, out, "Boot Hash:        deadbeef")
	require.Contains(t, out, "Device Fingerprint: 01234567")
	require.Contains(t, out, "Default Device:   yes")
}

func TestPrintDeviceInfo_NeverAttestedMinimalFields(t *testing.T) {
	device := &PairedDevice{
		Name:     "Bare Device",
		Address:  "11:22:33:44:55:66",
		PairedAt: time.Now(),
	}
	cfg := &DevicesConfig{DefaultDevice: "Other Device"}

	out := captureDeviceInfoStdout(t, func() {
		printDeviceInfo(device, cfg, defaultAttestationGracePeriod, attestationStatusNever, 0)
	})

	require.Contains(t, out, "Last Attested:    never")
	require.Contains(t, out, "Time Remaining:   n/a")
	require.Contains(t, out, "Security Level:   unknown")
	require.Contains(t, out, "Boot Verified:    false")
	require.Contains(t, out, "Boot Hash:        n/a")
	require.Contains(t, out, "Device Fingerprint: n/a")
	require.Contains(t, out, "Default Device:   no")
}

func TestPrintDeviceInfo_Expired(t *testing.T) {
	device := &PairedDevice{
		Name:                      "Expired Device",
		LastDeviceAttestationTime: time.Now().Add(-48 * time.Hour),
	}
	cfg := &DevicesConfig{}

	out := captureDeviceInfoStdout(t, func() {
		printDeviceInfo(device, cfg, time.Hour, attestationStatusExpired, 0)
	})

	require.Contains(t, out, "Time Remaining:   expired")
}

// deviceInfoTestHome points XKEY's HOME-based config resolution at a fresh
// temp directory, mirroring device_test.go's TestPhoneConfig_LoadSave setup.
func deviceInfoTestHome(t *testing.T) {
	t.Helper()
	tempDir := t.TempDir()
	t.Setenv("HOME", tempDir)
	t.Setenv("XDG_CONFIG_HOME", tempDir)
	t.Setenv("XDG_DATA_HOME", tempDir)
}

func TestRunDeviceInfo_NoConfigFile(t *testing.T) {
	deviceInfoTestHome(t)

	cmd := &cobra.Command{}
	err := runDeviceInfo(cmd, nil)
	require.ErrorIs(t, err, ErrDeviceNotPaired)
}

func TestRunDeviceInfo_EmptyDevices(t *testing.T) {
	deviceInfoTestHome(t)
	require.NoError(t, saveDevicesConfig(&DevicesConfig{}))

	cmd := &cobra.Command{}
	err := runDeviceInfo(cmd, nil)
	require.ErrorIs(t, err, ErrDeviceNotPaired)
}

func TestRunDeviceInfo_DeviceNotFound(t *testing.T) {
	deviceInfoTestHome(t)
	require.NoError(t, saveDevicesConfig(&DevicesConfig{
		Devices: []PairedDevice{{Name: "Phone A", PairedAt: time.Now()}},
	}))

	cmd := &cobra.Command{}
	err := runDeviceInfo(cmd, []string{"Nonexistent"})
	require.ErrorIs(t, err, ErrDeviceNotFound)

	var detail *DetailError
	require.True(t, errors.As(err, &detail))
	require.Contains(t, detail.Detail, "Nonexistent")
}

func TestRunDeviceInfo_DefaultDeviceSucceeds(t *testing.T) {
	deviceInfoTestHome(t)
	require.NoError(t, saveDevicesConfig(&DevicesConfig{
		Devices: []PairedDevice{
			{Name: "Phone A", Address: "11:22:33:44:55:66", PairedAt: time.Now()},
			{Name: "Phone B", Address: "AA:BB:CC:DD:EE:FF", PairedAt: time.Now()},
		},
		DefaultDevice: "Phone B",
	}))

	cmd := &cobra.Command{}
	out := captureDeviceInfoStdout(t, func() {
		require.NoError(t, runDeviceInfo(cmd, nil))
	})
	require.Contains(t, out, "Device Information: Phone B")
}

func TestRunDeviceInfo_ExplicitNameSucceeds(t *testing.T) {
	deviceInfoTestHome(t)
	require.NoError(t, saveDevicesConfig(&DevicesConfig{
		Devices: []PairedDevice{
			{Name: "Phone A", Address: "11:22:33:44:55:66", PairedAt: time.Now()},
		},
	}))

	cmd := &cobra.Command{}
	out := captureDeviceInfoStdout(t, func() {
		require.NoError(t, runDeviceInfo(cmd, []string{"Phone A"}))
	})
	require.Contains(t, out, "Device Information: Phone A")
}

func TestRunDeviceInfo_FirstDeviceFallback(t *testing.T) {
	deviceInfoTestHome(t)
	require.NoError(t, saveDevicesConfig(&DevicesConfig{
		Devices: []PairedDevice{
			{Name: "Only Device", Address: "11:22:33:44:55:66", PairedAt: time.Now()},
		},
	}))

	cmd := &cobra.Command{}
	out := captureDeviceInfoStdout(t, func() {
		require.NoError(t, runDeviceInfo(cmd, nil))
	})
	require.Contains(t, out, "Device Information: Only Device")
}

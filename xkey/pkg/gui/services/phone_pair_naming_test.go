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

package services

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/attestation/attesttest"
)

// writeAmbiguousDevicesConfig writes a devices.yaml under HOME holding two
// records that share name, so a test can drive a name-keyed lookup into the
// ambiguous case (#1307).
func writeAmbiguousDevicesConfig(t *testing.T, name string) string {
	t.Helper()
	tmpDir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(tmpDir, ".xkey"), 0700))

	cfg := phoneConfig{
		Devices: []phoneConfigDevice{
			{Name: name, Address: "AA:AA:AA:AA:AA:AA", NoisePublicKey: "keyA",
				LocalNoisePrivateKey: "irrelevant-a", PairedAt: time.Now().UTC()},
			{Name: name, Address: "BB:BB:BB:BB:BB:BB", NoisePublicKey: "keyB",
				LocalNoisePrivateKey: "irrelevant-b", PairedAt: time.Now().UTC()},
		},
	}
	data, err := yaml.Marshal(&cfg)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, ".xkey", "devices.yaml"), data, 0600))

	origHome := os.Getenv("HOME")
	t.Cleanup(func() { os.Setenv("HOME", origHome) })
	os.Setenv("HOME", tmpDir)
	return tmpDir
}

// TestPhoneService_Unpair_AmbiguousNameRefuses pins #1307: Unpair must
// refuse a name shared by more than one record rather than deleting
// whichever one happens to be first.
func TestPhoneService_Unpair_AmbiguousNameRefuses(t *testing.T) {
	writeAmbiguousDevicesConfig(t, "Pixel")

	svc := NewPhoneService()
	err := svc.Unpair("Pixel")
	svc.awaitNoticesDelivered()

	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrPhoneDeviceNameAmbiguous), "got %v, want ErrPhoneDeviceNameAmbiguous", err)

	devices, listErr := svc.ListDevices()
	require.NoError(t, listErr)
	assert.Len(t, devices, 2, "an ambiguous unpair must delete nothing")
}

// TestPhoneService_Connect_AmbiguousNameRefuses pins #1307: Connect must
// refuse rather than silently trusting whichever record's pinned key
// happens to be first when two records share the requested name.
func TestPhoneService_Connect_AmbiguousNameRefuses(t *testing.T) {
	writeAmbiguousDevicesConfig(t, "Pixel")

	svc := NewPhoneService()
	err := svc.Connect("Pixel")

	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrPhoneDeviceNameAmbiguous), "got %v, want ErrPhoneDeviceNameAmbiguous", err)
}

// TestPairRefusesInvalidDeviceName pins #1307: the phone-confirmed pairing
// name is untrusted input, and an empty or unprintable name must be refused
// before it is ever persisted as the record's lookup key.
func TestPairRefusesInvalidDeviceName(t *testing.T) {
	h := newPairingHarness(t)
	ca := attesttest.NewCA(t, "Trusted Attestation Root")
	h.trust(ca)
	device := attesttest.NewPhone(t, healthyDAK(t, ca))
	device.Name = "" // the phone confirms an empty name

	_, err := h.pair(device, 2, testPairAddress)

	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrPhoneInvalidDeviceName), "got %v, want ErrPhoneInvalidDeviceName", err)
	_, ok := h.savedConfig()
	assert.False(t, ok, "a refused pairing must write nothing")
}

// TestPairRefusesNameCollisionWithDifferentDevice pins #1307: a phone that
// confirms a name already used by a different, still-paired device (a
// different pinned key) must be refused rather than persisted, which would
// make every later name lookup ambiguous between the two devices.
func TestPairRefusesNameCollisionWithDifferentDevice(t *testing.T) {
	h := newPairingHarness(t)
	ca := attesttest.NewCA(t, "Trusted Attestation Root")
	h.trust(ca)

	h.writeDevicesConfig(`devices:
  - name: "Pixel 9"
    address: "11:22:33:44:55:66"
    noise_public_key: "ZXhpc3Rpbmcta2V5"
    local_noise_private_key: "irrelevant"
    paired_at: 2024-01-01T00:00:00Z
default_device: "Pixel 9"
`)

	device := attesttest.NewPhone(t, healthyDAK(t, ca))
	device.Name = "Pixel 9" // a different physical phone, same confirmed name

	_, err := h.pair(device, 2, testPairAddress)

	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrPhoneDeviceNameCollision), "got %v, want ErrPhoneDeviceNameCollision", err)

	cfg, ok := h.savedConfig()
	require.True(t, ok, "the pre-existing record must still be on disk")
	require.Len(t, cfg.Devices, 1, "the refused pairing must not have been appended")
	assert.Equal(t, "ZXhpc3Rpbmcta2V5", cfg.Devices[0].NoisePublicKey,
		"the unrelated device's own record must never be touched")
}

// TestPairReplacesStaleRecordAcrossAddressRotation pins #1307's identity-
// based replacement: re-pairing the SAME phone (same persistent Noise
// identity key) under a new address -- the shape of Android's periodic RPA
// rotation -- must replace the stale record rather than leave it behind as
// a duplicate.
func TestPairReplacesStaleRecordAcrossAddressRotation(t *testing.T) {
	h := newPairingHarness(t)
	ca := attesttest.NewCA(t, "Trusted Attestation Root")
	h.trust(ca)
	device := attesttest.NewPhone(t, healthyDAK(t, ca))
	device.Name = "Pixel 9"

	const oldAddress = "AA:AA:AA:AA:AA:AA"
	const newAddress = "BB:BB:BB:BB:BB:BB"

	_, err := h.pair(device, 2, oldAddress)
	require.NoError(t, err)

	_, err = h.pair(device, 2, newAddress)
	require.NoError(t, err)

	cfg, ok := h.savedConfig()
	require.True(t, ok)
	require.Len(t, cfg.Devices, 1, "the rotated-address re-pair must replace the stale entry, not duplicate it")
	assert.Equal(t, newAddress, cfg.Devices[0].Address)
}

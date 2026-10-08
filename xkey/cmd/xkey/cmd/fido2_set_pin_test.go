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
	"testing"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/authenticator"
	"github.com/stretchr/testify/require"
)

// --set-pin used to seed the daemon's PIN through the authenticator's
// SetPINForTesting helper (#377), which wrote the hash directly: it replaced
// whatever PIN a persistent store already held, reset the retry counter, and
// skipped the pinUvAuthToken invalidation the real setPIN path carries
// (#322). The seeding now goes through SetInitialPIN, a production API with
// a stated contract. These tests pin the wiring: the flag establishes a first
// PIN, refuses a policy-violating one, and refuses to overwrite one that is
// already there.

// seedPINConfig is a host-safe daemon configuration: memory-only key backend,
// no notifier, no UHID (newFIDO2Device does not open the device; Run does).
func seedPINConfig(t *testing.T, storageType FIDO2StorageType, storagePath, pin string) *FIDO2Config {
	t.Helper()
	return &FIDO2Config{
		StorageType:       storageType,
		StoragePath:       storagePath,
		DeviceName:        defaultFIDO2DeviceName,
		SerialNumber:      generateFIDO2SerialNumber(),
		Backend:           "software",
		AttestationFormat: "none",
		NotifyType:        "none",
		EnablePIN:         true,
		PIN:               fido2PINSecret(pin),
	}
}

func TestNewFIDO2Device_SetPINEstablishesInitialPIN(t *testing.T) {
	cfg := seedPINConfig(t, FIDO2StorageTypeMemory, t.TempDir(), "123456")

	device, err := newFIDO2Device(t.Context(), cfg, discardLogger())
	require.NoError(t, err)
	defer func() { _ = device.Close() }()

	require.True(t, device.auth.IsPINSet(), "--set-pin must establish the PIN")
	require.Equal(t, authenticator.DefaultConfig().PINMaxRetries, device.auth.PINRetries(),
		"a freshly established PIN starts with the full retry budget")
}

func TestNewFIDO2Device_SetPINRefusesPolicyViolatingPIN(t *testing.T) {
	cfg := seedPINConfig(t, FIDO2StorageTypeMemory, t.TempDir(), "12")

	device, err := newFIDO2Device(t.Context(), cfg, discardLogger())
	require.Nil(t, device, "no device may be handed back with an error")
	require.ErrorIs(t, err, ErrFIDO2PINSetFailed)
	require.ErrorIs(t, err, authenticator.ErrPINPolicyViolation,
		"the authenticator's PIN policy must reach the operator")
	require.NotErrorIs(t, err, ErrFIDO2PINAlreadySet)
}

// TestNewFIDO2Device_SetPINRefusesToOverwritePersistedPIN is the restart case
// the testing helper got wrong: a second start with --set-pin against a file
// store that already holds a PIN must refuse with the typed error and leave
// the stored PIN untouched, and a restart without --set-pin must come up
// with the PIN still set.
func TestNewFIDO2Device_SetPINRefusesToOverwritePersistedPIN(t *testing.T) {
	dir := t.TempDir()

	first, err := newFIDO2Device(t.Context(), seedPINConfig(t, FIDO2StorageTypeFile, dir, "123456"), discardLogger())
	require.NoError(t, err)
	require.True(t, first.auth.IsPINSet())
	require.NoError(t, first.Close())

	// Restart with --set-pin and a different PIN: refused, typed both ways.
	second, err := newFIDO2Device(t.Context(), seedPINConfig(t, FIDO2StorageTypeFile, dir, "654321"), discardLogger())
	require.Nil(t, second, "no device may be handed back with an error")
	require.ErrorIs(t, err, ErrFIDO2PINAlreadySet)
	require.ErrorIs(t, err, authenticator.ErrPINAlreadySet)
	require.NotErrorIs(t, err, ErrFIDO2PINSetFailed,
		"an already-set PIN is not a failed set; the operator needs the distinct message")

	// Restart without --set-pin: the persisted PIN is still there.
	third, err := newFIDO2Device(t.Context(), seedPINConfig(t, FIDO2StorageTypeFile, dir, ""), discardLogger())
	require.NoError(t, err)
	defer func() { _ = third.Close() }()
	require.True(t, third.auth.IsPINSet(), "the PIN established on the first start must persist")
}

func TestFIDO2Errors_PINAlreadySetIsDistinct(t *testing.T) {
	require.NotErrorIs(t, ErrFIDO2PINAlreadySet, ErrFIDO2PINSetFailed)
	require.Contains(t, ErrFIDO2PINAlreadySet.Error(), "fido2:")
	require.Contains(t, ErrFIDO2PINAlreadySet.Error(), "--set-pin")
}

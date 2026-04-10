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

//go:build integration && androidemu

package phone

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestAndroidE2E_EmulatorBoot verifies the Android emulator is accessible
// and has finished booting. This is a prerequisite for all Android E2E tests.
func TestAndroidE2E_EmulatorBoot(t *testing.T) {
	adbHost := os.Getenv("ANDROID_ADB_HOST")
	adb, err := NewADBHelper(adbHost)
	require.NoError(t, err, "ADB helper creation should succeed")

	if adbHost != "" {
		require.NoError(t, adb.Connect(), "ADB connect to emulator")
	}

	require.NoError(t, adb.WaitForBoot(3*time.Minute), "emulator should boot within 3 minutes")
}

// TestAndroidE2E_TCPPairing tests the full pairing flow between the Go
// desktop TCP relay and the Android app running in the emulator.
//
// Prerequisites (handled by docker-compose):
//   - Android emulator running (budtmo/docker-android)
//   - xKey desktop TCP relay running on xkey-desktop:8444
//   - xKey Android APK installed on the emulator
//
// This test:
//  1. Connects to the emulator via ADB
//  2. Configures the Android app to connect to the TCP relay
//  3. Launches the pairing activity
//  4. Waits for the pairing to complete
//  5. Verifies the pairing on both sides
//
// NOTE: This test requires the xkey-android app to have a TCP pairing
// client (TcpPairingClient.kt) and a test BroadcastReceiver for setting
// preferences via ADB. This is tracked as a separate xkey-android PR.
func TestAndroidE2E_TCPPairing(t *testing.T) {
	relayAddr := os.Getenv("XKEY_RELAY_ADDR")
	if relayAddr == "" {
		relayAddr = "xkey-desktop:8444"
	}

	adbHost := os.Getenv("ANDROID_ADB_HOST")
	adb, err := NewADBHelper(adbHost)
	require.NoError(t, err)

	if adbHost != "" {
		require.NoError(t, adb.Connect())
	}

	require.NoError(t, adb.WaitForBoot(3*time.Minute))

	// Configure the Android app to use TCP pairing with the relay address.
	t.Logf("Configuring Android app to connect to relay at %s", relayAddr)
	err = adb.SetPreference("com.automatethethings.xkey", "tcp_relay_address", relayAddr)
	require.NoError(t, err, "set TCP relay address preference")

	// Launch the pairing activity.
	t.Log("Launching pairing activity on Android emulator")
	err = adb.LaunchActivity(
		"com.automatethethings.xkey/.ui.pairing.PairingActivity",
		map[string]string{
			"transport": "tcp",
			"address":   relayAddr,
		},
	)
	require.NoError(t, err, "launch pairing activity")

	// Wait for the pairing to complete.
	// The Android app needs to:
	// 1. Connect to the TCP relay via TcpPairingClient
	// 2. Perform Noise XX handshake
	// 3. Exchange identity information
	// 4. Complete pairing
	//
	// TODO: Implement a proper synchronization mechanism (e.g., polling
	// a shared file or using ADB to check app state). For now, we use a
	// simple sleep to allow the pairing to complete.
	t.Log("Waiting for pairing to complete...")
	time.Sleep(10 * time.Second)

	// TODO: Verify pairing completed successfully on both sides:
	// - Check Android app shows paired device
	// - Check xKey desktop shows paired device
	// This requires the Android app's TCP pairing implementation (separate PR).
	t.Log("Android E2E TCP pairing test scaffold complete")
	t.Log("Full verification requires xkey-android TCP pairing client implementation")
}

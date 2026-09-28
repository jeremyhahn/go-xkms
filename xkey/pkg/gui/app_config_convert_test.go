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

package gui

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// nonDefaultGUIConfig returns a GUIConfig with every field the gui<->services
// bridge is supposed to carry set to a non-zero, non-default value, so a
// dropped field shows up as a mismatch rather than a false-positive zero-value
// match.
func nonDefaultGUIConfig() *GUIConfig {
	return &GUIConfig{
		AutoTray:                  false,
		Theme:                     ThemeDark,
		StartMinimized:            true,
		Notifications:             false,
		WindowWidth:               1280,
		WindowHeight:              900,
		RememberPosition:          false,
		WindowX:                   42,
		WindowY:                   84,
		ServerAddress:             "kms.example.com:9443",
		ServerProtocol:            "rest",
		ServerTLSEnabled:          true,
		ServerTLSSkipVerify:       true,
		ServerTLSCAFile:           "/etc/xkey/ca.pem",
		ServerAutoConnect:         true,
		AutoUnsealEnabled:         true,
		AutoUnsealBlobID:          "blob-123",
		AutoUnsealPCRs:            []int{0, 1, 7},
		AutoUnsealPCRBank:         "sha256",
		AutoUnsealPolicyType:      "pcr",
		AutoUnsealPolicyName:      "boot-policy",
		AutoUnsealBackend:         "tpm2",
		FIDO2AuthenticatorEnabled: false,
		ClipboardTimeout:          60,
		RequireAuth:               false,
		AppAutoLockMinutes:        5,
		AppLockOnScreenLock:       false,
		SetupComplete:             true,
		StorageType:               "barrier",
		BarrierInitialized:        true,
		BarrierStrategy:           "passphrase",
		BarrierAutoUnsealBlobID:   "barrier-blob-456",
		BarrierAutoUnsealEnabled:  true,
		SealerBackend:             "tpm2",
		APIExplorerSandboxPolicy:  "allow-scripts",
		BrowserExtensionEnabled:   false,
		DeveloperTools:            false,
		FIDO2RequireUserPresence:  false,
		FIDO2UserIntentCheck:      false,
	}
}

// TestConfigToData_DataToConfig_RoundTrip verifies that every field the
// gui<->services bridge is supposed to carry survives a
// configToData/dataToConfig round trip unchanged.
func TestConfigToData_DataToConfig_RoundTrip(t *testing.T) {
	original := nonDefaultGUIConfig()

	data := configToData(original)
	require.NotNil(t, data)

	roundTripped := dataToConfig(data)
	require.NotNil(t, roundTripped)

	assert.Equal(t, original.AutoTray, roundTripped.AutoTray)
	assert.Equal(t, original.Theme, roundTripped.Theme)
	assert.Equal(t, original.StartMinimized, roundTripped.StartMinimized)
	assert.Equal(t, original.Notifications, roundTripped.Notifications)
	assert.Equal(t, original.WindowWidth, roundTripped.WindowWidth)
	assert.Equal(t, original.WindowHeight, roundTripped.WindowHeight)
	assert.Equal(t, original.RememberPosition, roundTripped.RememberPosition)
	assert.Equal(t, original.WindowX, roundTripped.WindowX)
	assert.Equal(t, original.WindowY, roundTripped.WindowY)
	assert.Equal(t, original.ServerAddress, roundTripped.ServerAddress)
	assert.Equal(t, original.ServerProtocol, roundTripped.ServerProtocol)
	assert.Equal(t, original.ServerTLSEnabled, roundTripped.ServerTLSEnabled)
	assert.Equal(t, original.ServerTLSSkipVerify, roundTripped.ServerTLSSkipVerify)
	assert.Equal(t, original.ServerTLSCAFile, roundTripped.ServerTLSCAFile)
	assert.Equal(t, original.ServerAutoConnect, roundTripped.ServerAutoConnect)
	assert.Equal(t, original.AutoUnsealEnabled, roundTripped.AutoUnsealEnabled)
	assert.Equal(t, original.AutoUnsealBlobID, roundTripped.AutoUnsealBlobID)
	assert.Equal(t, original.AutoUnsealPCRs, roundTripped.AutoUnsealPCRs)
	assert.Equal(t, original.AutoUnsealPCRBank, roundTripped.AutoUnsealPCRBank)
	assert.Equal(t, original.AutoUnsealPolicyType, roundTripped.AutoUnsealPolicyType)
	assert.Equal(t, original.AutoUnsealPolicyName, roundTripped.AutoUnsealPolicyName)
	assert.Equal(t, original.AutoUnsealBackend, roundTripped.AutoUnsealBackend)
	assert.Equal(t, original.FIDO2AuthenticatorEnabled, roundTripped.FIDO2AuthenticatorEnabled)
	assert.Equal(t, original.ClipboardTimeout, roundTripped.ClipboardTimeout)
	assert.Equal(t, original.RequireAuth, roundTripped.RequireAuth)
	assert.Equal(t, original.AppAutoLockMinutes, roundTripped.AppAutoLockMinutes)
	assert.Equal(t, original.AppLockOnScreenLock, roundTripped.AppLockOnScreenLock)
	assert.Equal(t, original.SetupComplete, roundTripped.SetupComplete)
	assert.Equal(t, original.StorageType, roundTripped.StorageType)
	assert.Equal(t, original.BarrierInitialized, roundTripped.BarrierInitialized)
	assert.Equal(t, original.BarrierStrategy, roundTripped.BarrierStrategy)
	assert.Equal(t, original.BarrierAutoUnsealBlobID, roundTripped.BarrierAutoUnsealBlobID)
	assert.Equal(t, original.BarrierAutoUnsealEnabled, roundTripped.BarrierAutoUnsealEnabled)
	assert.Equal(t, original.SealerBackend, roundTripped.SealerBackend)
	assert.Equal(t, original.APIExplorerSandboxPolicy, roundTripped.APIExplorerSandboxPolicy)
	assert.Equal(t, original.BrowserExtensionEnabled, roundTripped.BrowserExtensionEnabled)
	assert.Equal(t, original.DeveloperTools, roundTripped.DeveloperTools)
	assert.Equal(t, original.FIDO2RequireUserPresence, roundTripped.FIDO2RequireUserPresence)
	assert.Equal(t, original.FIDO2UserIntentCheck, roundTripped.FIDO2UserIntentCheck)
}

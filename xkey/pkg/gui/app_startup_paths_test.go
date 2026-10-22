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

package gui

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/config"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/xhome"
)

// TestEnsureLocalTPMPolicies_UnusableHomeLeavesPoliciesClosed verifies that
// when the data directory cannot be resolved the TPM policy service stays
// closed and the data directory stays unset.
func TestEnsureLocalTPMPolicies_UnusableHomeLeavesPoliciesClosed(t *testing.T) {
	a := newNoTPMApp(t, "passphrase")
	logs := captureLog(a)
	a.dataDir = ""
	notADir := filepath.Join(t.TempDir(), "home-is-a-file")
	require.NoError(t, os.WriteFile(notADir, []byte("x"), 0o600))
	t.Setenv(xhome.EnvHome, notADir)

	a.ensureLocalTPMPolicies()

	assert.Nil(t, a.tpmPolicyService.Local())
	assert.Empty(t, a.dataDir)
	assert.True(t, logs.Contains("TPM policies: data directory unavailable"))
}

// startDataDirApp initializes a minimal App's data directory with the
// virtual FIDO2 device and local app access off, so postDataDirStartup
// touches neither /dev/uhid nor an IPC socket.
func startDataDirApp(t *testing.T) (*App, *logBuffer) {
	t.Helper()
	app := newMinimalApp(t)
	app.config.FIDO2AuthenticatorEnabled = false
	app.config.LocalAppAccessEnabled = false
	require.NoError(t, app.initializeDataDir())
	t.Cleanup(xkmssdk.Reset)
	require.NotNil(t, app.trustStore, "precondition: initializeDataDir must open the trust store")
	return app, captureLog(app)
}

// TestPostDataDirStartup_SeedsEmbeddedRoots verifies the first start after
// the data directory opens seeds the embedded trust roots.
func TestPostDataDirStartup_SeedsEmbeddedRoots(t *testing.T) {
	app, logs := startDataDirApp(t)

	app.postDataDirStartup()
	t.Cleanup(app.expiryChecker.Stop)

	assert.True(t, logs.Contains("seeded embedded trust roots"))
	assert.False(t, logs.Contains("failed to seed embedded roots"))
}

// TestPostDataDirStartup_TrustStoreLockedSkipsSeeding verifies that an
// enterprise policy forbidding trust store changes refuses the seeding,
// logs it, and the rest of the startup still runs.
func TestPostDataDirStartup_TrustStoreLockedSkipsSeeding(t *testing.T) {
	app, logs := startDataDirApp(t)
	app.trustService.SetPolicy(&config.PolicySection{UserCanManageTrustStore: false})

	app.postDataDirStartup()
	t.Cleanup(app.expiryChecker.Stop)

	assert.True(t, logs.Contains("failed to seed embedded roots"))
	assert.True(t, logs.Contains("user_can_manage_trust_store"))
	assert.False(t, logs.Contains("seeded embedded trust roots"))
	assert.True(t, app.dataReady.Load(), "a refused seeding must not stop the startup")
}

// TestInitPINService_UserPINReachesTheAuthenticator verifies that setting
// the user PIN through the wired PIN service hands its hash to the FIDO2
// authenticator, so CTAP2 clientPIN checks the same PIN.
func TestInitPINService_UserPINReachesTheAuthenticator(t *testing.T) {
	app := newPolicyTestApp(t)
	app.dataDir = t.TempDir()
	app.initPINService()
	require.False(t, app.authenticatorInstance.IsPINSet())

	require.NoError(t, app.pinService.SetSOPIN("", "so-pin-123456"))
	require.NoError(t, app.pinService.SetUserPIN("so-pin-123456", "user-pin-1234"))

	assert.True(t, app.pinService.IsPINSet())
	assert.True(t, app.authenticatorInstance.IsPINSet(), "the user PIN hash must reach the authenticator")
}

// TestInitPINService_RejectedUserPINLeavesTheAuthenticatorUnset verifies a
// user PIN refused for a wrong SO PIN never reaches the authenticator.
func TestInitPINService_RejectedUserPINLeavesTheAuthenticatorUnset(t *testing.T) {
	app := newPolicyTestApp(t)
	app.dataDir = t.TempDir()
	app.initPINService()
	require.NoError(t, app.pinService.SetSOPIN("", "so-pin-123456"))

	require.Error(t, app.pinService.SetUserPIN("wrong-so-pin-1", "user-pin-1234"))

	assert.False(t, app.authenticatorInstance.IsPINSet())
}

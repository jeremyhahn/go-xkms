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

	"github.com/jeremyhahn/go-xkms/xkey/pkg/config"
)

// TestNewApp_SealedEnterprisePolicyInstallsDefaultsBeforeSOLogin verifies
// that NewApp in an enterprise config directory installs the default
// extension policy, not the file's unverified relaxation, before the SO has
// logged in.
func TestNewApp_SealedEnterprisePolicyInstallsDefaultsBeforeSOLogin(t *testing.T) {
	dir := useRelaxedGUIConfigDir(t)
	sealRelaxedPolicy(t, dir, "so-pin-12345")

	app := NewApp(nil)

	got := app.autofillService.GetEnterprisePolicy()
	require.NotNil(t, got, "an enterprise directory must install an extension policy at construction")
	defaults := config.DefaultPolicy()
	assert.Equal(t, defaults.ExtensionRequireAuthentication, got.RequireAuthentication)
	assert.Equal(t, defaults.ExtensionMaxFillsPerMinute, got.MaxFillsPerMinute)
	assert.Empty(t, got.AllowedDomains, "the unverified file's allow-list must not reach the extension")
}

// TestNewApp_PersonalModeInstallsNoEnterprisePolicy verifies that an
// unsealed policy file leaves NewApp without an enterprise extension policy.
func TestNewApp_PersonalModeInstallsNoEnterprisePolicy(t *testing.T) {
	useRelaxedGUIConfigDir(t)

	app := NewApp(nil)

	assert.Nil(t, app.autofillService.GetEnterprisePolicy())
}

// TestNewApp_UnusableConfigDirStillConstructs verifies that a config
// directory which cannot be created is logged and NewApp still returns a
// wired App running on the built-in defaults.
func TestNewApp_UnusableConfigDirStillConstructs(t *testing.T) {
	isolateAppEnv(t)
	notADir := filepath.Join(t.TempDir(), "config-is-a-file")
	require.NoError(t, os.WriteFile(notADir, []byte("x"), 0o600))
	t.Setenv("XDG_CONFIG_HOME", notADir)
	logs := captureDefaultLog(t)

	app := NewApp(nil)

	require.NotNil(t, app)
	assert.NotNil(t, app.autofillService)
	assert.True(t, logs.Contains("failed to resolve config directory"))
}

// useRelaxedGUIConfigDir isolates the environment and writes the relaxed
// policy file into the config directory NewApp resolves, pointing
// config.Load at the same directory. It returns that directory.
func useRelaxedGUIConfigDir(t *testing.T) string {
	t.Helper()
	isolateAppEnv(t)
	dir, err := configDir()
	require.NoError(t, err)
	config.SetConfigDir(dir)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "xkey.yaml"), []byte(relaxedPolicyYAML), 0o600))
	return dir
}

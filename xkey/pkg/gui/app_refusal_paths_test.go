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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/config"
)

// TestApp_SetTheme_InvalidThemeRefused verifies that an unknown theme is
// refused and the current theme is kept.
func TestApp_SetTheme_InvalidThemeRefused(t *testing.T) {
	app := newWiredApp(t)
	before := app.GetTheme()

	err := app.SetTheme("neon")

	require.Error(t, err)
	assert.Equal(t, before, app.GetTheme())
}

// TestLoadTPMConfig_UnreadableConfigFile verifies that a config path that
// exists but cannot be read is refused with ErrConfigLoad, alongside the
// TPM defaults.
func TestLoadTPMConfig_UnreadableConfigFile(t *testing.T) {
	cfgDir := t.TempDir()
	config.SetConfigDir(cfgDir)
	t.Cleanup(config.ResetConfigDir)
	require.NoError(t, os.Mkdir(config.ConfigPath(), 0o700))

	cfg, err := loadTPMConfig(testLogger())

	assert.ErrorIs(t, err, ErrConfigLoad)
	assert.Equal(t, xkmssdk.DefaultTPMConfig.Device, cfg.Device)
}

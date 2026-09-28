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
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkeyconfig "github.com/jeremyhahn/go-xkms/xkey/pkg/config"
)

// fido2ConfigSourcedKeys are the viper keys buildFIDO2Config installs a
// config/environment-sourced value into via viper.SetDefault. SetDefault has
// no undo: unlike an override (viper.Set), a later default can only replace
// an earlier one, never remove it, so it is not one of the "mutations"
// resetViperForTest's snapshot/restore was built for (it restores by calling
// viper.Set, which -- being a higher-precedence override -- would otherwise
// permanently pin one test's resolved value ahead of every later test's own
// flag/env/default, corrupting the whole suite). Clearing any override left
// on these keys before each test is what actually gives every test in this
// file a clean slate.
var fido2ConfigSourcedKeys = []string{"fido2.storage", "fido2.storage_path", "fido2.name", "fido2.attestation"}

// isolateFIDO2ConfigDir points xkeyconfig.Load() (the instance
// buildFIDO2Config reads through) at an empty temporary directory, so a test
// controls exactly what the config file and the environment contribute,
// independent of whatever the host running the test suite has in
// ~/.config/xkey. It also resets the fido2 command's flags, so a flag set by
// an earlier test cannot leak in as "the flag source", and clears any
// lingering override on fido2ConfigSourcedKeys (see its doc).
func isolateFIDO2ConfigDir(t *testing.T) string {
	t.Helper()
	resetCommandFlagsForTest(t, fido2Cmd)
	for _, key := range fido2ConfigSourcedKeys {
		viper.Set(key, nil)
	}
	// A leaked SetDefault from an earlier test in this binary cannot be
	// unset, only replaced (see fido2ConfigSourcedKeys's doc), so each test
	// starts by replacing it with the command's own declared flag default --
	// exactly the value a fresh process would have before buildFIDO2Config
	// ever ran. Each test's own config/environment/flag setup still takes
	// precedence over this on top, in the order buildFIDO2Config resolves.
	viper.SetDefault("fido2.storage", defaultFIDO2StorageType)
	viper.SetDefault("fido2.storage_path", "")
	viper.SetDefault("fido2.name", defaultFIDO2DeviceName)
	viper.SetDefault("fido2.attestation", defaultFIDO2Attestation)

	dir := t.TempDir()
	xkeyconfig.SetConfigDir(dir)
	t.Cleanup(xkeyconfig.ResetConfigDir)
	return dir
}

// writeFIDO2ConfigFile writes xkey.yaml's fido2: section into dir.
func writeFIDO2ConfigFile(t *testing.T, dir, yamlBody string) {
	t.Helper()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "xkey.yaml"), []byte("fido2:\n"+yamlBody), 0600))
}

// TestBuildFIDO2Config_StorageFromConfigFile proves the config file's
// fido2.storage reaches buildFIDO2Config, not only fido2.attestation
// (go-xkms#871): pkg/config.FIDO2Config declares storage, storage_path and
// device_name exactly the way it declares attestation, so all four must be
// honoured the same way.
func TestBuildFIDO2Config_StorageFromConfigFile(t *testing.T) {
	dir := isolateFIDO2ConfigDir(t)
	writeFIDO2ConfigFile(t, dir, "  storage: file\n  storage_path: "+filepath.Join(dir, "fido2-data")+"\n  device_name: ConfiguredKey\n")

	cfg := buildFIDO2Config()
	assert.Equal(t, FIDO2StorageTypeFile, cfg.StorageType)
	assert.Equal(t, filepath.Join(dir, "fido2-data"), cfg.StoragePath)
	assert.Equal(t, "ConfiguredKey", cfg.DeviceName)
}

// TestBuildFIDO2Config_StorageFromEnv proves the XKEY_FIDO2_* environment
// variables pkg/config registers for these same keys reach buildFIDO2Config
// with no config file present at all.
func TestBuildFIDO2Config_StorageFromEnv(t *testing.T) {
	isolateFIDO2ConfigDir(t)
	t.Setenv("XKEY_FIDO2_STORAGE", "file")
	t.Setenv("XKEY_FIDO2_STORAGE_PATH", "/var/lib/xkey/fido2-env")
	t.Setenv("XKEY_FIDO2_DEVICE_NAME", "EnvKey")

	cfg := buildFIDO2Config()
	assert.Equal(t, FIDO2StorageTypeFile, cfg.StorageType)
	assert.Equal(t, "/var/lib/xkey/fido2-env", cfg.StoragePath)
	assert.Equal(t, "EnvKey", cfg.DeviceName)
}

// TestBuildFIDO2Config_FlagBeatsEnvAndConfigFile proves an explicit flag
// still wins over both sources, matching every other precedence chain in
// this package (resolveXKMSdURL, buildPIVConfig).
func TestBuildFIDO2Config_FlagBeatsEnvAndConfigFile(t *testing.T) {
	dir := isolateFIDO2ConfigDir(t)
	writeFIDO2ConfigFile(t, dir, "  storage: file\n  device_name: ConfiguredKey\n")
	t.Setenv("XKEY_FIDO2_STORAGE", "barrier")
	t.Setenv("XKEY_FIDO2_DEVICE_NAME", "EnvKey")

	require.NoError(t, setFlagForTest(t, fido2Cmd.Flags(), "storage", "memory"))
	require.NoError(t, setFlagForTest(t, fido2Cmd.Flags(), "name", "FlagKey"))

	cfg := buildFIDO2Config()
	assert.Equal(t, FIDO2StorageTypeMemory, cfg.StorageType, "the flag must win over the environment and the config file")
	assert.Equal(t, "FlagKey", cfg.DeviceName)
}

// TestBuildFIDO2Config_EnvBeatsConfigFile proves the environment variable
// wins over a config file value for the same key -- the precedence
// pkg/config's own viper instance already applies before buildFIDO2Config
// ever sees a value (TestLoadFromPath_EnvOverride covers the general
// mechanism; this proves buildFIDO2Config does not undo it).
func TestBuildFIDO2Config_EnvBeatsConfigFile(t *testing.T) {
	dir := isolateFIDO2ConfigDir(t)
	writeFIDO2ConfigFile(t, dir, "  device_name: ConfiguredKey\n")
	t.Setenv("XKEY_FIDO2_DEVICE_NAME", "EnvKey")

	cfg := buildFIDO2Config()
	assert.Equal(t, "EnvKey", cfg.DeviceName)
}

// TestBuildFIDO2Config_InvalidConfigStorageIsRejected proves a storage type
// pkg/config does not itself validate (FIDO2Config.Validate has no such
// check; it is a free-form string there) is still caught: it reaches
// FIDO2Config.Validate the same way an invalid --storage flag value would,
// with the same typed error.
func TestBuildFIDO2Config_InvalidConfigStorageIsRejected(t *testing.T) {
	dir := isolateFIDO2ConfigDir(t)
	writeFIDO2ConfigFile(t, dir, "  storage: quantum\n")

	cfg := buildFIDO2Config()
	require.Equal(t, FIDO2StorageType("quantum"), cfg.StorageType)

	err := cfg.Validate()
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrFIDO2InvalidStorageType)
}

// TestBuildFIDO2Config_NoSourceKeepsFlagDefault proves that with no config
// file, no environment variable and no flag, buildFIDO2Config resolves to
// the flag's own declared default -- the "run with default settings"
// behavior the command's Long help documents.
func TestBuildFIDO2Config_NoSourceKeepsFlagDefault(t *testing.T) {
	isolateFIDO2ConfigDir(t)

	cfg := buildFIDO2Config()
	assert.Equal(t, FIDO2StorageType(defaultFIDO2StorageType), cfg.StorageType)
	assert.Equal(t, defaultFIDO2DeviceName, cfg.DeviceName)
}

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

package config

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSaveToPath_ValidConfig(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "xkey.yaml")

	original := DefaultConfig()
	original.Log.Level = "debug"
	original.GUI.Theme = "dark"
	original.GUI.WindowWidth = 1920
	original.GUI.WindowHeight = 1080

	require.NoError(t, SaveToPath(original, cfgPath))

	loaded, err := LoadFromPath(cfgPath)
	require.NoError(t, err)
	require.NotNil(t, loaded)

	assert.Equal(t, "debug", loaded.Log.Level)
	assert.Equal(t, "dark", loaded.GUI.Theme)
	assert.Equal(t, 1920, loaded.GUI.WindowWidth)
	assert.Equal(t, 1080, loaded.GUI.WindowHeight)
	assert.Equal(t, original.Backend.Default, loaded.Backend.Default)
}

func TestSaveToPath_NilConfig(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "xkey.yaml")

	err := SaveToPath(nil, cfgPath)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrConfigSaveFailed),
		"expected ErrConfigSaveFailed, got %v", err)
}

func TestSaveToPath_InvalidConfig(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "xkey.yaml")

	cfg := DefaultConfig()
	cfg.Log.Level = "banana" // invalid log level

	err := SaveToPath(cfg, cfgPath)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrConfigInvalid),
		"expected ErrConfigInvalid, got %v", err)
}

func TestSaveToPath_InvalidConfigNegativeClipboard(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "xkey.yaml")

	cfg := DefaultConfig()
	cfg.GUI.ClipboardTimeout = -1

	err := SaveToPath(cfg, cfgPath)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrConfigInvalid),
		"expected ErrConfigInvalid, got %v", err)
}

func TestSaveToPath_CreatesDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	nestedPath := filepath.Join(tmpDir, "deeply", "nested", "dir", "xkey.yaml")

	cfg := DefaultConfig()
	require.NoError(t, SaveToPath(cfg, nestedPath))

	// Verify the file exists.
	info, err := os.Stat(nestedPath)
	require.NoError(t, err)
	assert.False(t, info.IsDir())
}

func TestSaveToPath_FilePermissions(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "xkey.yaml")

	cfg := DefaultConfig()
	require.NoError(t, SaveToPath(cfg, cfgPath))

	info, err := os.Stat(cfgPath)
	require.NoError(t, err)

	// The file should have 0600 permissions (owner read/write only).
	perm := info.Mode().Perm()
	assert.Equal(t, os.FileMode(0600), perm,
		"expected file permissions 0600, got %04o", perm)
}

func TestSaveToPath_DirPermissions(t *testing.T) {
	tmpDir := t.TempDir()
	newDir := filepath.Join(tmpDir, "newconfigdir")
	cfgPath := filepath.Join(newDir, "xkey.yaml")

	cfg := DefaultConfig()
	require.NoError(t, SaveToPath(cfg, cfgPath))

	info, err := os.Stat(newDir)
	require.NoError(t, err)
	require.True(t, info.IsDir())

	perm := info.Mode().Perm()
	assert.Equal(t, os.FileMode(0700), perm,
		"expected directory permissions 0700, got %04o", perm)
}

func TestSaveToPath_AtomicWrite(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "xkey.yaml")

	cfg := DefaultConfig()
	require.NoError(t, SaveToPath(cfg, cfgPath))

	// After a successful save, there should be no leftover temp files
	// in the directory. Temp files have the pattern ".xkey-config-*.yaml.tmp".
	entries, err := os.ReadDir(tmpDir)
	require.NoError(t, err)

	for _, entry := range entries {
		assert.False(t, strings.HasPrefix(entry.Name(), ".xkey-config-"),
			"found leftover temp file: %s", entry.Name())
	}
}

func TestSaveToPath_OverwriteExisting(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "xkey.yaml")

	// First save.
	original := DefaultConfig()
	original.Log.Level = "info"
	original.GUI.Theme = "system"
	require.NoError(t, SaveToPath(original, cfgPath))

	// Second save with modified values.
	modified := DefaultConfig()
	modified.Log.Level = "error"
	modified.GUI.Theme = "dark"
	modified.GUI.WindowWidth = 2560
	modified.GUI.WindowHeight = 1440
	require.NoError(t, SaveToPath(modified, cfgPath))

	// Read back and verify the new values.
	loaded, err := LoadFromPath(cfgPath)
	require.NoError(t, err)
	require.NotNil(t, loaded)

	assert.Equal(t, "error", loaded.Log.Level)
	assert.Equal(t, "dark", loaded.GUI.Theme)
	assert.Equal(t, 2560, loaded.GUI.WindowWidth)
	assert.Equal(t, 1440, loaded.GUI.WindowHeight)
}

// TestSave_UsesDefaultPath verifies that Save() delegates to SaveToPath
// with ConfigPath() as the target. We cannot call Save() directly without
// writing to the user's real config directory, so we verify the contract
// indirectly: Save returns ErrConfigSaveFailed for nil input, confirming
// it reaches SaveToPath's validation logic.
func TestSave_UsesDefaultPath(t *testing.T) {
	err := Save(nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrConfigSaveFailed),
		"Save(nil) should return ErrConfigSaveFailed, got %v", err)
}

func TestSaveToPath_RoundTrip_AllSections(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "xkey.yaml")

	cfg := DefaultConfig()
	cfg.Backend.Default = "tpm2"
	cfg.Backend.TPM2.Device = "/dev/tpmrm0"
	cfg.Backend.TPM2.Simulator = true
	cfg.Backend.TPM2.Hash = "sha256"
	cfg.FIDO2.DeviceName = "TestDevice"
	cfg.FIDO2.AlwaysUV = true
	cfg.FIDO2.ResidentKey = true
	cfg.OATH.Algorithm = "sha512"
	cfg.OATH.Digits = 8
	cfg.OATH.Period = 60
	cfg.Phone.Backend = "bluetooth"
	cfg.Phone.ServerAddress = "127.0.0.1:9000"
	cfg.XKMSD.Address = "localhost:8443"
	cfg.XKMSD.Protocol = "grpc"
	cfg.XKMSD.TLSEnabled = true
	cfg.TPM.Device = "/dev/tpmrm0"
	cfg.TPM.EncryptSessions = true
	cfg.PasswordProtection.Enabled = true
	cfg.PasswordProtection.Mode = "barrier"
	cfg.Trust.Roots = []string{"/etc/xkey/roots/ca.pem"}
	cfg.Trust.SystemTrust = true
	cfg.Attestation.Mode = "self"
	cfg.Attestation.CACert = "/tmp/ca.pem"
	cfg.Attestation.CAKey = "/tmp/ca.key"
	cfg.Log.Level = "trace"
	cfg.Log.File = "/tmp/xkey.log"
	cfg.GUI.Theme = "dark"
	cfg.GUI.WindowWidth = 1920
	cfg.GUI.WindowHeight = 1080
	cfg.GUI.ClipboardTimeout = 45
	cfg.GUI.StartMinimized = true
	cfg.GUI.RememberPosition = true
	cfg.GUI.WindowX = 50
	cfg.GUI.WindowY = 75
	cfg.GUI.Server.Address = "10.0.0.1:443"
	cfg.GUI.Server.Protocol = "rest"
	cfg.GUI.Server.TLSEnabled = true
	cfg.GUI.Server.AutoConnect = true
	cfg.GUI.AutoUnseal.Enabled = true
	cfg.GUI.AutoUnseal.BlobID = "blob1"
	cfg.GUI.AutoUnseal.PCRs = []int{0, 1, 7}
	cfg.GUI.AutoUnseal.PCRBank = "sha256"
	cfg.State.SetupComplete = true
	cfg.State.StorageType = "barrier"
	cfg.State.BarrierInitialized = true
	cfg.State.BarrierStrategy = "tpm-pcr"

	require.NoError(t, SaveToPath(cfg, cfgPath))

	loaded, err := LoadFromPath(cfgPath)
	require.NoError(t, err)
	require.NotNil(t, loaded)

	// Verify key fields survived the round-trip.
	assert.Equal(t, "tpm2", loaded.Backend.Default)
	assert.True(t, loaded.Backend.TPM2.Simulator)
	assert.Equal(t, "TestDevice", loaded.FIDO2.DeviceName)
	assert.True(t, loaded.FIDO2.AlwaysUV)
	assert.Equal(t, 8, loaded.OATH.Digits)
	assert.Equal(t, "bluetooth", loaded.Phone.Backend)
	assert.Equal(t, "localhost:8443", loaded.XKMSD.Address)
	assert.True(t, loaded.XKMSD.TLSEnabled)
	assert.True(t, loaded.PasswordProtection.Enabled)
	assert.Equal(t, []string{"/etc/xkey/roots/ca.pem"}, loaded.Trust.Roots)
	assert.Equal(t, "self", loaded.Attestation.Mode)
	assert.Equal(t, "trace", loaded.Log.Level)
	assert.Equal(t, "/tmp/xkey.log", loaded.Log.File)
	assert.Equal(t, "dark", loaded.GUI.Theme)
	assert.Equal(t, 1920, loaded.GUI.WindowWidth)
	assert.Equal(t, 1080, loaded.GUI.WindowHeight)
	assert.True(t, loaded.GUI.StartMinimized)
	assert.Equal(t, "10.0.0.1:443", loaded.GUI.Server.Address)
	assert.True(t, loaded.GUI.AutoUnseal.Enabled)
	assert.Equal(t, []int{0, 1, 7}, loaded.GUI.AutoUnseal.PCRs)
	assert.True(t, loaded.State.SetupComplete)
	assert.Equal(t, "tpm-pcr", loaded.State.BarrierStrategy)
}

func TestSaveToPath_InvalidBackend(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "xkey.yaml")

	cfg := DefaultConfig()
	cfg.Backend.Default = "nonexistent_backend"

	err := SaveToPath(cfg, cfgPath)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrConfigInvalid),
		"expected ErrConfigInvalid for invalid backend, got %v", err)
}

// --------------------------------------------------------------------------
// SaveToPath error path tests
// --------------------------------------------------------------------------

// TestSaveToPath_DirectoryCreationFailure verifies that SaveToPath returns
// ErrConfigDirCreate when the parent directory cannot be created (e.g.,
// because a file exists where a directory is expected).
func TestSaveToPath_DirectoryCreationFailure(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a regular file where MkdirAll expects to create a directory.
	blocker := filepath.Join(tmpDir, "blocker")
	require.NoError(t, os.WriteFile(blocker, []byte("not a dir"), 0600))

	// Attempt to save to a path nested under the file.
	cfgPath := filepath.Join(blocker, "nested", "xkey.yaml")

	cfg := DefaultConfig()
	err := SaveToPath(cfg, cfgPath)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrConfigDirCreate),
		"expected ErrConfigDirCreate, got %v", err)
}

// TestSaveToPath_ReadOnlyDirectory verifies that SaveToPath returns
// ErrConfigSaveFailed when it cannot create a temp file in a read-only
// parent directory.
func TestSaveToPath_ReadOnlyDirectory(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("read-only directory test only reliable on Linux")
	}
	if os.Getuid() == 0 {
		t.Skip("test requires non-root user for permission checks")
	}

	tmpDir := t.TempDir()
	readOnlyDir := filepath.Join(tmpDir, "readonly")
	require.NoError(t, os.MkdirAll(readOnlyDir, 0500))

	// Ensure cleanup can remove the directory.
	t.Cleanup(func() {
		os.Chmod(readOnlyDir, 0700)
	})

	cfgPath := filepath.Join(readOnlyDir, "xkey.yaml")
	cfg := DefaultConfig()

	err := SaveToPath(cfg, cfgPath)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrConfigSaveFailed),
		"expected ErrConfigSaveFailed for read-only directory, got %v", err)
}

// TestSaveToPath_InvalidConfigZeroWindowWidth verifies that SaveToPath
// returns ErrConfigInvalid for zero window width.
func TestSaveToPath_InvalidConfigZeroWindowWidth(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "xkey.yaml")

	cfg := DefaultConfig()
	cfg.GUI.WindowWidth = 0

	err := SaveToPath(cfg, cfgPath)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrConfigInvalid),
		"expected ErrConfigInvalid for zero window width, got %v", err)
}

// TestSaveToPath_InvalidConfigZeroWindowHeight verifies that SaveToPath
// returns ErrConfigInvalid for zero window height.
func TestSaveToPath_InvalidConfigZeroWindowHeight(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "xkey.yaml")

	cfg := DefaultConfig()
	cfg.GUI.WindowHeight = 0

	err := SaveToPath(cfg, cfgPath)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrConfigInvalid),
		"expected ErrConfigInvalid for zero window height, got %v", err)
}

// TestSave_ValidConfigToRedirectedHome verifies Save() successfully writes
// the config file when HOME is redirected to a temp directory.
func TestSave_ValidConfigToRedirectedHome(t *testing.T) {
	tmpDir := t.TempDir()
	configHome := filepath.Join(tmpDir, ".config")
	t.Setenv("HOME", tmpDir)
	t.Setenv("XDG_CONFIG_HOME", configHome)

	cfg := DefaultConfig()
	cfg.Log.Level = "warn"

	err := Save(cfg)
	require.NoError(t, err)

	// Verify the file was actually written.
	expectedPath := filepath.Join(configHome, "xkey", "xkey.yaml")
	_, statErr := os.Stat(expectedPath)
	assert.NoError(t, statErr, "Save() should have written %s", expectedPath)
}

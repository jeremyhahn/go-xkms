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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --------------------------------------------------------------------------
// migrateCLIConfig tests
// --------------------------------------------------------------------------

func TestMigrateCLIConfig_BackendSection(t *testing.T) {
	tmpDir := t.TempDir()
	yamlPath := filepath.Join(tmpDir, "config.yaml")

	yamlContent := `backend:
  default: tpm2
  tpm2:
    device: /dev/tpm0
    simulator: true
    hash: SHA-384
`
	require.NoError(t, os.WriteFile(yamlPath, []byte(yamlContent), 0600))

	cfg := DefaultConfig()
	err := migrateCLIConfig(cfg, yamlPath)
	require.NoError(t, err)

	assert.Equal(t, "tpm2", cfg.Backend.Default)
	assert.Equal(t, "/dev/tpm0", cfg.Backend.TPM2.Device)
	assert.True(t, cfg.Backend.TPM2.Simulator)
	assert.Equal(t, "SHA-384", cfg.Backend.TPM2.Hash)
}

func TestMigrateCLIConfig_FIDO2Section(t *testing.T) {
	tmpDir := t.TempDir()
	yamlPath := filepath.Join(tmpDir, "config.yaml")

	yamlContent := `fido2:
  storage: memory
  storage_path: /tmp/fido2-store
  attestation: self
  device_name: TestKey
  rpid_hash: true
  always_uv: true
  resident_key: true
  conformance_mode: true
`
	require.NoError(t, os.WriteFile(yamlPath, []byte(yamlContent), 0600))

	cfg := DefaultConfig()
	err := migrateCLIConfig(cfg, yamlPath)
	require.NoError(t, err)

	assert.Equal(t, "memory", cfg.FIDO2.Storage)
	assert.Equal(t, "/tmp/fido2-store", cfg.FIDO2.StoragePath)
	assert.Equal(t, "self", cfg.FIDO2.Attestation)
	assert.Equal(t, "TestKey", cfg.FIDO2.DeviceName)
	assert.True(t, cfg.FIDO2.RPIDHash)
	assert.True(t, cfg.FIDO2.AlwaysUV)
	assert.True(t, cfg.FIDO2.ResidentKey)
	assert.True(t, cfg.FIDO2.ConformanceMode)
}

func TestMigrateCLIConfig_LogSection(t *testing.T) {
	tmpDir := t.TempDir()
	yamlPath := filepath.Join(tmpDir, "config.yaml")

	yamlContent := `log:
  level: debug
  file: /tmp/test.log
`
	require.NoError(t, os.WriteFile(yamlPath, []byte(yamlContent), 0600))

	cfg := DefaultConfig()
	err := migrateCLIConfig(cfg, yamlPath)
	require.NoError(t, err)

	assert.Equal(t, "debug", cfg.Log.Level)
	assert.Equal(t, "/tmp/test.log", cfg.Log.File)
}

func TestMigrateCLIConfig_TPMSection(t *testing.T) {
	tmpDir := t.TempDir()
	yamlPath := filepath.Join(tmpDir, "config.yaml")

	yamlContent := `tpm:
  device: /dev/tpm1
  encrypt_sessions: false
  platform_pcr_bank: sha384
  seal_pcr_bank: sha512
  srk_handle: 2164260865
  ek_handle: 2164260866
`
	require.NoError(t, os.WriteFile(yamlPath, []byte(yamlContent), 0600))

	cfg := DefaultConfig()
	err := migrateCLIConfig(cfg, yamlPath)
	require.NoError(t, err)

	assert.Equal(t, "/dev/tpm1", cfg.TPM.Device)
	assert.False(t, cfg.TPM.EncryptSessions)
	assert.Equal(t, "sha384", cfg.TPM.PlatformPCRBank)
	assert.Equal(t, "sha512", cfg.TPM.SealPCRBank)
	assert.Equal(t, uint32(2164260865), cfg.TPM.SRKHandle)
	assert.Equal(t, uint32(2164260866), cfg.TPM.EKHandle)
}

func TestMigrateCLIConfig_PartialConfig(t *testing.T) {
	tmpDir := t.TempDir()
	yamlPath := filepath.Join(tmpDir, "config.yaml")

	yamlContent := `log:
  level: warn
`
	require.NoError(t, os.WriteFile(yamlPath, []byte(yamlContent), 0600))

	cfg := DefaultConfig()
	defaults := DefaultConfig()

	err := migrateCLIConfig(cfg, yamlPath)
	require.NoError(t, err)

	// The log level should be overridden.
	assert.Equal(t, "warn", cfg.Log.Level)

	// All other fields must remain at their default values.
	assert.Equal(t, defaults.Backend.Default, cfg.Backend.Default)
	assert.Equal(t, defaults.Backend.TPM2.Device, cfg.Backend.TPM2.Device)
	assert.Equal(t, defaults.FIDO2.Storage, cfg.FIDO2.Storage)
	assert.Equal(t, defaults.FIDO2.Attestation, cfg.FIDO2.Attestation)
	assert.Equal(t, defaults.FIDO2.DeviceName, cfg.FIDO2.DeviceName)
	assert.Equal(t, defaults.TPM.Device, cfg.TPM.Device)
	assert.Equal(t, defaults.TPM.EncryptSessions, cfg.TPM.EncryptSessions)
	assert.Equal(t, defaults.TPM.PlatformPCRBank, cfg.TPM.PlatformPCRBank)
	assert.Equal(t, defaults.GUI.Theme, cfg.GUI.Theme)
	assert.Equal(t, defaults.GUI.WindowWidth, cfg.GUI.WindowWidth)
	assert.Equal(t, defaults.GUI.WindowHeight, cfg.GUI.WindowHeight)
	assert.Equal(t, defaults.Log.File, cfg.Log.File)
}

func TestMigrateCLIConfig_AllSections(t *testing.T) {
	tmpDir := t.TempDir()
	yamlPath := filepath.Join(tmpDir, "config.yaml")

	yamlContent := `backend:
  default: tpm2
  tpm2:
    device: /dev/tpm0
    simulator: false
    hash: SHA-256
fido2:
  storage: memory
  attestation: self
  device_name: AllTestKey
  always_uv: true
oath:
  storage: file
  storage_path: /tmp/oath
  algorithm: SHA-512
  digits: 8
  period: 60
phone:
  backend: bluetooth
  server_address: 192.168.1.100:9090
  server_protocol: grpc
  server_tls_enabled: true
  device_filter: pixel
  attestation_policy: strict
xkmsd:
  address: localhost:8443
  protocol: grpc
  tls_enabled: true
  tls_skip_verify: false
  tls_ca_file: /etc/ssl/ca.pem
  tls_cert_file: /etc/ssl/cert.pem
  tls_key_file: /etc/ssl/key.pem
tpm:
  device: /dev/tpm1
  encrypt_sessions: false
  platform_pcr_bank: sha384
password_protection:
  enabled: true
  mode: tpm_sealed
trust:
  roots:
    - /etc/ssl/root1.pem
    - /etc/ssl/root2.pem
  system_trust: true
attestation:
  mode: packed
  ca_cert: /etc/ssl/attest-ca.pem
  ca_key: /etc/ssl/attest-ca.key
log:
  level: debug
  file: /var/log/xkey.log
`
	require.NoError(t, os.WriteFile(yamlPath, []byte(yamlContent), 0600))

	cfg := DefaultConfig()
	err := migrateCLIConfig(cfg, yamlPath)
	require.NoError(t, err)

	// Backend section.
	assert.Equal(t, "tpm2", cfg.Backend.Default)
	assert.Equal(t, "/dev/tpm0", cfg.Backend.TPM2.Device)
	assert.False(t, cfg.Backend.TPM2.Simulator)
	assert.Equal(t, "SHA-256", cfg.Backend.TPM2.Hash)

	// FIDO2 section.
	assert.Equal(t, "memory", cfg.FIDO2.Storage)
	assert.Equal(t, "self", cfg.FIDO2.Attestation)
	assert.Equal(t, "AllTestKey", cfg.FIDO2.DeviceName)
	assert.True(t, cfg.FIDO2.AlwaysUV)

	// OATH section.
	assert.Equal(t, "file", cfg.OATH.Storage)
	assert.Equal(t, "/tmp/oath", cfg.OATH.StoragePath)
	assert.Equal(t, "SHA-512", cfg.OATH.Algorithm)
	assert.Equal(t, 8, cfg.OATH.Digits)
	assert.Equal(t, 60, cfg.OATH.Period)

	// Phone section.
	assert.Equal(t, "bluetooth", cfg.Phone.Backend)
	assert.Equal(t, "192.168.1.100:9090", cfg.Phone.ServerAddress)
	assert.Equal(t, "grpc", cfg.Phone.ServerProtocol)
	assert.True(t, cfg.Phone.ServerTLSEnabled)
	assert.Equal(t, "pixel", cfg.Phone.DeviceFilter)
	assert.Equal(t, "strict", cfg.Phone.AttestationPolicy)

	// XKMSD section.
	assert.Equal(t, "localhost:8443", cfg.XKMSD.Address)
	assert.Equal(t, "grpc", cfg.XKMSD.Protocol)
	assert.True(t, cfg.XKMSD.TLSEnabled)
	assert.False(t, cfg.XKMSD.TLSSkipVerify)
	assert.Equal(t, "/etc/ssl/ca.pem", cfg.XKMSD.TLSCAFile)
	assert.Equal(t, "/etc/ssl/cert.pem", cfg.XKMSD.TLSCertFile)
	assert.Equal(t, "/etc/ssl/key.pem", cfg.XKMSD.TLSKeyFile)

	// TPM section.
	assert.Equal(t, "/dev/tpm1", cfg.TPM.Device)
	assert.False(t, cfg.TPM.EncryptSessions)
	assert.Equal(t, "sha384", cfg.TPM.PlatformPCRBank)

	// Password protection section.
	assert.True(t, cfg.PasswordProtection.Enabled)
	assert.Equal(t, "tpm_sealed", cfg.PasswordProtection.Mode)

	// Trust section.
	assert.Equal(t, []string{"/etc/ssl/root1.pem", "/etc/ssl/root2.pem"}, cfg.Trust.Roots)
	assert.True(t, cfg.Trust.SystemTrust)

	// Attestation section.
	assert.Equal(t, "packed", cfg.Attestation.Mode)
	assert.Equal(t, "/etc/ssl/attest-ca.pem", cfg.Attestation.CACert)
	assert.Equal(t, "/etc/ssl/attest-ca.key", cfg.Attestation.CAKey)

	// Log section.
	assert.Equal(t, "debug", cfg.Log.Level)
	assert.Equal(t, "/var/log/xkey.log", cfg.Log.File)
}

func TestMigrateCLIConfig_InvalidPath(t *testing.T) {
	cfg := DefaultConfig()
	err := migrateCLIConfig(cfg, filepath.Join(t.TempDir(), "nonexistent.yaml"))
	require.Error(t, err)
}

func TestMigrateCLIConfig_InvalidYAML(t *testing.T) {
	tmpDir := t.TempDir()
	yamlPath := filepath.Join(tmpDir, "config.yaml")

	invalidYAML := `backend:
  default: [unterminated
    : : : bad nesting
`
	require.NoError(t, os.WriteFile(yamlPath, []byte(invalidYAML), 0600))

	cfg := DefaultConfig()
	err := migrateCLIConfig(cfg, yamlPath)
	require.Error(t, err)
}

func TestMigrateCLIConfig_EmptyFile(t *testing.T) {
	tmpDir := t.TempDir()
	yamlPath := filepath.Join(tmpDir, "config.yaml")

	require.NoError(t, os.WriteFile(yamlPath, []byte(""), 0600))

	defaults := DefaultConfig()
	cfg := DefaultConfig()
	err := migrateCLIConfig(cfg, yamlPath)
	require.NoError(t, err)

	// Config should remain at defaults when the file is empty.
	assert.Equal(t, defaults.Backend.Default, cfg.Backend.Default)
	assert.Equal(t, defaults.FIDO2.Storage, cfg.FIDO2.Storage)
	assert.Equal(t, defaults.FIDO2.Attestation, cfg.FIDO2.Attestation)
	assert.Equal(t, defaults.TPM.Device, cfg.TPM.Device)
	assert.Equal(t, defaults.TPM.EncryptSessions, cfg.TPM.EncryptSessions)
	assert.Equal(t, defaults.Log.Level, cfg.Log.Level)
	assert.Equal(t, defaults.Log.File, cfg.Log.File)
}

// --------------------------------------------------------------------------
// migrateGUIConfig tests
// --------------------------------------------------------------------------

func TestMigrateGUIConfig_ThemeAndAppearance(t *testing.T) {
	tmpDir := t.TempDir()
	jsonPath := filepath.Join(tmpDir, "gui.json")

	jsonContent := `{
    "theme": "dark",
    "auto_tray": true,
    "start_minimized": true,
    "notifications": false,
    "clipboard_timeout": 45,
    "fido2_authenticator_enabled": false
}`
	require.NoError(t, os.WriteFile(jsonPath, []byte(jsonContent), 0600))

	cfg := DefaultConfig()
	err := migrateGUIConfig(cfg, jsonPath)
	require.NoError(t, err)

	assert.Equal(t, "dark", cfg.GUI.Theme)
	assert.True(t, cfg.GUI.AutoTray)
	assert.True(t, cfg.GUI.StartMinimized)
	assert.False(t, cfg.GUI.Notifications)
	assert.Equal(t, 45, cfg.GUI.ClipboardTimeout)
	assert.False(t, cfg.GUI.FIDO2AuthEnabled)
}

func TestMigrateGUIConfig_WindowSettings(t *testing.T) {
	tmpDir := t.TempDir()
	jsonPath := filepath.Join(tmpDir, "gui.json")

	jsonContent := `{
    "window_width": 1920,
    "window_height": 1080,
    "window_x": 100,
    "window_y": 50,
    "remember_position": true
}`
	require.NoError(t, os.WriteFile(jsonPath, []byte(jsonContent), 0600))

	cfg := DefaultConfig()
	err := migrateGUIConfig(cfg, jsonPath)
	require.NoError(t, err)

	assert.Equal(t, 1920, cfg.GUI.WindowWidth)
	assert.Equal(t, 1080, cfg.GUI.WindowHeight)
	assert.Equal(t, 100, cfg.GUI.WindowX)
	assert.Equal(t, 50, cfg.GUI.WindowY)
	assert.True(t, cfg.GUI.RememberPosition)
}

func TestMigrateGUIConfig_ServerSection(t *testing.T) {
	tmpDir := t.TempDir()
	jsonPath := filepath.Join(tmpDir, "gui.json")

	jsonContent := `{
    "server_address": "localhost:8443",
    "server_protocol": "grpc",
    "server_tls_enabled": true,
    "server_tls_skip_verify": false,
    "server_tls_ca_file": "/etc/ssl/ca.pem",
    "server_auto_connect": true
}`
	require.NoError(t, os.WriteFile(jsonPath, []byte(jsonContent), 0600))

	cfg := DefaultConfig()
	err := migrateGUIConfig(cfg, jsonPath)
	require.NoError(t, err)

	assert.Equal(t, "localhost:8443", cfg.GUI.Server.Address)
	assert.Equal(t, "grpc", cfg.GUI.Server.Protocol)
	assert.True(t, cfg.GUI.Server.TLSEnabled)
	assert.False(t, cfg.GUI.Server.TLSSkipVerify)
	assert.Equal(t, "/etc/ssl/ca.pem", cfg.GUI.Server.TLSCAFile)
	assert.True(t, cfg.GUI.Server.AutoConnect)
}

func TestMigrateGUIConfig_AutoUnsealSection(t *testing.T) {
	tmpDir := t.TempDir()
	jsonPath := filepath.Join(tmpDir, "gui.json")

	jsonContent := `{
    "auto_unseal_enabled": true,
    "auto_unseal_blob_id": "blob-123",
    "auto_unseal_pcrs": [0, 1, 7],
    "auto_unseal_pcr_bank": "sha256",
    "auto_unseal_policy_type": "pcr",
    "auto_unseal_policy_name": "default",
    "auto_unseal_backend": "tpm2"
}`
	require.NoError(t, os.WriteFile(jsonPath, []byte(jsonContent), 0600))

	cfg := DefaultConfig()
	err := migrateGUIConfig(cfg, jsonPath)
	require.NoError(t, err)

	assert.True(t, cfg.GUI.AutoUnseal.Enabled)
	assert.Equal(t, "blob-123", cfg.GUI.AutoUnseal.BlobID)
	assert.Equal(t, []int{0, 1, 7}, cfg.GUI.AutoUnseal.PCRs)
	assert.Equal(t, "sha256", cfg.GUI.AutoUnseal.PCRBank)
	assert.Equal(t, "pcr", cfg.GUI.AutoUnseal.PolicyType)
	assert.Equal(t, "default", cfg.GUI.AutoUnseal.PolicyName)
	assert.Equal(t, "tpm2", cfg.GUI.AutoUnseal.Backend)
}

func TestMigrateGUIConfig_StateSection(t *testing.T) {
	tmpDir := t.TempDir()
	jsonPath := filepath.Join(tmpDir, "gui.json")

	jsonContent := `{
    "setup_complete": true,
    "storage_type": "barrier",
    "barrier_initialized": true,
    "barrier_strategy": "tpm_sealed"
}`
	require.NoError(t, os.WriteFile(jsonPath, []byte(jsonContent), 0600))

	cfg := DefaultConfig()
	err := migrateGUIConfig(cfg, jsonPath)
	require.NoError(t, err)

	assert.True(t, cfg.State.SetupComplete)
	assert.Equal(t, "barrier", cfg.State.StorageType)
	assert.True(t, cfg.State.BarrierInitialized)
	assert.Equal(t, "tpm_sealed", cfg.State.BarrierStrategy)
}

func TestMigrateGUIConfig_FullConfig(t *testing.T) {
	tmpDir := t.TempDir()
	jsonPath := filepath.Join(tmpDir, "gui.json")

	jsonContent := `{
    "theme": "dark",
    "auto_tray": true,
    "start_minimized": false,
    "notifications": true,
    "clipboard_timeout": 45,
    "window_width": 1920,
    "window_height": 1080,
    "remember_position": true,
    "window_x": 100,
    "window_y": 50,
    "fido2_authenticator_enabled": true,
    "server_address": "localhost:8443",
    "server_protocol": "grpc",
    "server_tls_enabled": true,
    "server_tls_skip_verify": false,
    "server_tls_ca_file": "/etc/ssl/ca.pem",
    "server_auto_connect": true,
    "auto_unseal_enabled": true,
    "auto_unseal_blob_id": "blob-123",
    "auto_unseal_pcrs": [0, 1, 7],
    "auto_unseal_pcr_bank": "sha256",
    "auto_unseal_policy_type": "pcr",
    "auto_unseal_policy_name": "default",
    "auto_unseal_backend": "tpm2",
    "setup_complete": true,
    "storage_type": "barrier",
    "barrier_initialized": true,
    "barrier_strategy": "tpm_sealed"
}`
	require.NoError(t, os.WriteFile(jsonPath, []byte(jsonContent), 0600))

	cfg := DefaultConfig()
	err := migrateGUIConfig(cfg, jsonPath)
	require.NoError(t, err)

	// GUI appearance and behavior.
	assert.Equal(t, "dark", cfg.GUI.Theme)
	assert.True(t, cfg.GUI.AutoTray)
	assert.False(t, cfg.GUI.StartMinimized)
	assert.True(t, cfg.GUI.Notifications)
	assert.Equal(t, 45, cfg.GUI.ClipboardTimeout)
	assert.Equal(t, 1920, cfg.GUI.WindowWidth)
	assert.Equal(t, 1080, cfg.GUI.WindowHeight)
	assert.True(t, cfg.GUI.RememberPosition)
	assert.Equal(t, 100, cfg.GUI.WindowX)
	assert.Equal(t, 50, cfg.GUI.WindowY)
	assert.True(t, cfg.GUI.FIDO2AuthEnabled)

	// GUI server connection.
	assert.Equal(t, "localhost:8443", cfg.GUI.Server.Address)
	assert.Equal(t, "grpc", cfg.GUI.Server.Protocol)
	assert.True(t, cfg.GUI.Server.TLSEnabled)
	assert.False(t, cfg.GUI.Server.TLSSkipVerify)
	assert.Equal(t, "/etc/ssl/ca.pem", cfg.GUI.Server.TLSCAFile)
	assert.True(t, cfg.GUI.Server.AutoConnect)

	// GUI auto-unseal.
	assert.True(t, cfg.GUI.AutoUnseal.Enabled)
	assert.Equal(t, "blob-123", cfg.GUI.AutoUnseal.BlobID)
	assert.Equal(t, []int{0, 1, 7}, cfg.GUI.AutoUnseal.PCRs)
	assert.Equal(t, "sha256", cfg.GUI.AutoUnseal.PCRBank)
	assert.Equal(t, "pcr", cfg.GUI.AutoUnseal.PolicyType)
	assert.Equal(t, "default", cfg.GUI.AutoUnseal.PolicyName)
	assert.Equal(t, "tpm2", cfg.GUI.AutoUnseal.Backend)

	// State section.
	assert.True(t, cfg.State.SetupComplete)
	assert.Equal(t, "barrier", cfg.State.StorageType)
	assert.True(t, cfg.State.BarrierInitialized)
	assert.Equal(t, "tpm_sealed", cfg.State.BarrierStrategy)
}

func TestMigrateGUIConfig_InvalidPath(t *testing.T) {
	cfg := DefaultConfig()
	err := migrateGUIConfig(cfg, filepath.Join(t.TempDir(), "nonexistent.json"))
	require.Error(t, err)
}

func TestMigrateGUIConfig_InvalidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	jsonPath := filepath.Join(tmpDir, "gui.json")

	invalidJSON := `{"theme": "dark", "auto_tray": INVALID}`
	require.NoError(t, os.WriteFile(jsonPath, []byte(invalidJSON), 0600))

	cfg := DefaultConfig()
	err := migrateGUIConfig(cfg, jsonPath)
	require.Error(t, err)
}

// --------------------------------------------------------------------------
// fileExists tests
// --------------------------------------------------------------------------

func TestFileExists_ExistingFile(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "testfile.txt")

	require.NoError(t, os.WriteFile(filePath, []byte("content"), 0600))

	assert.True(t, fileExists(filePath))
}

func TestFileExists_NonexistentFile(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "does-not-exist.txt")

	assert.False(t, fileExists(filePath))
}

func TestFileExists_Directory(t *testing.T) {
	tmpDir := t.TempDir()
	dirPath := filepath.Join(tmpDir, "subdir")

	require.NoError(t, os.Mkdir(dirPath, 0755))

	assert.False(t, fileExists(dirPath))
}

// --------------------------------------------------------------------------
// Migrate() tests -- exercise the full Migrate() flow by redirecting HOME
// and XDG_CONFIG_HOME to temp directories with simulated legacy config files.
// --------------------------------------------------------------------------

// TestMigrate_UnifiedConfigAlreadyExists verifies that Migrate() skips
// migration when the unified config file already exists.
func TestMigrate_UnifiedConfigAlreadyExists(t *testing.T) {
	tmpDir := t.TempDir()
	configHome := filepath.Join(tmpDir, ".config")
	t.Setenv("HOME", tmpDir)
	t.Setenv("XDG_CONFIG_HOME", configHome)

	// Create the unified config so Migrate() sees it and skips.
	cfgDir := filepath.Join(configHome, "xkey")
	require.NoError(t, os.MkdirAll(cfgDir, 0700))
	cfgPath := filepath.Join(cfgDir, "xkey.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte("log:\n  level: info\n"), 0600))

	cfg, migrated, err := Migrate()
	require.NoError(t, err)
	assert.Nil(t, cfg)
	assert.False(t, migrated)
}

// TestMigrate_NoLegacyFiles verifies that Migrate() skips migration when
// no legacy config files exist and the unified config does not exist.
func TestMigrate_NoLegacyFiles(t *testing.T) {
	tmpDir := t.TempDir()
	configHome := filepath.Join(tmpDir, ".config")
	t.Setenv("HOME", tmpDir)
	t.Setenv("XDG_CONFIG_HOME", configHome)

	// No files exist at all.
	cfg, migrated, err := Migrate()
	require.NoError(t, err)
	assert.Nil(t, cfg)
	assert.False(t, migrated)
}

// TestMigrate_CLIConfigOnly verifies that Migrate() reads the old CLI YAML
// config and produces a unified config when only the CLI file exists.
func TestMigrate_CLIConfigOnly(t *testing.T) {
	tmpDir := t.TempDir()
	configHome := filepath.Join(tmpDir, ".config")
	t.Setenv("HOME", tmpDir)
	t.Setenv("XDG_CONFIG_HOME", configHome)

	// Create old CLI config at ~/.xkey/config.yaml
	cliDir := filepath.Join(tmpDir, ".xkey")
	require.NoError(t, os.MkdirAll(cliDir, 0700))
	cliYAML := `log:
  level: debug
backend:
  default: software
`
	require.NoError(t, os.WriteFile(filepath.Join(cliDir, "config.yaml"), []byte(cliYAML), 0600))

	cfg, migrated, err := Migrate()
	require.NoError(t, err)
	require.NotNil(t, cfg)
	assert.True(t, migrated)

	assert.Equal(t, "debug", cfg.Log.Level)
	assert.Equal(t, "software", cfg.Backend.Default)

	// Verify the unified config was written to disk.
	_, statErr := os.Stat(ConfigPath())
	assert.NoError(t, statErr, "unified config file should have been created")
}

// TestMigrate_GUIConfigOnly verifies that Migrate() reads the old GUI JSON
// config and produces a unified config when only the GUI file exists.
func TestMigrate_GUIConfigOnly(t *testing.T) {
	tmpDir := t.TempDir()
	configHome := filepath.Join(tmpDir, ".config")
	t.Setenv("HOME", tmpDir)
	t.Setenv("XDG_CONFIG_HOME", configHome)

	// Create old GUI config at ~/.config/xkey/gui.json
	guiDir := filepath.Join(configHome, "xkey")
	require.NoError(t, os.MkdirAll(guiDir, 0700))
	guiJSON := `{
    "theme": "dark",
    "window_width": 1920,
    "window_height": 1080,
    "clipboard_timeout": 60,
    "notifications": true,
    "auto_tray": true,
    "setup_complete": true,
    "storage_type": "barrier"
}`
	require.NoError(t, os.WriteFile(filepath.Join(guiDir, "gui.json"), []byte(guiJSON), 0600))

	cfg, migrated, err := Migrate()
	require.NoError(t, err)
	require.NotNil(t, cfg)
	assert.True(t, migrated)

	assert.Equal(t, "dark", cfg.GUI.Theme)
	assert.Equal(t, 1920, cfg.GUI.WindowWidth)
	assert.Equal(t, 1080, cfg.GUI.WindowHeight)
	assert.True(t, cfg.State.SetupComplete)
	assert.Equal(t, "barrier", cfg.State.StorageType)
}

// TestMigrate_BothLegacyFiles verifies that Migrate() merges both the old
// CLI YAML and old GUI JSON when both exist.
func TestMigrate_BothLegacyFiles(t *testing.T) {
	tmpDir := t.TempDir()
	configHome := filepath.Join(tmpDir, ".config")
	t.Setenv("HOME", tmpDir)
	t.Setenv("XDG_CONFIG_HOME", configHome)

	// Create old CLI config.
	cliDir := filepath.Join(tmpDir, ".xkey")
	require.NoError(t, os.MkdirAll(cliDir, 0700))
	cliYAML := `log:
  level: warn
backend:
  default: software
`
	require.NoError(t, os.WriteFile(filepath.Join(cliDir, "config.yaml"), []byte(cliYAML), 0600))

	// Create old GUI config.
	guiDir := filepath.Join(configHome, "xkey")
	require.NoError(t, os.MkdirAll(guiDir, 0700))
	guiJSON := `{
    "theme": "dark",
    "window_width": 1920,
    "window_height": 1080,
    "clipboard_timeout": 45,
    "notifications": false,
    "auto_tray": true
}`
	require.NoError(t, os.WriteFile(filepath.Join(guiDir, "gui.json"), []byte(guiJSON), 0600))

	cfg, migrated, err := Migrate()
	require.NoError(t, err)
	require.NotNil(t, cfg)
	assert.True(t, migrated)

	// CLI values.
	assert.Equal(t, "warn", cfg.Log.Level)
	assert.Equal(t, "software", cfg.Backend.Default)

	// GUI values.
	assert.Equal(t, "dark", cfg.GUI.Theme)
	assert.Equal(t, 1920, cfg.GUI.WindowWidth)
	assert.Equal(t, 1080, cfg.GUI.WindowHeight)
	assert.Equal(t, 45, cfg.GUI.ClipboardTimeout)
	assert.False(t, cfg.GUI.Notifications)
	assert.True(t, cfg.GUI.AutoTray)
}

// TestMigrate_CLIConfigInvalidYAML verifies that Migrate() returns
// ErrConfigMigrationFailed when the CLI config has invalid YAML.
func TestMigrate_CLIConfigInvalidYAML(t *testing.T) {
	tmpDir := t.TempDir()
	configHome := filepath.Join(tmpDir, ".config")
	t.Setenv("HOME", tmpDir)
	t.Setenv("XDG_CONFIG_HOME", configHome)

	// Create invalid old CLI config.
	cliDir := filepath.Join(tmpDir, ".xkey")
	require.NoError(t, os.MkdirAll(cliDir, 0700))
	invalidYAML := `backend:
  default: [invalid
`
	require.NoError(t, os.WriteFile(filepath.Join(cliDir, "config.yaml"), []byte(invalidYAML), 0600))

	cfg, migrated, err := Migrate()
	assert.Nil(t, cfg)
	assert.False(t, migrated)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrConfigMigrationFailed),
		"expected ErrConfigMigrationFailed, got %v", err)
}

// TestMigrate_GUIConfigInvalidJSON verifies that Migrate() returns
// ErrConfigMigrationFailed when the GUI config has invalid JSON.
func TestMigrate_GUIConfigInvalidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	configHome := filepath.Join(tmpDir, ".config")
	t.Setenv("HOME", tmpDir)
	t.Setenv("XDG_CONFIG_HOME", configHome)

	// Create invalid old GUI config.
	guiDir := filepath.Join(configHome, "xkey")
	require.NoError(t, os.MkdirAll(guiDir, 0700))
	invalidJSON := `{"theme": INVALID}`
	require.NoError(t, os.WriteFile(filepath.Join(guiDir, "gui.json"), []byte(invalidJSON), 0600))

	cfg, migrated, err := Migrate()
	assert.Nil(t, cfg)
	assert.False(t, migrated)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrConfigMigrationFailed),
		"expected ErrConfigMigrationFailed, got %v", err)
}

// --------------------------------------------------------------------------
// oldCLIConfigPath and oldGUIConfigPath tests
// --------------------------------------------------------------------------

// TestOldCLIConfigPath_WithValidHome verifies oldCLIConfigPath returns an
// absolute path under HOME when HOME is set.
func TestOldCLIConfigPath_WithValidHome(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	path := oldCLIConfigPath()
	expected := filepath.Join(tmpDir, ".xkey", "config.yaml")
	assert.Equal(t, expected, path)
}

// TestOldCLIConfigPath_WithEmptyHome verifies oldCLIConfigPath returns a
// relative fallback path when HOME is empty.
func TestOldCLIConfigPath_WithEmptyHome(t *testing.T) {
	t.Setenv("HOME", "")

	path := oldCLIConfigPath()
	expected := filepath.Join(".xkey", "config.yaml")
	assert.Equal(t, expected, path)
}

// TestOldGUIConfigPath_WithValidConfigDir verifies oldGUIConfigPath returns
// the path under XDG_CONFIG_HOME when it is set.
func TestOldGUIConfigPath_WithValidConfigDir(t *testing.T) {
	tmpDir := t.TempDir()
	configHome := filepath.Join(tmpDir, ".config")
	t.Setenv("HOME", tmpDir)
	t.Setenv("XDG_CONFIG_HOME", configHome)

	path := oldGUIConfigPath()
	expected := filepath.Join(configHome, "xkey", "gui.json")
	assert.Equal(t, expected, path)
}

// TestOldGUIConfigPath_FallbackToHomeDotConfig verifies oldGUIConfigPath
// falls back to $HOME/.config when XDG_CONFIG_HOME is unset.
func TestOldGUIConfigPath_FallbackToHomeDotConfig(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)
	t.Setenv("XDG_CONFIG_HOME", "")

	path := oldGUIConfigPath()
	// When XDG_CONFIG_HOME is empty, os.UserConfigDir() uses $HOME/.config on Linux.
	assert.Contains(t, path, "xkey")
	assert.Contains(t, path, "gui.json")
}

// TestOldGUIConfigPath_BothFallbacks verifies oldGUIConfigPath returns a
// relative fallback when both HOME and XDG_CONFIG_HOME are empty.
func TestOldGUIConfigPath_BothFallbacks(t *testing.T) {
	t.Setenv("HOME", "")
	t.Setenv("XDG_CONFIG_HOME", "")

	path := oldGUIConfigPath()
	expected := filepath.Join(".config", "xkey", "gui.json")
	assert.Equal(t, expected, path)
}

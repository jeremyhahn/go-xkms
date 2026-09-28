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
	"strings"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/xhome"
)

func TestConfigDir_ReturnsNonEmptyStringEndingWithXkey(t *testing.T) {
	dir := ConfigDir()
	assert.NotEmpty(t, dir)
	assert.True(t, strings.HasSuffix(dir, "xkey"),
		"ConfigDir() should end with %q, got %q", "xkey", dir)
}

func TestConfigDir_ContainsConfigParent(t *testing.T) {
	dir := ConfigDir()
	// On Linux with XDG, ConfigDir should contain ".config" as a parent segment.
	// On other platforms the exact parent varies, but the suffix is always "xkey".
	assert.Contains(t, dir, string(filepath.Separator))
}

func TestConfigPath_ReturnsPathEndingWithXkeyYaml(t *testing.T) {
	p := ConfigPath()
	assert.True(t, strings.HasSuffix(p, "xkey.yaml"),
		"ConfigPath() should end with %q, got %q", "xkey.yaml", p)
}

func TestConfigPath_ContainsConfigDir(t *testing.T) {
	p := ConfigPath()
	dir := ConfigDir()
	assert.True(t, strings.HasPrefix(p, dir),
		"ConfigPath() %q should start with ConfigDir() %q", p, dir)
}

func TestSystemConfigPath_ReturnsEtcXkeyPath(t *testing.T) {
	p := SystemConfigPath()
	assert.Equal(t, "/etc/xkey/xkey.yaml", p)
}

func TestSystemConfigPath_IsAbsolute(t *testing.T) {
	p := SystemConfigPath()
	assert.True(t, filepath.IsAbs(p), "SystemConfigPath() should be absolute, got %q", p)
}

func TestLoadFromPath_ValidFile(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "xkey.yaml")

	yamlContent := `backend:
  default: software
log:
  level: debug
gui:
  theme: dark
  window_width: 1280
  window_height: 800
  clipboard_timeout: 30
`
	require.NoError(t, os.WriteFile(cfgPath, []byte(yamlContent), 0600))

	cfg, err := LoadFromPath(cfgPath)
	require.NoError(t, err)
	require.NotNil(t, cfg)

	assert.Equal(t, "software", cfg.Backend.Default)
	assert.Equal(t, "debug", cfg.Log.Level)
	assert.Equal(t, "dark", cfg.GUI.Theme)
	assert.Equal(t, 1280, cfg.GUI.WindowWidth)
	assert.Equal(t, 800, cfg.GUI.WindowHeight)
	assert.Equal(t, 30, cfg.GUI.ClipboardTimeout)
}

func TestLoadFromPath_FileNotFound(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "nonexistent", "xkey.yaml")

	cfg, err := LoadFromPath(cfgPath)
	assert.Nil(t, cfg)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrConfigNotFound),
		"expected ErrConfigNotFound, got %v", err)
}

func TestLoadFromPath_InvalidYAML(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "xkey.yaml")

	invalidYAML := `
backend:
  default: [unterminated
    this is not: valid: yaml: at: all
`
	require.NoError(t, os.WriteFile(cfgPath, []byte(invalidYAML), 0600))

	cfg, err := LoadFromPath(cfgPath)
	assert.Nil(t, cfg)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrConfigLoadFailed),
		"expected ErrConfigLoadFailed, got %v", err)
}

func TestLoadFromPath_InvalidConfig(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "xkey.yaml")

	// "banana" is not a valid log level
	yamlContent := `log:
  level: banana
`
	require.NoError(t, os.WriteFile(cfgPath, []byte(yamlContent), 0600))

	cfg, err := LoadFromPath(cfgPath)
	assert.Nil(t, cfg)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrConfigInvalid),
		"expected ErrConfigInvalid, got %v", err)
}

func TestLoadFromPath_PartialConfig(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "xkey.yaml")

	// Only set the log section; everything else should come from defaults.
	yamlContent := `log:
  level: warn
`
	require.NoError(t, os.WriteFile(cfgPath, []byte(yamlContent), 0600))

	cfg, err := LoadFromPath(cfgPath)
	require.NoError(t, err)
	require.NotNil(t, cfg)

	// Explicit value from the file.
	assert.Equal(t, "warn", cfg.Log.Level)

	// Defaults should be applied for unspecified sections.
	defaults := DefaultConfig()
	assert.Equal(t, defaults.Backend.Default, cfg.Backend.Default)
	assert.Equal(t, defaults.GUI.WindowWidth, cfg.GUI.WindowWidth)
	assert.Equal(t, defaults.GUI.WindowHeight, cfg.GUI.WindowHeight)
	assert.Equal(t, defaults.GUI.ClipboardTimeout, cfg.GUI.ClipboardTimeout)
	assert.Equal(t, defaults.GUI.Theme, cfg.GUI.Theme)
	assert.Equal(t, defaults.TPM.Device, cfg.TPM.Device)
}

func TestLoadFromPath_FullConfig(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "xkey.yaml")

	yamlContent := `backend:
  default: tpm2
  tpm2:
    device: /dev/tpmrm0
    simulator: true
    hash: sha384
fido2:
  storage: file
  attestation: packed
  device_name: TestKey
  always_uv: true
  resident_key: true
piv:
  backend: pkcs11
  storage: pkcs11
  storage_path: /var/lib/xkey/piv
  tpm_device: /dev/piv-tpm
  pkcs11_library: /usr/lib/softhsm/libsofthsm2.so
  pkcs11_token: piv-token
oath:
  algorithm: sha256
  digits: 8
  period: 60
phone:
  backend: bluetooth
  server_address: 127.0.0.1:9000
  server_protocol: grpc
  server_tls_enabled: true
xkmsd:
  address: localhost:8443
  protocol: grpc
  tls_enabled: true
tpm:
  device: /dev/tpmrm0
  encrypt_sessions: true
  platform_pcr_bank: sha256
  srk_handle: 2164260865
password_protection:
  enabled: true
  mode: barrier
trust:
  roots:
    - /etc/xkey/roots/ca.pem
  system_trust: true
attestation:
  mode: self
  ca_cert: /tmp/ca.pem
  ca_key: /tmp/ca.key
log:
  level: trace
  file: /tmp/xkey.log
gui:
  theme: dark
  auto_tray: false
  start_minimized: true
  notifications: false
  clipboard_timeout: 60
  window_width: 1920
  window_height: 1080
  remember_position: true
  window_x: 100
  window_y: 200
  fido2_authenticator_enabled: false
  server:
    address: 10.0.0.1:443
    protocol: rest
    tls_enabled: true
    tls_skip_verify: false
    auto_connect: true
  auto_unseal:
    enabled: true
    blob_id: myblob
    pcrs: [0, 1, 7]
    pcr_bank: sha256
    policy_type: pcr
    policy_name: boot-policy
    backend: tpm2
state:
  setup_complete: true
  storage_type: barrier
  barrier_initialized: true
  barrier_strategy: tpm-pcr
`
	require.NoError(t, os.WriteFile(cfgPath, []byte(yamlContent), 0600))

	cfg, err := LoadFromPath(cfgPath)
	require.NoError(t, err)
	require.NotNil(t, cfg)

	// Backend
	assert.Equal(t, "tpm2", cfg.Backend.Default)
	assert.Equal(t, "/dev/tpmrm0", cfg.Backend.TPM2.Device)
	assert.True(t, cfg.Backend.TPM2.Simulator)
	assert.Equal(t, "sha384", cfg.Backend.TPM2.Hash)

	// FIDO2
	assert.Equal(t, "file", cfg.FIDO2.Storage)
	assert.Equal(t, "packed", cfg.FIDO2.Attestation)
	assert.Equal(t, "TestKey", cfg.FIDO2.DeviceName)
	assert.True(t, cfg.FIDO2.AlwaysUV)
	assert.True(t, cfg.FIDO2.ResidentKey)

	// PIV
	assert.Equal(t, "pkcs11", cfg.PIV.Backend)
	assert.Equal(t, "pkcs11", cfg.PIV.Storage)
	assert.Equal(t, "/var/lib/xkey/piv", cfg.PIV.StoragePath)
	assert.Equal(t, "/dev/piv-tpm", cfg.PIV.TPMDevice)
	assert.Equal(t, "/usr/lib/softhsm/libsofthsm2.so", cfg.PIV.PKCS11Library)
	assert.Equal(t, "piv-token", cfg.PIV.PKCS11Token)

	// OATH
	assert.Equal(t, "sha256", cfg.OATH.Algorithm)
	assert.Equal(t, 8, cfg.OATH.Digits)
	assert.Equal(t, 60, cfg.OATH.Period)

	// Phone
	assert.Equal(t, "bluetooth", cfg.Phone.Backend)
	assert.Equal(t, "127.0.0.1:9000", cfg.Phone.ServerAddress)
	assert.True(t, cfg.Phone.ServerTLSEnabled)

	// XKMSD
	assert.Equal(t, "localhost:8443", cfg.XKMSD.Address)
	assert.Equal(t, "grpc", cfg.XKMSD.Protocol)
	assert.True(t, cfg.XKMSD.TLSEnabled)

	// TPM
	assert.Equal(t, "/dev/tpmrm0", cfg.TPM.Device)
	assert.True(t, cfg.TPM.EncryptSessions)
	assert.Equal(t, "sha256", cfg.TPM.PlatformPCRBank)
	assert.Equal(t, uint32(2164260865), cfg.TPM.SRKHandle)

	// PasswordProtection
	assert.True(t, cfg.PasswordProtection.Enabled)
	assert.Equal(t, "barrier", cfg.PasswordProtection.Mode)

	// Trust
	assert.Equal(t, []string{"/etc/xkey/roots/ca.pem"}, cfg.Trust.Roots)
	assert.True(t, cfg.Trust.SystemTrust)

	// Attestation
	assert.Equal(t, "self", cfg.Attestation.Mode)
	assert.Equal(t, "/tmp/ca.pem", cfg.Attestation.CACert)
	assert.Equal(t, "/tmp/ca.key", cfg.Attestation.CAKey)

	// Log
	assert.Equal(t, "trace", cfg.Log.Level)
	assert.Equal(t, "/tmp/xkey.log", cfg.Log.File)

	// GUI
	assert.Equal(t, "dark", cfg.GUI.Theme)
	assert.False(t, cfg.GUI.AutoTray)
	assert.True(t, cfg.GUI.StartMinimized)
	assert.False(t, cfg.GUI.Notifications)
	assert.Equal(t, 60, cfg.GUI.ClipboardTimeout)
	assert.Equal(t, 1920, cfg.GUI.WindowWidth)
	assert.Equal(t, 1080, cfg.GUI.WindowHeight)
	assert.True(t, cfg.GUI.RememberPosition)
	assert.Equal(t, 100, cfg.GUI.WindowX)
	assert.Equal(t, 200, cfg.GUI.WindowY)
	assert.False(t, cfg.GUI.FIDO2AuthEnabled)

	// GUI.Server
	assert.Equal(t, "10.0.0.1:443", cfg.GUI.Server.Address)
	assert.Equal(t, "rest", cfg.GUI.Server.Protocol)
	assert.True(t, cfg.GUI.Server.TLSEnabled)
	assert.False(t, cfg.GUI.Server.TLSSkipVerify)
	assert.True(t, cfg.GUI.Server.AutoConnect)

	// GUI.AutoUnseal
	assert.True(t, cfg.GUI.AutoUnseal.Enabled)
	assert.Equal(t, "myblob", cfg.GUI.AutoUnseal.BlobID)
	assert.Equal(t, []int{0, 1, 7}, cfg.GUI.AutoUnseal.PCRs)
	assert.Equal(t, "sha256", cfg.GUI.AutoUnseal.PCRBank)
	assert.Equal(t, "pcr", cfg.GUI.AutoUnseal.PolicyType)
	assert.Equal(t, "boot-policy", cfg.GUI.AutoUnseal.PolicyName)
	assert.Equal(t, "tpm2", cfg.GUI.AutoUnseal.Backend)

	// State
	assert.True(t, cfg.State.SetupComplete)
	assert.Equal(t, "barrier", cfg.State.StorageType)
	assert.True(t, cfg.State.BarrierInitialized)
	assert.Equal(t, "tpm-pcr", cfg.State.BarrierStrategy)
}

// TestLoadFromPath_EnvOverride verifies that environment variable overrides
// are applied when loading a config file. LoadFromPath creates its own viper
// instance with XKEY_ env prefix binding, so setting XKEY_LOG_LEVEL should
// override the value from the file.
// TestLoadFromPath_EnvOverride proves that an XKEY_ environment variable
// reaches its leaf whether the section is present in the file, absent from
// it, or defaulted, and whatever the leaf's type (#140).
func TestLoadFromPath_EnvOverride(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "xkey.yaml")

	yamlContent := `xkmsd:
  protocol: grpc
  address: file.example.com:9443
log:
  level: info
`
	require.NoError(t, os.WriteFile(cfgPath, []byte(yamlContent), 0600))

	t.Setenv("XKEY_XKMSD_ADDRESS", "env.example.com:9443")
	t.Setenv("XKEY_LOG_LEVEL", "debug")
	t.Setenv("XKEY_TPM_DEVICE", "/dev/env-tpm")
	t.Setenv("XKEY_FIDO2_ALWAYS_UV", "true")
	t.Setenv("XKEY_GUI_CLIPBOARD_TIMEOUT", "5")
	t.Setenv("XKEY_TRUST_ROOTS", "a.pem,b.pem")
	t.Setenv("XKEY_GUI_SERVER_ADDRESS", "gui.example.com:8443")
	t.Setenv("XKEY_BACKEND_TPM2_DEVICE", "/dev/env-backend-tpm")
	t.Setenv("XKEY_POLICY_MIN_PIN_LENGTH", "8")
	t.Setenv("XKEY_GUI_AUTO_UNSEAL_PCRS", "0,7")

	cfg, err := LoadFromPath(cfgPath)
	require.NoError(t, err)
	require.NotNil(t, cfg)

	assert.Equal(t, "env.example.com:9443", cfg.XKMSD.Address, "environment must win over the file")
	assert.Equal(t, "grpc", cfg.XKMSD.Protocol, "a file key the environment does not name keeps its file value")
	assert.Equal(t, "debug", cfg.Log.Level, "environment must win over the file in a present section")
	assert.Equal(t, "/dev/env-tpm", cfg.TPM.Device, "environment must win over the default in an absent section")
	assert.True(t, cfg.FIDO2.AlwaysUV, "a bool leaf is settable")
	assert.Equal(t, 5, cfg.GUI.ClipboardTimeout, "an int leaf is settable")
	assert.Equal(t, []string{"a.pem", "b.pem"}, cfg.Trust.Roots, "a list of scalars splits on commas")
	assert.Equal(t, "gui.example.com:8443", cfg.GUI.Server.Address, "a leaf two sections deep is settable")
	assert.Equal(t, "/dev/env-backend-tpm", cfg.Backend.TPM2.Device, "a nested sub-section leaf is settable")
	assert.Equal(t, 8, cfg.Policy.MinPINLength, "a policy leaf is settable")
	assert.Equal(t, []int{0, 7}, cfg.GUI.AutoUnseal.PCRs, "a list of ints splits on commas")

	assert.Equal(t, "/dev/tpmrm0", DefaultConfig().TPM.Device, "the probe value must differ from the default")
}

// TestLoadFromPath_EnvOverride_EmptyValueIsUnset proves that an environment
// variable set to the empty string does not clobber the file value: an empty
// variable is the same as an absent one.
func TestLoadFromPath_EnvOverride_EmptyValueIsUnset(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "xkey.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte("xkmsd:\n  address: file.example.com:9443\n"), 0600))

	t.Setenv("XKEY_XKMSD_ADDRESS", "")

	cfg, err := LoadFromPath(cfgPath)
	require.NoError(t, err)
	assert.Equal(t, "file.example.com:9443", cfg.XKMSD.Address)
}

// TestLoadFromPath_EnvOverride_InvalidValueIsRejected proves that a value
// supplied by the environment goes through the same validation as one from
// the file.
func TestLoadFromPath_EnvOverride_InvalidValueIsRejected(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "xkey.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte("log:\n  level: info\n"), 0600))

	t.Setenv("XKEY_LOG_LEVEL", "shouting")

	cfg, err := LoadFromPath(cfgPath)
	require.Error(t, err)
	assert.Nil(t, cfg)
	assert.ErrorIs(t, err, ErrConfigInvalid)
	assert.Contains(t, err.Error(), "log.level")
}

// TestLoadFromPath_EnvOverride_CompositeLeafIsRejected proves that a variable
// set for a key one variable cannot express (a map, a list of objects) fails
// the load with a typed error rather than being silently ignored.
func TestLoadFromPath_EnvOverride_CompositeLeafIsRejected(t *testing.T) {
	for _, envName := range []string{"XKEY_FIDO2_EXTENSIONS", "XKEY_BACKENDS_LOCAL", "XKEY_BACKENDS_REMOTE", "XKEY_BACKENDS_DEFAULTS"} {
		t.Run(envName, func(t *testing.T) {
			tmpDir := t.TempDir()
			cfgPath := filepath.Join(tmpDir, "xkey.yaml")
			require.NoError(t, os.WriteFile(cfgPath, []byte("log:\n  level: info\n"), 0600))

			t.Setenv(envName, "not-a-map")

			cfg, err := LoadFromPath(cfgPath)
			require.Error(t, err)
			assert.Nil(t, cfg)
			assert.ErrorIs(t, err, ErrConfigLoadFailed)
		})
	}
}

// TestLoadFromPath_PIVEnvOverride proves the piv.* leaves registered by
// registerConfigKeys are reachable through XKEY_PIV_* the same way every
// other section is: the environment wins over the file, and a key the file
// does not name is still settable from an unconfigured default (go-xkms#871).
func TestLoadFromPath_PIVEnvOverride(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "xkey.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte("piv:\n  backend: software\n  storage_path: /file/path\n"), 0600))

	t.Setenv("XKEY_PIV_BACKEND", "tpm2")
	t.Setenv("XKEY_PIV_TPM_DEVICE", "/dev/env-piv-tpm")

	cfg, err := LoadFromPath(cfgPath)
	require.NoError(t, err)
	assert.Equal(t, "tpm2", cfg.PIV.Backend, "environment must win over the file")
	assert.Equal(t, "/file/path", cfg.PIV.StoragePath, "a file key the environment does not name keeps its file value")
	assert.Equal(t, "/dev/env-piv-tpm", cfg.PIV.TPMDevice, "environment must win over the default in an absent key")
}

// TestLoadFromPath_PIVInvalidBackendIsRejected proves piv.backend goes
// through Validate whether it came from a file or the environment.
func TestLoadFromPath_PIVInvalidBackendIsRejected(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "xkey.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte("piv:\n  backend: quantum\n"), 0600))

	cfg, err := LoadFromPath(cfgPath)
	require.Error(t, err)
	assert.Nil(t, cfg)
	assert.ErrorIs(t, err, ErrConfigInvalid)
	assert.Contains(t, err.Error(), "piv.backend")
}

// TestLoadFromPath_PIVInvalidStorageIsRejected mirrors
// TestLoadFromPath_PIVInvalidBackendIsRejected for piv.storage.
func TestLoadFromPath_PIVInvalidStorageIsRejected(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "xkey.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte("piv:\n  storage: floppy\n"), 0600))

	cfg, err := LoadFromPath(cfgPath)
	require.Error(t, err)
	assert.Nil(t, cfg)
	assert.ErrorIs(t, err, ErrConfigInvalid)
	assert.Contains(t, err.Error(), "piv.storage")
}

func TestIsConfigNotFoundError_WithOsErrNotExist(t *testing.T) {
	assert.True(t, isConfigNotFoundError(os.ErrNotExist))
}

func TestIsConfigNotFoundError_WithWrappedOsErrNotExist(t *testing.T) {
	wrapped := &os.PathError{Op: "open", Path: "/no/such/file", Err: os.ErrNotExist}
	assert.True(t, isConfigNotFoundError(wrapped))
}

func TestIsConfigNotFoundError_WithOtherError(t *testing.T) {
	assert.False(t, isConfigNotFoundError(errors.New("some other error")))
}

func TestIsConfigNotFoundError_WithPermissionDenied(t *testing.T) {
	assert.False(t, isConfigNotFoundError(os.ErrPermission))
}

func TestLoadFromPath_EmptyFile(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "xkey.yaml")

	// An empty YAML file should parse cleanly; all fields get defaults.
	require.NoError(t, os.WriteFile(cfgPath, []byte(""), 0600))

	cfg, err := LoadFromPath(cfgPath)
	require.NoError(t, err)
	require.NotNil(t, cfg)

	defaults := DefaultConfig()
	assert.Equal(t, defaults.Backend.Default, cfg.Backend.Default)
	assert.Equal(t, defaults.Log.Level, cfg.Log.Level)
	assert.Equal(t, defaults.GUI.WindowWidth, cfg.GUI.WindowWidth)
}

func TestLoadFromPath_InvalidBackend(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "xkey.yaml")

	yamlContent := `backend:
  default: nonexistent_backend
`
	require.NoError(t, os.WriteFile(cfgPath, []byte(yamlContent), 0600))

	cfg, err := LoadFromPath(cfgPath)
	assert.Nil(t, cfg)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrConfigInvalid),
		"expected ErrConfigInvalid for invalid backend, got %v", err)
}

// --------------------------------------------------------------------------
// Load() tests -- exercise the full Load() path by redirecting HOME and
// XDG_CONFIG_HOME to temp directories so we never touch real config files.
// --------------------------------------------------------------------------

// TestLoad_NoConfigFilesReturnsDefaults verifies that Load() returns a valid
// default config when neither user config nor system config exists.
func TestLoad_NoConfigFilesReturnsDefaults(t *testing.T) {
	tmpDir := t.TempDir()

	// Redirect HOME to an empty temp directory so ConfigPath() and
	// SystemConfigPath() point to nonexistent files.
	t.Setenv("HOME", tmpDir)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(tmpDir, ".config"))

	cfg, err := Load()
	require.NoError(t, err)
	require.NotNil(t, cfg)

	defaults := DefaultConfig()
	assert.Equal(t, defaults.Backend.Default, cfg.Backend.Default)
	assert.Equal(t, defaults.Log.Level, cfg.Log.Level)
	assert.Equal(t, defaults.GUI.WindowWidth, cfg.GUI.WindowWidth)
	assert.Equal(t, defaults.GUI.WindowHeight, cfg.GUI.WindowHeight)
}

// TestLoad_NoConfigFiles_EnvironmentStillApplies proves that with no user
// and no system config file, an XKEY_ variable still overrides the default:
// the first-run path goes through viper like every other path.
func TestLoad_NoConfigFiles_EnvironmentStillApplies(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(tmpDir, ".config"))
	t.Setenv("XKEY_LOG_LEVEL", "debug")
	t.Setenv("XKEY_XKMSD_ADDRESS", "env.example.com:9443")

	cfg, err := Load()
	require.NoError(t, err)
	assert.Equal(t, "debug", cfg.Log.Level)
	assert.Equal(t, "env.example.com:9443", cfg.XKMSD.Address)
	assert.Equal(t, DefaultConfig().TPM.Device, cfg.TPM.Device, "an unset leaf keeps its default")
}

// TestLoad_NoConfigFiles_InvalidEnvironmentIsRejected proves that the
// first-run path validates an environment value like a file value.
func TestLoad_NoConfigFiles_InvalidEnvironmentIsRejected(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(tmpDir, ".config"))
	t.Setenv("XKEY_LOG_LEVEL", "shouting")

	cfg, err := Load()
	require.Error(t, err)
	assert.Nil(t, cfg)
	assert.ErrorIs(t, err, ErrConfigInvalid)
}

// TestLoadFromHome_NoConfigFiles_EnvironmentStillApplies proves the same for
// the home-directory loader, valid and invalid.
func TestLoadFromHome_NoConfigFiles_EnvironmentStillApplies(t *testing.T) {
	home := &xhome.Home{Root: t.TempDir()}
	t.Setenv("XKEY_LOG_LEVEL", "debug")

	cfg, err := LoadFromHome(home)
	require.NoError(t, err)
	assert.Equal(t, "debug", cfg.Log.Level)

	t.Setenv("XKEY_LOG_LEVEL", "shouting")
	cfg, err = LoadFromHome(home)
	require.Error(t, err)
	assert.Nil(t, cfg)
	assert.ErrorIs(t, err, ErrConfigInvalid)
}

// TestLoad_UserConfigExists verifies that Load() reads the user config file
// from ConfigPath() when it exists.
func TestLoad_UserConfigExists(t *testing.T) {
	tmpDir := t.TempDir()
	configHome := filepath.Join(tmpDir, ".config")
	t.Setenv("HOME", tmpDir)
	t.Setenv("XDG_CONFIG_HOME", configHome)

	// Create the user config file at the expected path.
	cfgDir := filepath.Join(configHome, "xkey")
	require.NoError(t, os.MkdirAll(cfgDir, 0700))

	yamlContent := `log:
  level: debug
gui:
  window_width: 1024
  window_height: 768
  clipboard_timeout: 30
`
	cfgPath := filepath.Join(cfgDir, "xkey.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte(yamlContent), 0600))

	cfg, err := Load()
	require.NoError(t, err)
	require.NotNil(t, cfg)

	assert.Equal(t, "debug", cfg.Log.Level)
}

// TestLoad_UserConfigInvalidYAML verifies that Load() returns
// ErrConfigLoadFailed when the user config file exists but has invalid YAML.
func TestLoad_UserConfigInvalidYAML(t *testing.T) {
	tmpDir := t.TempDir()
	configHome := filepath.Join(tmpDir, ".config")
	t.Setenv("HOME", tmpDir)
	t.Setenv("XDG_CONFIG_HOME", configHome)

	cfgDir := filepath.Join(configHome, "xkey")
	require.NoError(t, os.MkdirAll(cfgDir, 0700))

	invalidYAML := `backend:
  default: [unterminated
`
	cfgPath := filepath.Join(cfgDir, "xkey.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte(invalidYAML), 0600))

	cfg, err := Load()
	assert.Nil(t, cfg)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrConfigLoadFailed),
		"expected ErrConfigLoadFailed, got %v", err)
}

// TestLoad_UserConfigInvalidValues verifies that Load() returns
// ErrConfigInvalid when the user config file has invalid values.
func TestLoad_UserConfigInvalidValues(t *testing.T) {
	tmpDir := t.TempDir()
	configHome := filepath.Join(tmpDir, ".config")
	t.Setenv("HOME", tmpDir)
	t.Setenv("XDG_CONFIG_HOME", configHome)

	cfgDir := filepath.Join(configHome, "xkey")
	require.NoError(t, os.MkdirAll(cfgDir, 0700))

	yamlContent := `log:
  level: banana
`
	cfgPath := filepath.Join(cfgDir, "xkey.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte(yamlContent), 0600))

	cfg, err := Load()
	assert.Nil(t, cfg)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrConfigInvalid),
		"expected ErrConfigInvalid, got %v", err)
}

// --------------------------------------------------------------------------
// ConfigDir() fallback path tests
// --------------------------------------------------------------------------

// TestConfigDir_FallbackToHomeDotConfig verifies that when XDG_CONFIG_HOME
// is unset and os.UserConfigDir() relies on HOME, the result still ends
// with xkey as the final path component.
func TestConfigDir_FallbackToHomeDotConfig(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)
	// Clear XDG_CONFIG_HOME so os.UserConfigDir() falls through to HOME/.config
	t.Setenv("XDG_CONFIG_HOME", "")

	dir := ConfigDir()
	assert.NotEmpty(t, dir)
	assert.True(t, strings.HasSuffix(dir, "xkey"),
		"ConfigDir() should end with 'xkey', got %q", dir)
}

// TestConfigDir_BothHomeFallbacks verifies ConfigDir() returns a relative
// path fallback when both HOME and XDG_CONFIG_HOME are invalid. On Linux,
// os.UserConfigDir() uses $XDG_CONFIG_HOME or $HOME/.config. When HOME
// is empty, os.UserConfigDir fails. os.UserHomeDir also fails if HOME is empty.
// This exercises the innermost fallback branch (line 38).
func TestConfigDir_BothHomeFallbacks(t *testing.T) {
	t.Setenv("HOME", "")
	t.Setenv("XDG_CONFIG_HOME", "")

	dir := ConfigDir()
	assert.NotEmpty(t, dir)
	// When both fail, should return the relative fallback: .config/xkey
	assert.True(t, strings.HasSuffix(dir, "xkey"),
		"ConfigDir() should end with 'xkey', got %q", dir)
	assert.Equal(t, filepath.Join(".config", configDirName), dir)
}

// --------------------------------------------------------------------------
// isConfigNotFoundError -- cover the ViperConfigFileNotFoundError branch
// --------------------------------------------------------------------------

func TestIsConfigNotFoundError_WithViperNotFoundError(t *testing.T) {
	// viper.ConfigFileNotFoundError has unexported fields (name, locations),
	// so we use a zero-value struct literal. The errors.As type assertion
	// in isConfigNotFoundError only checks the type, not field values.
	viperErr := viper.ConfigFileNotFoundError{}
	assert.True(t, isConfigNotFoundError(viperErr),
		"isConfigNotFoundError should return true for viper.ConfigFileNotFoundError")
}

// --------------------------------------------------------------------------
// ComputePolicyHMAC -- nil salt edge case
// --------------------------------------------------------------------------

func TestComputePolicyHMAC_NilSalt(t *testing.T) {
	policy := testPolicy()

	mac, err := ComputePolicyHMAC(policy, "some-pin", nil)
	assert.Nil(t, mac)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrPolicyKeyDerivationFailed),
		"expected ErrPolicyKeyDerivationFailed for nil salt, got %v", err)
}

// TestDeriveHMACKey_NilSalt verifies that deriveHMACKey rejects nil salt
// the same way it rejects empty salt.
func TestDeriveHMACKey_NilSalt(t *testing.T) {
	key, err := deriveHMACKey("valid-pin", nil)
	assert.Nil(t, key)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrPolicyKeyDerivationFailed),
		"expected ErrPolicyKeyDerivationFailed for nil salt, got %v", err)
}

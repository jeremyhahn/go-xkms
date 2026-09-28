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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkeyconfig "github.com/jeremyhahn/go-xkms/xkey/pkg/config"
)

// withLoadedPIVConfig injects cfg into the package-level loadedConfig for the
// duration of the test, restoring the previous value on cleanup -- the same
// injection xkmsd_client_test.go and auth_piv_test.go's withPIVStoragePath
// use, since buildPIVConfig reads the unified config through GetConfig()
// rather than a mockable interface (go-xkms#871).
func withLoadedPIVConfig(t *testing.T, piv xkeyconfig.PIVConfig) {
	t.Helper()
	previous := loadedConfig
	cfg := xkeyconfig.DefaultConfig()
	cfg.PIV = piv
	loadedConfig = cfg
	t.Cleanup(func() { loadedConfig = previous })
}

// TestBuildPIVConfig_ConfigUsedWhenNoFlag proves the loaded config's piv.*
// fields -- which pkg/config.Load merges from the XKEY_PIV_* environment and
// the config file's piv: section -- reach buildPIVConfig when no flag names
// a value, for every setting the command exposes.
func TestBuildPIVConfig_ConfigUsedWhenNoFlag(t *testing.T) {
	resetCommandFlagsForTest(t, PIVCmd)
	withLoadedPIVConfig(t, xkeyconfig.PIVConfig{
		Backend:       "pkcs11",
		Storage:       "file",
		StoragePath:   "/var/lib/xkey/piv-config",
		TPMDevice:     "/dev/config-tpm",
		PKCS11Library: "/usr/lib/config-pkcs11.so",
		PKCS11Token:   "config-token",
	})

	cfg, err := buildPIVConfig(PIVCmd)
	require.NoError(t, err)
	assert.Equal(t, PIVBackendPKCS11, cfg.Backend)
	assert.Equal(t, PIVStorageTypeFile, cfg.StorageType)
	assert.Equal(t, "/var/lib/xkey/piv-config", cfg.StoragePath)
	assert.Equal(t, "/dev/config-tpm", cfg.TPMDevice)
	assert.Equal(t, "/usr/lib/config-pkcs11.so", cfg.PKCS11Library)
	assert.Equal(t, "config-token", cfg.PKCS11Token)
}

// TestBuildPIVConfig_FlagBeatsLoadedConfig proves an explicit flag on cmd
// wins over the loaded config, for both a string setting (backend) and a
// storage override.
func TestBuildPIVConfig_FlagBeatsLoadedConfig(t *testing.T) {
	resetCommandFlagsForTest(t, PIVCmd)
	withLoadedPIVConfig(t, xkeyconfig.PIVConfig{Backend: "pkcs11", Storage: "pkcs11"})

	require.NoError(t, setFlagForTest(t, PIVCmd.PersistentFlags(), "backend", "tpm2"))
	require.NoError(t, setFlagForTest(t, PIVCmd.PersistentFlags(), "piv-storage", "file"))

	cfg, err := buildPIVConfig(PIVCmd)
	require.NoError(t, err)
	assert.Equal(t, PIVBackendTPM2, cfg.Backend, "the flag must win over the loaded config")
	assert.Equal(t, PIVStorageTypeFile, cfg.StorageType, "the flag must win over the loaded config")
}

// TestBuildPIVConfig_InvalidConfigBackendIsRejected proves an unknown
// piv.backend reaching buildPIVConfig from the config still produces the
// same typed error an invalid --backend flag would, at Validate.
func TestBuildPIVConfig_InvalidConfigBackendIsRejected(t *testing.T) {
	resetCommandFlagsForTest(t, PIVCmd)
	withLoadedPIVConfig(t, xkeyconfig.PIVConfig{Backend: "quantum"})

	cfg, err := buildPIVConfig(PIVCmd)
	require.NoError(t, err, "buildPIVConfig itself does not validate")
	require.Equal(t, PIVBackendType("quantum"), cfg.Backend)

	err = cfg.Validate()
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrPIVInvalidBackend)
}

// TestResolvePIVPKCS11Secret_StdinBeatsEnv proves --pkcs11-pin-stdin outranks
// XKEY_PIV_PKCS11_PIN on a command that declares the flag, the same
// precedence pin_input.go's pinSource.resolve gives the host PIN.
func TestResolvePIVPKCS11Secret_StdinBeatsEnv(t *testing.T) {
	resetCommandFlagsForTest(t, PIVCmd)
	t.Setenv("XKEY_PIV_PKCS11_PIN", "from-env")
	stubStdin(t, []byte("from-stdin\n"), nil)
	require.NoError(t, setFlagForTest(t, PIVCmd.PersistentFlags(), "pkcs11-pin-stdin", "true"))

	pin, err := resolvePIVPKCS11Secret(PIVCmd, pivPKCS11PINSource)
	require.NoError(t, err)
	assert.Equal(t, "from-stdin", pin)
}

// TestResolvePIVPKCS11Secret_EnvWhenStdinFlagNotSet proves the environment
// variable is used when the flag is declared but not set.
func TestResolvePIVPKCS11Secret_EnvWhenStdinFlagNotSet(t *testing.T) {
	resetCommandFlagsForTest(t, PIVCmd)
	t.Setenv("XKEY_PIV_PKCS11_SO_PIN", "from-env-so-pin")

	pin, err := resolvePIVPKCS11Secret(PIVCmd, pivPKCS11SOPINSource)
	require.NoError(t, err)
	assert.Equal(t, "from-env-so-pin", pin)
}

// TestResolvePIVPKCS11Secret_NilCmdUsesEnvOnly proves the sibling commands
// that call buildPIVConfig without declaring --pkcs11-pin-stdin (cert,
// device listen, provision) still resolve the PIN from its environment
// variable, matching resolvePIVPKCS11Secret's documented nil-cmd contract.
func TestResolvePIVPKCS11Secret_NilCmdUsesEnvOnly(t *testing.T) {
	t.Setenv("XKEY_PIV_PKCS11_PIN", "from-env-nil-cmd")

	pin, err := resolvePIVPKCS11Secret(nil, pivPKCS11PINSource)
	require.NoError(t, err)
	assert.Equal(t, "from-env-nil-cmd", pin)
}

// TestResolvePIVPKCS11Secret_NoSourceIsEmptyNotError proves an unset PIN is
// not itself an error: whether one is required is the caller's decision
// (createPIVStorage's PKCS#11 session open), the same contract
// resolvePINInput documents for the host PIN.
func TestResolvePIVPKCS11Secret_NoSourceIsEmptyNotError(t *testing.T) {
	resetCommandFlagsForTest(t, PIVCmd)
	t.Setenv("XKEY_PIV_PKCS11_PIN", "")

	pin, err := resolvePIVPKCS11Secret(PIVCmd, pivPKCS11PINSource)
	require.NoError(t, err)
	assert.Empty(t, pin)
}

// TestBuildPIVConfig_PKCS11SecretsNeverComeFromLoadedConfig proves the
// PKCS#11 PIN/SO-PIN are not read from GetConfig().PIV at all -- there is no
// field to read, by construction (xkeyconfig.PIVConfig has no PIN field) --
// so a loaded config can never leak a PIN even if an operator mistakenly
// writes one into xkey.yaml under an unrelated key.
func TestBuildPIVConfig_PKCS11SecretsNeverComeFromLoadedConfig(t *testing.T) {
	resetCommandFlagsForTest(t, PIVCmd)
	withLoadedPIVConfig(t, xkeyconfig.PIVConfig{Backend: "pkcs11"})
	t.Setenv("XKEY_PIV_PKCS11_PIN", "")
	t.Setenv("XKEY_PIV_PKCS11_SO_PIN", "")

	cfg, err := buildPIVConfig(PIVCmd)
	require.NoError(t, err)
	assert.Empty(t, cfg.PKCS11PIN)
	assert.Empty(t, cfg.PKCS11SOPIN)
}

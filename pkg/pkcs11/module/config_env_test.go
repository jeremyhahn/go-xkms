// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

package module

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Environment overrides applied on top of a configuration file.
//
// A PKCS#11 module is loaded into somebody else's process and cannot ask for
// arguments, so the environment is the only channel an operator has for
// pointing it at a different daemon or turning transport security on. Every
// field these tests cover changes where key material goes or how it is
// protected on the way, which is why an override that is silently dropped
// matters more here than a missing feature would.

// TestApplyEnvOverrides_ReplacesEveryConfiguredField proves each supported
// variable reaches its field.
//
// The exhaustive sweep is deliberate. A single variable read into the wrong
// field, or forgotten when the field was added, leaves an operator's
// deployment running on the compiled-in default: still functional, still
// pointed at the wrong daemon, with nothing in the logs to say so. The two
// security-relevant fields — TLS and the insecure-transport opt-out — are set
// away from their defaults so that a no-op override cannot pass.
func TestApplyEnvOverrides_ReplacesEveryConfiguredField(t *testing.T) {
	t.Setenv(EnvTarget, "dns:///kms.example:9443")
	t.Setenv(EnvTLSEnabled, "true")
	t.Setenv(EnvTLSCert, "/etc/xkms/client.crt")
	t.Setenv(EnvTLSKey, "/etc/xkms/client.key")
	t.Setenv(EnvTLSCA, "/etc/xkms/ca.crt")
	t.Setenv(EnvAllowInsecureTransport, "yes")
	t.Setenv(EnvTimeout, "45s")
	t.Setenv(EnvDefaultBackend, "pkcs11")
	t.Setenv(EnvAutoInitToken, "1")
	t.Setenv(EnvSOPIN, "env-so-pin")
	t.Setenv(EnvUserPIN, "env-user-pin")
	t.Setenv(EnvTokenLabel, "Env Token")
	t.Setenv(EnvStorageType, StorageTypeFile)
	t.Setenv(EnvStoragePath, "/var/lib/xkms/pkcs11")
	t.Setenv(EnvPIVBackends, "tpm2,software")

	cfg := DefaultConfig()
	applyEnvOverrides(cfg)

	assert.Equal(t, "dns:///kms.example:9443", cfg.Target)
	assert.True(t, cfg.TLS.Enabled)
	assert.Equal(t, "/etc/xkms/client.crt", cfg.TLS.CertFile)
	assert.Equal(t, "/etc/xkms/client.key", cfg.TLS.KeyFile)
	assert.Equal(t, "/etc/xkms/ca.crt", cfg.TLS.CAFile)
	assert.True(t, cfg.AllowInsecureTransport)
	assert.Equal(t, 45*time.Second, cfg.Timeout)
	assert.Equal(t, "pkcs11", cfg.DefaultBackend)
	assert.True(t, cfg.AutoInitToken)
	assert.Equal(t, "env-so-pin", cfg.SOPIN)
	assert.Equal(t, "env-user-pin", cfg.UserPIN)
	assert.Equal(t, "Env Token", cfg.TokenLabel)
	assert.Equal(t, StorageTypeFile, cfg.StorageType)
	assert.Equal(t, "/var/lib/xkms/pkcs11", cfg.StoragePath)
	assert.Equal(t, []string{"tpm2", "software"}, cfg.PIVBackends)
}

// TestApplyEnvOverrides_LeavesUnsetVariablesAlone proves an unset variable
// does not clear the value a configuration file supplied.
//
// The overrides run after the file is read, so treating an empty environment
// variable as an instruction would wipe the file's settings wholesale — the
// operator's target, certificates and PINs all replaced by empty strings, and
// the module then falling back to defaults it was explicitly configured away
// from.
func TestApplyEnvOverrides_LeavesUnsetVariablesAlone(t *testing.T) {
	t.Setenv(EnvTarget, "")
	t.Setenv(EnvTLSEnabled, "")
	t.Setenv(EnvTimeout, "")
	t.Setenv(EnvDefaultBackend, "")
	t.Setenv(EnvStorageType, "")
	t.Setenv(EnvPIVBackends, "")

	cfg := &Config{
		Target:         "unix:///run/xkms/from-file.sock",
		Timeout:        11 * time.Second,
		DefaultBackend: "tpm2",
		StorageType:    StorageTypeFile,
		StoragePath:    "/var/lib/xkms/from-file",
		PIVBackends:    []string{"from-file"},
	}
	cfg.TLS.Enabled = true

	applyEnvOverrides(cfg)

	assert.Equal(t, "unix:///run/xkms/from-file.sock", cfg.Target)
	assert.True(t, cfg.TLS.Enabled, "an unset override must not turn TLS off")
	assert.Equal(t, 11*time.Second, cfg.Timeout)
	assert.Equal(t, "tpm2", cfg.DefaultBackend)
	assert.Equal(t, StorageTypeFile, cfg.StorageType)
	assert.Equal(t, []string{"from-file"}, cfg.PIVBackends)
}

// TestApplyEnvOverrides_IgnoresUnparsableTimeout proves a malformed duration
// leaves the configured timeout in place.
//
// The timeout bounds every backend call, so replacing it with the zero value
// on a typo would make every operation fail its deadline immediately. Keeping
// the previous value is the conservative choice, and it is the one this test
// pins: the alternative — a zero timeout — is a total outage from a single
// mistyped variable.
func TestApplyEnvOverrides_IgnoresUnparsableTimeout(t *testing.T) {
	t.Setenv(EnvTimeout, "thirty seconds please")

	cfg := &Config{Timeout: 17 * time.Second}
	applyEnvOverrides(cfg)

	assert.Equal(t, 17*time.Second, cfg.Timeout,
		"an unparsable duration must not collapse the timeout to zero")
}

// TestApplyEnvOverrides_BooleanSpellings proves the accepted spellings of a
// boolean variable, and that anything else reads as false.
//
// Operators write these by hand in unit files and container manifests, so
// "1", "yes" and "on" all have to work. Reading an unrecognised spelling as
// true would be the dangerous direction for AllowInsecureTransport, where a
// typo would disable transport security; false is the safe reading.
func TestApplyEnvOverrides_BooleanSpellings(t *testing.T) {
	cases := []struct {
		value string
		want  bool
	}{
		{"true", true},
		{"TRUE", true},
		{"1", true},
		{"yes", true},
		{"on", true},
		{"false", false},
		{"0", false},
		{"no", false},
		{"perhaps", false},
	}

	for _, tc := range cases {
		t.Run(tc.value, func(t *testing.T) {
			t.Setenv(EnvTLSEnabled, tc.value)

			cfg := &Config{}
			applyEnvOverrides(cfg)

			assert.Equal(t, tc.want, cfg.TLS.Enabled)
		})
	}
}

// TestLoadWithPath_EnvironmentOverridesTheFile proves the precedence order
// LoadWithPath documents: defaults, then file, then environment.
//
// This is the ordering an operator relies on to redirect a module without
// editing a file they may not own — a container image ships the file, the
// deployment supplies the environment. If the file won, the environment would
// appear to work in a bare test and be ignored in production.
func TestLoadWithPath_EnvironmentOverridesTheFile(t *testing.T) {
	t.Setenv(EnvTarget, "unix:///run/xkms/from-env.sock")

	cfg, err := LoadWithPath(t.TempDir() + "/no-such-config.conf")
	require.NoError(t, err)

	assert.Equal(t, "unix:///run/xkms/from-env.sock", cfg.Target)
	assert.NotEmpty(t, cfg.Timeout, "LoadWithPath must still apply defaults to fields the environment did not set")
}

// TestLoadWithPath_RejectsInvalidResultingConfiguration proves the validation
// runs after the overrides are applied, not before.
//
// Validating the file and then letting the environment replace a validated
// target with an unparsable one would defeat the check entirely: the module
// would come up, connect to nothing, and report the failure as a device error
// at the first operation instead of as a configuration error at load.
func TestLoadWithPath_RejectsInvalidResultingConfiguration(t *testing.T) {
	t.Setenv(EnvTarget, "not-a-supported-target-scheme")

	cfg, err := LoadWithPath(t.TempDir() + "/no-such-config.conf")
	require.Error(t, err, "an environment override that invalidates the configuration must fail the load")
	assert.Nil(t, cfg)
}

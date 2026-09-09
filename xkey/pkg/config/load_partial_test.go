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
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeConfigFile writes yamlContent to a fresh temp directory and returns
// the path of the written xkey.yaml.
func writeConfigFile(t *testing.T, yamlContent string) string {
	t.Helper()
	cfgPath := filepath.Join(t.TempDir(), "xkey.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte(yamlContent), 0600))
	return cfgPath
}

// TestLoadFromPath_PartialSectionKeepsDefaults pins the #114 merge semantics
// for every defaulted section: a file that sets exactly one leaf key of a
// section gets that key, and every other key in the whole Config — the rest
// of the named section included — equals its DefaultConfig value.
//
// Each case compares the entire loaded Config against DefaultConfig with the
// one expected change applied, so a regression in any field of any section
// fails the case rather than only the fields a hand-written assertion list
// happened to name.
func TestLoadFromPath_PartialSectionKeepsDefaults(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		want func(c *Config)
	}{
		{
			name: "policy",
			yaml: "policy:\n  min_pin_length: 8\n",
			want: func(c *Config) { c.Policy.MinPINLength = 8 },
		},
		{
			name: "backend nested leaf",
			yaml: "backend:\n  tpm2:\n    device: /dev/tpm0\n",
			want: func(c *Config) { c.Backend.TPM2.Device = "/dev/tpm0" },
		},
		{
			name: "fido2",
			yaml: "fido2:\n  device_name: Fleet Key\n",
			want: func(c *Config) { c.FIDO2.DeviceName = "Fleet Key" },
		},
		{
			name: "oath",
			yaml: "oath:\n  digits: 8\n",
			want: func(c *Config) { c.OATH.Digits = 8 },
		},
		{
			name: "phone",
			yaml: "phone:\n  server_address: kms.example.com:8443\n",
			want: func(c *Config) { c.Phone.ServerAddress = "kms.example.com:8443" },
		},
		{
			name: "xkmsd",
			yaml: "xkmsd:\n  address: kms.example.com:8443\n",
			want: func(c *Config) { c.XKMSD.Address = "kms.example.com:8443" },
		},
		{
			name: "tpm",
			yaml: "tpm:\n  seal_pcr_bank: sha384\n",
			want: func(c *Config) { c.TPM.SealPCRBank = "sha384" },
		},
		{
			name: "password_protection",
			yaml: "password_protection:\n  enabled: true\n",
			want: func(c *Config) { c.PasswordProtection.Enabled = true },
		},
		{
			name: "trust",
			yaml: "trust:\n  system_trust: true\n",
			want: func(c *Config) { c.Trust.SystemTrust = true },
		},
		{
			name: "attestation",
			yaml: "attestation:\n  ca_cert: /etc/xkey/attestation-ca.pem\n",
			want: func(c *Config) { c.Attestation.CACert = "/etc/xkey/attestation-ca.pem" },
		},
		{
			name: "log",
			yaml: "log:\n  file: /var/log/xkey.log\n",
			want: func(c *Config) { c.Log.File = "/var/log/xkey.log" },
		},
		{
			name: "gui",
			yaml: "gui:\n  window_width: 800\n",
			want: func(c *Config) { c.GUI.WindowWidth = 800 },
		},
		{
			name: "state",
			yaml: "state:\n  setup_complete: true\n",
			want: func(c *Config) { c.State.SetupComplete = true },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := LoadFromPath(writeConfigFile(t, tc.yaml))
			require.NoError(t, err)

			expected := DefaultConfig()
			tc.want(expected)
			assert.Equal(t, expected, cfg)
		})
	}
}

// TestLoadFromPath_PartialPolicyKeepsSecureGates spells out the rows from
// #114 by name: tightening one policy value must not switch off the Require*
// gates or zero the lockout counter.
func TestLoadFromPath_PartialPolicyKeepsSecureGates(t *testing.T) {
	cfg, err := LoadFromPath(writeConfigFile(t, "policy:\n  min_pin_length: 8\n"))
	require.NoError(t, err)

	defaults := DefaultPolicy()
	assert.Equal(t, 8, cfg.Policy.MinPINLength)
	assert.True(t, cfg.Policy.RequireUserPIN)
	assert.True(t, cfg.Policy.RequireSOPIN)
	assert.True(t, cfg.Policy.RequireEncryptedStorage)
	assert.Equal(t, defaults.StorageType, cfg.Policy.StorageType)
	assert.Equal(t, defaults.PINMaxAttempts, cfg.Policy.PINMaxAttempts)
	assert.True(t, cfg.Policy.ExtensionRequireAuthentication)
	assert.True(t, cfg.Policy.ExtensionRequirePairing)
	assert.True(t, cfg.Policy.ExtensionForceAudit)
	assert.Equal(t, defaults.PolicyVersion, cfg.Policy.PolicyVersion)
}

// TestLoadFromPath_ExplicitZeroValueWins guards the case a naive
// fill-in-the-defaults fix breaks: a value the file sets to its zero value is
// a deliberate setting and must not be overwritten by the default.
func TestLoadFromPath_ExplicitZeroValueWins(t *testing.T) {
	cfg, err := LoadFromPath(writeConfigFile(t, "policy:\n  require_user_pin: false\n  pin_max_attempts: 0\ngui:\n  auto_tray: false\n"))
	require.NoError(t, err)

	assert.False(t, cfg.Policy.RequireUserPIN)
	assert.Equal(t, 0, cfg.Policy.PINMaxAttempts)
	assert.False(t, cfg.GUI.AutoTray)

	// The keys next to them are untouched.
	assert.True(t, cfg.Policy.RequireSOPIN)
	assert.True(t, cfg.GUI.Notifications)
}

// TestLoadFromPath_SliceReplacesDefault checks that a list the file sets
// replaces the seeded default outright rather than appending to it or
// leaving default elements behind past the file's length.
func TestLoadFromPath_SliceReplacesDefault(t *testing.T) {
	cfg, err := LoadFromPath(writeConfigFile(t, "policy:\n  allowed_backends: [tpm2]\n  platform_pcrs: [0, 7]\n"))
	require.NoError(t, err)

	assert.Equal(t, []string{"tpm2"}, cfg.Policy.AllowedBackends)
	assert.Equal(t, []int{0, 7}, cfg.Policy.PlatformPCRs)
	assert.True(t, cfg.Policy.RequireUserPIN)
}

// TestLoad_PartialPolicyKeepsDefaults proves the default-path loader shares
// the merge semantics, since Load and LoadFromHome decode through the same
// function as LoadFromPath.
func TestLoad_PartialPolicyKeepsDefaults(t *testing.T) {
	tmpDir := t.TempDir()
	SetConfigDir(tmpDir)
	t.Cleanup(ResetConfigDir)
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "xkey.yaml"), []byte("policy:\n  min_pin_length: 8\n"), 0600))

	cfg, err := Load()
	require.NoError(t, err)

	expected := DefaultConfig()
	expected.Policy.MinPINLength = 8
	assert.Equal(t, expected, cfg)
}

// TestLoadFromPath_PartialSectionInvalidValueStillRefused makes sure the
// merge does not soften validation: a bad value inside a partial section is
// refused with ErrConfigInvalid exactly as it is in a complete one.
func TestLoadFromPath_PartialSectionInvalidValueStillRefused(t *testing.T) {
	cfg, err := LoadFromPath(writeConfigFile(t, "state:\n  mode: corporate\n"))
	require.Error(t, err)
	assert.Nil(t, cfg)
	assert.ErrorIs(t, err, ErrConfigInvalid)
}
